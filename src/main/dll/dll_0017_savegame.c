/*
 * savegame (DLL 0x17) - the live save-game buffer and its persistence.
 *
 * Owns the in-RAM save image gSaveGameData (0xF70 bytes; the first 0x6EC
 * are the persisted slot, mirrored to lbl_803DD498 and optionally to a
 * restart-point allocation). Provides:
 *   - new-game/load/save flow (gplayNewGame, trySaveGame, gplaySaveGame,
 *     saveGame_save) over the three on-disk slots, via loadSaveGame/_saveGame.
 *   - save-select summaries (saveSelect_getInfo): name, percent-complete
 *     (save byte 0x55D), rank tiers and task-hint phrases.
 *   - per-map act state and object-group status bits, backed by GameBit_*
 *     and cached in the contiguous .bss block gTransientMapBits /
 *     gMapObjGroupStatuses / gExtendedMapActLookup (SaveGameMapState).
 *     Cleared group bits below an act threshold are queued as transient
 *     bits that expire after a few frames (SaveGame_updateTransientMapBits).
 *   - object-position persistence keyed by placement objectId
 *     (saveGame_saveObjectPos / restore / unsave), 0x3F slots at 0x168.
 *   - per-character save/restart points (position, angle, map) and the
 *     time-attack record table at save offset 0x6EC.
 *   - the high-score files (saveData, saveScoreFn_800e88b4) and unlockable
 *     cheat/debug option bits.
 */
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/dll/player_status.h"
#include "main/mapEventTypes.h"
#include "dolphin/os/OSReboot.h"
#include "string.h"
#include "main/gamebits.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/dll_0016_screentransition.h"
#include "main/dll/DR/dll_80209FE0_shared.h"

typedef struct SaveGameTimeEntry
{
    int objId;
    f32 time;
} SaveGameTimeEntry;

typedef struct SaveGameData
{
    u8 pad0[0x20 - 0x0];
    u8 currentCharacter;
    u8 pad21[0x55E - 0x21];
    u8 taskCount;
    u8 pad55F[0x560 - 0x55F];
    f32 playTime;
    u8 pad564[0x6A4 - 0x564];
    s16 camActionNo;
    u8 pad6A6[0x6EC - 0x6A6];
    s16 timeEntryCount; /* 0x6ec: number of valid entries in timeEntries */
    u8 pad6EE[0x6F0 - 0x6EE];
    SaveGameTimeEntry timeEntries[(0xF70 - 0x6F0) / 8]; /* 0x6f0: time-attack record table */
} SaveGameData;

STATIC_ASSERT(offsetof(SaveGameData, timeEntryCount) == 0x6EC);
STATIC_ASSERT(offsetof(SaveGameData, timeEntries) == 0x6F0);
STATIC_ASSERT(sizeof(SaveGameData) == 0xF70);

extern u32 FUN_80006768();
extern u32 FUN_8000676c();
extern u32 FUN_80006c20();
extern u32 FUN_80017500();
extern u32 FUN_8005d018();
extern u8 gGameplayPreviewSettings;
extern u32 DAT_803a3e26;
extern u32 DAT_803a3e27;
extern u32 DAT_803a3e28;
extern u32 DAT_803a3e2a;
extern u32 DAT_803a3e2c;
extern u32 DAT_803a3e2d;
extern u32 gGameplayPreviewColorRed;
extern u32 gGameplayPreviewColorGreen;
extern u32 gGameplayPreviewColorBlue;
extern u32 gGameplayRegisteredDebugOptions;
extern u32* DAT_803dd6d0;
extern u32* DAT_803dd6e8;
extern u8 gSaveGameData[];
extern u8 saveGameLoadStatus;
extern s8 gSaveGameCurrentSlot;
extern u8* lbl_803DD498;
extern char sGameplayFoxName;
extern u8 saveData[228];
extern f32 lbl_803E06C8;
extern f32 lbl_803E06CC;
extern u16 gSaveGameMapActBits[];
extern u16 gSaveGameMapObjGroupBits[];
extern u32 gMapObjGroupStatuses[];
extern u8 gExtendedMapActLookup[];
extern int gSaveGameObjGroupCacheIdx;
extern s8 gSaveGameMapActCacheIdx;
extern u32 pRestartPoint;
extern f32 lbl_803E06D0;
extern f32 lbl_803E06D4;
extern int loadSaveGame(int slot, void* save);
extern int _saveGame(int slot, int save, int data);
extern int maybeTryLoadSave(int a);
extern void mm_free(u32);
extern int unlockLevel(s32 val, int idx, int flag);

extern void audioStopByMask(int mask);
extern void stopRumble2(void);

extern void mapLoadByCoords(f32 x, f32 y, f32 z, int act);
extern int getCurUiDll(void);
extern void loadUiDll(int index);


extern void playerAddHealth(u8* player, int v);
extern void* mmAlloc(int size, int type, int flag);

#define SAVEGAME_OBJECT_POSITION_COUNT 0x3f
#define SAVEGAME_OBJECT_POSITION_OFFSET 0x168
#define SAVEGAME_OBJECT_POSITION_DIRTY_OFFSET 0x20158
#define SAVEGAME_LIVE_BUFFER_SIZE 0xf70
#define SAVEGAME_ACTIVE_SIZE 0x6ec
#define SAVEGAME_PLAYER_NAME_OFFSET 0x1c
#define SAVEGAME_CURRENT_CHARACTER_OFFSET 0x20
#define SAVEGAME_NEW_FILE_FLAG_OFFSET 0x21
#define SAVEGAME_CHARACTER_POSITION_OFFSET 0x684
#define SAVE_SCORE_FILE_STRIDE 0x28
#define SAVE_SCORE_TABLE_OFFSET 0x1c
#define SAVE_SCORE_ENTRY_COUNT 5
/* number of on-disk save-game slots */
#define SAVEGAME_SLOT_COUNT 3
#define SAVEGAME_MAP_COUNT 0x78
#define SAVEGAME_EXTENDED_MAP_THRESHOLD 0x50
#define SAVEGAME_TRANSIENT_MAP_BIT_COUNT 20
#define SAVEGAME_TRANSIENT_MAP_BIT_TTL 3

enum
{
    SAVEGAME_EMPTY_TASK_HINT = -1,
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

typedef struct SaveGameObjectPosition
{
    u32 objectId;
    f32 x;
    f32 y;
    f32 z;
} SaveGameObjectPosition;

typedef struct SaveGameImage
{
    u8 header[SAVEGAME_OBJECT_POSITION_OFFSET];
    SaveGameObjectPosition positions[SAVEGAME_OBJECT_POSITION_COUNT];
} SaveGameImage;

typedef struct SaveGameRomListPosition
{
    u8 pad0[0x8];
    f32 x;
    f32 y;
    f32 z;
    u32 objectId;
} SaveGameRomListPosition;

typedef struct SaveScoreEntry
{
    u32 score : 31;
    u32 flag : 1;
    u8 initials[4];
} SaveScoreEntry;

typedef struct SaveScoreFile
{
    u8 pad0[SAVE_SCORE_TABLE_OFFSET];
    SaveScoreEntry entries[SAVE_SCORE_ENTRY_COUNT];
} SaveScoreFile;

typedef struct SaveGameDefaultPosition
{
    f32 x;
    f32 y;
    f32 z;
} SaveGameDefaultPosition;

typedef struct SaveGameCharacterPosition
{
    f32 x;
    f32 y;
    f32 z;
    s8 angle;
    s8 map;
    u8 padE[2];
} SaveGameCharacterPosition;

#define SAVEGAME_CHARACTER_POSITION(save)                                                     \
    (&((SaveGameCharacterPosition *)((save) + SAVEGAME_CHARACTER_POSITION_OFFSET))             \
         [(save)[SAVEGAME_CURRENT_CHARACTER_OFFSET]])

typedef struct SaveSelectInfo
{
    u8 name[4];
    u8 percentComplete;
    u8 rankA;
    u8 rankB;
    u8 pad7;
    u32 playTime;
    void* taskTexts[5];
    u8 valid;
    u8 active;
    u8 pad22[2];
} SaveSelectInfo;

typedef struct MapBitTransient
{
    s8 mapId;
    u8 shift;
    s8 timer;
} MapBitTransient;

extern MapBitTransient gTransientMapBits[];

/* The three .bss objects gTransientMapBits (0x803A2F80), gMapObjGroupStatuses
 * (+0x3C) and gExtendedMapActLookup (+0x21C) are contiguous; the retail VtableFn
 * addresses them through a single base register (#16 overlay). */
typedef struct SaveGameMapState
{
    MapBitTransient transient[20]; /* 0x000 */
    u32 groupStatuses[120];        /* 0x03C */
    u8 extendedMapActLookup[40];   /* 0x21C */
} SaveGameMapState;
#define gSaveGameMapState (*(SaveGameMapState*)gTransientMapBits)

extern SaveGameDefaultPosition gSaveGameDefaultPosition;

int saveGame_restoreObjectPosToRomList(SaveGameRomListPosition* object)
{
    u8* walker;
    u8* slot;
    int i;

    for (i = 0; i < SAVEGAME_OBJECT_POSITION_COUNT; i++)
    {
        if (object->objectId == ((SaveGameImage*)gSaveGameData)->positions[i].objectId)
        {
            slot = gSaveGameData;
            slot += i * sizeof(SaveGameObjectPosition);
            object->x = *(f32*)(slot + SAVEGAME_OBJECT_POSITION_OFFSET + 4);
            object->y = *(f32*)(slot + SAVEGAME_OBJECT_POSITION_OFFSET + 8);
            object->z = *(f32*)(slot + SAVEGAME_OBJECT_POSITION_OFFSET + 12);
            return 1;
        }
    }

    return 0;
}

void saveGame_unsaveObjectPos(u8* obj)
{
    int i;
    SaveGameObjectPosition* slot;
    u32 objectId;
    int status;

    if ((((GameObject*)obj)->anim.flags & 0x2000) != 0)
    {
        return;
    }
    status = saveGameLoadStatus;
    if (status != 0)
    {
        return;
    }

    for (i = 0; i < SAVEGAME_OBJECT_POSITION_COUNT; i++)
    {
        objectId = *(u32*)(*(u8**)&((GameObject*)obj)->anim.placementData + 0x14);
        if (objectId == ((SaveGameImage*)gSaveGameData)->positions[i].objectId)
        {
            break;
        }
    }
    if (i == SAVEGAME_OBJECT_POSITION_COUNT)
    {
        return;
    }

    slot = (SaveGameObjectPosition*)gSaveGameData + i;
    for (; i < SAVEGAME_OBJECT_POSITION_COUNT - 1; i++, slot++)
    {
        *(u32*)((u8*)slot + SAVEGAME_OBJECT_POSITION_OFFSET + 0) = *(u32*)((u8*)slot + SAVEGAME_OBJECT_POSITION_OFFSET + 16);
        *(f32*)((u8*)slot + SAVEGAME_OBJECT_POSITION_OFFSET + 4) = *(f32*)((u8*)slot + SAVEGAME_OBJECT_POSITION_OFFSET + 20);
        *(f32*)((u8*)slot + SAVEGAME_OBJECT_POSITION_OFFSET + 8) = *(f32*)((u8*)slot + SAVEGAME_OBJECT_POSITION_OFFSET + 24);
        *(f32*)((u8*)slot + SAVEGAME_OBJECT_POSITION_OFFSET + 12) = *(f32*)((u8*)slot + SAVEGAME_OBJECT_POSITION_OFFSET + 28);
    }
    *(u32*)(gSaveGameData + SAVEGAME_OBJECT_POSITION_DIRTY_OFFSET) = 0;
}

int trySaveGame(int slot)
{
    int loaded;

    gSaveGameCurrentSlot = slot;
    memset(gSaveGameData, 0, SAVEGAME_LIVE_BUFFER_SIZE);
    if ((lbl_803DD498[0x21] & 0x80) == 0)
    {
        memset(lbl_803DD498, 0, SAVEGAME_ACTIVE_SIZE);
    }

    loaded = loadSaveGame((u8)gSaveGameCurrentSlot, lbl_803DD498);
    if (loaded != 0)
    {
        if (lbl_803DD498[0x21] == 0)
        {
            loaded = gplayNewGame(&sGameplayFoxName, (u8)gSaveGameCurrentSlot);
        }
        else
        {
            memcpy(gSaveGameData, lbl_803DD498, SAVEGAME_ACTIVE_SIZE);
        }
    }
    else
    {
        gplayNewGame(&sGameplayFoxName, -1);
    }
    return loaded;
}

int saveScoreFn_800e88b4(u8 slot, u8 flag, u32 score, u8* initials)
{
    int rank;
    SaveScoreFile* file;
    int off;
    int i;

    rank = 0;
    off = slot * SAVE_SCORE_FILE_STRIDE;
    file = (SaveScoreFile*)(saveData + off);
    for (; rank < SAVE_SCORE_ENTRY_COUNT; rank++)
    {
        if (score > file->entries[rank].score)
        {
            for (i = SAVE_SCORE_ENTRY_COUNT - 1; i > rank; i--)
            {
                file->entries[i].score = file->entries[i - 1].score;
                file->entries[i].flag = file->entries[i - 1].flag;
                file->entries[i].initials[0] = file->entries[i - 1].initials[0];
                file->entries[i].initials[1] = file->entries[i - 1].initials[1];
                file->entries[i].initials[2] = file->entries[i - 1].initials[2];
                file->entries[i].initials[3] = file->entries[i - 1].initials[3];
            }

            file->entries[rank].score = score;
            file->entries[rank].flag = flag;
            ((SaveScoreFile*)((int)saveData + off))->entries[rank].initials[0] = initials[0];
            ((SaveScoreFile*)((int)saveData + off))->entries[rank].initials[1] = initials[1];
            ((SaveScoreFile*)((int)saveData + off))->entries[rank].initials[2] = initials[2];
            ((SaveScoreFile*)((int)saveData + off))->entries[rank].initials[3] = initials[3];
            return rank;
        }
    }

    return -1;
}

int gplayNewGame(char* name, int slot)
{
    SaveGameDefaultPosition defaultPos;
    int i;
    u8* dst;
    u8 c;
    u8* save;

    defaultPos = gSaveGameDefaultPosition;

    memset(gSaveGameData, 0, SAVEGAME_LIVE_BUFFER_SIZE);
    if ((lbl_803DD498[SAVEGAME_NEW_FILE_FLAG_OFFSET] & 0x80) == 0)
    {
        memset(lbl_803DD498, 0, SAVEGAME_ACTIVE_SIZE);
    }

    save = gSaveGameData;
    save[SAVEGAME_CURRENT_CHARACTER_OFFSET] = 0;
    save[0] = 0xc;
    save[1] = 0xc;
    *(u16*)(save + 6) = 0x19;
    *(u16*)(save + 4) = 0;
    save[0xa] = 1;
    *(s8*)(save + 0x692) = -1;
    save[0xc] = 0xc;
    save[0xd] = 0xc;
    *(u16*)(save + 0x12) = 0x19;
    *(u16*)(save + 0x10) = 0;
    save[0x16] = 1;
    *(s8*)(save + 0x6a2) = -1;
    save[0x19] = 0x14;
    *(s16*)(save + 0x6a4) = -1;
    *(f32*)(save + 0x6a8) = lbl_803E06C8;
    *(s16*)(save + 0x6ac) = -1;
    *(s16*)(save + 0x6ae) = -1;
    *(s16*)(save + 0x6b2) = -1;
    *(s16*)(save + 0x6b4) = -1;
    *(s16*)(save + 0x6b6) = -1;
    *(s16*)(save + 0x6b8) = -1;
    *(s16*)(save + 0x6ba) = -1;
    *(s8*)(save + 0x6e9) = -1;
    *(s8*)(save + 0x6ea) = -1;
    *(s8*)(save + 0x6eb) = -1;
    save[0x6e8] = 9;
    save[0x23] = 0;
    save[SAVEGAME_NEW_FILE_FLAG_OFFSET] = 1;

    for (i = 0; i < SAVEGAME_MAP_COUNT; i++)
    {
        if (gSaveGameMapActBits[i] != 0)
        {
            (*gMapEventInterface)->setMapAct(i, 1);
        }
    }

    SaveGame_gplaySetObjGroupStatus(7, 0, 1);
    SaveGame_gplaySetObjGroupStatus(7, 2, 1);
    SaveGame_gplaySetObjGroupStatus(7, 3, 1);
    SaveGame_gplaySetObjGroupStatus(7, 5, 1);
    SaveGame_gplaySetObjGroupStatus(7, 10, 1);
    SaveGame_gplaySetObjGroupStatus(0x1d, 0, 1);
    SaveGame_gplaySetObjGroupStatus(0x1d, 0x1f, 1);
    SaveGame_gplaySetObjGroupStatus(0x13, 0, 1);
    SaveGame_gplaySetObjGroupStatus(0x13, 0x16, 1);
    GameBit_Set(0x967, 1);

    *(f32*)(gSaveGameData + gSaveGameData[SAVEGAME_CURRENT_CHARACTER_OFFSET] * 0x10 +
        SAVEGAME_CHARACTER_POSITION_OFFSET) = defaultPos.x;
    *(f32*)(gSaveGameData + gSaveGameData[SAVEGAME_CURRENT_CHARACTER_OFFSET] * 0x10 +
        SAVEGAME_CHARACTER_POSITION_OFFSET + 4) = defaultPos.y;
    *(f32*)(gSaveGameData + gSaveGameData[SAVEGAME_CURRENT_CHARACTER_OFFSET] * 0x10 +
        SAVEGAME_CHARACTER_POSITION_OFFSET + 8) = defaultPos.z;
    gSaveGameData[0x55d] = 1;

    if (name != NULL)
    {
        dst = gSaveGameData + SAVEGAME_PLAYER_NAME_OFFSET;
        do
        {
            c = *(u8*)name;
            name++;
            *dst++ = c;
        }
        while (c != '\0');
    }
    else
    {
        gSaveGameData[SAVEGAME_PLAYER_NAME_OFFSET + 0] = 'F';
        gSaveGameData[SAVEGAME_PLAYER_NAME_OFFSET + 1] = 'O';
        gSaveGameData[SAVEGAME_PLAYER_NAME_OFFSET + 2] = 'X';
        gSaveGameData[SAVEGAME_PLAYER_NAME_OFFSET + 3] = '\0';
    }

    memcpy(lbl_803DD498, gSaveGameData, SAVEGAME_ACTIVE_SIZE);
    if ((s8)slot != -1)
    {
        gSaveGameCurrentSlot = slot;
        if (name != NULL)
        {
            return _saveGame((u8)slot, (int)lbl_803DD498, (int)saveData);
        }
    }
    return 0;
}

void SaveGame_gplaySetObjGroupStatus(int idx, int shift, int value)
{
    SaveGameMapState* s = &gSaveGameMapState;
    u8 createTransient = 0;
    u32 newStatus;
    int oldStatus;
    u32 bit;
    int i;
    MapBitTransient* transient;
    MapBitTransient* slot;
    s8 found;

    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD)
    {
        idx = s->extendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    }
    if (!(idx < SAVEGAME_MAP_COUNT && gSaveGameMapObjGroupBits[idx] != 0))
    {
        return;
    }
    {
        if (value == -1)
        {
            value = 1;
        }
        if (value == -2)
        {
            value = 0;
            createTransient = 1;
        }

        newStatus = GameBit_Get(gSaveGameMapObjGroupBits[idx]);
        oldStatus = newStatus;
        if (value != 0)
        {
            bit = 1 << shift;
            newStatus = newStatus | bit;
        }
        else
        {
            bit = 1 << shift;
            bit = ~bit;
            newStatus = newStatus & bit;
        }

        GameBit_Set(gSaveGameMapObjGroupBits[idx], newStatus);
        gSaveGameObjGroupCacheIdx = idx;
        (&gSaveGameObjGroupCacheIdx)[1] = newStatus;

        if (value != 0)
        {
            if ((oldStatus & (1 << shift)) == 0)
            {
                u32* gp = s->groupStatuses;
                for (i = 0; i < SAVEGAME_MAP_COUNT; i++)
                {
                    if (gSaveGameMapObjGroupBits[i] == gSaveGameMapObjGroupBits[idx])
                    {
                        gp[i] |= (u32)(1 << shift);
                    }
                }
            }
        }
        else
        {
            u32* gp = s->groupStatuses;
            for (i = 0; i < SAVEGAME_MAP_COUNT; i++)
            {
                if (gSaveGameMapObjGroupBits[i] == gSaveGameMapObjGroupBits[idx])
                {
                    gp[i] &= ~(u32)(1 << shift);
                }
            }

            if (!createTransient)
            {
                transient = s->transient;
                for (i = 0; i < SAVEGAME_TRANSIENT_MAP_BIT_COUNT; i++)
                {
                    if (transient[i].mapId == idx && transient[i].shift == shift)
                    {
                        found = i;
                        goto checkedTransient;
                    }
                }
                found = -1;
            checkedTransient:
                if (found == -1)
                {
                    for (i = 0; i < SAVEGAME_TRANSIENT_MAP_BIT_COUNT; i++)
                    {
                        if (transient[i].mapId == -1)
                        {
                            slot = &transient[i];
                            slot->mapId = idx;
                            slot->shift = shift;
                            slot->timer = SAVEGAME_TRANSIENT_MAP_BIT_TTL;
                            break;
                        }
                    }
                }
            }
        }
    }
}

int saveSelect_getInfo(void* outPtr)
{
    SaveSelectInfo* info;
    u8 save[SAVEGAME_ACTIVE_SIZE];
    int slot;
    int i;
    u8* taskIds;
    u8 newFileFlag;

    slot = 0;
    do
    {
        info = (SaveSelectInfo*)outPtr + slot;
        if (loadSaveGame((u8)slot, save) != 0)
        {
            newFileFlag = save[SAVEGAME_NEW_FILE_FLAG_OFFSET];
            info->valid = newFileFlag;
            if (newFileFlag != 0)
            {
            memcpy(info, save + SAVEGAME_PLAYER_NAME_OFFSET, sizeof(info->name));

            info->percentComplete = (u8)((save[0x55d] * 100) / 0xbb);
            if (save[0x55d] > 0xb3)
            {
                info->rankA = 6;
                info->rankB = 4;
            }
            else if (save[0x55d] > 0xb0)
            {
                info->rankA = 5;
                info->rankB = 4;
            }
            else if (save[0x55d] > 0xa1)
            {
                info->rankA = 4;
                info->rankB = 4;
            }
            else if (save[0x55d] > 0x8a)
            {
                info->rankA = 4;
                info->rankB = 3;
            }
            else if (save[0x55d] > 0x81)
            {
                info->rankA = 3;
                info->rankB = 3;
            }
            else if (save[0x55d] > 0x71)
            {
                info->rankA = 3;
                info->rankB = 2;
            }
            else if (save[0x55d] > 0x62)
            {
                info->rankA = 2;
                info->rankB = 2;
            }
            else if (save[0x55d] > 0x48)
            {
                info->rankA = 2;
                info->rankB = 1;
            }
            else if (save[0x55d] > 0x3d)
            {
                info->rankA = 1;
                info->rankB = 1;
            }
            else if (save[0x55d] > 8)
            {
                info->rankA = 1;
                info->rankB = 0;
            }
            else
            {
                info->rankA = 0;
                info->rankB = 0;
            }

            info->playTime = (u32)(((SaveGameData*)save)->playTime / lbl_803E06CC);
            info->taskTexts[0] = NULL;
            info->taskTexts[1] = NULL;
            info->taskTexts[2] = NULL;
            info->taskTexts[3] = NULL;
            info->taskTexts[4] = NULL;
            taskIds = save + 0x558;
            for (i = 0; i < save[0x55e]; i++)
            {
                info->taskTexts[i] = gameTextGetPhrase(taskIds[i] + 0xf4, 0);
            }
            info->active = 0;
            info->valid = save[SAVEGAME_NEW_FILE_FLAG_OFFSET];
            }
            else
            {
                memset(info, 0, sizeof(SaveSelectInfo));
            }
        }
        else
        {
            return 0;
        }

        slot++;
    }
    while (slot < SAVEGAME_SLOT_COUNT);

    return 1;
}

void saveFileStruct_unlockCheat(u32 cheatId)
{
    gGameplayRegisteredDebugOptions = gGameplayRegisteredDebugOptions | 1 << (cheatId & 0xff);
}

u32 isCheatUnlocked(u32 cheatId)
{
    return gGameplayRegisteredDebugOptions & 1 << (cheatId & 0xff);
}

void saveFileStruct_resetVolumes(void)
{
    gGameplayPreviewColorRed = 0x7f;
    gGameplayPreviewColorGreen = 0x7f;
    gGameplayPreviewColorBlue = 0x7f;
}

u8* getSaveFileStruct(void)
{
    return &gGameplayPreviewSettings;
}

void loadSaveSettings(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
                      u64 param_5, u64 param_6, u64 param_7,
                      u64 param_8)
{
    FUN_8005d018(DAT_803a3e2a);
    FUN_80017500(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, DAT_803a3e26);
    FUN_80006c20(DAT_803a3e2c);
    FUN_80006768(DAT_803a3e2d, '\0');
    (**(VtableFn**)(*DAT_803dd6e8 + 0x50))(DAT_803a3e27);
    (**(VtableFn**)(*DAT_803dd6d0 + 0x6c))(DAT_803a3e28);
    FUN_8000676c((u32)gGameplayPreviewColorGreen, 10, 0, 1, 0);
    FUN_8000676c((u32)gGameplayPreviewColorRed, 10, 1, 0, 0);
    FUN_8000676c((u32)gGameplayPreviewColorBlue, 10, 0, 0, 1);
    return;
}

int saveFn_800e8508(void)
{
    int loadResult;

    loadResult = maybeTryLoadSave((int)saveData);
    if ((loadResult == 0) || (saveData[0] == '\0'))
    {
        memset(saveData, 0, 0xE4);
        saveData[6] = 0;
        saveData[2] = 1;
        saveData[8] = 1;
        saveData[0] = 1;
        saveData[10] = 0x7F;
        saveData[11] = 0x7F;
        saveData[12] = 0x7F;
    }
    return loadResult;
}

void gplaySaveGame(int param)
{
    gSaveGameData[0x21] = 0;
    gSaveGameCurrentSlot = param;
    if (gSaveGameData[0x22] == 0)
    {
        memcpy(lbl_803DD498, gSaveGameData, 0x564);
        if (pRestartPoint != 0)
        {
            memcpy((void*)pRestartPoint, gSaveGameData, 0x564);
        }
    }
    if ((s8)gSaveGameCurrentSlot == -1)
    {
        gSaveGameCurrentSlot = 0;
    }
    if ((s8)lbl_803DD498[0] < 1)
    {
        lbl_803DD498[0] = 1;
    }
    if ((s8)lbl_803DD498[0xc] < 1)
    {
        lbl_803DD498[0xc] = 1;
    }
    _saveGame((u8)gSaveGameCurrentSlot, (int)lbl_803DD498, (int)saveData);
}

void titleDoLoadSave(void)
{
    OSSetSaveRegion(0, 0);
    gSaveGameCurrentSlot = (s8)((lbl_803DD498[0x21] & 0x60) >> 5);
    lbl_803DD498[0x21] = lbl_803DD498[0x21] & ~0xE0;
    (*gMapEventInterface)->gotoSavegame();
}

void saveGame_save(void)
{
    if (gSaveGameData[0x22] == 0)
    {
        memcpy(lbl_803DD498, gSaveGameData, 0x564);
        if (pRestartPoint != 0)
        {
            memcpy((void*)pRestartPoint, gSaveGameData, 0x564);
        }
    }
    if ((s8)gSaveGameCurrentSlot == -1)
    {
        gSaveGameCurrentSlot = 0;
    }
    if ((s8)lbl_803DD498[0] < 1)
    {
        lbl_803DD498[0] = 1;
    }
    if ((s8)lbl_803DD498[0xc] < 1)
    {
        lbl_803DD498[0xc] = 1;
    }
    _saveGame((u8)gSaveGameCurrentSlot, (int)lbl_803DD498, (int)saveData);
}

void SaveGame_func08_nop(void)
{
}

u8 getSaveGameLoadStatus(void) { return saveGameLoadStatus; }

void setSaveGameLoadingFlag(void) { if (saveGameLoadStatus == 2) saveGameLoadStatus = 1; }
s32 isSaveGameLoading(void) { return saveGameLoadStatus == 2; }

void clearSaveGameLoadingFlag(void) { saveGameLoadStatus = 0x0; }

void SaveGame_release(void) { if (pRestartPoint != 0) mm_free(pRestartPoint); }

void SaveGame_initialise(void)
{
    s8* base = (s8*)gTransientMapBits;
    int i;
    memset(base + 0x328, 0, SAVEGAME_LIVE_BUFFER_SIZE);
    if (!(lbl_803DD498[0x21] & 0x80))
    {
        memset(lbl_803DD498, 0, SAVEGAME_ACTIVE_SIZE);
    }
    pRestartPoint = 0;
    gSaveGameMapActCacheIdx = -1;
    gSaveGameObjGroupCacheIdx = -1;
    memset(base + 0x244, 0, 0xe4);
    base[0x24a] = 0;
    base[0x246] = 1;
    base[0x24c] = 1;
    base[0x244] = 1;
    base[0x24e] = SAVEGAME_DEFAULT_VOLUME;
    base[0x24f] = SAVEGAME_DEFAULT_VOLUME;
    base[0x250] = SAVEGAME_DEFAULT_VOLUME;
    base[0x00] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x03] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x06] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x09] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x0c] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x0f] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x12] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x15] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x18] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x1b] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x1e] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x21] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x24] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x27] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x2a] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x2d] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x30] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x33] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x36] = SAVEGAME_EMPTY_TASK_HINT;
    base[0x39] = SAVEGAME_EMPTY_TASK_HINT;
}

void SaveGame_gplayClearRestartPoint(void)
{
    if (pRestartPoint != 0)
    {
        mm_free(pRestartPoint);
        pRestartPoint = 0;
    }
}

void loadMapForCurrentSaveGame(void);

void SaveGame_gplayGotoRestartPoint(void)
{
    if (pRestartPoint != 0)
    {
        memcpy(gSaveGameData, (void*)pRestartPoint, SAVEGAME_ACTIVE_SIZE);
    }
    else
    {
        memcpy(gSaveGameData, lbl_803DD498, SAVEGAME_ACTIVE_SIZE);
    }
    loadMapForCurrentSaveGame();
}

void SaveGame_gplayGotoSavegame(void)
{
    if ((s8)lbl_803DD498[0] < 1) lbl_803DD498[0] = 1;
    if ((s8)lbl_803DD498[0xc] < 1) lbl_803DD498[0xc] = 1;
    memcpy(gSaveGameData, lbl_803DD498, SAVEGAME_ACTIVE_SIZE);
    loadMapForCurrentSaveGame();
}

void loadMapForCurrentSaveGame(void)
{
    char* base;
    gSaveGameMapActCacheIdx = -1;
    gSaveGameObjGroupCacheIdx = -1;
    unlockLevel(0, 0, 1);
    memset((char*)gSaveGameData + 0x6ec, 0, 0x884);
    cutsceneExit();
    audioStopByMask(7);
    stopRumble2();
    resetYbutton();
    base = (char*)gSaveGameData + ((SaveGameData*)gSaveGameData)->currentCharacter * 16;
    mapLoadByCoords(*(f32*)(base + 0x684), *(f32*)(base + 0x688), *(f32*)(base + 0x68c), *(s8*)(base + 0x691));
    if (getCurUiDll() != 4)
    {
        loadUiDll(1);
    }
    screenTransitionFn_800d7b04(0x1e, 1);
    saveGameLoadStatus = 2;
}

void saveGame_saveObjectPos(int* obj);

void saveGame_saveObjectPos(int* obj)
{
    int v;
    int i;
    int status;
    if (((GameObject*)obj)->anim.flags & 0x2000) return;
    status = saveGameLoadStatus;
    if (status == 0)
    {
        for (i = 0; i < SAVEGAME_OBJECT_POSITION_COUNT; i++)
        {
            v = ((SaveGameImage*)gSaveGameData)->positions[i].objectId;
            if (v == 0) break;
            if (*(u32*)(*(u8**)&((GameObject*)obj)->anim.placementData + 0x14) == v) break;
        }
        if (i == SAVEGAME_OBJECT_POSITION_COUNT) return;
        {
            int objectId = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
            char* entry;
            *(int*)((entry = (char*)gSaveGameData + i * sizeof(SaveGameObjectPosition)) + SAVEGAME_OBJECT_POSITION_OFFSET) = objectId;
            *(f32*)(entry + SAVEGAME_OBJECT_POSITION_OFFSET + 4) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)(entry + SAVEGAME_OBJECT_POSITION_OFFSET + 8) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)(entry + SAVEGAME_OBJECT_POSITION_OFFSET + 0xc) = ((GameObject*)obj)->anim.localPosZ;
        }
        *(f32*)(*(int*)&((GameObject*)obj)->anim.placementData + 8) = ((GameObject*)obj)->anim.localPosX;
        ((GameObject*)((GameObject*)obj)->anim.placementData)->anim.localPosX = ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)((GameObject*)obj)->anim.placementData)->anim.localPosY = ((GameObject*)obj)->anim.localPosZ;
    }
}

void SaveGame_setCamActionNo(s16 actionNo) { ((SaveGameData*)gSaveGameData)->camActionNo = actionNo; }
void* SaveGame_getLast(void) { return gSaveGameData; }
s32 SaveGame_getCamActionNo(void) { return ((SaveGameData*)gSaveGameData)->camActionNo; }
void* saveGameGetEnvState(void) { return gSaveGameData + 0x6a8; }
f32 SaveGame_getPlayTime(void) { return ((SaveGameData*)gSaveGameData)->playTime; }

void SaveGame_updateTimes(void)
{
    u8* p;
    int i;
    u8* base;
    s16 cnt;
    i = 0;
    base = gSaveGameData;
    ((SaveGameData*)base)->playTime = ((SaveGameData*)base)->playTime + timeDelta;
    p = base;
    while (i < ((SaveGameData*)base)->timeEntryCount)
    {
        if (((SaveGameData*)base)->playTime > *(f32*)(p + 0x6f4))
        {
            cnt = (((SaveGameData*)base)->timeEntryCount -= 1);
            *(int*)(p + 0x6f0) = ((SaveGameTimeEntry*)(base + 0x6f0))[cnt].objId;
            *(f32*)(p + 0x6f4) = ((SaveGameTimeEntry*)(base + 0x6f0))[((SaveGameData*)base)->timeEntryCount].time;
        }
        else
        {
            p += 8;
            i++;
        }
    }
    if (((SaveGameData*)gSaveGameData)->taskCount > 5) *(u8*)0 = 0; /* assert: task count <= 5 */
    if (((SaveGameData*)lbl_803DD498)->taskCount > 5) *(u8*)0 = 0; /* assert: task count <= 5 */
}

f32 SaveGame_gplayGetTime(int id)
{
    s16 count;
    u8* p;
    int i;
    if (id == -1) return lbl_803E06D0;
    i = 0;
    p = gSaveGameData;
    count = ((SaveGameData*)p)->timeEntryCount;
    for (; i < count; i++)
    {
        if (*(int*)(p + 0x6f0) == id)
        {
            p = gSaveGameData;
            return ((SaveGameTimeEntry*)(p + 0x6f0))[i].time - ((SaveGameData*)p)->playTime;
        }
        p += 8;
    }
    return lbl_803E06D0;
}

int SaveGame_gplayShouldNotSaveTime(int id)
{
    u8* p;
    s16 count;
    int i;
    if (id == -1) return 1;
    p = gSaveGameData;
    count = ((SaveGameData*)p)->timeEntryCount;
    for (i = 0; i < count; i++)
    {
        if (*(int*)(p + 0x6f0) == id) return 0;
        p += 8;
    }
    return 1;
}

void SaveGame_gplayAddTime(int id, f32 time)
{
    u8* base;
    u8* p;
    s16 count;
    int i;
    f32 total;
    if (id == -1) return;
    base = gSaveGameData;
    count = ((SaveGameData*)base)->timeEntryCount;
    if (count == 0x100) return;
    total = lbl_803E06D4 * time;
    total += ((SaveGameData*)base)->playTime;
    i = 0;
    p = base;
    for (; i < count; i++)
    {
        if (*(int*)(p + 0x6f0) == id) break;
        p += 8;
    }
    if (i == count)
    {
        ((SaveGameData*)base)->timeEntryCount++;
    }
    base = gSaveGameData;
    p = base;
    p += i * 8;
    *(int*)(p + 0x6f0) = id;
    *(f32*)(p + 0x6f4) = total;
}

void* SaveGame_getTrickyEnergy(void) { return gSaveGameData + 0x18; }
void SaveGame_setCharacter(u8 c) { ((SaveGameData*)gSaveGameData)->currentCharacter = c; }
u8 SaveGame_getCurChar(void) { return ((SaveGameData*)gSaveGameData)->currentCharacter; }
char* getSaveFileName(void) { return (char*)gSaveGameData + 0x1c; }

void* SaveGame_getCurCharPos(void)
{
    int idx = ((SaveGameData*)gSaveGameData)->currentCharacter;
    return gSaveGameData + idx * 16 + 0x684;
}

void* SaveGame_getCurCharacterState(void)
{
    int idx = ((SaveGameData*)gSaveGameData)->currentCharacter;
    return gSaveGameData + idx * 12;
}

s32 SaveGame_gplayGetRestartGameNotCleared(void) { return pRestartPoint != 0; }
u16 SaveGame_getMapObjGroupBit(int idx) { return gSaveGameMapObjGroupBits[idx]; }

void SaveGame_setMapActLut(int val, int idx)
{
    *(u8*)((char*)gExtendedMapActLookup + idx - SAVEGAME_EXTENDED_MAP_THRESHOLD) = val;
}

void updateSavedHealth(void)
{
    int idx = ((SaveGameData*)gSaveGameData)->currentCharacter * 12;
    *((u8*)gSaveGameData + idx) = lbl_803DD498[idx];
}

u32 SaveGame_mapGetObjGroups(int idx)
{
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) idx = *(u8*)((char*)gExtendedMapActLookup + idx -
        SAVEGAME_EXTENDED_MAP_THRESHOLD);
    return gMapObjGroupStatuses[idx];
}

void mapClearBit(int idx, int bit)
{
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) idx = *(u8*)((char*)gExtendedMapActLookup + idx -
        SAVEGAME_EXTENDED_MAP_THRESHOLD);
    gMapObjGroupStatuses[idx] &= ~(1 << bit);
}

void SaveGame_resetObjGroups(int idx)
{
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) idx = *(u8*)((char*)gExtendedMapActLookup + idx -
        SAVEGAME_EXTENDED_MAP_THRESHOLD);
    gMapObjGroupStatuses[idx] = 0;
}

void SaveGame_mapUpdateObjGroups(int idx)
{
    u16 bit;
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) idx = *(u8*)((char*)gExtendedMapActLookup + idx -
        SAVEGAME_EXTENDED_MAP_THRESHOLD);
    bit = gSaveGameMapObjGroupBits[idx];
    if (bit != 0)
    {
        gMapObjGroupStatuses[idx] = GameBit_Get(bit);
    }
}

u8 SaveGame_getMapAct(int idx)
{
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) idx = *(u8*)((char*)gExtendedMapActLookup + idx -
        SAVEGAME_EXTENDED_MAP_THRESHOLD);
    if (idx != gSaveGameMapActCacheIdx)
    {
        gSaveGameMapActCacheIdx = idx;
        if (idx < 0 || idx >= SAVEGAME_MAP_COUNT || gSaveGameMapActBits[idx] == 0)
        {
            *((s8*)&gSaveGameMapActCacheIdx + 1) = 0;
        }
        else
        {
            *((s8*)&gSaveGameMapActCacheIdx + 1) = GameBit_Get(gSaveGameMapActBits[idx]);
        }
    }
    return *((u8*)&gSaveGameMapActCacheIdx + 1);
}

int SaveGame_gplayGetObjGroupStatus(int idx, int shift)
{
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) idx = *(u8*)((char*)gExtendedMapActLookup + idx -
        SAVEGAME_EXTENDED_MAP_THRESHOLD);
    if (idx != gSaveGameObjGroupCacheIdx)
    {
        gSaveGameObjGroupCacheIdx = idx;
        (&gSaveGameObjGroupCacheIdx)[1] = GameBit_Get(gSaveGameMapObjGroupBits[idx]);
    }
    return ((&gSaveGameObjGroupCacheIdx)[1] >> shift) & 1;
}

void SaveGame_gplaySetAct(int idx, int act)
{
    int j;
    u16 bit;
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) idx = *(u8*)((char*)gExtendedMapActLookup + idx -
        SAVEGAME_EXTENDED_MAP_THRESHOLD);
    GameBit_Set(gSaveGameMapActBits[idx], act);
    gSaveGameMapActCacheIdx = idx;
    *((s8*)&gSaveGameMapActCacheIdx + 1) = act;
    j = idx;
    if (j >= SAVEGAME_EXTENDED_MAP_THRESHOLD) j = *(u8*)((char*)gExtendedMapActLookup + j -
        SAVEGAME_EXTENDED_MAP_THRESHOLD);
    bit = gSaveGameMapObjGroupBits[j];
    if (bit != 0)
    {
        gMapObjGroupStatuses[j] = GameBit_Get(bit);
    }
}

s8 SaveGame_findTransientMapBit(int a, int b)
{
    int i;
    for (i = 0; i < SAVEGAME_TRANSIENT_MAP_BIT_COUNT; i++)
    {
        if (a == gTransientMapBits[i].mapId && b == gTransientMapBits[i].shift)
        {
            return i;
        }
    }
    return -1;
}

void SaveGame_gplaySavePoint(f32* pos, s16 angle, int flags, int mapByte)
{
    u8* base;
    if (flags & 4)
    {
        gSaveGameData[0x22] = 0;
    }
    base = gSaveGameData;
    if (base[0x22] == 0)
    {
        if (flags & 1)
        {
            memcpy(lbl_803DD498, base, 0x5d8);
            if (pRestartPoint != 0)
            {
                memcpy((void*)pRestartPoint, gSaveGameData, 0x5d8);
            }
        }
        else
        {
            SAVEGAME_CHARACTER_POSITION(base)->x = pos[0];
            SAVEGAME_CHARACTER_POSITION(base)->y = pos[1];
            SAVEGAME_CHARACTER_POSITION(base)->z = pos[2];
            SAVEGAME_CHARACTER_POSITION(base)->angle = (s8)(angle >> 8);
            SAVEGAME_CHARACTER_POSITION(base)->map = mapByte;
            memcpy(lbl_803DD498, base, SAVEGAME_ACTIVE_SIZE);
            if (pRestartPoint != 0)
            {
                mm_free(pRestartPoint);
                pRestartPoint = 0;
            }
        }
        if (flags & 2)
        {
            base[0x22] = 1;
        }
    }
}

void SaveGame_gplayRestartPoint(f32* pos, s16 angle, int b691, int flag)
{
    int healed = 0;
    if (pRestartPoint == 0)
    {
        pRestartPoint = (u32)mmAlloc(SAVEGAME_ACTIVE_SIZE, 0xffff00ff, 0);
        if (pRestartPoint == 0) return;
    }
    if (flag != 0)
    {
        GameBit_Set(0x970, 1);
        if (Player_GetCurrentHealth((int)Obj_GetPlayerObject()) > 1)
        {
            playerAddHealth((u8*)Obj_GetPlayerObject(), -1);
            healed = 1;
        }
    }
    memcpy((void*)pRestartPoint, gSaveGameData, SAVEGAME_ACTIVE_SIZE);
    SAVEGAME_CHARACTER_POSITION((u8 *)pRestartPoint)->x = pos[0];
    SAVEGAME_CHARACTER_POSITION((u8 *)pRestartPoint)->y = pos[1];
    SAVEGAME_CHARACTER_POSITION((u8 *)pRestartPoint)->z = pos[2];
    SAVEGAME_CHARACTER_POSITION((u8 *)pRestartPoint)->angle = (s8)(angle >> 8);
    ((SaveGameCharacterPosition *)((u8 *)pRestartPoint + SAVEGAME_CHARACTER_POSITION_OFFSET))
        [gSaveGameData[SAVEGAME_CURRENT_CHARACTER_OFFSET]]
            .map = b691;
    GameBit_Set(0x970, 0);
    if (flag != 0 && healed != 0)
    {
        playerAddHealth((u8*)Obj_GetPlayerObject(), 1);
    }
}

void SaveGame_updateTransientMapBits(void)
{
    int i;
    for (i = 0; i < SAVEGAME_TRANSIENT_MAP_BIT_COUNT; i++)
    {
        if (gTransientMapBits[i].mapId != -1)
        {
            gTransientMapBits[i].timer--;
            if (gTransientMapBits[i].timer <= 0)
            {
                gTransientMapBits[i].mapId = -1;
            }
        }
    }
}

void* fn_800E888C(u8 a, u8 b) { return saveData + a * 40 + b * 8 + 28; }
