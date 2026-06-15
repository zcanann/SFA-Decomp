#include "main/asset_load.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/dll/player_status.h"
#include "main/mapEventTypes.h"

typedef struct SaveGameData
{
    u8 pad0[0x20 - 0x0];
    u8 currentCharacter;
    u8 pad21[0x55E - 0x21];
    u8 unk55E;
    u8 pad55F[0x560 - 0x55F];
    f32 playTime;
    u8 pad564[0x6A4 - 0x564];
    s16 camActionNo;
    u8 pad6A6[0xF70 - 0x6A6];
} SaveGameData;

static inline u8* Gameplay_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (u8*)objAnim->banks[objAnim->bankIndex];
}

extern undefined4 FUN_800033a8();
extern undefined8 FUN_80003494();
extern undefined4 FUN_80006768();
extern undefined4 FUN_8000676c();
extern undefined4 FUN_80006770();
extern int FUN_80006b7c();
extern undefined4 FUN_80006b84();
extern undefined4 FUN_80006b8c();
extern undefined4 FUN_80006c20();
extern undefined4 FUN_80017488();
extern undefined4 FUN_80017498();
extern undefined4 FUN_80017500();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_800176cc();
extern undefined4 FUN_800176dc();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_8005d018();
extern undefined4 FUN_80072564();
extern undefined4 FUN_800d783c();
extern undefined4 FUN_8011e80c();
extern void OSSetSaveRegion(void* start, void* end);
extern longlong FUN_80286830();
extern uint FUN_80286834();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_802c28f0;
extern undefined4 DAT_802c28f4;
extern undefined4 DAT_802c28f8;
extern short DAT_80312370;
extern short DAT_80312460;
extern undefined4 DAT_80312630;
extern short DAT_80312632;
extern char DAT_803a3be0;
extern undefined4 DAT_803a3be1;
extern undefined4 DAT_803a3be2;
extern uint DAT_803a3c1c;
extern undefined4 DAT_803a3dac;
extern undefined1 gGameplayPreviewSettings;
extern undefined4 DAT_803a3e26;
extern undefined4 DAT_803a3e27;
extern undefined4 DAT_803a3e28;
extern undefined4 DAT_803a3e2a;
extern undefined4 DAT_803a3e2c;
extern undefined4 DAT_803a3e2d;
extern undefined4 gGameplayPreviewColorRed;
extern undefined4 gGameplayPreviewColorGreen;
extern undefined4 gGameplayPreviewColorBlue;
extern undefined4 gGameplayRegisteredDebugOptions;
extern undefined1 DAT_803a3f08;
extern undefined4 DAT_803a3f09;
extern undefined4 DAT_803a3f0c;
extern undefined4 DAT_803a3f0e;
extern undefined4 DAT_803a3f12;
extern undefined4 DAT_803a3f14;
extern undefined4 DAT_803a3f15;
extern undefined4 DAT_803a3f18;
extern undefined4 DAT_803a3f1a;
extern undefined4 DAT_803a3f1e;
extern undefined4 DAT_803a3f21;
extern char DAT_803a3f24;
extern undefined4 DAT_803a3f25;
extern undefined4 DAT_803a3f26;
extern undefined4 DAT_803a3f27;
extern undefined4 DAT_803a3f28;
extern undefined4 DAT_803a3f29;
extern undefined4 DAT_803a3f2b;
extern undefined4 DAT_803a4070;
extern undefined4 DAT_803a4074;
extern undefined4 DAT_803a4078;
extern undefined4 DAT_803a407c;
extern undefined4 DAT_803a4460;
extern undefined4 DAT_803a4465;
extern undefined4 DAT_803a458c;
extern undefined4 DAT_803a4590;
extern undefined4 DAT_803a4594;
extern undefined4 DAT_803a4599;
extern undefined4 DAT_803a459a;
extern undefined4 DAT_803a45aa;
extern undefined4 DAT_803a45ac;
extern undefined4 DAT_803a45b0;
extern undefined4 DAT_803a45b4;
extern undefined4 DAT_803a45b6;
extern undefined4 DAT_803a45ba;
extern undefined4 DAT_803a45bc;
extern undefined4 DAT_803a45be;
extern undefined4 DAT_803a45c0;
extern undefined4 DAT_803a45c2;
extern undefined4 DAT_803a45f0;
extern undefined4 DAT_803a45f1;
extern undefined4 DAT_803a45f2;
extern undefined4 DAT_803a45f3;
extern undefined4 DAT_803a4e78;
extern undefined4 DAT_803dc4f0;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6e8;
extern undefined4 DAT_803de100;
extern undefined4 DAT_803de104;
extern undefined4 DAT_803de10c;
extern undefined4* DAT_803de110;
extern f32 lbl_803E1348;
extern undefined4 uRam803de108;
extern u8 gSaveGameData[];
extern u8 saveGameLoadStatus;
extern s8 lbl_803DB890;
extern u8* lbl_803DD498;
extern char sGameplayFoxName;
extern u8 saveData[228];
extern f32 lbl_803E06C8;
extern f32 lbl_803E06CC;
extern u16 lbl_80311720[];
extern u16 lbl_80311810[];
extern u32 gMapObjGroupStatuses[];
extern u8 gExtendedMapActLookup[];
extern int lbl_803DD48C;

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
#define SAVEGAME_MAP_COUNT 0x78
#define SAVEGAME_EXTENDED_MAP_THRESHOLD 0x50
#define SAVEGAME_TRANSIENT_MAP_BIT_COUNT 20
#define SAVEGAME_TRANSIENT_MAP_BIT_TTL 3
#define SAVEGAME_CHARACTER_POSITION(save)                                                     \
    ((SaveGameCharacterPosition *)((save) +                                                     \
                                  (save)[SAVEGAME_CURRENT_CHARACTER_OFFSET] *                  \
                                      sizeof(SaveGameCharacterPosition) +                       \
                                  SAVEGAME_CHARACTER_POSITION_OFFSET))

typedef struct SaveGameObjectPosition
{
    u32 objectId;
    f32 x;
    f32 y;
    f32 z;
} SaveGameObjectPosition;

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
 * (+0x3C) and gExtendedMapActLookup (+0x21C) are contiguous; the retail code
 * addresses them through a single base register (#16 overlay). */
typedef struct SaveGameMapState
{
    MapBitTransient transient[20]; /* 0x000 */
    u32 groupStatuses[120];        /* 0x03C */
    u8 extendedMapActLookup[40];   /* 0x21C */
} SaveGameMapState;
#define gSaveGameMapState (*(SaveGameMapState*)gTransientMapBits)

extern SaveGameDefaultPosition lbl_802C2170;

int saveGame_restoreObjectPosToRomList(SaveGameRomListPosition* object)
{
    u8* walker;
    int i;

    for (i = 0, walker = gSaveGameData; i < SAVEGAME_OBJECT_POSITION_COUNT; walker += sizeof(SaveGameObjectPosition), i++)
    {
        if (object->objectId == ((SaveGameObjectPosition*)(walker + SAVEGAME_OBJECT_POSITION_OFFSET))->objectId)
        {
            SaveGameObjectPosition* slot =
                (SaveGameObjectPosition*)(gSaveGameData + SAVEGAME_OBJECT_POSITION_OFFSET) + i;
            object->x = slot->x;
            object->y = slot->y;
            object->z = slot->z;
            return 1;
        }
    }

    return 0;
}

void saveGame_unsaveObjectPos(u8* obj)
{
    int i;
    u8* saveBase;
    SaveGameObjectPosition* slot;
    u32 objectId;

    if ((((GameObject*)obj)->anim.flags & 0x2000) != 0)
    {
        return;
    }
    if (saveGameLoadStatus == 0)
    {
        objectId = *(u32*)(*(u8**)&((GameObject*)obj)->anim.placementData + 0x14);
        saveBase = gSaveGameData;
        for (i = 0; i < SAVEGAME_OBJECT_POSITION_COUNT; i++)
        {
            if (objectId == ((SaveGameObjectPosition*)(saveBase + SAVEGAME_OBJECT_POSITION_OFFSET))->objectId)
            {
                break;
            }
            saveBase += sizeof(SaveGameObjectPosition);
        }
        if (i == SAVEGAME_OBJECT_POSITION_COUNT)
        {
            return;
        }

        slot = (SaveGameObjectPosition*)(saveBase + SAVEGAME_OBJECT_POSITION_OFFSET);
        for (; i < SAVEGAME_OBJECT_POSITION_COUNT - 1; i++, slot++)
        {
            slot[0].objectId = slot[1].objectId;
            slot[0].x = slot[1].x;
            slot[0].y = slot[1].y;
            slot[0].z = slot[1].z;
        }
        *(u32*)(gSaveGameData + SAVEGAME_OBJECT_POSITION_DIRTY_OFFSET) = 0;
    }
}

extern void* memset(void* dst, int val, u32 n);
extern void* memcpy(void* dst, const void* src, u32 n);
extern int loadSaveGame(int slot, void* save);
extern int _saveGame(int slot, int save, int data);
extern void GameBit_Set(int eventId, int value);
extern u32 GameBit_Get(int eventId);
extern void* gameTextGetPhrase(int textId, int variant);

int trySaveGame(int slot)
{
    int loaded;

    lbl_803DB890 = (s8)slot;
    memset(gSaveGameData, 0, SAVEGAME_LIVE_BUFFER_SIZE);
    if ((lbl_803DD498[0x21] & 0x80) == 0)
    {
        memset(lbl_803DD498, 0, SAVEGAME_ACTIVE_SIZE);
    }

    loaded = loadSaveGame((u8)lbl_803DB890, lbl_803DD498);
    if (loaded != 0)
    {
        if (lbl_803DD498[0x21] == 0)
        {
            loaded = gplayNewGame(&sGameplayFoxName, (u8)lbl_803DB890);
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
    int i;
    SaveScoreEntry* scores;

    scores = (SaveScoreEntry*)(saveData + slot * SAVE_SCORE_FILE_STRIDE + SAVE_SCORE_TABLE_OFFSET);
    for (rank = 0; rank < SAVE_SCORE_ENTRY_COUNT; rank++)
    {
        if (score > scores[rank].score)
        {
            for (i = SAVE_SCORE_ENTRY_COUNT - 1; i > rank; i--)
            {
                scores[i].score = scores[i - 1].score;
                scores[i].flag = scores[i - 1].flag;
                scores[i].initials[0] = scores[i - 1].initials[0];
                scores[i].initials[1] = scores[i - 1].initials[1];
                scores[i].initials[2] = scores[i - 1].initials[2];
                scores[i].initials[3] = scores[i - 1].initials[3];
            }

            scores[rank].score = score;
            scores[rank].flag = flag;
            scores[rank].initials[0] = initials[0];
            scores[rank].initials[1] = initials[1];
            scores[rank].initials[2] = initials[2];
            scores[rank].initials[3] = initials[3];
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

    defaultPos = lbl_802C2170;

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
    save[0x692] = -1;
    save[0xc] = 0xc;
    save[0xd] = 0xc;
    *(u16*)(save + 0x12) = 0x19;
    *(u16*)(save + 0x10) = 0;
    save[0x16] = 1;
    save[0x6a2] = -1;
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
    save[0x6e9] = -1;
    save[0x6ea] = -1;
    save[0x6eb] = -1;
    save[0x6e8] = 9;
    save[0x23] = 0;
    save[SAVEGAME_NEW_FILE_FLAG_OFFSET] = 1;

    for (i = 0; i < SAVEGAME_MAP_COUNT; i++)
    {
        if (lbl_80311720[i] != 0)
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

    *(f32*)(save + save[SAVEGAME_CURRENT_CHARACTER_OFFSET] * 0x10 +
        SAVEGAME_CHARACTER_POSITION_OFFSET) = defaultPos.x;
    *(f32*)(save + save[SAVEGAME_CURRENT_CHARACTER_OFFSET] * 0x10 +
        SAVEGAME_CHARACTER_POSITION_OFFSET + 4) = defaultPos.y;
    *(f32*)(save + save[SAVEGAME_CURRENT_CHARACTER_OFFSET] * 0x10 +
        SAVEGAME_CHARACTER_POSITION_OFFSET + 8) = defaultPos.z;
    save[0x55d] = 1;

    if (name != NULL)
    {
        dst = save + SAVEGAME_PLAYER_NAME_OFFSET;
        do
        {
            c = (u8) * name++;
            *dst++ = c;
        }
        while (c != '\0');
    }
    else
    {
        save[SAVEGAME_PLAYER_NAME_OFFSET + 0] = 'F';
        save[SAVEGAME_PLAYER_NAME_OFFSET + 1] = 'O';
        save[SAVEGAME_PLAYER_NAME_OFFSET + 2] = 'X';
        save[SAVEGAME_PLAYER_NAME_OFFSET + 3] = '\0';
    }

    memcpy(lbl_803DD498, save, SAVEGAME_ACTIVE_SIZE);
    if ((s8)slot == -1)
    {
        return 0;
    }
    lbl_803DB890 = (s8)slot;
    if (name == NULL)
    {
        return 0;
    }
    return _saveGame((u8)slot, (int)lbl_803DD498, (int)saveData);
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
    u32* groupStatuses;

    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD)
    {
        idx = s->extendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    }
    if (idx < SAVEGAME_MAP_COUNT && lbl_80311810[idx] != 0)
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

        newStatus = GameBit_Get(lbl_80311810[idx]);
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

        GameBit_Set(lbl_80311810[idx], newStatus);
        lbl_803DD48C = idx;
        (&lbl_803DD48C)[1] = newStatus;

        groupStatuses = s->groupStatuses;
        if (value != 0)
        {
            if ((oldStatus & (1 << shift)) == 0)
            {
                for (i = 0; i < SAVEGAME_MAP_COUNT; i++)
                {
                    if (lbl_80311810[i] == lbl_80311810[idx])
                    {
                        groupStatuses[i] |= (u32)(1 << shift);
                    }
                }
            }
        }
        else
        {
            for (i = 0; i < SAVEGAME_MAP_COUNT; i++)
            {
                if (lbl_80311810[i] == lbl_80311810[idx])
                {
                    groupStatuses[i] &= ~(u32)(1 << shift);
                }
            }

            if (!createTransient)
            {
                transient = s->transient;
                for (i = 0; i < SAVEGAME_TRANSIENT_MAP_BIT_COUNT; i++, transient++)
                {
                    if (transient->mapId == idx && transient->shift == shift)
                    {
                        return;
                    }
                }

                transient = s->transient;
                for (i = 0; i < SAVEGAME_TRANSIENT_MAP_BIT_COUNT; i++, transient++)
                {
                    if (transient->mapId == -1)
                    {
                        transient->mapId = (s8)idx;
                        transient->shift = (u8)shift;
                        transient->timer = SAVEGAME_TRANSIENT_MAP_BIT_TTL;
                        break;
                    }
                }
            }
        }
    }
}

int saveSelect_getInfo(void* outPtr)
{
    u8 save[SAVEGAME_ACTIVE_SIZE];
    int slot;
    int i;
    SaveSelectInfo* info;
    u8 completion;
    u8* taskIds;

    slot = 0;
    info = (SaveSelectInfo*)outPtr;
    do
    {
        if (loadSaveGame((u8)slot, save) == 0)
        {
            return 0;
        }

        info->valid = save[SAVEGAME_NEW_FILE_FLAG_OFFSET];
        if (info->valid == 0)
        {
            memset(info, 0, sizeof(SaveSelectInfo));
        }
        else
        {
            memcpy(info, save + SAVEGAME_PLAYER_NAME_OFFSET, sizeof(info->name));

            completion = save[0x55d];
            info->percentComplete = (u8)((completion * 100) / 0xbb);
            if (completion > 0xb3)
            {
                info->rankA = 6;
                info->rankB = 4;
            }
            else if (completion > 0xb0)
            {
                info->rankA = 5;
                info->rankB = 4;
            }
            else if (completion > 0xa1)
            {
                info->rankA = 4;
                info->rankB = 4;
            }
            else if (completion > 0x8a)
            {
                info->rankA = 4;
                info->rankB = 3;
            }
            else if (completion > 0x81)
            {
                info->rankA = 3;
                info->rankB = 3;
            }
            else if (completion > 0x71)
            {
                info->rankA = 3;
                info->rankB = 2;
            }
            else if (completion > 0x62)
            {
                info->rankA = 2;
                info->rankB = 2;
            }
            else if (completion > 0x48)
            {
                info->rankA = 2;
                info->rankB = 1;
            }
            else if (completion > 0x3d)
            {
                info->rankA = 1;
                info->rankB = 1;
            }
            else if (completion > 8)
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

        info++;
        slot++;
    }
    while (slot < 3);

    return 1;
}

void saveFileStruct_unlockCheat(uint cheatId)
{
    gGameplayRegisteredDebugOptions = gGameplayRegisteredDebugOptions | 1 << (cheatId & 0xff);
    return;
}

uint isCheatUnlocked(uint cheatId)
{
    return gGameplayRegisteredDebugOptions & 1 << (cheatId & 0xff);
}

void saveFileStruct_resetVolumes(void)
{
    gGameplayPreviewColorRed = 0x7f;
    gGameplayPreviewColorGreen = 0x7f;
    gGameplayPreviewColorBlue = 0x7f;
    return;
}

u8* getSaveFileStruct(void)
{
    return &gGameplayPreviewSettings;
}

void loadSaveSettings(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                      undefined8 param_5, undefined8 param_6, undefined8 param_7,
                      undefined8 param_8)
{
    FUN_8005d018(DAT_803a3e2a);
    FUN_80017500(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (uint)DAT_803a3e26);
    FUN_80006c20(DAT_803a3e2c);
    FUN_80006768(DAT_803a3e2d, '\0');
    (**(code**)(*DAT_803dd6e8 + 0x50))(DAT_803a3e27);
    (**(code**)(*DAT_803dd6d0 + 0x6c))(DAT_803a3e28);
    FUN_8000676c((uint)gGameplayPreviewColorGreen, 10, 0, 1, 0);
    FUN_8000676c((uint)gGameplayPreviewColorRed, 10, 1, 0, 0);
    FUN_8000676c((uint)gGameplayPreviewColorBlue, 10, 0, 0, 1);
    return;
}

undefined* FUN_800e82d8(void)
{
    return (undefined*)&DAT_803a4460;
}

void FUN_800e8630(int obj)
{
    int placementId;
    undefined1* slot;
    int baseIndex;
    int foundIndex;
    int remaining;

    if ((*(ushort*)&((GameObject*)obj)->anim.flags & 0x2000) != 0)
    {
        return;
    }
    if (DAT_803de100 != '\0')
    {
        return;
    }
    baseIndex = 0;
    slot = &DAT_803a3f08;
    remaining = 9;
    while ((foundIndex = baseIndex, *(int*)(slot + 0x168) != 0 &&
        (placementId = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14), placementId != *(int*)(slot + 0x168))))
    {
        foundIndex = baseIndex + 1;
        if ((*(int*)(slot + 0x178) == 0) || (placementId == *(int*)(slot + 0x178))) break;
        foundIndex = baseIndex + 2;
        if ((*(int*)(slot + 0x188) == 0) || (placementId == *(int*)(slot + 0x188))) break;
        foundIndex = baseIndex + 3;
        if ((*(int*)(slot + 0x198) == 0) || (placementId == *(int*)(slot + 0x198))) break;
        foundIndex = baseIndex + 4;
        if ((*(int*)(slot + 0x1a8) == 0) || (placementId == *(int*)(slot + 0x1a8))) break;
        foundIndex = baseIndex + 5;
        if ((*(int*)(slot + 0x1b8) == 0) || (placementId == *(int*)(slot + 0x1b8))) break;
        foundIndex = baseIndex + 6;
        if ((*(int*)(slot + 0x1c8) == 0) || (placementId == *(int*)(slot + 0x1c8))) break;
        slot = slot + 0x70;
        baseIndex = baseIndex + 7;
        remaining = remaining + -1;
        foundIndex = baseIndex;
        if (remaining == 0) break;
    }
    if (foundIndex == 0x3f)
    {
        return;
    }
    (&DAT_803a4070)[foundIndex * 4] = *(undefined4*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
    (&DAT_803a4074)[foundIndex * 4] = *(undefined4*)&((GameObject*)obj)->anim.localPosX;
    (&DAT_803a4078)[foundIndex * 4] = *(undefined4*)&((GameObject*)obj)->anim.localPosY;
    (&DAT_803a407c)[foundIndex * 4] = *(undefined4*)&((GameObject*)obj)->anim.localPosZ;
    *(undefined4*)(*(int*)&((GameObject*)obj)->anim.placementData + 8) = *(undefined4*)&((GameObject*)obj)->anim
        .localPosX;
    *(undefined4*)(*(int*)&((GameObject*)obj)->anim.placementData + 0xc) = *(undefined4*)&((GameObject*)obj)->
        anim.localPosY;
    *(undefined4*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x10) = *(undefined4*)&((GameObject*)obj)->
        anim.localPosZ;
    return;
}

undefined4* FUN_800e87a8(void)
{
    return &DAT_803a45b0;
}

extern int maybeTryLoadSave(int a);

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

extern u32 pRestartPoint;

void gplaySaveGame(int param)
{
    gSaveGameData[0x21] = 0;
    lbl_803DB890 = (s8)param;
    if (gSaveGameData[0x22] == 0)
    {
        memcpy(lbl_803DD498, gSaveGameData, 0x564);
        if (pRestartPoint != 0)
        {
            memcpy((void*)pRestartPoint, gSaveGameData, 0x564);
        }
    }
    if ((s8)lbl_803DB890 == -1)
    {
        lbl_803DB890 = 0;
    }
    if ((s8)lbl_803DD498[0] < 1)
    {
        lbl_803DD498[0] = 1;
    }
    if ((s8)lbl_803DD498[0xc] < 1)
    {
        lbl_803DD498[0xc] = 1;
    }
    _saveGame((u8)lbl_803DB890, (int)lbl_803DD498, (int)saveData);
}

void titleDoLoadSave(void)
{
    OSSetSaveRegion(0, 0);
    lbl_803DB890 = (s8)((lbl_803DD498[0x21] & 0x60) >> 5);
    lbl_803DD498[0x21] = lbl_803DD498[0x21] & ~0xE0;
    (*gMapEventInterface)->gotoSavegame();
    return;
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
    if ((s8)lbl_803DB890 == -1)
    {
        lbl_803DB890 = 0;
    }
    if ((s8)lbl_803DD498[0] < 1)
    {
        lbl_803DD498[0] = 1;
    }
    if ((s8)lbl_803DD498[0xc] < 1)
    {
        lbl_803DD498[0xc] = 1;
    }
    _saveGame((u8)lbl_803DB890, (int)lbl_803DD498, (int)saveData);
}

undefined FUN_800e8b98(void)
{
    return DAT_803de100;
}

void FUN_800e8f58(undefined8 param_1, double param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    undefined4 savedX;
    undefined4 savedY;
    undefined4 savedZ;
    char* dst;
    int act;
    short* actFlags;
    char* src;
    char c;
    undefined8 saveHandle;
    undefined8 result;

    result = FUN_80286840();
    savedZ = DAT_802c28f8;
    savedY = DAT_802c28f4;
    savedX = DAT_802c28f0;
    src = (char*)((ulonglong)result >> 0x20);
    FUN_800033a8(-0x7fc5c0f8, 0, 0xf70);
    if ((*(byte*)(DAT_803de110 + 0x21) & 0x80) == 0)
    {
        FUN_800033a8(DAT_803de110, 0, 0x6ec);
    }
    DAT_803a3f28 = 0;
    DAT_803a3f08 = 0xc;
    DAT_803a3f09 = 0xc;
    DAT_803a3f0e = 0x19;
    DAT_803a3f0c = 0;
    DAT_803a3f12 = 1;
    DAT_803a459a = 0xff;
    DAT_803a3f14 = 0xc;
    DAT_803a3f15 = 0xc;
    DAT_803a3f1a = 0x19;
    DAT_803a3f18 = 0;
    DAT_803a3f1e = 1;
    DAT_803a45aa = 0xff;
    DAT_803a3f21 = 0x14;
    DAT_803a45ac = 0xffff;
    DAT_803a45b0 = lbl_803E1348;
    DAT_803a45b4 = 0xffff;
    DAT_803a45b6 = 0xffff;
    DAT_803a45ba = 0xffff;
    DAT_803a45bc = 0xffff;
    DAT_803a45be = 0xffff;
    DAT_803a45c0 = 0xffff;
    DAT_803a45c2 = 0xffff;
    DAT_803a45f1 = 0xff;
    DAT_803a45f2 = 0xff;
    DAT_803a45f3 = 0xff;
    DAT_803a45f0 = 9;
    DAT_803a3f2b = 0;
    DAT_803a3f29 = 1;
    act = 0;
    actFlags = &DAT_80312370;
    do
    {
        if (*actFlags != 0)
        {
            (*gMapEventInterface)->setMapAct(act, 1);
        }
        actFlags = actFlags + 1;
        act = act + 1;
    }
    while (act < 0x78);
    FUN_800e95e8(7, 0, 1);
    FUN_800e95e8(7, 2, 1);
    FUN_800e95e8(7, 3, 1);
    FUN_800e95e8(7, 5, 1);
    FUN_800e95e8(7, 10, 1);
    FUN_800e95e8(0x1d, 0, 1);
    FUN_800e95e8(0x1d, 0x1f, 1);
    FUN_800e95e8(0x13, 0, 1);
    FUN_800e95e8(0x13, 0x16, 1);
    FUN_80017698(0x967, 1);
    (&DAT_803a458c)[(uint)DAT_803a3f28 * 4] = savedX;
    (&DAT_803a4590)[(uint)DAT_803a3f28 * 4] = savedY;
    (&DAT_803a4594)[(uint)DAT_803a3f28 * 4] = savedZ;
    DAT_803a4465 = 1;
    if (src == (char*)0x0)
    {
        DAT_803a3f24 = 0x46;
        DAT_803a3f25 = 0x4f;
        DAT_803a3f26 = 0x58;
        DAT_803a3f27 = 0;
        src = (char*)0x0;
    }
    else
    {
        dst = &DAT_803a3f24;
        do
        {
            c = *src;
            src = src + 1;
            *dst = c;
            dst = dst + 1;
        }
        while (c != '\0');
    }
    saveHandle = FUN_80003494(DAT_803de110, 0x803a3f08, 0x6ec);
    c = (char)result;
    if ((c != -1) && (DAT_803dc4f0 = c, src != (char*)0x0))
    {
        FUN_80072564(saveHandle, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (uint)result & 0xff,
                     DAT_803de110, &gGameplayPreviewSettings);
    }
    FUN_8028688c();
    return;
}

void FUN_800e95e8(undefined4 param_1, undefined4 param_2, int param_3)
{
    bool keepTransient;
    char foundIndex;
    uint flags;
    char scanIndex;
    short* eventIds;
    char* entry;
    uint* groupStatuses;
    uint shift;
    uint newFlags;
    uint mapId;
    char* history;
    int i;
    int j;
    longlong packed;

    packed = FUN_80286830();
    mapId = (uint)((ulonglong)packed >> 0x20);
    shift = (uint)packed;
    history = &DAT_803a3be0;
    if (0x4fffffffff < packed)
    {
        mapId = (uint)(byte)(&DAT_803a3dac)[mapId];
    }
    if ((int)mapId < 0x78)
    {
        if ((ushort)(&DAT_80312460)[mapId] != 0)
        {
            if (param_3 == -1)
            {
                param_3 = 1;
            }
            keepTransient = param_3 == -2;
            if (keepTransient)
            {
                param_3 = 0;
            }
            flags = FUN_80017690((uint)(ushort)(&DAT_80312460)[mapId]);
            if (param_3 == 0)
            {
                newFlags = flags & ~(1 << shift);
            }
            else
            {
                newFlags = flags | 1 << shift;
            }
            FUN_80017698((uint)(ushort)(&DAT_80312460)[mapId], newFlags);
            DAT_803de104 = mapId;
            uRam803de108 = newFlags;
            if (param_3 == 0)
            {
                eventIds = &DAT_80312460;
                groupStatuses = &DAT_803a3c1c;
                flags = ~(1 << shift);
                i = 0x14;
                do
                {
                    if (*eventIds == (&DAT_80312460)[mapId])
                    {
                        *groupStatuses = *groupStatuses & flags;
                    }
                    if (eventIds[1] == (&DAT_80312460)[mapId])
                    {
                        groupStatuses[1] = groupStatuses[1] & flags;
                    }
                    if (eventIds[2] == (&DAT_80312460)[mapId])
                    {
                        groupStatuses[2] = groupStatuses[2] & flags;
                    }
                    if (eventIds[3] == (&DAT_80312460)[mapId])
                    {
                        groupStatuses[3] = groupStatuses[3] & flags;
                    }
                    if (eventIds[4] == (&DAT_80312460)[mapId])
                    {
                        groupStatuses[4] = groupStatuses[4] & flags;
                    }
                    if (eventIds[5] == (&DAT_80312460)[mapId])
                    {
                        groupStatuses[5] = groupStatuses[5] & flags;
                    }
                    eventIds = eventIds + 6;
                    groupStatuses = groupStatuses + 6;
                    i = i + -1;
                }
                while (i != 0);
                if (!keepTransient)
                {
                    scanIndex = '\0';
                    i = 4;
                    entry = history;
                    do
                    {
                        if ((((((mapId == (int)*entry) && (foundIndex = scanIndex, shift == (byte)entry[1])) ||
                                    ((foundIndex = scanIndex + '\x01', mapId == (int)entry[3] && (shift == (byte)entry[4])))
                                ) || ((foundIndex = scanIndex + '\x02', mapId == (int)entry[6] &&
                                    (shift == (byte)entry[7])))) ||
                                ((foundIndex = scanIndex + '\x03', mapId == (int)entry[9] && (shift == (byte)entry[10]))))
                            || ((mapId == (int)entry[0xc] &&
                                (foundIndex = scanIndex + '\x04', shift == (byte)entry[0xd]))))
                            goto LAB_800e9628;
                        entry = entry + 0xf;
                        scanIndex = scanIndex + '\x05';
                        i = i + -1;
                    }
                    while (i != 0);
                    foundIndex = -1;
                LAB_800e9628:
                    if (foundIndex == -1)
                    {
                        i = 0;
                        j = 0x14;
                        do
                        {
                            if (*history == -1)
                            {
                                i = i * 3;
                                (&DAT_803a3be0)[i] = (char)mapId;
                                (&DAT_803a3be1)[i] = (char)packed;
                                (&DAT_803a3be2)[i] = 3;
                                break;
                            }
                            history = history + 3;
                            i = i + 1;
                            j = j + -1;
                        }
                        while (j != 0);
                    }
                }
            }
            else
            {
                shift = 1 << shift;
                if ((flags & shift) == 0)
                {
                    eventIds = &DAT_80312460;
                    groupStatuses = &DAT_803a3c1c;
                    i = 0x14;
                    do
                    {
                        if (*eventIds == (&DAT_80312460)[mapId])
                        {
                            *groupStatuses = *groupStatuses | shift;
                        }
                        if (eventIds[1] == (&DAT_80312460)[mapId])
                        {
                            groupStatuses[1] = groupStatuses[1] | shift;
                        }
                        if (eventIds[2] == (&DAT_80312460)[mapId])
                        {
                            groupStatuses[2] = groupStatuses[2] | shift;
                        }
                        if (eventIds[3] == (&DAT_80312460)[mapId])
                        {
                            groupStatuses[3] = groupStatuses[3] | shift;
                        }
                        if (eventIds[4] == (&DAT_80312460)[mapId])
                        {
                            groupStatuses[4] = groupStatuses[4] | shift;
                        }
                        if (eventIds[5] == (&DAT_80312460)[mapId])
                        {
                            groupStatuses[5] = groupStatuses[5] | shift;
                        }
                        eventIds = eventIds + 6;
                        groupStatuses = groupStatuses + 6;
                        i = i + -1;
                    }
                    while (i != 0);
                }
            }
        }
    }
    FUN_8028687c();
    return;
}

void FUN_800e9e9c(void)
{
    uint uVar1;
    int iVar2;
    undefined4 extraout_r4;
    undefined4 uVar3;
    undefined4 in_r6;
    undefined4 in_r7;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined8 in_f4;
    undefined8 in_f5;
    undefined8 in_f6;
    undefined8 in_f7;
    undefined8 in_f8;

    DAT_803de10c = 0xff;
    DAT_803de104 = 0xffffffff;
    FUN_80042b9c(0, 0, 1);
    uVar3 = 0x884;
    FUN_800033a8(-0x7fc5ba0c, 0, 0x884);
    FUN_800176cc();
    FUN_80006770(7);
    FUN_80006b8c();
    FUN_8011e80c();
    uVar1 = (uint)DAT_803a3f28;
    FUN_800176dc((double)(float)(&DAT_803a458c)[uVar1 * 4], (double)(float)(&DAT_803a4590)[uVar1 * 4],
                 (double)(float)(&DAT_803a4594)[uVar1 * 4], in_f4, in_f5, in_f6, in_f7, in_f8,
                 (int)(char)(&DAT_803a4599)[uVar1 * 0x10], extraout_r4, uVar3, in_r6, in_r7, in_r8, in_r9,
                 in_r10);
    iVar2 = FUN_80006b7c();
    if (iVar2 != 4)
    {
        FUN_80006b84(1);
    }
    FUN_800d783c(0x1e, 1);
    DAT_803de100 = 2;
    return;
}

undefined4
FUN_800ea8c8(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    undefined4 uVar1;
    undefined* puVar2;

    uVar1 = FUN_80017498();
    puVar2 = FUN_800e82d8();
    FUN_80017488(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                 (uint)(byte)(&DAT_803a4e78)[*(short*)(&DAT_80312630 + (uint)(byte)puVar2[5] * 2)
    ]
    )
    ;
    return uVar1;
}

undefined FUN_800ea9ac(void)
{
    undefined* puVar1;

    puVar1 = FUN_800e82d8();
    return puVar1[5];
}

void FUN_800ea9b8(void)
{
    uint mapId;
    undefined* history;
    short i;
    uint flagWord;
    uint bit;
    uint flagId;
    uint unaff_r27;
    uint cachedFlagId;
    uint scanId;
    short* mapFlags;

    mapId = FUN_80286834();
    history = FUN_800e82d8();
    cachedFlagId = 0xffffffff;
    if (history[6] == '\0')
    {
        mapFlags = &DAT_80312632;
        for (scanId = 1; (short)scanId < 0xce; scanId = scanId + 1)
        {
            if ((*mapFlags == 0xffff) || (*mapFlags == -1))
            {
                bit = 1 << (scanId & 0x1f);
                flagId = (uint)(short)((short)((scanId & 0xff) >> 5) + 0x12f);
                flagWord = FUN_80017690(flagId);
                if ((flagWord & bit) == 0)
                {
                    FUN_80017698(flagId, flagWord | bit);
                }
            }
            mapFlags = mapFlags + 1;
        }
    }
    flagId = 1 << (mapId & 0x1f);
    flagWord = (uint)(short)((short)((mapId & 0xff) >> 5) + 0x12f);
    scanId = FUN_80017690(flagWord);
    if ((scanId & flagId) == 0)
    {
        FUN_80017698(flagWord, scanId | flagId);
        if (history[6] != '\x05')
        {
            history[6] = history[6] + '\x01';
        }
        for (i = 4; i != 0; i = i + -1)
        {
            history[i] = history[i + -1];
        }
        *history = (char)mapId;
        if ((uint)(byte)history[5] == (mapId & 0xff)
        )
        {
            do
            {
                history[5] = history[5] + '\x01';
                mapId = (uint)(short)(((byte)history[5] >> 5) + 0x12f);
                if (mapId != (int)(short)cachedFlagId)
                {
                    unaff_r27 = FUN_80017690(mapId);
                    cachedFlagId = mapId;
                }
            }
            while ((unaff_r27 & 1 << ((byte)history[5] & 0x1f)) != 0);
        }
    }
    FUN_80286880();
    return;
}

void SaveGame_func08_nop(void)
{
}

void screens_release(void);

u8 getSaveGameLoadStatus(void) { return saveGameLoadStatus; }

void setSaveGameLoadingFlag(void) { if (saveGameLoadStatus == 2) saveGameLoadStatus = 1; }
s32 isSaveGameLoading(void) { return saveGameLoadStatus == 2; }

void Carryable_init(int obj, int state);

void clearSaveGameLoadingFlag(void) { saveGameLoadStatus = 0x0; }

s32 Carryable_isHeld(u8* obj);

extern void mm_free(u32);
void SaveGame_release(void) { if (pRestartPoint != 0) mm_free(pRestartPoint); }

enum
{
    SAVEGAME_EMPTY_TASK_HINT = -1,
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

extern s8 lbl_803DD494;

void SaveGame_initialise(void)
{
    s8* base = (s8*)gTransientMapBits;
    int i;
    memset(base + 0x328, 0, 0xf70);
    if (!(lbl_803DD498[0x21] & 0x80))
    {
        memset(lbl_803DD498, 0, 0x6ec);
    }
    pRestartPoint = 0;
    lbl_803DD494 = -1;
    lbl_803DD48C = -1;
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

extern void* getLastSavedGameTexts(void);

void SaveGame_gplayClearRestartPoint(void)
{
    if (pRestartPoint != 0)
    {
        mm_free(pRestartPoint);
        pRestartPoint = 0;
    }
}

extern void loadMapForCurrentSaveGame(void);

void SaveGame_gplayGotoRestartPoint(void)
{
    if (pRestartPoint != 0)
    {
        memcpy(gSaveGameData, (void*)pRestartPoint, 0x6ec);
    }
    else
    {
        memcpy(gSaveGameData, lbl_803DD498, 0x6ec);
    }
    loadMapForCurrentSaveGame();
}

void SaveGame_gplayGotoSavegame(void)
{
    if ((s8)lbl_803DD498[0] < 1) lbl_803DD498[0] = 1;
    if ((s8)lbl_803DD498[0xc] < 1) lbl_803DD498[0xc] = 1;
    memcpy(gSaveGameData, lbl_803DD498, 0x6ec);
    loadMapForCurrentSaveGame();
}

extern void unlockLevel(int a, int b, int c);
extern void cutsceneExit(void);
extern void audioStopByMask(int mask);
extern void stopRumble2(void);
extern void resetYbutton(void);
extern void mapLoadByCoords(f32 x, f32 y, f32 z, int act);
extern int getCurUiDll(void);
extern void loadUiDll(int dll);
extern void screenTransitionFn_800d7b04(int duration, int type);

void loadMapForCurrentSaveGame(void)
{
    char* base;
    lbl_803DD494 = -1;
    lbl_803DD48C = -1;
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

extern void* Obj_GetPlayerObject(void);
extern f32 timeDelta;
void saveGame_saveObjectPos(int* obj);

void saveGame_saveObjectPos(int* obj)
{
    register u8* slot;
    register int v;
    register int i;
    if (((GameObject*)obj)->anim.flags & 0x2000) return;
    if (saveGameLoadStatus == 0)
    {
        slot = gSaveGameData;
        for (i = 0; i < SAVEGAME_OBJECT_POSITION_COUNT; i++)
        {
            v = *(int*)(slot + SAVEGAME_OBJECT_POSITION_OFFSET);
            if (v == 0) break;
            if (*(u32*)(*(u8**)&((GameObject*)obj)->anim.placementData + 0x14) == (u32)v) break;
            slot += sizeof(SaveGameObjectPosition);
        }
        if (i == SAVEGAME_OBJECT_POSITION_COUNT) return;
        {
            register int objectId = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
            register char* entry = (char*)gSaveGameData + i * sizeof(SaveGameObjectPosition);
            *(int*)(entry + SAVEGAME_OBJECT_POSITION_OFFSET) = objectId;
            *(f32*)(entry + SAVEGAME_OBJECT_POSITION_OFFSET + 4) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)(entry + SAVEGAME_OBJECT_POSITION_OFFSET + 8) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)(entry + SAVEGAME_OBJECT_POSITION_OFFSET + 0xc) = ((GameObject*)obj)->anim.localPosZ;
        }
        *(f32*)(*(int*)&((GameObject*)obj)->anim.placementData + 8) = ((GameObject*)obj)->anim.localPosX;
        *(f32*)(*(int*)&((GameObject*)obj)->anim.placementData + 0xc) = ((GameObject*)obj)->anim.localPosY;
        *(f32*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x10) = ((GameObject*)obj)->anim.localPosZ;
    }
}

void Carryable_stopCarrying(int* obj, u8* param2);

void SaveGame_setCamActionNo(s16 actionNo) { ((SaveGameData*)gSaveGameData)->camActionNo = actionNo; }
void* SaveGame_getLast(void) { return gSaveGameData; }
s32 SaveGame_getCamActionNo(void) { return ((SaveGameData*)gSaveGameData)->camActionNo; }
void* saveGameGetEnvState(void) { return (char*)gSaveGameData + 0x6a8; }
f32 SaveGame_getPlayTime(void) { return ((SaveGameData*)gSaveGameData)->playTime; }
extern f32 lbl_803E06D0;
extern f32 lbl_803E06D4;

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
    while (i < *(s16*)(base + 0x6ec))
    {
        if (((SaveGameData*)base)->playTime > *(f32*)(p + 0x6f4))
        {
            cnt = *(s16*)(base + 0x6ec) - 1;
            *(s16*)(base + 0x6ec) = cnt;
            *(int*)(p + 0x6f0) = *(int*)(base + cnt * 8 + 0x6f0);
            *(f32*)(p + 0x6f4) = *(f32*)(base + *(s16*)(base + 0x6ec) * 8 + 0x6f4);
        }
        else
        {
            p += 8;
            i++;
        }
    }
    if (((SaveGameData*)gSaveGameData)->unk55E > 5) *(u8*)0 = 0;
    if (((SaveGameData*)lbl_803DD498)->unk55E > 5) *(u8*)0 = 0;
}

f32 SaveGame_gplayGetTime(int id)
{
    s16 count;
    u8* p;
    int i;
    if (id == -1) return lbl_803E06D0;
    i = 0;
    p = gSaveGameData;
    count = *(s16*)(p + 0x6ec);
    for (; i < count; i++)
    {
        if (*(int*)(p + 0x6f0) == id)
        {
            p = gSaveGameData;
            return *(f32*)(p + i * 8 + 0x6f4) - ((SaveGameData*)p)->playTime;
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
    count = *(s16*)(p + 0x6ec);
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
    count = *(s16*)(base + 0x6ec);
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
        (*(s16*)(base + 0x6ec))++;
    }
    base = gSaveGameData;
    p = base + i * 8;
    *(int*)(p + 0x6f0) = id;
    *(f32*)(p + 0x6f4) = total;
}

void* SaveGame_getTrickyEnergy(void) { return (char*)gSaveGameData + 0x18; }
void SaveGame_setCharacter(u8 c) { ((SaveGameData*)gSaveGameData)->currentCharacter = c; }
u8 SaveGame_getCurChar(void) { return ((SaveGameData*)gSaveGameData)->currentCharacter; }
char* getSaveFileName(void) { return (char*)gSaveGameData + 0x1c; }

void* SaveGame_getCurCharPos(void)
{
    int idx = ((SaveGameData*)gSaveGameData)->currentCharacter;
    return (char*)gSaveGameData + idx * 16 + 0x684;
}

void* SaveGame_getCurCharacterState(void)
{
    int idx = ((SaveGameData*)gSaveGameData)->currentCharacter;
    return (char*)gSaveGameData + idx * 12;
}

s32 SaveGame_gplayGetRestartGameNotCleared(void) { return pRestartPoint != 0; }
u16 SaveGame_getMapObjGroupBit(int idx) { return lbl_80311810[idx]; }

void SaveGame_setMapActLut(int val, int idx)
{
    *(u8*)((char*)gExtendedMapActLookup + idx - SAVEGAME_EXTENDED_MAP_THRESHOLD) = (u8)val;
}

extern u32 lbl_803DD4A0;

void updateSavedHealth(void)
{
    int idx = ((SaveGameData*)gSaveGameData)->currentCharacter * 12;
    *((u8*)gSaveGameData + idx) = lbl_803DD498[idx];
}

extern void* gameTextGet(int idx);

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
    bit = lbl_80311810[idx];
    if (bit != 0)
    {
        gMapObjGroupStatuses[idx] = GameBit_Get(bit);
    }
}

u8 SaveGame_getMapAct(int idx)
{
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) idx = *(u8*)((char*)gExtendedMapActLookup + idx -
        SAVEGAME_EXTENDED_MAP_THRESHOLD);
    if (idx != lbl_803DD494)
    {
        lbl_803DD494 = (s8)idx;
        if (idx < 0 || idx >= SAVEGAME_MAP_COUNT || lbl_80311720[idx] == 0)
        {
            *((s8*)&lbl_803DD494 + 1) = 0;
        }
        else
        {
            *((s8*)&lbl_803DD494 + 1) = (s8)GameBit_Get(lbl_80311720[idx]);
        }
    }
    return *((u8*)&lbl_803DD494 + 1);
}

int SaveGame_gplayGetObjGroupStatus(int idx, int shift)
{
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) idx = *(u8*)((char*)gExtendedMapActLookup + idx -
        SAVEGAME_EXTENDED_MAP_THRESHOLD);
    if (idx != lbl_803DD48C)
    {
        lbl_803DD48C = idx;
        (&lbl_803DD48C)[1] = GameBit_Get(lbl_80311810[idx]);
    }
    return ((&lbl_803DD48C)[1] >> shift) & 1;
}

void SaveGame_gplaySetAct(int idx, int act)
{
    int j;
    u16 bit;
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) idx = *(u8*)((char*)gExtendedMapActLookup + idx -
        SAVEGAME_EXTENDED_MAP_THRESHOLD);
    GameBit_Set(lbl_80311720[idx], act);
    lbl_803DD494 = (s8)idx;
    *((s8*)&lbl_803DD494 + 1) = (s8)act;
    j = idx;
    if (j >= SAVEGAME_EXTENDED_MAP_THRESHOLD) j = *(u8*)((char*)gExtendedMapActLookup + j -
        SAVEGAME_EXTENDED_MAP_THRESHOLD);
    bit = lbl_80311810[j];
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
            return (s8)i;
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
            SAVEGAME_CHARACTER_POSITION(base)->map = (s8)mapByte;
            memcpy(lbl_803DD498, base, 0x6ec);
            if (pRestartPoint != 0)
            {
                mm_free(pRestartPoint);
                pRestartPoint = 0;
            }
        }
    }
    if (flags & 2)
    {
        base[0x22] = 1;
    }
}

extern void playerAddHealth(u8* player, int v);
extern void* mmAlloc(int size, int heap, int flags);

void SaveGame_gplayRestartPoint(f32* pos, s16 angle, int b691, int flag)
{
    int healed = 0;
    if (pRestartPoint == 0)
    {
        pRestartPoint = (u32)mmAlloc(0x6ec, 0xffff00ff, 0);
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
    memcpy((void*)pRestartPoint, gSaveGameData, 0x6ec);
    SAVEGAME_CHARACTER_POSITION((u8 *)pRestartPoint)->x = pos[0];
    SAVEGAME_CHARACTER_POSITION((u8 *)pRestartPoint)->y = pos[1];
    SAVEGAME_CHARACTER_POSITION((u8 *)pRestartPoint)->z = pos[2];
    SAVEGAME_CHARACTER_POSITION((u8 *)pRestartPoint)->angle = (s8)(angle >> 8);
    SAVEGAME_CHARACTER_POSITION((u8 *)pRestartPoint)->map = (s8)b691;
    GameBit_Set(0x970, 0);
    if (flag != 0 && healed != 0)
    {
        playerAddHealth((u8*)Obj_GetPlayerObject(), 1);
    }
}

extern char* sMapDirectoryNameTable[];

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

extern s16 lbl_803119E0[];

void* fn_800E888C(u8 a, u8 b) { return (char*)saveData + a * 40 + b * 8 + 28; }

void screens_remove(void);
