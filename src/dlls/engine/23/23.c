#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "main/frame_timing.h"
#include "main/audio/audio_control_api.h"
#include "main/dll/dll_0017_savegame_api.h"
#include "main/dll/savegame_object_api.h"
#include "main/dll/player_api.h"
#include "main/model_engine.h"
#include "main/model_engine_ui_api.h"
#include "string.h"
#include "sys/objects.h"
#include "main/map_load.h"
#include "main/mm.h"
#include "main/dll/savegame.h"
#include "main/dll/savegame_env_api.h"
#include "main/dll/player_state.h"
#include "main/dll/player_status.h"
#include "main/mapEventTypes.h"
#include "dolphin/os/OSReboot.h"
#include "main/gamebits.h"
#include "main/dll/tricky_api.h"
#include "main/textrender_api.h"
#include "main/gameloop_api.h"
#include "main/dll/dll_0016_screentransition.h"
#include "track/intersect_card_api.h"
#include "main/pad.h"
#include "main/dll/savegame_load_api.h"

u32 pRestartPoint;
u8* gSaveGameWorkBuffer;
s8 gSaveGameMapActCacheIdx[2];
int gSaveGameObjGroupCacheIdx[2];
u8 saveGameLoadStatus;

s8 gSaveGameCurrentSlot = -1;
char sGameplayFoxName[] = "FOX";

typedef struct SaveGameTimeEntry
{
    int objId;
    f32 time;
} SaveGameTimeEntry;

typedef struct SaveGameData
{
    PlayerStatus characterStatus[2];
    u8 pad18[0x1C - 0x18];
    char playerName[4];
    u8 currentCharacter;
    u8 newFileFlag;
    u8 pad22[0x168 - 0x22];
    SaveGameObjectPosition positions[SAVEGAME_OBJECT_POSITION_COUNT];
    /* 5 gametext phrase ids for the "last saved game" task hints shown on the
     * file-select card; engine/21 getLastSavedGameTexts() hands out the same
     * block, and each id is offset by 0xf4 before gameTextGetPhrase. */
    u8 taskHintIds[5];
    /* completion score out of SAVEGAME_COMPLETION_SCORE_MAX; drives the
     * file-select percentage and the two rank digits. A new file starts at 1. */
    u8 completionScore;
    u8 taskCount;
    u8 pad55F[0x560 - 0x55F];
    f32 playTime;
    u8 pad564[0x684 - 0x564];
    SaveGameCharacterPosition characterPositions[2];
    s16 camActionNo;
    u8 pad6A6[0x6A8 - 0x6A6];
    SaveGameEnvState env;
    s16 timeEntryCount; /* 0x6ec: number of valid entries in timeEntries */
    u8 pad6EE[0x6F0 - 0x6EE];
    SaveGameTimeEntry timeEntries[(0xF70 - 0x6F0) / 8]; /* 0x6f0: time-attack record table */
} SaveGameData;

STATIC_ASSERT(offsetof(SaveGameData, playerName) == 0x1C);
STATIC_ASSERT(sizeof(((SaveGameData*)0)->characterStatus) == 0x18);
STATIC_ASSERT(offsetof(SaveGameData, currentCharacter) == 0x20);
STATIC_ASSERT(offsetof(SaveGameData, positions) == 0x168);
STATIC_ASSERT(offsetof(SaveGameData, taskHintIds) == 0x558);
STATIC_ASSERT(offsetof(SaveGameData, completionScore) == 0x55D);
STATIC_ASSERT(offsetof(SaveGameData, taskCount) == 0x55E);
STATIC_ASSERT(offsetof(SaveGameData, playTime) == 0x560);
STATIC_ASSERT(offsetof(SaveGameData, characterPositions) == 0x684);
STATIC_ASSERT(offsetof(SaveGameData, camActionNo) == 0x6A4);
STATIC_ASSERT(offsetof(SaveGameData, timeEntryCount) == 0x6EC);
STATIC_ASSERT(offsetof(SaveGameData, timeEntries) == 0x6F0);
STATIC_ASSERT(sizeof(SaveGameData) == 0xF70);

#define SAVEGAME_OBJECT_POSITION_DIRTY_OFFSET 0x20158
#define SAVEGAME_LIVE_BUFFER_SIZE             0xf70
#define SAVEGAME_ACTIVE_SIZE                  0x6ec
#define SAVEGAME_CURRENT_CHARACTER_OFFSET     0x20
#define SAVEGAME_NEW_FILE_FLAG_OFFSET         0x21
#define SAVEGAME_CHARACTER_POSITION_OFFSET    0x684
#define SAVEGAME_COMPLETION_SCORE_MAX         0xbb
#define SAVE_SCORE_FILE_STRIDE                0x28
#define SAVE_SCORE_TABLE_OFFSET               0x1c
/* number of on-disk save-game slots */
#define SAVEGAME_SLOT_COUNT              3
#define SAVEGAME_MAP_COUNT               0x78
#define SAVEGAME_EXTENDED_MAP_THRESHOLD  0x50
#define SAVEGAME_EXTENDED_MAP_COUNT      (SAVEGAME_MAP_COUNT - SAVEGAME_EXTENDED_MAP_THRESHOLD)
#define SAVEGAME_TRANSIENT_MAP_BIT_COUNT 20
#define SAVEGAME_TRANSIENT_MAP_BIT_TTL   3

enum
{
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

typedef struct SaveGameRomListPosition
{
    u8 pad0[0x8];
    f32 x;
    f32 y;
    f32 z;
    u32 objectId;
} SaveGameRomListPosition;

typedef struct SaveScoreFile
{
    u8 pad0[SAVE_SCORE_TABLE_OFFSET];
    SaveScoreEntry entries[SAVE_SCORE_ENTRY_COUNT];
} SaveScoreFile;

#define SAVEGAME_CHARACTER_POSITION(save)                                                                              \
    (&((SaveGameCharacterPosition*)((save) +                                                                           \
                                    SAVEGAME_CHARACTER_POSITION_OFFSET))[(save)[SAVEGAME_CURRENT_CHARACTER_OFFSET]])

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
    u8 chaptersUnlocked;
    u8 pad22[2];
} SaveSelectInfo;

typedef struct MapBitTransient
{
    s8 mapId;
    u8 shift;
    s8 timer;
} MapBitTransient;

extern u16 gSaveGameMapActBits[];
extern u16 gSaveGameMapObjGroupBits[];
const Vec3f gSaveGameDefaultPosition = {
    570.6483764648438f, -82.0f, 15790.8203125f};

void loadMapForCurrentSaveGame(void);

u32 gMapObjGroupStatuses[SAVEGAME_MAP_COUNT];
extern u8 gExtendedMapActLookup[SAVEGAME_EXTENDED_MAP_COUNT];

MapBitTransient gTransientMapBits[SAVEGAME_TRANSIENT_MAP_BIT_COUNT];

typedef struct SaveGameRecord
{
    MapBitTransient transientMapBits[SAVEGAME_TRANSIENT_MAP_BIT_COUNT];
    u32 mapObjGroupStatuses[SAVEGAME_MAP_COUNT];
    u8 extendedMapActLookup[SAVEGAME_EXTENDED_MAP_COUNT];
    SaveData options;
    SaveGameData game;
} SaveGameRecord;

STATIC_ASSERT(offsetof(SaveGameRecord, mapObjGroupStatuses) == 0x3C);
STATIC_ASSERT(offsetof(SaveGameRecord, extendedMapActLookup) == 0x21C);
STATIC_ASSERT(offsetof(SaveGameRecord, options) == 0x244);
STATIC_ASSERT(offsetof(SaveGameRecord, game) == 0x328);
STATIC_ASSERT(sizeof(SaveGameRecord) == 0x1298);

#define gSaveGameRecord (*(SaveGameRecord*)gTransientMapBits)

static inline s8 saveGame_findTransientMapBit(int mapId, int shift, const SaveGameRecord* record)
{
    int i;

    for (i = 0; i < SAVEGAME_TRANSIENT_MAP_BIT_COUNT; i++)
    {
        if (mapId == record->transientMapBits[i].mapId && shift == record->transientMapBits[i].shift)
        {
            return i;
        }
    }
    return -1;
}

static inline void saveGame_addTransientMapBit(int mapId, int shift, SaveGameRecord* record)
{
    int i;
    MapBitTransient* transient;

    for (i = 0; i < SAVEGAME_TRANSIENT_MAP_BIT_COUNT; i++)
    {
        if (record->transientMapBits[i].mapId == -1)
        {
            (transient = &record->transientMapBits[i])->mapId = mapId;
            transient->shift = shift;
            transient->timer = SAVEGAME_TRANSIENT_MAP_BIT_TTL;
            return;
        }
    }
}

int saveGame_restoreObjectPosToRomList(void* objectData)
{
    SaveGameRomListPosition* object = objectData;
    u8* slot;
    int i;

    for (i = 0; i < SAVEGAME_OBJECT_POSITION_COUNT; i++)
    {
        if (object->objectId == ((SaveGameData*)gSaveGameData)->positions[i].objectId)
        {
            slot = gSaveGameData;
            i = i * sizeof(SaveGameObjectPosition);
            slot += i;
            object->x = ((SaveGameObjectPosition*)(slot + SAVEGAME_OBJECT_POSITION_OFFSET))->x;
            object->y = ((SaveGameObjectPosition*)(slot + SAVEGAME_OBJECT_POSITION_OFFSET))->y;
            object->z = ((SaveGameObjectPosition*)(slot + SAVEGAME_OBJECT_POSITION_OFFSET))->z;
            return 1;
        }
    }

    return 0;
}

void saveGame_unsaveObjectPos(GameObject* obj)
{
    int i;
    SaveGameObjectPosition* slot;
    u32 objectId;

    if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0 || (s32)saveGameLoadStatus != 0)
    {
        return;
    }

    for (i = 0; i < SAVEGAME_OBJECT_POSITION_COUNT; i++)
    {
        objectId = ((SaveGameRomListPosition*)obj->anim.placementData)->objectId;
        if (objectId == ((SaveGameData*)gSaveGameData)->positions[i].objectId)
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
        ((SaveGameData*)slot)->positions[0].objectId = ((SaveGameData*)slot)->positions[1].objectId;
        ((SaveGameData*)slot)->positions[0].x = ((SaveGameData*)slot)->positions[1].x;
        ((SaveGameData*)slot)->positions[0].y = ((SaveGameData*)slot)->positions[1].y;
        ((SaveGameData*)slot)->positions[0].z = ((SaveGameData*)slot)->positions[1].z;
    }
    *(u32*)(gSaveGameData + SAVEGAME_OBJECT_POSITION_DIRTY_OFFSET) = 0;
}

void saveGame_saveObjectPos(GameObject* obj)
{
    int objectId;
    int i;
    if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0 || (s32)saveGameLoadStatus != 0)
    {
        return;
    }
    for (i = 0; i < SAVEGAME_OBJECT_POSITION_COUNT; i++)
    {
        objectId = ((SaveGameData*)gSaveGameData)->positions[i].objectId;
        if (objectId == 0)
            break;
        if (((SaveGameRomListPosition*)obj->anim.placementData)->objectId == objectId)
            break;
    }
    if (i == SAVEGAME_OBJECT_POSITION_COUNT)
        return;
    *(u32*)((int)gSaveGameData + SAVEGAME_OBJECT_POSITION_OFFSET + (i << 4)) =
        ((SaveGameRomListPosition*)obj->anim.placementData)->objectId;
    *(f32*)((int)gSaveGameData + (SAVEGAME_OBJECT_POSITION_OFFSET + 4) + (i << 4)) = obj->anim.localPosX;
    *(f32*)((int)gSaveGameData + (SAVEGAME_OBJECT_POSITION_OFFSET + 8) + (i << 4)) = obj->anim.localPosY;
    *(f32*)((int)gSaveGameData + (SAVEGAME_OBJECT_POSITION_OFFSET + 12) + (i << 4)) =
        obj->anim.localPosZ;
    ((SaveGameRomListPosition*)obj->anim.placementData)->x = obj->anim.localPosX;
    ((SaveGameRomListPosition*)obj->anim.placementData)->y = obj->anim.localPosY;
    ((SaveGameRomListPosition*)obj->anim.placementData)->z = obj->anim.localPosZ;
}

void SaveGame_setCamActionNo(s16 actionNo)
{
    ((SaveGameData*)gSaveGameData)->camActionNo = actionNo;
}

s32 SaveGame_getCamActionNo(void)
{
    return ((SaveGameData*)gSaveGameData)->camActionNo;
}
SaveGameEnvState* saveGameGetEnvState(void)
{
    return (SaveGameEnvState*)(gSaveGameData + 0x6a8);
}

int loadGameOptions(void)
{
    int loadResult;

    loadResult = maybeTryLoadSave(saveData);
    if ((loadResult == 0) || (((SaveData*)saveData)->optionsValid == 0))
    {
        memset(saveData, 0, SAVE_DATA_SIZE);
        ((SaveData*)saveData)->widescreenEnabled = 0;
        ((SaveData*)saveData)->subtitlesEnabled = 1;
        ((SaveData*)saveData)->rumbleEnabled = 1;
        ((SaveData*)saveData)->optionsValid = 1;
        ((SaveData*)saveData)->musicVolume = SAVEGAME_DEFAULT_VOLUME;
        ((SaveData*)saveData)->sfxVolume = SAVEGAME_DEFAULT_VOLUME;
        ((SaveData*)saveData)->speechVolume = SAVEGAME_DEFAULT_VOLUME;
    }
    return loadResult;
}

void gplaySaveGame(int param)
{
    ((SaveGameData*)gSaveGameData)->newFileFlag = 0;
    gSaveGameCurrentSlot = param;
    if (gSaveGameData[0x22] == 0)
    {
        memcpy(gSaveGameWorkBuffer, gSaveGameData, 0x564);
        if (pRestartPoint != 0)
        {
            memcpy((void*)pRestartPoint, gSaveGameData, 0x564);
        }
    }
    if (gSaveGameCurrentSlot == -1)
    {
        gSaveGameCurrentSlot = 0;
    }
    if (((SaveGameData*)gSaveGameWorkBuffer)->characterStatus[0].health < 1)
    {
        ((SaveGameData*)gSaveGameWorkBuffer)->characterStatus[0].health = 1;
    }
    if (((SaveGameData*)gSaveGameWorkBuffer)->characterStatus[1].health < 1)
    {
        ((SaveGameData*)gSaveGameWorkBuffer)->characterStatus[1].health = 1;
    }
    _saveGame((u8)gSaveGameCurrentSlot, gSaveGameWorkBuffer, saveData);
}

void titleDoLoadSave(void)
{
    OSSetSaveRegion(0, 0);
    gSaveGameCurrentSlot = (s8)((((SaveGameData*)gSaveGameWorkBuffer)->newFileFlag & 0x60) >> 5);
    ((SaveGameData*)gSaveGameWorkBuffer)->newFileFlag = ((SaveGameData*)gSaveGameWorkBuffer)->newFileFlag & ~0xE0;
    (*gMapEventInterface)->gotoSavegame();
}

void saveGame_save(void)
{
    if (gSaveGameData[0x22] == 0)
    {
        memcpy(gSaveGameWorkBuffer, gSaveGameData, 0x564);
        if (pRestartPoint != 0)
        {
            memcpy((void*)pRestartPoint, gSaveGameData, 0x564);
        }
    }
    if (gSaveGameCurrentSlot == -1)
    {
        gSaveGameCurrentSlot = 0;
    }
    if (((SaveGameData*)gSaveGameWorkBuffer)->characterStatus[0].health < 1)
    {
        ((SaveGameData*)gSaveGameWorkBuffer)->characterStatus[0].health = 1;
    }
    if (((SaveGameData*)gSaveGameWorkBuffer)->characterStatus[1].health < 1)
    {
        ((SaveGameData*)gSaveGameWorkBuffer)->characterStatus[1].health = 1;
    }
    _saveGame((u8)gSaveGameCurrentSlot, gSaveGameWorkBuffer, saveData);
}

void clearSaveGameLoadingFlag(void)
{
    saveGameLoadStatus = 0x0;
}

void setSaveGameLoadingFlag(void)
{
    if (saveGameLoadStatus == 2)
        saveGameLoadStatus = 1;
}
s32 isSaveGameLoading(void)
{
    return saveGameLoadStatus == 2;
}

int getSaveGameLoadStatus(void)
{
    return saveGameLoadStatus;
}

int trySaveGame(int slot)
{
    int loaded;

    gSaveGameCurrentSlot = slot;
    memset(gSaveGameData, 0, SAVEGAME_LIVE_BUFFER_SIZE);
    if ((((SaveGameData*)gSaveGameWorkBuffer)->newFileFlag & 0x80) == 0)
    {
        memset(gSaveGameWorkBuffer, 0, SAVEGAME_ACTIVE_SIZE);
    }

    loaded = loadSaveGame((u8)gSaveGameCurrentSlot, gSaveGameWorkBuffer);
    if (loaded != 0)
    {
        if (((SaveGameData*)gSaveGameWorkBuffer)->newFileFlag == 0)
        {
            loaded = gplayNewGame(sGameplayFoxName, (u8)gSaveGameCurrentSlot);
        }
        else
        {
            memcpy(gSaveGameData, gSaveGameWorkBuffer, SAVEGAME_ACTIVE_SIZE);
        }
    }
    else
    {
        gplayNewGame(sGameplayFoxName, -1);
    }
    return loaded;
}

void* getHighScoreEntry(u8 fileIdx, u8 rank)
{
    return &((SaveScoreFile*)(saveData + fileIdx * SAVE_SCORE_FILE_STRIDE))->entries[rank];
}

int insertHighScore(u8 slot, u8 flag, u32 score, u8* initials)
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
                ((SaveScoreFile*)(saveData + off))->entries[i].initials[1] =
                    ((SaveScoreFile*)(saveData + off))->entries[i - 1].initials[1];
                ((SaveScoreFile*)(saveData + off))->entries[i].initials[2] =
                    ((SaveScoreFile*)(saveData + off))->entries[i - 1].initials[2];
                ((SaveScoreFile*)(saveData + off))->entries[i].initials[3] =
                    ((SaveScoreFile*)(saveData + off))->entries[i - 1].initials[3];
            }

            ((SaveScoreFile*)(saveData + off))->entries[rank].score = score;
            ((SaveScoreFile*)(saveData + off))->entries[rank].flag = flag;
            ((SaveScoreFile*)((int)saveData + off))->entries[rank].initials[0] = initials[0];
            ((SaveScoreFile*)((int)saveData + off))->entries[rank].initials[1] = initials[1];
            ((SaveScoreFile*)((int)saveData + off))->entries[rank].initials[2] = initials[2];
            ((SaveScoreFile*)((int)saveData + off))->entries[rank].initials[3] = initials[3];
            return rank;
        }
    }

    return -1;
}
char* getSaveFileName(void)
{
    return ((SaveGameData*)gSaveGameData)->playerName;
}

/* K&R definition: the header prototype passes slot as int (callers emit no
   narrowing), but the retail body treated slot as s8 -- the raw stb into
   gSaveGameCurrentSlot with the extsb only at the compare proves it. */
int gplayNewGame(name, slot)
char* name;
s8 slot;
{
    Vec3f defaultPos;
    int i;
    u8* dst;
    u8 ch;
    u8* save;

    defaultPos = gSaveGameDefaultPosition;

    memset(gSaveGameData, 0, SAVEGAME_LIVE_BUFFER_SIZE);
    if ((((SaveGameData*)gSaveGameWorkBuffer)->newFileFlag & 0x80) == 0)
    {
        memset(gSaveGameWorkBuffer, 0, SAVEGAME_ACTIVE_SIZE);
    }

    save = gSaveGameData;
    save[SAVEGAME_CURRENT_CHARACTER_OFFSET] = 0;
    ((SaveGameData*)save)->characterStatus[0].health = 0xc;
    ((SaveGameData*)save)->characterStatus[0].maxHealth = 0xc;
    ((SaveGameData*)save)->characterStatus[0].maxMagic = 0x19;
    ((SaveGameData*)save)->characterStatus[0].magic = 0;
    ((SaveGameData*)save)->characterStatus[0].healCountMax = 1;
    ((SaveGameData*)save)->characterPositions[0].mapDataFileId = -1;
    ((SaveGameData*)save)->characterStatus[1].health = 0xc;
    ((SaveGameData*)save)->characterStatus[1].maxHealth = 0xc;
    ((SaveGameData*)save)->characterStatus[1].maxMagic = 0x19;
    ((SaveGameData*)save)->characterStatus[1].magic = 0;
    ((SaveGameData*)save)->characterStatus[1].healCountMax = 1;
    ((SaveGameData*)save)->characterPositions[1].mapDataFileId = -1;
    save[0x19] = 0x14;
    ((SaveGameData*)save)->camActionNo = -1;
    ((SaveGameData*)save)->env.unk00 = 4.3e+04f;
    ((SaveGameData*)save)->env.skyEnvfxActIds[0] = -1;
    ((SaveGameData*)save)->env.skyEnvfxActIds[1] = -1;
    ((SaveGameData*)save)->env.cloudActionEnvfxActId = -1;
    ((SaveGameData*)save)->env.sky2EnvfxActId = -1;
    ((SaveGameData*)save)->env.cloudEnvfxActIds[0] = -1;
    ((SaveGameData*)save)->env.cloudEnvfxActIds[1] = -1;
    ((SaveGameData*)save)->env.cloudEnvfxActIds[2] = -1;
    ((SaveGameData*)save)->env.cloudStationary[0] = -1;
    ((SaveGameData*)save)->env.cloudStationary[1] = -1;
    ((SaveGameData*)save)->env.cloudStationary[2] = -1;
    ((SaveGameData*)save)->env.envFlags = 9;
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
    mainSetBits(GAMEBIT_ITEM_Firefly_Disabled, 1);

    SAVEGAME_CHARACTER_POSITION(gSaveGameData)->x = defaultPos.x;
    ((SaveGameData*)(gSaveGameData + gSaveGameData[SAVEGAME_CURRENT_CHARACTER_OFFSET] * 0x10))
        ->characterPositions[0]
        .y = defaultPos.y;
    ((SaveGameData*)(gSaveGameData + gSaveGameData[SAVEGAME_CURRENT_CHARACTER_OFFSET] * 0x10))
        ->characterPositions[0]
        .z = defaultPos.z;
    ((SaveGameData*)gSaveGameData)->completionScore = 1;

    if (name != NULL)
    {
        dst = (u8*)((SaveGameData*)gSaveGameData)->playerName;
        do
        {
            ch = *(u8*)name;
            name++;
            *dst++ = ch;
        } while (ch != '\0');
    }
    else
    {
        ((SaveGameData*)gSaveGameData)->playerName[0] = 'F';
        ((SaveGameData*)gSaveGameData)->playerName[1] = 'O';
        ((SaveGameData*)gSaveGameData)->playerName[2] = 'X';
        ((SaveGameData*)gSaveGameData)->playerName[3] = '\0';
    }

    memcpy(gSaveGameWorkBuffer, gSaveGameData, SAVEGAME_ACTIVE_SIZE);
    if (slot != -1)
    {
        gSaveGameCurrentSlot = slot;
        if (name != NULL)
        {
            return _saveGame((u8)slot, gSaveGameWorkBuffer, saveData);
        }
    }
    return 0;
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
            newFileFlag = ((SaveGameData*)save)->newFileFlag;
            info->valid = newFileFlag;
            if (newFileFlag != 0)
            {
                memcpy(info, ((SaveGameData*)save)->playerName, sizeof(info->name));

                info->percentComplete = (u8)((((SaveGameData*)save)->completionScore * 100) / SAVEGAME_COMPLETION_SCORE_MAX);
                if (((SaveGameData*)save)->completionScore > 0xb3)
                {
                    info->rankA = 6;
                    info->rankB = 4;
                }
                else if (((SaveGameData*)save)->completionScore > 0xb0)
                {
                    info->rankA = 5;
                    info->rankB = 4;
                }
                else if (((SaveGameData*)save)->completionScore > 0xa1)
                {
                    info->rankA = 4;
                    info->rankB = 4;
                }
                else if (((SaveGameData*)save)->completionScore > 0x8a)
                {
                    info->rankA = 4;
                    info->rankB = 3;
                }
                else if (((SaveGameData*)save)->completionScore > 0x81)
                {
                    info->rankA = 3;
                    info->rankB = 3;
                }
                else if (((SaveGameData*)save)->completionScore > 0x71)
                {
                    info->rankA = 3;
                    info->rankB = 2;
                }
                else if (((SaveGameData*)save)->completionScore > 0x62)
                {
                    info->rankA = 2;
                    info->rankB = 2;
                }
                else if (((SaveGameData*)save)->completionScore > 0x48)
                {
                    info->rankA = 2;
                    info->rankB = 1;
                }
                else if (((SaveGameData*)save)->completionScore > 0x3d)
                {
                    info->rankA = 1;
                    info->rankB = 1;
                }
                else if (((SaveGameData*)save)->completionScore > 8)
                {
                    info->rankA = 1;
                    info->rankB = 0;
                }
                else
                {
                    info->rankA = 0;
                    info->rankB = 0;
                }

                info->playTime = (u32)(((SaveGameData*)save)->playTime / 6e+01f);
                info->taskTexts[0] = NULL;
                info->taskTexts[1] = NULL;
                info->taskTexts[2] = NULL;
                info->taskTexts[3] = NULL;
                info->taskTexts[4] = NULL;
                taskIds = ((SaveGameData*)save)->taskHintIds;
                for (i = 0; i < ((SaveGameData*)save)->taskCount; i++)
                {
                    info->taskTexts[i] = gameTextGetPhrase(taskIds[i] + 0xf4, 0);
                }
                info->chaptersUnlocked = 0;
                info->valid = ((SaveGameData*)save)->newFileFlag;
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
    } while (slot < SAVEGAME_SLOT_COUNT);

    return 1;
}

void SaveGame_gplaySetObjGroupStatus(int mapId, int groupBit, int enabled)
{
    SaveGameRecord* s[1];
    u8 createTransient;
    u32 newStatus;
    int oldStatus;
    u32 bit;
    int i;

    s[0] = &gSaveGameRecord;
    createTransient = 0;

    if (mapId >= SAVEGAME_EXTENDED_MAP_THRESHOLD)
    {
        mapId = s[0]->extendedMapActLookup[mapId - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    }
    if (!(mapId < SAVEGAME_MAP_COUNT && gSaveGameMapObjGroupBits[mapId] != 0))
    {
        return;
    }
    {
        if (enabled == -1)
        {
            enabled = 1;
        }
        if (enabled == -2)
        {
            enabled = 0;
            createTransient = 1;
        }

        newStatus = mainGetBit(gSaveGameMapObjGroupBits[mapId]);
        oldStatus = newStatus;
        if (enabled != 0)
        {
            bit = 1 << groupBit;
            newStatus = newStatus | bit;
        }
        else
        {
            bit = 1 << groupBit;
            bit = ~bit;
            newStatus = newStatus & bit;
        }

        mainSetBits(gSaveGameMapObjGroupBits[mapId], newStatus);
        gSaveGameObjGroupCacheIdx[0] = mapId;
        gSaveGameObjGroupCacheIdx[1] = newStatus;

        if (enabled != 0)
        {
            if ((oldStatus & (1 << groupBit)) == 0)
            {
                u32* gp = s[0]->mapObjGroupStatuses;
                for (i = 0; i < SAVEGAME_MAP_COUNT; i++)
                {
                    if (gSaveGameMapObjGroupBits[i] == gSaveGameMapObjGroupBits[mapId])
                    {
                        gp[i] |= 1 << groupBit;
                    }
                }
            }
        }
        else
        {
            u32* gp = s[0]->mapObjGroupStatuses;
            for (i = 0; i < SAVEGAME_MAP_COUNT; i++)
            {
                if (gSaveGameMapObjGroupBits[i] == gSaveGameMapObjGroupBits[mapId])
                {
                    gp[i] &= ~(1 << groupBit);
                }
            }

            if (!createTransient)
            {
                if (saveGame_findTransientMapBit(mapId, groupBit, s[0]) == -1)
                {
                    saveGame_addTransientMapBit(mapId, groupBit, s[0]);
                }
            }
        }
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

s8 SaveGame_findTransientMapBit(int mapId, int shift)
{
    return saveGame_findTransientMapBit(mapId, shift, &gSaveGameRecord);
}

void mapClearBit(int idx, int bit)
{
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD)
        idx = gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    gMapObjGroupStatuses[idx] &= ~(1 << bit);
}

void SaveGame_resetObjGroups(int idx)
{
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD)
        idx = gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    gMapObjGroupStatuses[idx] = 0;
}

u32 SaveGame_mapGetObjGroups(int idx)
{
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD)
        idx = gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    return gMapObjGroupStatuses[idx];
}

void SaveGame_mapUpdateObjGroups(int idx)
{
    u16 bit;
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD)
        idx = gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    bit = gSaveGameMapObjGroupBits[idx];
    if (bit != 0)
    {
        gMapObjGroupStatuses[idx] = mainGetBit(bit);
    }
}
u16 SaveGame_getMapObjGroupBit(int idx)
{
    return gSaveGameMapObjGroupBits[idx];
}

int SaveGame_gplayGetObjGroupStatus(int idx, int shift)
{
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD)
        idx = gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    if (idx != gSaveGameObjGroupCacheIdx[0])
    {
        gSaveGameObjGroupCacheIdx[0] = idx;
        gSaveGameObjGroupCacheIdx[1] = mainGetBit(gSaveGameMapObjGroupBits[idx]);
    }
    return (gSaveGameObjGroupCacheIdx[1] >> shift) & 1;
}

u8 SaveGame_getMapAct(int idx)
{
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD)
        idx = gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    if (idx != gSaveGameMapActCacheIdx[0])
    {
        gSaveGameMapActCacheIdx[0] = idx;
        if (idx < 0 || idx >= SAVEGAME_MAP_COUNT || gSaveGameMapActBits[idx] == 0)
        {
            *((s8*)&gSaveGameMapActCacheIdx + 1) = 0;
        }
        else
        {
            *((s8*)&gSaveGameMapActCacheIdx + 1) = mainGetBit(gSaveGameMapActBits[idx]);
        }
    }
    return *((u8*)&gSaveGameMapActCacheIdx + 1);
}

void SaveGame_gplaySetAct(int idx, int act)
{
    int j;
    u16 bit;
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD)
        idx = gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    mainSetBits(gSaveGameMapActBits[idx], act);
    gSaveGameMapActCacheIdx[0] = idx;
    *((s8*)&gSaveGameMapActCacheIdx + 1) = act;
    j = idx;
    if (j >= SAVEGAME_EXTENDED_MAP_THRESHOLD)
        j = gExtendedMapActLookup[j - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    bit = gSaveGameMapObjGroupBits[j];
    if (bit != 0)
    {
        gMapObjGroupStatuses[j] = mainGetBit(bit);
    }
}

void SaveGame_setMapActLut(int val, int idx)
{
    gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD] = val;
}

void updateSavedHealth(void)
{
    int idx = ((SaveGameData*)gSaveGameData)->currentCharacter;
    ((SaveGameData*)gSaveGameData)->characterStatus[idx].health =
        ((SaveGameData*)gSaveGameWorkBuffer)->characterStatus[idx].health;
}
f32 SaveGame_getPlayTime(void)
{
    return ((SaveGameData*)gSaveGameData)->playTime;
}

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
        if (((SaveGameData*)base)->playTime > ((SaveGameData*)p)->timeEntries[0].time)
        {
            cnt = (((SaveGameData*)base)->timeEntryCount -= 1);
            ((SaveGameTimeEntry*)(p + 0x6f0))->objId = ((SaveGameTimeEntry*)(base + 0x6f0))[cnt].objId;
            ((SaveGameTimeEntry*)(p + 0x6f0))->time = ((SaveGameTimeEntry*)(base + 0x6f0))[((SaveGameData*)base)->timeEntryCount].time;
        }
        else
        {
            p += 8;
            i++;
        }
    }
    if (((SaveGameData*)gSaveGameData)->taskCount > 5)
        *(u8*)0 = 0; /* assert: task count <= 5 */
    if (((SaveGameData*)gSaveGameWorkBuffer)->taskCount > 5)
        *(u8*)0 = 0; /* assert: task count <= 5 */
}

f32 SaveGame_gplayGetTimeRemaining(int id)
{
    s16 count;
    u8* p;
    int i;
    if (id == -1)
        return 0.0f;
    i = 0;
    p = gSaveGameData;
    count = ((SaveGameData*)p)->timeEntryCount;
    for (; i < count; i++)
    {
        if (((SaveGameData*)p)->timeEntries[0].objId == id)
        {
            p = gSaveGameData;
            return ((SaveGameTimeEntry*)(p + 0x6f0))[i].time - ((SaveGameData*)p)->playTime;
        }
        p += 8;
    }
    return 0.0f;
}

int SaveGame_gplayDidTimeExpire(int id)
{
    u8* p;
    s16 count;
    int i;
    if (id == -1)
        return 1;
    p = gSaveGameData;
    count = ((SaveGameData*)p)->timeEntryCount;
    for (i = 0; i < count; i++)
    {
        if (((SaveGameData*)p)->timeEntries[0].objId == id)
            return 0;
        p += 8;
    }
    return 1;
}

void SaveGame_gplayAddTime(int id, f32 time)
{
    SaveGameData* base;
    u8* p;
    s16 count;
    int i;
    f32 total;
    if (id == -1)
        return;
    base = (SaveGameData*)gSaveGameData;
    count = base->timeEntryCount;
    if (count == 0x100)
        return;
    total = 2e+01f * time;
    total += base->playTime;
    i = 0;
    p = (u8*)base;
    for (; i < count; i++)
    {
        if (((SaveGameData*)p)->timeEntries[0].objId == id)
            break;
        p += 8;
    }
    if (i == count)
    {
        base->timeEntryCount++;
    }
    *(int*)((int)gSaveGameData + 0x6f0 + (i << 3)) = id;
    *(f32*)((int)gSaveGameData + 0x6f4 + (i << 3)) = total;
}

void* SaveGame_getSidekickStats(void)
{
    return gSaveGameData + 0x18;
}

void* SaveGame_getCurCharPos(void)
{
    int idx = ((SaveGameData*)gSaveGameData)->currentCharacter;
    return &((SaveGameData*)gSaveGameData)->characterPositions[idx];
}

void* SaveGame_getPlayerStats(void)
{
    int idx = ((SaveGameData*)gSaveGameData)->currentCharacter;
    return gSaveGameData + idx * 12;
}
void SaveGame_setCharacter(u8 c)
{
    ((SaveGameData*)gSaveGameData)->currentCharacter = c;
}
u8 SaveGame_getCurChar(void)
{
    return ((SaveGameData*)gSaveGameData)->currentCharacter;
}
void* SaveGame_getState(void)
{
    return gSaveGameData;
}

void loadMapForCurrentSaveGame(void)
{
    SaveGameData* base;
    gSaveGameMapActCacheIdx[0] = -1;
    gSaveGameObjGroupCacheIdx[0] = -1;
    unlockLevel(0, 0, 1);
    memset((char*)gSaveGameData + 0x6ec, 0, 0x884);
    cutsceneExit();
    audioStopByMask(7);
    stopRumble2();
    resetYbutton();
    base = (SaveGameData*)((char*)gSaveGameData + ((SaveGameData*)gSaveGameData)->currentCharacter * 16);
    mapLoadByCoords(base->characterPositions[0].x, base->characterPositions[0].y,
                    base->characterPositions[0].z, base->characterPositions[0].mapLayer);
    if (getCurUiDll() != 4)
    {
        loadUiDll(1);
    }
    screenTransition_holdThenFadeIn(0x1e, 1);
    saveGameLoadStatus = 2;
}

s32 SaveGame_gplayGetRestartGameNotCleared(void)
{
    return pRestartPoint != 0;
}

void SaveGame_gplayClearRestartPoint(void)
{
    if (pRestartPoint != 0)
    {
        mm_free((void*)pRestartPoint);
        pRestartPoint = 0;
    }
}

void SaveGame_gplayGotoRestartPoint(void)
{
    if (pRestartPoint != 0)
    {
        memcpy(gSaveGameData, (void*)pRestartPoint, SAVEGAME_ACTIVE_SIZE);
    }
    else
    {
        memcpy(gSaveGameData, gSaveGameWorkBuffer, SAVEGAME_ACTIVE_SIZE);
    }
    loadMapForCurrentSaveGame();
}

void SaveGame_gplayRestartPoint(f32* pos, s16 angle, int mapLayer, int bDazed)
{
    int healed = 0;
    if (pRestartPoint == 0)
    {
        pRestartPoint = (u32)mmAlloc(SAVEGAME_ACTIVE_SIZE, 0xffff00ff, 0);
        if (pRestartPoint == 0)
            return;
    }
    if (bDazed != 0)
    {
        mainSetBits(GAMEBIT_CF_DoStandUpAnim, 1);
        if (Player_GetCurrentHealth((int)Obj_GetPlayerObject()) > 1)
        {
            playerAddHealth(Obj_GetPlayerObject(), -1);
            healed = 1;
        }
    }
    memcpy((void*)pRestartPoint, gSaveGameData, SAVEGAME_ACTIVE_SIZE);
    SAVEGAME_CHARACTER_POSITION((u8*)pRestartPoint)->x = pos[0];
    SAVEGAME_CHARACTER_POSITION((u8*)pRestartPoint)->y = pos[1];
    SAVEGAME_CHARACTER_POSITION((u8*)pRestartPoint)->z = pos[2];
    SAVEGAME_CHARACTER_POSITION((u8*)pRestartPoint)->angle = (s8)(angle >> 8);
    ((SaveGameCharacterPosition*)((u8*)pRestartPoint +
                                  SAVEGAME_CHARACTER_POSITION_OFFSET))[gSaveGameData[SAVEGAME_CURRENT_CHARACTER_OFFSET]]
        .mapLayer = mapLayer;
    mainSetBits(GAMEBIT_CF_DoStandUpAnim, 0);
    if (bDazed != 0 && healed != 0)
    {
        playerAddHealth(Obj_GetPlayerObject(), 1);
    }
}

void SaveGame_gplayGotoSavegame(void)
{
    if (((SaveGameData*)gSaveGameWorkBuffer)->characterStatus[0].health < 1)
        ((SaveGameData*)gSaveGameWorkBuffer)->characterStatus[0].health = 1;
    if (((SaveGameData*)gSaveGameWorkBuffer)->characterStatus[1].health < 1)
        ((SaveGameData*)gSaveGameWorkBuffer)->characterStatus[1].health = 1;
    memcpy(gSaveGameData, gSaveGameWorkBuffer, SAVEGAME_ACTIVE_SIZE);
    loadMapForCurrentSaveGame();
}

void SaveGame_gplaySavePoint(f32* pos, s16 angle, int flags, int mapLayer)
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
            memcpy(gSaveGameWorkBuffer, base, 0x5d8);
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
            SAVEGAME_CHARACTER_POSITION(base)->mapLayer = mapLayer;
            memcpy(gSaveGameWorkBuffer, base, SAVEGAME_ACTIVE_SIZE);
            if (pRestartPoint != 0)
            {
                mm_free((void*)pRestartPoint);
                pRestartPoint = 0;
            }
        }
        if (flags & 2)
        {
            base[0x22] = 1;
        }
    }
}

void SaveGame_func08_nop(void)
{
}

void SaveGame_release(void)
{
    if (pRestartPoint != 0)
        mm_free((void*)pRestartPoint);
}

void SaveGame_initialise(void)
{
    SaveGameRecord* record = &gSaveGameRecord;

    memset(&record->game, 0, sizeof(record->game));
    if (!(((SaveGameData*)gSaveGameWorkBuffer)->newFileFlag & 0x80))
    {
        memset(gSaveGameWorkBuffer, 0, SAVEGAME_ACTIVE_SIZE);
    }
    pRestartPoint = 0;
    gSaveGameMapActCacheIdx[0] = -1;
    gSaveGameObjGroupCacheIdx[0] = -1;
    memset(&record->options, 0, sizeof(record->options));
    record->options.widescreenEnabled = 0;
    record->options.subtitlesEnabled = 1;
    record->options.rumbleEnabled = 1;
    record->options.optionsValid = 1;
    record->options.musicVolume = SAVEGAME_DEFAULT_VOLUME;
    record->options.sfxVolume = SAVEGAME_DEFAULT_VOLUME;
    record->options.speechVolume = SAVEGAME_DEFAULT_VOLUME;
    record->transientMapBits[0].mapId = -1;
    record->transientMapBits[1].mapId = -1;
    record->transientMapBits[2].mapId = -1;
    record->transientMapBits[3].mapId = -1;
    record->transientMapBits[4].mapId = -1;
    record->transientMapBits[5].mapId = -1;
    record->transientMapBits[6].mapId = -1;
    record->transientMapBits[7].mapId = -1;
    record->transientMapBits[8].mapId = -1;
    record->transientMapBits[9].mapId = -1;
    record->transientMapBits[10].mapId = -1;
    record->transientMapBits[11].mapId = -1;
    record->transientMapBits[12].mapId = -1;
    record->transientMapBits[13].mapId = -1;
    record->transientMapBits[14].mapId = -1;
    record->transientMapBits[15].mapId = -1;
    record->transientMapBits[16].mapId = -1;
    record->transientMapBits[17].mapId = -1;
    record->transientMapBits[18].mapId = -1;
    record->transientMapBits[19].mapId = -1;
}

u16 gSaveGameMapActBits[120] = {
    0x0000, 0x0000, 0x076E, 0x08EC, 0x04FE, 0x00DF, 0x00E0, 0x00E1, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6,
    0x00E7, 0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x0492, 0x0000, 0x05D0, 0x0000, 0x00ED, 0x00ED, 0x00ED, 0x00F0, 0x0000,
    0x0229, 0x00EE, 0x0000, 0x00EF, 0x0000, 0x0000, 0x0000, 0x03EE, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0349, 0x0000, 0x0492, 0x0492, 0x0547, 0x0000, 0x05D0, 0x0000, 0x076F, 0x0000, 0x0144, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0CC2, 0x0B81, 0x00E1, 0x0000, 0x0000,
    0x0000, 0x00E1, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

u16 gSaveGameMapObjGroupBits[120] = {
    0x03E0, 0x03E0, 0x05DB, 0x08ED, 0x0500, 0x07CE, 0x0480, 0x0452, 0x0452, 0x047B, 0x04AE, 0x0405, 0x0458, 0x036A,
    0x04A6, 0x045A, 0x047C, 0x0000, 0x042E, 0x0493, 0x0000, 0x05D1, 0x0000, 0x03AD, 0x03AD, 0x03AD, 0x0517, 0x0373,
    0x0443, 0x03B7, 0x0421, 0x0C84, 0x0000, 0x0000, 0x0000, 0x0397, 0x0000, 0x0000, 0x0000, 0x0473, 0x0000, 0x0000,
    0x0000, 0x04A3, 0x0A62, 0x0000, 0x0493, 0x0493, 0x0548, 0x0000, 0x05D1, 0x0601, 0x05DC, 0x0000, 0x0145, 0x0000,
    0x04AE, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0DD1, 0x0000,
    0x0D38, 0x0452, 0x0D75, 0x0000, 0x0BC7, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x03E0, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};
typedef struct SaveGameDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback slot03;
    ObjectDescriptorCallback slot04;
    ObjectDescriptorCallback slot05;
    ObjectDescriptorCallback slot06;
    ObjectDescriptorCallback slot07;
    ObjectDescriptorCallback slot08;
    ObjectDescriptorCallback gplaySavePoint;
    ObjectDescriptorCallback gplayGotoSavegame;
    ObjectDescriptorCallback gplayRestartPoint;
    ObjectDescriptorCallback gplayGotoRestartPoint;
    ObjectDescriptorCallback gplayClearRestartPoint;
    ObjectDescriptorCallback gplayGetRestartGameNotCleared;
    ObjectDescriptorCallback slot0F;
    ObjectDescriptorCallback slot10;
    ObjectDescriptorCallback slot11;
    ObjectDescriptorCallback getMapAct;
    ObjectDescriptorCallback gplaySetAct;
    ObjectDescriptorCallback setMapActLut;
    ObjectDescriptorCallback gplayGetObjGroupStatus;
    ObjectDescriptorCallback gplaySetObjGroupStatus;
    ObjectDescriptorCallback getMapObjGroupBit;
    ObjectDescriptorCallback mapUpdateObjGroups;
    ObjectDescriptorCallback mapGetObjGroups;
    ObjectDescriptorCallback resetObjGroups;
    ObjectDescriptorCallback gplayAddTime;
    ObjectDescriptorCallback gplayDidTimeExpire;
    ObjectDescriptorCallback gplayGetTimeRemaining;
    ObjectDescriptorCallback updateTimes;
    ObjectDescriptorCallback getCurChar;
    ObjectDescriptorCallback setCharacter;
    ObjectDescriptorCallback slot21;
    ObjectDescriptorCallback slot22;
    ObjectDescriptorCallback slot23;
    ObjectDescriptorCallback getState;
    ObjectDescriptorCallback getPlayerStats;
    ObjectDescriptorCallback getCurCharPos;
    ObjectDescriptorCallback getSidekickStats;
    ObjectDescriptorCallback slot28;
    ObjectDescriptorCallback slot29;
    ObjectDescriptorCallback slot2A;
    ObjectDescriptorCallback slot2B;
    ObjectDescriptorCallback slot2C;
    ObjectDescriptorCallback getPlayTime;
    ObjectDescriptorCallback slot2E;
    ObjectDescriptorCallback slot2F;
    ObjectDescriptorCallback slot30;
    ObjectDescriptorCallback slot31;
    ObjectDescriptorCallback slot32;
    ObjectDescriptorCallback slot33;
} SaveGameDllInterface;

SaveGameDllInterface SaveGame_funcs = {
    0,
    0,
    0,
    0x00330000,
    (ObjectDescriptorCallback)SaveGame_initialise,
    (ObjectDescriptorCallback)SaveGame_release,
    0,
    0,
    0,
    0,
    0,
    0,
    (ObjectDescriptorCallback)SaveGame_func08_nop,
    (ObjectDescriptorCallback)SaveGame_gplaySavePoint,
    (ObjectDescriptorCallback)SaveGame_gplayGotoSavegame,
    (ObjectDescriptorCallback)SaveGame_gplayRestartPoint,
    (ObjectDescriptorCallback)SaveGame_gplayGotoRestartPoint,
    (ObjectDescriptorCallback)SaveGame_gplayClearRestartPoint,
    (ObjectDescriptorCallback)SaveGame_gplayGetRestartGameNotCleared,
    0,
    0,
    0,
    (ObjectDescriptorCallback)SaveGame_getMapAct,
    (ObjectDescriptorCallback)SaveGame_gplaySetAct,
    (ObjectDescriptorCallback)SaveGame_setMapActLut,
    (ObjectDescriptorCallback)SaveGame_gplayGetObjGroupStatus,
    (ObjectDescriptorCallback)SaveGame_gplaySetObjGroupStatus,
    (ObjectDescriptorCallback)SaveGame_getMapObjGroupBit,
    (ObjectDescriptorCallback)SaveGame_mapUpdateObjGroups,
    (ObjectDescriptorCallback)SaveGame_mapGetObjGroups,
    (ObjectDescriptorCallback)SaveGame_resetObjGroups,
    (ObjectDescriptorCallback)SaveGame_gplayAddTime,
    (ObjectDescriptorCallback)SaveGame_gplayDidTimeExpire,
    (ObjectDescriptorCallback)SaveGame_gplayGetTimeRemaining,
    (ObjectDescriptorCallback)SaveGame_updateTimes,
    (ObjectDescriptorCallback)SaveGame_getCurChar,
    (ObjectDescriptorCallback)SaveGame_setCharacter,
    0,
    0,
    0,
    (ObjectDescriptorCallback)SaveGame_getState,
    (ObjectDescriptorCallback)SaveGame_getPlayerStats,
    (ObjectDescriptorCallback)SaveGame_getCurCharPos,
    (ObjectDescriptorCallback)SaveGame_getSidekickStats,
    0,
    0,
    0,
    0,
    0,
    (ObjectDescriptorCallback)SaveGame_getPlayTime,
    0,
    0,
    0,
    0,
    0,
    0,
};

u8 gSaveGameData[SAVEGAME_LIVE_BUFFER_SIZE];
u8 saveData[SAVE_DATA_SIZE];
u8 gExtendedMapActLookup[SAVEGAME_EXTENDED_MAP_COUNT];
