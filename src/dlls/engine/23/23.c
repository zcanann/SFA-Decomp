#include "main/dll/savegame.h"
#include "main/dll/dll_0015_save_settings.h"
#include "main/gametext_internal.h"
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
#include "main/dll/FRONT/frontend_control.h"

SaveGameData* pRestartPoint;
SaveGameData* gSaveGameWorkBuffer;
s8 gSaveGameMapActCacheIdx[2];
int gSaveGameObjGroupCacheIdx[2];
u8 saveGameLoadStatus;

s8 gSaveGameCurrentSlot = -1;
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
u8 gSaveGameLanguageMap[5] = {LANGUAGE_ENGLISH, LANGUAGE_FRENCH, LANGUAGE_ITALIAN, LANGUAGE_SPANISH, LANGUAGE_GERMAN};
#endif
char sGameplayFoxName[] = "FOX";

#define SAVEGAME_OBJECT_POSITION_OVERRUN_OFFSET 0x20158
#define SAVEGAME_LIVE_BUFFER_SIZE               0xf70
#define SAVEGAME_ACTIVE_SIZE                    0x6ec
#define SAVEGAME_COMPLETION_SCORE_MAX           0xbb
#define SAVE_SCORE_FILE_STRIDE                  0x28
/* number of on-disk save-game slots */
#define SAVEGAME_SLOT_COUNT              3
#define SAVEGAME_MAP_COUNT               0x78
#define SAVEGAME_EXTENDED_MAP_THRESHOLD  0x50
#define SAVEGAME_EXTENDED_MAP_COUNT      (SAVEGAME_MAP_COUNT - SAVEGAME_EXTENDED_MAP_THRESHOLD)
#define SAVEGAME_TRANSIENT_MAP_BIT_COUNT 20
#define SAVEGAME_TRANSIENT_MAP_BIT_TTL   3

enum {
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

typedef struct SaveGameRomListPosition {
    u8 pad0[0x8];
    f32 x;
    f32 y;
    f32 z;
    u32 objectId;
} SaveGameRomListPosition;

#define SAVEGAME_CHARACTER_POSITION(save) (&(save)->characterPositions[(save)->currentCharacter])

typedef struct SaveSelectInfo {
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

typedef struct MapBitTransient {
    s8 mapId;
    u8 shift;
    s8 timer;
} MapBitTransient;

STATIC_ASSERT(offsetof(MapBitTransient, mapId) == 0);
STATIC_ASSERT(offsetof(MapBitTransient, shift) == 1);
STATIC_ASSERT(offsetof(MapBitTransient, timer) == 2);
STATIC_ASSERT(sizeof(MapBitTransient) == 3);

extern u16 gSaveGameMapActBits[];
extern u16 gSaveGameMapObjGroupBits[];
const Vec3f gSaveGameDefaultPosition = {570.6483764648438f, -82.0f, 15790.8203125f};

void loadMapForCurrentSaveGame(void);

SaveGameState gSaveGameState;
u8 saveData[SAVE_DATA_SIZE];
u8 gExtendedMapActLookup[SAVEGAME_EXTENDED_MAP_COUNT];
u32 gMapObjGroupStatuses[SAVEGAME_MAP_COUNT];
MapBitTransient gTransientMapBits[SAVEGAME_TRANSIENT_MAP_BIT_COUNT];

static inline s8 saveGame_findTransientMapBit(int mapId, int shift, const MapBitTransient* entries) {
    int i;

    for (i = 0; i < SAVEGAME_TRANSIENT_MAP_BIT_COUNT; i++) {
        if (mapId == entries[i].mapId && shift == entries[i].shift) {
            return i;
        }
    }
    return -1;
}

static inline void saveGame_addTransientMapBit(int mapId, int shift, MapBitTransient* entries) {
    int i;

    for (i = 0; i < SAVEGAME_TRANSIENT_MAP_BIT_COUNT; i++) {
        if (entries[i].mapId == -1) {
            entries[i].mapId = mapId;
            entries[i].shift = shift;
            entries[i].timer = SAVEGAME_TRANSIENT_MAP_BIT_TTL;
            return;
        }
    }
}

void SaveGame_initialise(void) {
    int i;
    memset(&gSaveGameState, 0, sizeof(gSaveGameState));
    if (!(gSaveGameWorkBuffer->newFileFlag & 0x80)) {
        memset(gSaveGameWorkBuffer, 0, SAVEGAME_ACTIVE_SIZE);
    }
    pRestartPoint = 0;
    gSaveGameMapActCacheIdx[0] = -1;
    gSaveGameObjGroupCacheIdx[0] = -1;
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
    saveFileStruct_resetOptions();
#else
    memset(saveData, 0, sizeof(saveData));
    ((SaveData*)saveData)->widescreenEnabled = 0;
    ((SaveData*)saveData)->subtitlesEnabled = 1;
    ((SaveData*)saveData)->rumbleEnabled = 1;
    ((SaveData*)saveData)->optionsValid = 1;
    ((SaveData*)saveData)->musicVolume = SAVEGAME_DEFAULT_VOLUME;
    ((SaveData*)saveData)->sfxVolume = SAVEGAME_DEFAULT_VOLUME;
    ((SaveData*)saveData)->speechVolume = SAVEGAME_DEFAULT_VOLUME;
#endif
    for (i = 0; i < SAVEGAME_TRANSIENT_MAP_BIT_COUNT; i++) {
        gTransientMapBits[i].mapId = -1;
    }
}

void SaveGame_release(void) {
    if (pRestartPoint != 0) {
        mm_free(pRestartPoint);
    }
}

void SaveGame_func08_nop(void) {
}

void SaveGame_gplaySavePoint(f32* pos, s16 angle, int flags, int mapLayer) {
    SaveGameData* base;
    if (flags & 4) {
        gSaveGameState.save.savePointLocked = 0;
    }
    base = &gSaveGameState.save;
    if (base->savePointLocked == 0) {
        if (flags & 1) {
            memcpy(gSaveGameWorkBuffer, base, 0x5d8);
            if (pRestartPoint != 0) {
                memcpy(pRestartPoint, &gSaveGameState.save, 0x5d8);
            }
        } else {
            SAVEGAME_CHARACTER_POSITION(base)->x = pos[0];
            SAVEGAME_CHARACTER_POSITION(base)->y = pos[1];
            SAVEGAME_CHARACTER_POSITION(base)->z = pos[2];
            SAVEGAME_CHARACTER_POSITION(base)->angle = (s8)(angle >> 8);
            SAVEGAME_CHARACTER_POSITION(base)->mapLayer = mapLayer;
            memcpy(gSaveGameWorkBuffer, base, SAVEGAME_ACTIVE_SIZE);
            if (pRestartPoint != 0) {
                mm_free(pRestartPoint);
                pRestartPoint = 0;
            }
        }
        if (flags & 2) {
            base->savePointLocked = 1;
        }
    }
}

void SaveGame_gplayGotoSavegame(void) {
    if (gSaveGameWorkBuffer->characterStatus[0].health < 1) {
        gSaveGameWorkBuffer->characterStatus[0].health = 1;
    }
    if (gSaveGameWorkBuffer->characterStatus[1].health < 1) {
        gSaveGameWorkBuffer->characterStatus[1].health = 1;
    }
    memcpy(&gSaveGameState.save, gSaveGameWorkBuffer, SAVEGAME_ACTIVE_SIZE);
    loadMapForCurrentSaveGame();
}

void SaveGame_gplayRestartPoint(f32* pos, s16 angle, int mapLayer, int bDazed) {
    int healed = 0;
    if (pRestartPoint == 0) {
        pRestartPoint = mmAlloc(SAVEGAME_ACTIVE_SIZE, 0xffff00ff, 0);
        if (pRestartPoint == 0) {
            return;
        }
    }
    if (bDazed != 0) {
        mainSetBits(GAMEBIT_CF_DoStandUpAnim, 1);
        if (playerGetCurHealth(Obj_GetPlayerObject()) > 1) {
            playerAddHealth(Obj_GetPlayerObject(), -1);
            healed = 1;
        }
    }
    memcpy(pRestartPoint, &gSaveGameState.save, SAVEGAME_ACTIVE_SIZE);
    SAVEGAME_CHARACTER_POSITION(pRestartPoint)->x = pos[0];
    SAVEGAME_CHARACTER_POSITION(pRestartPoint)->y = pos[1];
    SAVEGAME_CHARACTER_POSITION(pRestartPoint)->z = pos[2];
    SAVEGAME_CHARACTER_POSITION(pRestartPoint)->angle = (s8)(angle >> 8);
    pRestartPoint->characterPositions[gSaveGameState.save.currentCharacter].mapLayer = mapLayer;
    mainSetBits(GAMEBIT_CF_DoStandUpAnim, 0);
    if (bDazed != 0 && healed != 0) {
        playerAddHealth(Obj_GetPlayerObject(), 1);
    }
}

void SaveGame_gplayGotoRestartPoint(void) {
    if (pRestartPoint != 0) {
        memcpy(&gSaveGameState.save, pRestartPoint, SAVEGAME_ACTIVE_SIZE);
    } else {
        memcpy(&gSaveGameState.save, gSaveGameWorkBuffer, SAVEGAME_ACTIVE_SIZE);
    }
    loadMapForCurrentSaveGame();
}

void SaveGame_gplayClearRestartPoint(void) {
    if (pRestartPoint != 0) {
        mm_free(pRestartPoint);
        pRestartPoint = 0;
    }
}

s32 SaveGame_gplayGetRestartGameNotCleared(void) {
    return pRestartPoint != 0;
}

void loadMapForCurrentSaveGame(void) {
    int character;
    gSaveGameMapActCacheIdx[0] = -1;
    gSaveGameObjGroupCacheIdx[0] = -1;
    unlockLevel(0, 0, 1);
    memset(&gSaveGameState.runtime, 0, sizeof(gSaveGameState.runtime));
    cutsceneExit();
    audioStopByMask(7);
    stopRumble2();
    resetYbutton();
    character = gSaveGameState.save.currentCharacter;
    mapLoadByCoords(gSaveGameState.save.characterPositions[character].x,
                    gSaveGameState.save.characterPositions[character].y,
                    gSaveGameState.save.characterPositions[character].z,
                    gSaveGameState.save.characterPositions[character].mapLayer);
    if (getCurUiDll() != 4) {
        loadUiDll(1);
    }
    screenTransition_holdThenFadeIn(0x1e, 1);
    saveGameLoadStatus = 2;
}

void* SaveGame_getState(void) {
    return &gSaveGameState.save;
}

u8 SaveGame_getCurChar(void) {
    return gSaveGameState.save.currentCharacter;
}

void SaveGame_setCharacter(u8 c) {
    gSaveGameState.save.currentCharacter = c;
}

void* SaveGame_getPlayerStats(void) {
    int idx = gSaveGameState.save.currentCharacter;
    return &gSaveGameState.save.characterStatus[idx];
}

void* SaveGame_getCurCharPos(void) {
    int idx = gSaveGameState.save.currentCharacter;
    return &gSaveGameState.save.characterPositions[idx];
}

TrickyStats* SaveGame_getTrickyStats(void) {
    return &gSaveGameState.save.trickyStats;
}

void SaveGame_gplayAddTime(int id, f32 time) {
    SaveGameState* base;
    s16 count;
    int i;
    f32 total;
    if (id == -1) {
        return;
    }
    base = &gSaveGameState;
    count = base->runtime.timeEntryCount;
    if (count == SAVEGAME_TIME_ENTRY_CAPACITY) {
        return;
    }
    total = 2e+01f * time;
    total += base->save.playTime;
    i = 0;
    for (; i < count; i++) {
        if (base->runtime.timeEntries[i].objId == id) {
            break;
        }
    }
    if (i == count) {
        base->runtime.timeEntryCount++;
    }
    gSaveGameState.runtime.timeEntries[i].objId = id;
    gSaveGameState.runtime.timeEntries[i].time = total;
}

int SaveGame_gplayDidTimeExpire(int id) {
    s16 count;
    int i;
    if (id == -1) {
        return 1;
    }
    count = gSaveGameState.runtime.timeEntryCount;
    for (i = 0; i < count; i++) {
        if (gSaveGameState.runtime.timeEntries[i].objId == id) {
            return 0;
        }
    }
    return 1;
}

f32 SaveGame_gplayGetTimeRemaining(int id) {
    s16 count;
    int i;
    if (id == -1) {
        return 0.0f;
    }
    i = 0;
    count = gSaveGameState.runtime.timeEntryCount;
    for (; i < count; i++) {
        if (gSaveGameState.runtime.timeEntries[i].objId == id) {
            return gSaveGameState.runtime.timeEntries[i].time - gSaveGameState.save.playTime;
        }
    }
    return 0.0f;
}

void SaveGame_updateTimes(void) {
    int i;
    SaveGameState* base;
    s16 cnt;
    i = 0;
    base = &gSaveGameState;
    base->save.playTime = base->save.playTime + timeDelta;
    while (i < base->runtime.timeEntryCount) {
        if (base->save.playTime > base->runtime.timeEntries[i].time) {
            cnt = (base->runtime.timeEntryCount -= 1);
            base->runtime.timeEntries[i].objId = gSaveGameState.runtime.timeEntries[cnt].objId;
            base->runtime.timeEntries[i].time = gSaveGameState.runtime.timeEntries[base->runtime.timeEntryCount].time;
        } else {
            i++;
        }
    }
    if (gSaveGameState.save.taskCount > 5) {
        *(u8*)0 = 0; /* assert: task count <= 5 */
    }
    if (gSaveGameWorkBuffer->taskCount > 5) {
        *(u8*)0 = 0; /* assert: task count <= 5 */
    }
}

f32 SaveGame_getPlayTime(void) {
    return gSaveGameState.save.playTime;
}

void updateSavedHealth(void) {
    int idx = gSaveGameState.save.currentCharacter;
    gSaveGameState.save.characterStatus[idx].health = gSaveGameWorkBuffer->characterStatus[idx].health;
}

void SaveGame_setMapActLut(int val, int idx) {
    gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD] = val;
}

void SaveGame_gplaySetAct(int idx, int act) {
    int j;
    u16 bit;
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) {
        idx = gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    }
    mainSetBits(gSaveGameMapActBits[idx], act);
    gSaveGameMapActCacheIdx[0] = idx;
    *((s8*)&gSaveGameMapActCacheIdx + 1) = act;
    j = idx;
    if (j >= SAVEGAME_EXTENDED_MAP_THRESHOLD) {
        j = gExtendedMapActLookup[j - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    }
    bit = gSaveGameMapObjGroupBits[j];
    if (bit != 0) {
        gMapObjGroupStatuses[j] = mainGetBit(bit);
    }
}

u8 SaveGame_getMapAct(int idx) {
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) {
        idx = gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    }
    if (idx != gSaveGameMapActCacheIdx[0]) {
        gSaveGameMapActCacheIdx[0] = idx;
        if (idx < 0 || idx >= SAVEGAME_MAP_COUNT || gSaveGameMapActBits[idx] == 0) {
            *((s8*)&gSaveGameMapActCacheIdx + 1) = 0;
        } else {
            *((s8*)&gSaveGameMapActCacheIdx + 1) = mainGetBit(gSaveGameMapActBits[idx]);
        }
    }
    return *((u8*)&gSaveGameMapActCacheIdx + 1);
}

int SaveGame_gplayGetObjGroupStatus(int idx, int shift) {
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) {
        idx = gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    }
    if (idx != gSaveGameObjGroupCacheIdx[0]) {
        gSaveGameObjGroupCacheIdx[0] = idx;
        gSaveGameObjGroupCacheIdx[1] = mainGetBit(gSaveGameMapObjGroupBits[idx]);
    }
    return (gSaveGameObjGroupCacheIdx[1] >> shift) & 1;
}

u16 SaveGame_getMapObjGroupBit(int idx) {
    return gSaveGameMapObjGroupBits[idx];
}

void SaveGame_mapUpdateObjGroups(int idx) {
    u16 bit;
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) {
        idx = gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    }
    bit = gSaveGameMapObjGroupBits[idx];
    if (bit != 0) {
        gMapObjGroupStatuses[idx] = mainGetBit(bit);
    }
}

u32 SaveGame_mapGetObjGroups(int idx) {
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) {
        idx = gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    }
    return gMapObjGroupStatuses[idx];
}

void SaveGame_resetObjGroups(int idx) {
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) {
        idx = gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    }
    gMapObjGroupStatuses[idx] = 0;
}

void mapClearBit(int idx, int bit) {
    if (idx >= SAVEGAME_EXTENDED_MAP_THRESHOLD) {
        idx = gExtendedMapActLookup[idx - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    }
    gMapObjGroupStatuses[idx] &= ~(1 << bit);
}

s8 SaveGame_findTransientMapBit(int mapId, int shift) {
    return saveGame_findTransientMapBit(mapId, shift, gTransientMapBits);
}

void SaveGame_updateTransientMapBits(void) {
    int i;
    for (i = 0; i < SAVEGAME_TRANSIENT_MAP_BIT_COUNT; i++) {
        if (gTransientMapBits[i].mapId != -1) {
            gTransientMapBits[i].timer--;
            if (gTransientMapBits[i].timer <= 0) {
                gTransientMapBits[i].mapId = -1;
            }
        }
    }
}

void SaveGame_gplaySetObjGroupStatus(int mapId, int groupBit, int enabled) {
    u8 suppressTransient;
    u32 newStatus;
    int oldStatus;
    u32 bit;
    int i;

    suppressTransient = 0;

    if (mapId >= SAVEGAME_EXTENDED_MAP_THRESHOLD) {
        mapId = gExtendedMapActLookup[mapId - SAVEGAME_EXTENDED_MAP_THRESHOLD];
    }
    if (!(mapId < SAVEGAME_MAP_COUNT && gSaveGameMapObjGroupBits[mapId] != 0)) {
        return;
    }
    if (enabled == -1) {
        enabled = 1;
    }
    if (enabled == -2) {
        enabled = 0;
        suppressTransient = 1;
    }

    newStatus = mainGetBit(gSaveGameMapObjGroupBits[mapId]);
    oldStatus = newStatus;
    if (enabled != 0) {
        bit = 1 << groupBit;
        newStatus |= bit;
    } else {
        bit = 1 << groupBit;
        bit = ~bit;
        newStatus &= bit;
    }

    mainSetBits(gSaveGameMapObjGroupBits[mapId], newStatus);
    gSaveGameObjGroupCacheIdx[0] = mapId;
    gSaveGameObjGroupCacheIdx[1] = newStatus;

    if (enabled != 0) {
        if ((oldStatus & (1 << groupBit)) == 0) {
            for (i = 0; i < SAVEGAME_MAP_COUNT; i++) {
                if (gSaveGameMapObjGroupBits[i] == gSaveGameMapObjGroupBits[mapId]) {
                    gMapObjGroupStatuses[i] |= 1 << groupBit;
                }
            }
        }
    } else {
        for (i = 0; i < SAVEGAME_MAP_COUNT; i++) {
            if (gSaveGameMapObjGroupBits[i] == gSaveGameMapObjGroupBits[mapId]) {
                gMapObjGroupStatuses[i] &= ~(1 << groupBit);
            }
        }

        if (!suppressTransient) {
            if (saveGame_findTransientMapBit(mapId, groupBit, gTransientMapBits) == -1) {
                saveGame_addTransientMapBit(mapId, groupBit, gTransientMapBits);
            }
        }
    }
}

int saveSelect_getInfo(void* outPtr) {
    SaveSelectInfo* info;
    u8 save[SAVEGAME_ACTIVE_SIZE];
    int slot;
    int i;
    u8* taskIds;
    u8 newFileFlag;

    slot = 0;
    do {
        info = (SaveSelectInfo*)outPtr + slot;
        if (loadSaveGame((u8)slot, save) != 0) {
            newFileFlag = ((SaveGameData*)save)->newFileFlag;
            info->valid = newFileFlag;
            if (newFileFlag != 0) {
                memcpy(info, ((SaveGameData*)save)->playerName, sizeof(info->name));

                info->percentComplete =
                    (u8)((((SaveGameData*)save)->completionScore * 100) / SAVEGAME_COMPLETION_SCORE_MAX);
                if (((SaveGameData*)save)->completionScore > 0xb3) {
                    info->rankA = 6;
                    info->rankB = 4;
                } else if (((SaveGameData*)save)->completionScore > 0xb0) {
                    info->rankA = 5;
                    info->rankB = 4;
                } else if (((SaveGameData*)save)->completionScore > 0xa1) {
                    info->rankA = 4;
                    info->rankB = 4;
                } else if (((SaveGameData*)save)->completionScore > 0x8a) {
                    info->rankA = 4;
                    info->rankB = 3;
                } else if (((SaveGameData*)save)->completionScore > 0x81) {
                    info->rankA = 3;
                    info->rankB = 3;
                } else if (((SaveGameData*)save)->completionScore > 0x71) {
                    info->rankA = 3;
                    info->rankB = 2;
                } else if (((SaveGameData*)save)->completionScore > 0x62) {
                    info->rankA = 2;
                    info->rankB = 2;
                } else if (((SaveGameData*)save)->completionScore > 0x48) {
                    info->rankA = 2;
                    info->rankB = 1;
                } else if (((SaveGameData*)save)->completionScore > 0x3d) {
                    info->rankA = 1;
                    info->rankB = 1;
                } else if (((SaveGameData*)save)->completionScore > 8) {
                    info->rankA = 1;
                    info->rankB = 0;
                } else {
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
                for (i = 0; i < ((SaveGameData*)save)->taskCount; i++) {
                    info->taskTexts[i] = gameTextGetPhrase(taskIds[i] + 0xf4, 0);
                }
                info->chaptersUnlocked = 0;
                info->valid = ((SaveGameData*)save)->newFileFlag;
            } else {
                memset(info, 0, sizeof(SaveSelectInfo));
            }
        } else {
            return 0;
        }

        slot++;
    } while (slot < SAVEGAME_SLOT_COUNT);

    return 1;
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
    SaveGameData* save;

    defaultPos = gSaveGameDefaultPosition;

    memset(&gSaveGameState, 0, SAVEGAME_LIVE_BUFFER_SIZE);
    if ((gSaveGameWorkBuffer->newFileFlag & 0x80) == 0) {
        memset(gSaveGameWorkBuffer, 0, SAVEGAME_ACTIVE_SIZE);
    }

    save = &gSaveGameState.save;
    save->currentCharacter = 0;
    save->characterStatus[0].health = 0xc;
    save->characterStatus[0].maxHealth = 0xc;
    save->characterStatus[0].maxMagic = 0x19;
    save->characterStatus[0].magic = 0;
    save->characterStatus[0].healCountMax = 1;
    save->characterPositions[0].mapDataFileId = -1;
    save->characterStatus[1].health = 0xc;
    save->characterStatus[1].maxHealth = 0xc;
    save->characterStatus[1].maxMagic = 0x19;
    save->characterStatus[1].magic = 0;
    save->characterStatus[1].healCountMax = 1;
    save->characterPositions[1].mapDataFileId = -1;
    save->trickyStats.maxEnergy = 0x14;
    save->camActionNo = -1;
    save->env.unk00 = 4.3e+04f;
    save->env.skyEnvfxActIds[0] = -1;
    save->env.skyEnvfxActIds[1] = -1;
    save->env.cloudActionEnvfxActId = -1;
    save->env.sky2EnvfxActId = -1;
    save->env.cloudEnvfxActIds[0] = -1;
    save->env.cloudEnvfxActIds[1] = -1;
    save->env.cloudEnvfxActIds[2] = -1;
    save->env.cloudStationary[0] = -1;
    save->env.cloudStationary[1] = -1;
    save->env.cloudStationary[2] = -1;
    save->env.envFlags = 9;
    save->unknown23 = 0;
    save->newFileFlag = 1;

    for (i = 0; i < SAVEGAME_MAP_COUNT; i++) {
        if (gSaveGameMapActBits[i] != 0) {
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

    SAVEGAME_CHARACTER_POSITION(&gSaveGameState.save)->x = defaultPos.x;
    gSaveGameState.save.characterPositions[gSaveGameState.save.currentCharacter].y = defaultPos.y;
    gSaveGameState.save.characterPositions[gSaveGameState.save.currentCharacter].z = defaultPos.z;
    gSaveGameState.save.completionScore = 1;

    if (name != NULL) {
        dst = (u8*)gSaveGameState.save.playerName;
        do {
            ch = *(u8*)name;
            name++;
            *dst++ = ch;
        } while (ch != '\0');
    } else {
        gSaveGameState.save.playerName[0] = 'F';
        gSaveGameState.save.playerName[1] = 'O';
        gSaveGameState.save.playerName[2] = 'X';
        gSaveGameState.save.playerName[3] = '\0';
    }

    memcpy(gSaveGameWorkBuffer, &gSaveGameState.save, SAVEGAME_ACTIVE_SIZE);
    if (slot != -1) {
        gSaveGameCurrentSlot = slot;
        if (name != NULL) {
            return _saveGame((u8)slot, gSaveGameWorkBuffer, saveData);
        }
    }
    return 0;
}

char* getSaveFileName(void) {
    return gSaveGameState.save.playerName;
}

int insertHighScore(u8 slot, u8 flag, u32 score, u8* initials) {
    int rank;
    int off;
    int i;

    rank = 0;
    off = slot * SAVE_SCORE_FILE_STRIDE;
    for (; rank < SAVE_SCORE_ENTRY_COUNT; rank++) {
        if (score > ((SaveData*)saveData)->scores[slot][rank].score) {
            for (i = SAVE_SCORE_ENTRY_COUNT - 1; i > rank; i--) {
                ((SaveData*)saveData)->scores[slot][i].score = ((SaveData*)saveData)->scores[slot][i - 1].score;
                ((SaveData*)saveData)->scores[slot][i].flag = ((SaveData*)saveData)->scores[slot][i - 1].flag;
                ((SaveData*)saveData)->scores[slot][i].initials[0] =
                    ((SaveData*)saveData)->scores[slot][i - 1].initials[0];
                ((SaveData*)saveData)->scores[slot][i].initials[1] =
                    ((SaveData*)saveData)->scores[slot][i - 1].initials[1];
                ((SaveData*)saveData)->scores[slot][i].initials[2] =
                    ((SaveData*)saveData)->scores[slot][i - 1].initials[2];
                ((SaveData*)saveData)->scores[slot][i].initials[3] =
                    ((SaveData*)saveData)->scores[slot][i - 1].initials[3];
            }

            ((SaveData*)saveData)->scores[slot][rank].score = score;
            ((SaveData*)saveData)->scores[slot][rank].flag = flag;
            ((SaveData*)((int)saveData + off))->scores[0][rank].initials[0] = initials[0];
            ((SaveData*)((int)saveData + off))->scores[0][rank].initials[1] = initials[1];
            ((SaveData*)((int)saveData + off))->scores[0][rank].initials[2] = initials[2];
            ((SaveData*)((int)saveData + off))->scores[0][rank].initials[3] = initials[3];
            return rank;
        }
    }

    return -1;
}

void* getHighScoreEntry(u8 fileIdx, u8 rank) {
    return &((SaveData*)saveData)->scores[fileIdx][rank];
}

int trySaveGame(int slot) {
    int loaded;

    gSaveGameCurrentSlot = slot;
    memset(&gSaveGameState, 0, SAVEGAME_LIVE_BUFFER_SIZE);
    if ((gSaveGameWorkBuffer->newFileFlag & 0x80) == 0) {
        memset(gSaveGameWorkBuffer, 0, SAVEGAME_ACTIVE_SIZE);
    }

    loaded = loadSaveGame((u8)gSaveGameCurrentSlot, gSaveGameWorkBuffer);
    if (loaded != 0) {
        if (gSaveGameWorkBuffer->newFileFlag == 0) {
            loaded = gplayNewGame(sGameplayFoxName, (u8)gSaveGameCurrentSlot);
        } else {
            memcpy(&gSaveGameState.save, gSaveGameWorkBuffer, SAVEGAME_ACTIVE_SIZE);
        }
    } else {
        gplayNewGame(sGameplayFoxName, -1);
    }
    return loaded;
}

int getSaveGameLoadStatus(void) {
    return saveGameLoadStatus;
}

s32 isSaveGameLoading(void) {
    return saveGameLoadStatus == 2;
}

void setSaveGameLoadingFlag(void) {
    if (saveGameLoadStatus == 2) {
        saveGameLoadStatus = 1;
    }
}

void clearSaveGameLoadingFlag(void) {
    saveGameLoadStatus = 0x0;
}

void saveGame_save(void) {
    if (gSaveGameState.save.savePointLocked == 0) {
        memcpy(gSaveGameWorkBuffer, &gSaveGameState.save, 0x564);
        if (pRestartPoint != 0) {
            memcpy(pRestartPoint, &gSaveGameState.save, 0x564);
        }
    }
    if (gSaveGameCurrentSlot == -1) {
        gSaveGameCurrentSlot = 0;
    }
    if (gSaveGameWorkBuffer->characterStatus[0].health < 1) {
        gSaveGameWorkBuffer->characterStatus[0].health = 1;
    }
    if (gSaveGameWorkBuffer->characterStatus[1].health < 1) {
        gSaveGameWorkBuffer->characterStatus[1].health = 1;
    }
    _saveGame((u8)gSaveGameCurrentSlot, gSaveGameWorkBuffer, saveData);
}

void titleDoLoadSave(void) {
    OSSetSaveRegion(0, 0);
    gSaveGameCurrentSlot = (s8)((gSaveGameWorkBuffer->newFileFlag & 0x60) >> 5);
    gSaveGameWorkBuffer->newFileFlag = gSaveGameWorkBuffer->newFileFlag & ~0xE0;
    (*gMapEventInterface)->gotoSavegame();
}

void gplaySaveGame(int param) {
    gSaveGameState.save.newFileFlag = 0;
    gSaveGameCurrentSlot = param;
    if (gSaveGameState.save.savePointLocked == 0) {
        memcpy(gSaveGameWorkBuffer, &gSaveGameState.save, 0x564);
        if (pRestartPoint != 0) {
            memcpy(pRestartPoint, &gSaveGameState.save, 0x564);
        }
    }
    if (gSaveGameCurrentSlot == -1) {
        gSaveGameCurrentSlot = 0;
    }
    if (gSaveGameWorkBuffer->characterStatus[0].health < 1) {
        gSaveGameWorkBuffer->characterStatus[0].health = 1;
    }
    if (gSaveGameWorkBuffer->characterStatus[1].health < 1) {
        gSaveGameWorkBuffer->characterStatus[1].health = 1;
    }
    _saveGame((u8)gSaveGameCurrentSlot, gSaveGameWorkBuffer, saveData);
}

int loadGameOptions(void) {
    int loadResult;

    loadResult = maybeTryLoadSave(saveData);
    if ((loadResult == 0) || (((SaveData*)saveData)->optionsValid == 0)) {
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
        saveFileStruct_resetOptions();
#else
        memset(saveData, 0, SAVE_DATA_SIZE);
        ((SaveData*)saveData)->widescreenEnabled = 0;
        ((SaveData*)saveData)->subtitlesEnabled = 1;
        ((SaveData*)saveData)->rumbleEnabled = 1;
        ((SaveData*)saveData)->optionsValid = 1;
        ((SaveData*)saveData)->musicVolume = SAVEGAME_DEFAULT_VOLUME;
        ((SaveData*)saveData)->sfxVolume = SAVEGAME_DEFAULT_VOLUME;
        ((SaveData*)saveData)->speechVolume = SAVEGAME_DEFAULT_VOLUME;
#endif
    }
    return loadResult;
}

#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
void saveGameOptions(void) {
    cardWriteOptions(saveData);
}
#endif

SaveGameEnvState* saveGameGetEnvState(void) {
    return &gSaveGameState.save.env;
}

s32 SaveGame_getCamActionNo(void) {
    return gSaveGameState.save.camActionNo;
}

void SaveGame_setCamActionNo(s16 actionNo) {
    gSaveGameState.save.camActionNo = actionNo;
}

void saveGame_saveObjectPos(GameObject* obj) {
    int objectId;
    int i;
    if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0 || (s32)saveGameLoadStatus != 0) {
        return;
    }
    for (i = 0; i < SAVEGAME_OBJECT_POSITION_COUNT; i++) {
        objectId = gSaveGameState.save.positions[i].objectId;
        if (objectId == 0) {
            break;
        }
        if (((SaveGameRomListPosition*)obj->anim.placementData)->objectId == objectId) {
            break;
        }
    }
    if (i == SAVEGAME_OBJECT_POSITION_COUNT) {
        return;
    }
    gSaveGameState.save.positions[i].objectId = ((SaveGameRomListPosition*)obj->anim.placementData)->objectId;
    gSaveGameState.save.positions[i].x = obj->anim.localPosX;
    gSaveGameState.save.positions[i].y = obj->anim.localPosY;
    gSaveGameState.save.positions[i].z = obj->anim.localPosZ;
    ((SaveGameRomListPosition*)obj->anim.placementData)->x = obj->anim.localPosX;
    ((SaveGameRomListPosition*)obj->anim.placementData)->y = obj->anim.localPosY;
    ((SaveGameRomListPosition*)obj->anim.placementData)->z = obj->anim.localPosZ;
}

void saveGame_unsaveObjectPos(GameObject* obj) {
    int i;
    u32 objectId;

    if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0 || (s32)saveGameLoadStatus != 0) {
        return;
    }

    for (i = 0; i < SAVEGAME_OBJECT_POSITION_COUNT; i++) {
        objectId = ((SaveGameRomListPosition*)obj->anim.placementData)->objectId;
        if (objectId == gSaveGameState.save.positions[i].objectId) {
            break;
        }
    }
    if (i == SAVEGAME_OBJECT_POSITION_COUNT) {
        return;
    }

    for (; i < SAVEGAME_OBJECT_POSITION_COUNT - 1; i++) {
        gSaveGameState.save.positions[i].objectId = gSaveGameState.save.positions[i + 1].objectId;
        gSaveGameState.save.positions[i].x = gSaveGameState.save.positions[i + 1].x;
        gSaveGameState.save.positions[i].y = gSaveGameState.save.positions[i + 1].y;
        gSaveGameState.save.positions[i].z = gSaveGameState.save.positions[i + 1].z;
    }
    /* Retail writes beyond live state into unrelated BSS; preserve the bug. */
    *(u32*)((u8*)&gSaveGameState + SAVEGAME_OBJECT_POSITION_OVERRUN_OFFSET) = 0;
}

int saveGame_restoreObjectPosToRomList(void* objectData) {
    SaveGameRomListPosition* object = objectData;
    SaveGameData* save;
    int i;

    for (i = 0; i < SAVEGAME_OBJECT_POSITION_COUNT; i++) {
        if (object->objectId == gSaveGameState.save.positions[i].objectId) {
            save = &gSaveGameState.save;
            object->x = save->positions[i].x;
            object->y = save->positions[i].y;
            object->z = save->positions[i].z;
            return 1;
        }
    }

    return 0;
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
    ObjectDescriptorCallback getTrickyStats;
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
    (ObjectDescriptorCallback)SaveGame_getTrickyStats,
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
