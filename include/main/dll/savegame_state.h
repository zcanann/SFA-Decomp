#ifndef MAIN_DLL_SAVEGAME_STATE_H_
#define MAIN_DLL_SAVEGAME_STATE_H_

#include "main/dll/player_state.h"
#include "main/dll/savegame_env_api.h"
#include "main/mapEventTypes.h"

#define SAVEGAME_OBJECT_POSITION_COUNT 0x3f

typedef struct SaveGameObjectPosition {
    u32 objectId;
    f32 x;
    f32 y;
    f32 z;
} SaveGameObjectPosition;

/* One saved character's spawn state; SaveGameData.characterPositions[] and the
 * record SaveGame_getCurCharPos() hands out to the map/shader code. */
typedef struct SaveGameCharacterPosition {
    f32 x;
    f32 y;
    f32 z;
    s8 angle;
    s8 mapLayer;
    s8 mapDataFileId;
    u8 padF;
} SaveGameCharacterPosition;

typedef struct SaveGameData {
    PlayerStatus characterStatus[2];
    TrickyStats trickyStats;
    char playerName[4];
    u8 currentCharacter;
    u8 newFileFlag;
    u8 savePointLocked;
    u8 unknown23;
    u8 unknown24[0x168 - 0x24];
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
} SaveGameData;

STATIC_ASSERT(offsetof(SaveGameData, playerName) == 0x1C);
STATIC_ASSERT(sizeof(((SaveGameData*)0)->characterStatus) == 0x18);
STATIC_ASSERT(offsetof(SaveGameData, trickyStats) == 0x18);
STATIC_ASSERT(offsetof(SaveGameData, currentCharacter) == 0x20);
STATIC_ASSERT(offsetof(SaveGameData, newFileFlag) == 0x21);
STATIC_ASSERT(offsetof(SaveGameData, savePointLocked) == 0x22);
STATIC_ASSERT(offsetof(SaveGameData, unknown23) == 0x23);
STATIC_ASSERT(offsetof(SaveGameData, positions) == 0x168);
STATIC_ASSERT(offsetof(SaveGameData, taskHintIds) == 0x558);
STATIC_ASSERT(offsetof(SaveGameData, completionScore) == 0x55D);
STATIC_ASSERT(offsetof(SaveGameData, taskCount) == 0x55E);
STATIC_ASSERT(offsetof(SaveGameData, playTime) == 0x560);
STATIC_ASSERT(offsetof(SaveGameData, characterPositions) == 0x684);
STATIC_ASSERT(offsetof(SaveGameData, camActionNo) == 0x6A4);
STATIC_ASSERT(offsetof(SaveGameData, env) == 0x6A8);
STATIC_ASSERT(sizeof(SaveGameData) == 0x6EC);

#define SAVEGAME_TIME_ENTRY_CAPACITY 256

typedef struct SaveGameTimeEntry {
    int objId;
    f32 time;
} SaveGameTimeEntry;

/* Cleared together when loading a map; never copied into a checkpoint. */
typedef struct SaveGameRuntimeState {
    s16 timeEntryCount;
    u8 unknown02[2];
    SaveGameTimeEntry timeEntries[SAVEGAME_TIME_ENTRY_CAPACITY];
    u8 unknown804[0x80];
} SaveGameRuntimeState;

typedef struct SaveGameState {
    SaveGameData save;
    SaveGameRuntimeState runtime;
} SaveGameState;

STATIC_ASSERT(sizeof(SaveGameObjectPosition) == 0x10);
STATIC_ASSERT(sizeof(SaveGameCharacterPosition) == 0x10);
STATIC_ASSERT(sizeof(SaveGameTimeEntry) == 8);
STATIC_ASSERT(offsetof(SaveGameRuntimeState, timeEntryCount) == 0);
STATIC_ASSERT(offsetof(SaveGameRuntimeState, timeEntries) == 4);
STATIC_ASSERT(offsetof(SaveGameRuntimeState, unknown804) == 0x804);
STATIC_ASSERT(sizeof(SaveGameRuntimeState) == 0x884);
STATIC_ASSERT(offsetof(SaveGameState, runtime) == 0x6EC);
STATIC_ASSERT(sizeof(SaveGameState) == 0xF70);

extern SaveGameState gSaveGameState;
extern SaveGameData* gSaveGameWorkBuffer;

#endif
