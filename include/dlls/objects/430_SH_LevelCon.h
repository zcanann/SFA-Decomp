#ifndef DLLS_OBJECTS_430_SH_LEVEL_CON_H_
#define DLLS_OBJECTS_430_SH_LEVEL_CON_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"

typedef struct GameBitLatchState {
    int activeMask;
} GameBitLatchState;

typedef struct ShLevelControlState {
    union {
        u32 flags;
        s32 storyFlags;
    };
    union {
        u8 waitCounter;
        u8 earlySceneDelay;
    };
    u8 mapAct;
    union {
        u8 bloopEventState;
        u8 thornTailState;
    };
    u8 mapEventCountdown;
    union {
        struct {
            f32 airMeterTimer;
            f32 hudTextTimer;
            s16 dayNightMusicLatch;
            s16 musicLatch;
        };
        struct {
            u8 unknown08[0x0A];
            s16 mapOverride;
        };
    };
} ShLevelControlState;

STATIC_ASSERT(sizeof(GameBitLatchState) == 0x04);
STATIC_ASSERT(offsetof(GameBitLatchState, activeMask) == 0x00);

STATIC_ASSERT(sizeof(ShLevelControlState) == 0x14);
STATIC_ASSERT(offsetof(ShLevelControlState, flags) == 0x00);
STATIC_ASSERT(offsetof(ShLevelControlState, storyFlags) == 0x00);
STATIC_ASSERT(offsetof(ShLevelControlState, waitCounter) == 0x04);
STATIC_ASSERT(offsetof(ShLevelControlState, mapAct) == 0x05);
STATIC_ASSERT(offsetof(ShLevelControlState, bloopEventState) == 0x06);
STATIC_ASSERT(offsetof(ShLevelControlState, mapEventCountdown) == 0x07);
STATIC_ASSERT(offsetof(ShLevelControlState, airMeterTimer) == 0x08);
STATIC_ASSERT(offsetof(ShLevelControlState, hudTextTimer) == 0x0C);
STATIC_ASSERT(offsetof(ShLevelControlState, dayNightMusicLatch) == 0x10);
STATIC_ASSERT(offsetof(ShLevelControlState, musicLatch) == 0x12);
STATIC_ASSERT(offsetof(ShLevelControlState, earlySceneDelay) == 0x04);
STATIC_ASSERT(offsetof(ShLevelControlState, thornTailState) == 0x06);
STATIC_ASSERT(offsetof(ShLevelControlState, unknown08) == 0x08);
STATIC_ASSERT(offsetof(ShLevelControlState, mapOverride) == 0x12);

struct ObjSeqState;

int SH_LevelControl_getExtraSize(void);
void SH_LevelControl_free(void);
int SH_LevelControl_sequenceCallback(void* obj, void* unused, struct ObjSeqState* updateState);
void SH_LevelControl_updateTotemPuzzleMapState(void* obj, void* state);
void GameBitLatch_Update(GameBitLatchState* state, int mask, s16 clearIfSetBit, s16 clearIfClearBit, s16 latchBit,
                         int musicId);
void GameBitLatch_UpdateInverted(GameBitLatchState* state, int mask, s16 clearIfSetBit, s16 clearIfClearBit,
                                 s16 latchBit, int musicId);
void SH_LevelControl_update(GameObject* obj);
void SH_LevelControl_init(GameObject* obj);

extern ObjectDescriptor gSH_LevelControlObjDescriptor;

#endif /* DLLS_OBJECTS_430_SH_LEVEL_CON_H_ */
