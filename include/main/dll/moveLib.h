#ifndef MAIN_DLL_MOVE_LIB_H_
#define MAIN_DLL_MOVE_LIB_H_

#include "global.h"
#include "main/game_object.h"
#include "main/objseq.h"

typedef enum MoveLibPhase
{
    MOVELIB_PHASE_IDLE = 0,
    MOVELIB_PHASE_TURN = 1,
    MOVELIB_PHASE_RUN = 2,
    MOVELIB_PHASE_SETUP = 3,
    MOVELIB_PHASE_DONE = 6,
    MOVELIB_PHASE_FINISH = 7,
    MOVELIB_PHASE_HELD = 8
} MoveLibPhase;

typedef struct MoveLibState
{
    f32 animPhase;
    f32 startOffsetX;
    f32 startOffsetY;
    f32 startOffsetZ;
    f32 targetX;
    f32 targetY;
    f32 targetZ;
    u8 animChannels[0x5a0];
    s16 turnTable[15];
    s16 eventTable[15];
    int setupFlag;
    int turnState;
    u8 phase;
    u8 needsReinit;
    u8 pad602[2];
    void* lastTarget;
    void* lockTarget;
    s16 yawLimitA;
    s16 yawLimitB;
    u8 pointCount;
    u8 modeBits;
    u8 pad612[2];
    f32 lookAtMaxDistance;
    int reattackDelayBase;
    int reattackDelayMin;
    int reattackTimer;
} MoveLibState;

STATIC_ASSERT(offsetof(MoveLibState, targetX) == 0x10);
STATIC_ASSERT(offsetof(MoveLibState, turnTable) == 0x5bc);
STATIC_ASSERT(offsetof(MoveLibState, eventTable) == 0x5da);
STATIC_ASSERT(offsetof(MoveLibState, setupFlag) == 0x5f8);
STATIC_ASSERT(offsetof(MoveLibState, phase) == 0x600);
STATIC_ASSERT(offsetof(MoveLibState, pointCount) == 0x610);
STATIC_ASSERT(offsetof(MoveLibState, lookAtMaxDistance) == 0x614);
STATIC_ASSERT(offsetof(MoveLibState, reattackTimer) == 0x620);
STATIC_ASSERT(sizeof(MoveLibState) == 0x624);

void dll_2E_func03(GameObject* obj, MoveLibState* state);
void dll_2E_func05(GameObject* obj, MoveLibState* state, s16 minYaw, s16 maxYaw, int count);
void dll_2E_func06(GameObject* obj, MoveLibState* state, int point);
int dll_2E_func07(GameObject* obj, ObjSeqState* seq, MoveLibState* state, s16 minYaw, s16 maxYaw);

#endif /* MAIN_DLL_MOVE_LIB_H_ */
