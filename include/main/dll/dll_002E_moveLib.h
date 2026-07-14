#ifndef MAIN_DLL_DLL_002E_MOVELIB_H_
#define MAIN_DLL_DLL_002E_MOVELIB_H_

#include "global.h"
#include "dolphin/mtx/vec_types.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/curve_walker.h"

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

typedef struct MoveLibTarget
{
    s16 angle;
    s16 angleY;
    s16 angleZ;
    u8 pad06[6];
    f32 x;
    f32 y;
    f32 z;
} MoveLibTarget;

STATIC_ASSERT(offsetof(MoveLibTarget, x) == 0xc);
STATIC_ASSERT(sizeof(MoveLibTarget) == 0x18);

typedef struct MoveLibWaypointDef
{
    u8 pad00[0x2c];
    s8 angleX;
    s8 angleY;
} MoveLibWaypointDef;

typedef struct MoveLibHermiteState
{
    Vec start;
    Vec startTangent;
    Vec end;
    Vec endTangent;
    f32 phase;
    f32 length;
} MoveLibHermiteState;

STATIC_ASSERT(offsetof(MoveLibHermiteState, startTangent) == 0xc);
STATIC_ASSERT(offsetof(MoveLibHermiteState, end) == 0x18);
STATIC_ASSERT(offsetof(MoveLibHermiteState, endTangent) == 0x24);
STATIC_ASSERT(offsetof(MoveLibHermiteState, phase) == 0x30);
STATIC_ASSERT(sizeof(MoveLibHermiteState) == 0x38);

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
    GameObject* lastTarget;
    GameObject* lockTarget;
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
void dll_2E_func04(MoveLibState* state, GameObject* target);
void dll_2E_func05(GameObject* obj, MoveLibState* state, s16 minYaw, s16 maxYaw, int count);
void dll_2E_func06(GameObject* obj, MoveLibState* state, int point);
int dll_2E_func07(GameObject* obj, ObjSeqState* seq, MoveLibState* state, s16 minYaw, s16 maxYaw);
void dll_2E_func08(MoveLibState* state, int reattackDelayBase, int reattackDelayMin);
void dll_2E_func09(MoveLibState* state, const void* turnTable, const void* eventTable, int count);
int dll_2E_func0A(int curvePointIndex, void* out);
f32 dll_2E_func0B(int obj, int curvePointIndex);
int dll_2E_func0C(int curvePointIndex, MoveLibTarget* out);
int dll_2E_func0D(GameObject* obj, const MoveLibTarget* target, f32 speed, int move, f32* out, u8* flags);
int dll_2E_func0E(GameObject* obj, RomCurveWalker* route, f32 phase, MoveLibHermiteState* state,
                  int curveVariant, f32* rootOut, int* flags);
int dll_2E_func0F_ret_0(void);
void dll_2E_setLookAtMaxDistance(MoveLibState* state, f32 value);
void dll_2E_release_nop(void);
void dll_2E_initialise_nop(void);
f32 fn_80114224(const Vec* start, const Vec* end, const Vec* startTangent, const Vec* endTangent, int steps);
int fn_80114408(GameObject* obj, const MoveLibWaypointDef* def, MoveLibHermiteState* state, f32* phaseOut,
                f32 speed);

#endif /* MAIN_DLL_DLL_002E_MOVELIB_H_ */
