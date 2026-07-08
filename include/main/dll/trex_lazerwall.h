#ifndef MAIN_DLL_TREX_LAZERWALL_H_
#define MAIN_DLL_TREX_LAZERWALL_H_

#include "global.h"

typedef struct TREXLazerwallUpdateTimedChallengeState
{
    u8 pad0[0x9B0 - 0x0];
    s32 stack;    /* 0x9B0: challenge node stack handle */
    s32 timerObj; /* 0x9B4: timer object */
    u8 pad9B8[0x9BC - 0x9B8];
    f32 nodeTargetY; /* 0x9BC: target Y of the current curve node */
    u8 pad9C0[0x9CA - 0x9C0];
    s16 unk9CA; /* 0x9CA */
    u8 pad9CC[0x9D3 - 0x9CC];
    u8 curveNodeTag; /* 0x9D3: current curve node tag */
    u8 flags;        /* 0x9D4: status flags (LAZERWALL_FLAG_*) */
    u8 pad9D5[0x9D6 - 0x9D5];
    u8 popStateEnabled; /* 0x9D6: gates the queued-state pop (0xff = pop enabled) */
    u8 pad9D7[0x9D8 - 0x9D7];
} TREXLazerwallUpdateTimedChallengeState;

typedef struct RomCurveSearchPair
{
    u32 a;
    u32 b;
} RomCurveSearchPair;

/* rom-curve node record returned by gRomCurveInterface->getById; only the
 * fields touched here are named (full layout in dll_0015_curves.h, which this
 * TU can't include without an extern conflict). */
typedef struct LazerwallCurveNode
{
    u8 pad00[0x8];
    f32 x; /* 0x08 */
    f32 y; /* 0x0C */
    f32 z; /* 0x10 */
    u8 pad14[0x19 - 0x14];
    u8 type; /* 0x19 */
    u8 pad1A[0x2C - 0x1A];
    s8 rotZ; /* 0x2C (placement extension) */
} LazerwallCurveNode;
STATIC_ASSERT(offsetof(LazerwallCurveNode, x) == 0x8);
STATIC_ASSERT(offsetof(LazerwallCurveNode, y) == 0xc);
STATIC_ASSERT(offsetof(LazerwallCurveNode, z) == 0x10);
STATIC_ASSERT(offsetof(LazerwallCurveNode, type) == 0x19);
STATIC_ASSERT(offsetof(LazerwallCurveNode, rotZ) == 0x2c);

/* timer object's query slot (vtable+0x54): fills elapsed/now/limit outparams */
typedef void (*TimerQueryFn)(int timer, int* elapsed, int* now, int* limit);

int TREX_Lazerwall_popQueuedState(int arg1, int arg2);
int TREX_Lazerwall_waitForStartBit(void);
int TREX_Lazerwall_updateTimedChallenge(int arg1);

#endif /* MAIN_DLL_TREX_LAZERWALL_H_ */
