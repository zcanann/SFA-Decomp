/*
 * trex_lazerwall - ThornTail/T-Rex "lazerwall" timed-challenge object.
 *
 * Three handlers, all installed as vtable slots by the spshopkeeper DLL
 * (dll_0286_spshopkeeper.c, lbl_803AD068[3..5]):
 *
 *   popQueuedState - advances the player along the rom-curve segment nearest
 *     the player, pushing a per-node kind onto the challenge's stack and
 *     popping the next queued state id.
 *   waitForStartBit - gate that returns 6 (a sequence/state id) once the
 *     challenge-start game bit is set.
 *   updateTimedChallenge - per-frame tick while the challenge runs. Queries
 *     the timer object (timerObj) for elapsed/limit times; when the game timer
 *     is disabled, the limit is reached, or the start tick fires, it stops the
 *     timer, clears the running bit, records win (limit reached) vs lose, pops
 *     up the HUD result, frees the object group and closes the title-menu HUD.
 *
 * Game bits owned/used here: 0x617 start, 0x624 win, 0x625 lose, 0x626 running.
 */
#include "main/mapEvent.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/dll/rom_curve_interface.h"
#include "main/gameplay_runtime.h"
#include "sfa_light_decls.h"

#define GAMEBIT_LAZERWALL_START 0x617
#define GAMEBIT_LAZERWALL_WIN 0x624
#define GAMEBIT_LAZERWALL_LOSE 0x625
#define GAMEBIT_LAZERWALL_RUNNING 0x626

/* challenge state-machine id returned to advance past the start gate */
#define WAITFORSTART_RESULT 6

/* node kinds pushed onto the challenge stack (rom-curve node tag 0xC == A) */
#define LAZERWALL_NODE_TAG_A 0xc
#define LAZERWALL_NODE_KIND_A 1
#define LAZERWALL_NODE_KIND_B 2

#define LAZERWALL_FLAG_ADVANCED 0x20 /* flags bit set after a curve advance */

typedef struct TREXLazerwallUpdateTimedChallengeState
{
    u8 pad0[0x9B0 - 0x0];
    s32 stack;            /* 0x9B0: challenge node stack handle */
    s32 timerObj;           /* 0x9B4: timer object */
    u8 pad9B8[0x9BC - 0x9B8];
    f32 nodeTargetY;           /* 0x9BC: target Y of the current curve node */
    u8 pad9C0[0x9CA - 0x9C0];
    s16 unk9CA;           /* 0x9CA */
    u8 pad9CC[0x9D3 - 0x9CC];
    u8 curveNodeTag;            /* 0x9D3: current curve node tag */
    u8 flags;            /* 0x9D4: status flags (LAZERWALL_FLAG_*) */
    u8 pad9D5[0x9D6 - 0x9D5];
    u8 popStateEnabled;   /* 0x9D6: gates the queued-state pop (0xff = pop enabled) */
    u8 pad9D7[0x9D8 - 0x9D7];
} TREXLazerwallUpdateTimedChallengeState;

extern int Stack_IsEmpty(int stack);
extern int Stack_IsFull(int stack);
extern int Stack_Pop(int stack, int* out);
extern int Stack_Push(int stack, int* in);


extern void hudFn_8011f38c(u8 x);

/* this TU sees the title-menu interface under a differently-named extern; alias
 * to the canonical name */
extern u32* gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy

extern f32 lbl_803E59DC;
extern const f32 lbl_803E59E0; /* curve-node Y bias */
extern u32 lbl_803E59D0;       /* head of the rom-curve search pair (first type id) */

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
    f32 x;     /* 0x08 */
    f32 y;     /* 0x0C */
    f32 z;     /* 0x10 */
    u8 pad14[0x19 - 0x14];
    u8 type;   /* 0x19 */
    u8 pad1A[0x2C - 0x1A];
    s8 rotZ;   /* 0x2C (placement extension) */
} LazerwallCurveNode;
STATIC_ASSERT(offsetof(LazerwallCurveNode, x) == 0x8);
STATIC_ASSERT(offsetof(LazerwallCurveNode, y) == 0xc);
STATIC_ASSERT(offsetof(LazerwallCurveNode, z) == 0x10);
STATIC_ASSERT(offsetof(LazerwallCurveNode, type) == 0x19);
STATIC_ASSERT(offsetof(LazerwallCurveNode, rotZ) == 0x2c);

/* timer object's query slot (vtable+0x54): fills elapsed/now/limit outparams */
typedef void (*TimerQueryFn)(int timer, int* elapsed, int* now, int* limit);

int TREX_Lazerwall_popQueuedState(int arg1, int arg2)
{
    int state;
    int playerObj;
    int stackHandle;
    int node;
    u32 head[2];
    int pushKindA;
    int pushKindB;
    int popOut;

    *(RomCurveSearchPair*)head = *(RomCurveSearchPair*)&lbl_803E59D0;
    playerObj = (int)Obj_GetPlayerObject();
    state = *(int*)&((GameObject*)arg1)->extra;

    if (*(s8*)(arg2 + 0x27a) != 0)
    {
        if (Stack_IsEmpty(((TREXLazerwallUpdateTimedChallengeState*)state)->stack) != 0)
        {
            int (*findFn)(f32 x, f32 y, f32 z, int* types, int typeCount, int action) =
                (int (*)(f32, f32, f32, int*, int, int))(*gRomCurveInterface)->find;
            int found = findFn(((GameObject*)playerObj)->anim.localPosX,
                               ((GameObject*)playerObj)->anim.localPosY,
                               ((GameObject*)playerObj)->anim.localPosZ,
                               (int*)head, 2, -1);

            if (found != -1)
            {
                node = (int)(*gRomCurveInterface)->getById(found);
                ((GameObject*)arg1)->anim.localPosX = ((LazerwallCurveNode*)node)->x;
                ((GameObject*)arg1)->anim.localPosY = lbl_803E59E0 + ((LazerwallCurveNode*)node)->y;
                ((GameObject*)arg1)->anim.localPosZ = ((LazerwallCurveNode*)node)->z;
                *(s16*)arg1 = (s16)((s32)((LazerwallCurveNode*)node)->rotZ << 8);
                ((TREXLazerwallUpdateTimedChallengeState*)state)->nodeTargetY = lbl_803E59E0 + ((LazerwallCurveNode*)node)->y;
                ((TREXLazerwallUpdateTimedChallengeState*)state)->unk9CA = 0;
                ((TREXLazerwallUpdateTimedChallengeState*)state)->curveNodeTag = *(u8*)(node + 0x19);
            }

            if ((s8) * (u8*)(node + 0x19) == LAZERWALL_NODE_TAG_A)
            {
                pushKindA = LAZERWALL_NODE_KIND_A;
                stackHandle = ((TREXLazerwallUpdateTimedChallengeState*)state)->stack;
                if (Stack_IsFull(stackHandle) == 0)
                {
                    Stack_Push(stackHandle, &pushKindA);
                }
            }
            else
            {
                pushKindB = LAZERWALL_NODE_KIND_B;
                stackHandle = ((TREXLazerwallUpdateTimedChallengeState*)state)->stack;
                if (Stack_IsFull(stackHandle) == 0)
                {
                    Stack_Push(stackHandle, &pushKindB);
                }
            }

            *(f32*)(arg2 + 0x280) = lbl_803E59DC;
            ((TREXLazerwallUpdateTimedChallengeState*)state)->flags = (u8)(
                ((TREXLazerwallUpdateTimedChallengeState*)state)->flags | LAZERWALL_FLAG_ADVANCED);
        }
    }

    ((TREXLazerwallUpdateTimedChallengeState*)state)->popStateEnabled = 0xff;
    if (((TREXLazerwallUpdateTimedChallengeState*)state)->popStateEnabled == 0xff)
    {
        stackHandle = ((TREXLazerwallUpdateTimedChallengeState*)state)->stack;
        popOut = 0;
        if (Stack_IsEmpty(stackHandle) == 0)
        {
            Stack_Pop(stackHandle, &popOut);
        }
        return popOut + 1;
    }
    return 0;
}

int TREX_Lazerwall_waitForStartBit(void)
{
    if (GameBit_Get(GAMEBIT_LAZERWALL_START) != 0)
    {
        return WAITFORSTART_RESULT;
    }
    return 0;
}

int TREX_Lazerwall_updateTimedChallenge(int arg1)
{
    int state;
    int elapsed;
    int now;
    int limit;

    state = *(int*)&((GameObject*)arg1)->extra;
    *(u8*)&((GameObject*)arg1)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)arg1)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    ((TREXLazerwallUpdateTimedChallengeState*)state)->popStateEnabled = 0;
    ObjHits_DisableObject(arg1);

    (*(TimerQueryFn*)(*(int*)*(int*)(((TREXLazerwallUpdateTimedChallengeState*)state)->timerObj + 0x68)
        + 0x54))(
        ((TREXLazerwallUpdateTimedChallengeState*)state)->timerObj, &elapsed, &now, &limit);

    now = now - elapsed;

    if (isGameTimerDisabled() != 0 || now >= limit || elapsed != 0)
    {
        gameTimerStop();
        hudFn_8011f6f0(0);
        GameBit_Set(GAMEBIT_LAZERWALL_RUNNING, 0);

        if (now >= limit)
        {
            GameBit_Set(GAMEBIT_LAZERWALL_WIN, 1);
        }
        else
        {
            GameBit_Set(GAMEBIT_LAZERWALL_LOSE, 1);
        }

        hudFn_8011f38c(2);

        (*gMapEventInterface)->setObjGroupStatus((s32)((GameObject*)arg1)->anim.mapEventSlot, 6, 0);

        (*(void (**)(int, int, int, int, int))((char*)*gTitleMenuControlInterface + 0x4))(0, 0xf3, 0, 0, 0);
    }

    return 0;
}
