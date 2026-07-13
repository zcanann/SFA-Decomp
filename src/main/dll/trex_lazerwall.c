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
#include "main/dll/tricky.h"
#include "main/model_engine.h"
#include "main/dll/trex_lazerwall.h"

#define GAMEBIT_LAZERWALL_START   0x617
#define GAMEBIT_LAZERWALL_WIN     0x624
#define GAMEBIT_LAZERWALL_LOSE    0x625
#define GAMEBIT_LAZERWALL_RUNNING 0x626

/* challenge state-machine id returned to advance past the start gate */
#define WAITFORSTART_RESULT 6

/* node kinds pushed onto the challenge stack (rom-curve node tag 0xC == A) */
#define LAZERWALL_NODE_TAG_A  0xc
#define LAZERWALL_NODE_KIND_A 1
#define LAZERWALL_NODE_KIND_B 2

#define LAZERWALL_FLAG_ADVANCED 0x20 /* flags bit set after a curve advance */

/* this TU sees the title-menu interface under a differently-named extern; alias
 * to the canonical name */
extern u32* gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy

extern f32 lbl_803E59DC;
extern const f32 lbl_803E59E0; /* curve-node Y bias */
extern u32 lbl_803E59D0;       /* head of the rom-curve search pair (first type id) */


extern void hudFn_8011f38c(u8 x);

int TREX_Lazerwall_popQueuedState(int obj, int animState)
{
    int state;
    int playerObj;
    RingBufferQueue* stackHandle;
    int node;
    u32 head[2];
    int pushKindA;
    int pushKindB;
    int popOut;

    *(RomCurveSearchPair*)head = *(RomCurveSearchPair*)&lbl_803E59D0;
    playerObj = (int)Obj_GetPlayerObject();
    state = *(int*)&((GameObject*)obj)->extra;

    if (*(s8*)(animState + 0x27a) != 0)
    {
        if (Stack_IsEmpty(((TREXLazerwallUpdateTimedChallengeState*)state)->stack) != 0)
        {
            int (*findFn)(f32 x, f32 y, f32 z, int* types, int typeCount, int action) =
                (int (*)(f32, f32, f32, int*, int, int))(*gRomCurveInterface)->find;
            int found = findFn(((GameObject*)playerObj)->anim.localPosX, ((GameObject*)playerObj)->anim.localPosY,
                               ((GameObject*)playerObj)->anim.localPosZ, (int*)head, 2, -1);

            if (found != -1)
            {
                node = (int)(*gRomCurveInterface)->getById(found);
                ((GameObject*)obj)->anim.localPosX = ((LazerwallCurveNode*)node)->x;
                ((GameObject*)obj)->anim.localPosY = lbl_803E59E0 + ((LazerwallCurveNode*)node)->y;
                ((GameObject*)obj)->anim.localPosZ = ((LazerwallCurveNode*)node)->z;
                *(s16*)obj = (s16)((s32)((LazerwallCurveNode*)node)->rotZ << 8);
                ((TREXLazerwallUpdateTimedChallengeState*)state)->nodeTargetY =
                    lbl_803E59E0 + ((LazerwallCurveNode*)node)->y;
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

            *(f32*)(animState + 0x280) = lbl_803E59DC;
            ((TREXLazerwallUpdateTimedChallengeState*)state)->flags =
                (u8)(((TREXLazerwallUpdateTimedChallengeState*)state)->flags | LAZERWALL_FLAG_ADVANCED);
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
    if (mainGetBit(GAMEBIT_LAZERWALL_START) != 0)
    {
        return WAITFORSTART_RESULT;
    }
    return 0;
}

int TREX_Lazerwall_updateTimedChallenge(int obj)
{
    int state;
    int elapsed;
    int now;
    int limit;

    state = *(int*)&((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
        (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    ((TREXLazerwallUpdateTimedChallengeState*)state)->popStateEnabled = 0;
    ObjHits_DisableObject(obj);

    (*(TimerQueryFn*)(*(int*)*(int*)(((TREXLazerwallUpdateTimedChallengeState*)state)->timerObj + 0x68) + 0x54))(
        ((TREXLazerwallUpdateTimedChallengeState*)state)->timerObj, &elapsed, &now, &limit);

    now = now - elapsed;

    if (isGameTimerDisabled() != 0 || now >= limit || elapsed != 0)
    {
        gameTimerStop();
        hudFn_8011f6f0(0);
        mainSetBits(GAMEBIT_LAZERWALL_RUNNING, 0);

        if (now >= limit)
        {
            mainSetBits(GAMEBIT_LAZERWALL_WIN, 1);
        }
        else
        {
            mainSetBits(GAMEBIT_LAZERWALL_LOSE, 1);
        }

        hudFn_8011f38c(2);

        (*gMapEventInterface)->setObjGroupStatus((s32)((GameObject*)obj)->anim.mapEventSlot, 6, 0);

        (*(void (**)(int, int, int, int, int))((char*)*gTitleMenuControlInterface + 0x4))(0, 0xf3, 0, 0, 0);
    }

    return 0;
}
