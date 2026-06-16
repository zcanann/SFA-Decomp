#include "main/mapEvent.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/dll/rom_curve_interface.h"

typedef struct TREXLazerwallUpdateTimedChallengeState
{
    u8 pad0[0x9B0 - 0x0];
    s32 stack;
    s32 unk9B4;
    u8 pad9B8[0x9BC - 0x9B8];
    f32 unk9BC;
    u8 pad9C0[0x9CA - 0x9C0];
    s16 unk9CA;
    u8 pad9CC[0x9D3 - 0x9CC];
    u8 unk9D3;
    u8 unk9D4;
    u8 pad9D5[0x9D6 - 0x9D5];
    u8 unk9D6;
    u8 pad9D7[0x9D8 - 0x9D7];
} TREXLazerwallUpdateTimedChallengeState;

extern void* Obj_GetPlayerObject(void);

extern int Stack_IsEmpty(int stack);
extern int Stack_IsFull(int stack);
extern int Stack_Pop(int stack, int* out);
extern int Stack_Push(int stack, int* in);

extern int isGameTimerDisabled(void);
extern void gameTimerStop(void);
extern void hudFn_8011f6f0(int x);
extern void hudFn_8011f38c(int x);

extern undefined4* gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy

extern f32 lbl_803E59DC;
extern const f32 lbl_803E59E0;
extern u32 lbl_803E59D0;
extern u32 lbl_803E59D4;

typedef struct LazerwallHeadPair {
    u32 a;
    u32 b;
} LazerwallHeadPair;

int TREX_Lazerwall_popQueuedState(int arg1, int arg2)
{
    int state;
    int playerObj;
    int hit;
    u32 head[2];
    int pushKindA;
    int pushKindB;
    int popOut;

    *(LazerwallHeadPair*)head = *(LazerwallHeadPair*)&lbl_803E59D0;
    playerObj = (int)Obj_GetPlayerObject();
    state = *(int*)(arg1 + 0xb8);

    if (*(s8*)(arg2 + 0x27a) != 0)
    {
        if (Stack_IsEmpty(((TREXLazerwallUpdateTimedChallengeState*)state)->stack) != 0)
        {
            int found = (*gRomCurveInterface)->find((int*)head, 2, -1,
                                                    ((GameObject*)playerObj)->anim.localPosX,
                                                    ((GameObject*)playerObj)->anim.localPosY,
                                                    ((GameObject*)playerObj)->anim.localPosZ);

            if (found != -1)
            {
                hit = (int)(*gRomCurveInterface)->getById(found);
                ((GameObject*)arg1)->anim.localPosX = *(f32*)(hit + 0x8);
                ((GameObject*)arg1)->anim.localPosY = lbl_803E59E0 + *(f32*)(hit + 0xc);
                ((GameObject*)arg1)->anim.localPosZ = *(f32*)(hit + 0x10);
                *(s16*)arg1 = (s16)((s32) * (s8*)(hit + 0x2c) << 8);
                ((TREXLazerwallUpdateTimedChallengeState*)state)->unk9BC = lbl_803E59E0 + *(f32*)(hit + 0xc);
                ((TREXLazerwallUpdateTimedChallengeState*)state)->unk9CA = 0;
                ((TREXLazerwallUpdateTimedChallengeState*)state)->unk9D3 = *(u8*)(hit + 0x19);
            }

            if ((s8) * (u8*)(hit + 0x19) == 0xc)
            {
                pushKindA = 1;
                playerObj = ((TREXLazerwallUpdateTimedChallengeState*)state)->stack;
                if (Stack_IsFull(playerObj) == 0)
                {
                    Stack_Push(playerObj, &pushKindA);
                }
            }
            else
            {
                pushKindB = 2;
                playerObj = ((TREXLazerwallUpdateTimedChallengeState*)state)->stack;
                if (Stack_IsFull(playerObj) == 0)
                {
                    Stack_Push(playerObj, &pushKindB);
                }
            }

            *(f32*)(arg2 + 0x280) = lbl_803E59DC;
            ((TREXLazerwallUpdateTimedChallengeState*)state)->unk9D4 = (u8)(
                ((TREXLazerwallUpdateTimedChallengeState*)state)->unk9D4 | 0x20);
        }
    }

    ((TREXLazerwallUpdateTimedChallengeState*)state)->unk9D6 = 0xff;
    if (((TREXLazerwallUpdateTimedChallengeState*)state)->unk9D6 == 0xff)
    {
        playerObj = ((TREXLazerwallUpdateTimedChallengeState*)state)->stack;
        popOut = 0;
        if (Stack_IsEmpty(playerObj) == 0)
        {
            Stack_Pop(playerObj, &popOut);
        }
        return popOut + 1;
    }
    return 0;
}

int TREX_Lazerwall_waitForStartBit(void)
{
    if (GameBit_Get(0x617) != 0)
    {
        return 6;
    }
    return 0;
}

int TREX_Lazerwall_updateTimedChallenge(int arg1)
{
    int state;
    int local10;
    int localC;
    int local8;

    state = *(int*)&((GameObject*)arg1)->extra;
    *(u8*)&((GameObject*)arg1)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)arg1)->anim.resetHitboxMode | 8);
    ((TREXLazerwallUpdateTimedChallengeState*)state)->unk9D6 = 0;
    ObjHits_DisableObject(arg1);

    (*(void (**)(int, int*, int*, int*))(*(int*)*(int*)(((TREXLazerwallUpdateTimedChallengeState*)state)->unk9B4 + 0x68)
        + 0x54))(
        ((TREXLazerwallUpdateTimedChallengeState*)state)->unk9B4, &local10, &localC, &local8);

    localC = localC - local10;

    if (isGameTimerDisabled() != 0 || localC >= local8 || local10 != 0)
    {
        gameTimerStop();
        hudFn_8011f6f0(0);
        GameBit_Set(0x626, 0);

        if (localC >= local8)
        {
            GameBit_Set(0x624, 1);
        }
        else
        {
            GameBit_Set(0x625, 1);
        }

        hudFn_8011f38c(2);

        (*gMapEventInterface)->setObjGroupStatus((s32)((GameObject*)arg1)->anim.mapEventSlot, 6, 0);

        (*(void (**)(int, int, int, int, int))((char*)*gTitleMenuControlInterface + 0x4))(0, 0xf3, 0, 0, 0);
    }

    return 0;
}
