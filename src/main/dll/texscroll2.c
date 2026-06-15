#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/dll/wallanimator.h"
#include "main/objhits.h"

typedef struct KaldachomState
{
    u8 pad0[0x4A - 0x0];
    u8 unk4A;
    u8 pad4B[0x50 - 0x4B];
} KaldachomState;

int kaldachom_stateHandlerA04(int obj, int p2)
{
    extern f32 lbl_803E3060;
    extern f32 lbl_803E3090;

    if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
    {
        if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 3, lbl_803E3060, 0);
            ((GroundBaddieState*)p2)->baddie.moveDone = 0;
        }
        Sfx_PlayFromObject(obj, SFXsc_attack01);
    }
    ((GroundBaddieState*)p2)->baddie.unk34D = 3;
    ((GroundBaddieState*)p2)->baddie.moveSpeed = lbl_803E3090;
    ((GroundBaddieState*)p2)->baddie.animSpeedA = lbl_803E3060;
    return 0;
}

int kaldachom_stateHandlerA06(int obj, int p2)
{
    extern f32 lbl_803E3060;
    extern f32 lbl_803E3090;

    if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
    {
        if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 8, lbl_803E3060, 0);
            ((GroundBaddieState*)p2)->baddie.moveDone = 0;
        }
        Sfx_PlayFromObject(obj, SFXsc_attack01);
    }
    ((GameObject*)obj)->anim.rotX += 546;
    ((GroundBaddieState*)p2)->baddie.unk34D = 1;
    ((GroundBaddieState*)p2)->baddie.moveSpeed = lbl_803E3090;
    ((GroundBaddieState*)p2)->baddie.animSpeedA = lbl_803E3060;
    return 0;
}

int kaldachom_stateHandlerA03(int obj, int p2)
{
    extern f32 lbl_803E3060;
    extern f32 lbl_803E3094;

    if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
    {
        ObjHits_EnableObject((u32)obj);
        if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, randomGetRange(6, 7), lbl_803E3060, 0);
            ((GroundBaddieState*)p2)->baddie.moveDone = 0;
        }
    }
    ((GroundBaddieState*)p2)->baddie.moveSpeed = lbl_803E3094;
    ((GroundBaddieState*)p2)->baddie.unk34D = 1;
    return 0;
}

int kaldachom_stateHandlerA05(int obj, int p2)
{
    extern char lbl_803203F8[];
    extern f32 lbl_80320404[];
    extern f32 lbl_803E3060;
    int sub = *(int*)&((GroundBaddieState*)((GameObject*)obj)->extra)->control;

    if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
    {
        if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, *(s16*)(lbl_803203F8 + 8), lbl_803E3060, 0);
            ((GroundBaddieState*)p2)->baddie.moveDone = 0;
        }
        ((KaldachomState*)sub)->unk4A = 4;
    }
    ((GroundBaddieState*)p2)->baddie.moveSpeed = lbl_80320404[(u32)((KaldachomState*)sub)->unk4A];
    ((GroundBaddieState*)p2)->baddie.unk34D = 1;
    return 0;
}

int kaldachom_stateHandlerA02(int obj, int p2)
{
    extern s16 lbl_803203F8[];
    extern f32 lbl_80320404[];
    extern f32 lbl_803E3060;
    int sub = *(int*)&((GroundBaddieState*)((GameObject*)obj)->extra)->control;

    if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
    {
        if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, lbl_803203F8[(s32)randomGetRange(0, 4)], lbl_803E3060, 0);
            ((GroundBaddieState*)p2)->baddie.moveDone = 0;
        }
        ObjHits_EnableObject((u32)obj);
        ((KaldachomState*)sub)->unk4A = 4;
    }
    ((GroundBaddieState*)p2)->baddie.moveSpeed = lbl_80320404[(u32)((KaldachomState*)sub)->unk4A];
    ((GroundBaddieState*)p2)->baddie.unk34D = 1;
    return 0;
}

int kaldachom_stateHandlerA01(int obj, int p2)
{
    extern f32 lbl_803E3060;
    extern f32 lbl_803E307C;
    GroundBaddieState* state = ((GameObject*)obj)->extra;

    if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
    {
        if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 5, lbl_803E3060, 0);
            ((GroundBaddieState*)p2)->baddie.moveDone = 0;
        }
        ObjHits_DisableObject((u32)obj);
        ((GroundBaddieState*)p2)->baddie.moveSpeed = lbl_803E307C;
        ((GroundBaddieState*)p2)->baddie.animSpeedA = lbl_803E3060;
    }
    else if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveDone != 0)
    {
        GameBit_Set(state->gameBitB, 0);
        if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 4, lbl_803E3060, 0);
            ((GroundBaddieState*)p2)->baddie.moveDone = 0;
        }
        state->targetState = 0;
    }
    if ((s32)(((GroundBaddieState*)p2)->baddie.eventFlags & 0x1000) != 0)
    {
        ((GroundBaddieState*)p2)->baddie.eventFlags &= 0xffffefff;
        kaldachompme_setLinkedMouthMode((u8*)obj, 2);
    }
    return 0;
}

int kaldachom_stateHandlerA00(int obj, int p2)
{
    extern f32 lbl_803E3060;
    extern f32 lbl_803E3098;
    extern f32 lbl_803E309C;
    GroundBaddieState* state = ((GameObject*)obj)->extra;

    if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
    {
        if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 4, lbl_803E3060, 0);
            ((GroundBaddieState*)p2)->baddie.moveDone = 0;
        }
        kaldachompme_setLinkedMouthMode((u8*)obj, 1);
        ((GroundBaddieState*)p2)->baddie.physicsActive = 1;
        GameBit_Set(state->gameBitB, 1);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
        ((GameObject*)obj)->anim.alpha = 0xff;
        ((GroundBaddieState*)p2)->baddie.unk34D = 1;
        ((GroundBaddieState*)p2)->baddie.moveSpeed =
            lbl_803E3098 + ((f32)(u32)
        state->aggression / lbl_803E309C
        )
        ;
        ObjHits_EnableObject((u32)obj);
    }
    else if ((s32)(s8)((GroundBaddieState*)p2)->baddie.moveDone != 0)
    {
        state->targetState = 1;
    }
    return 0;
}
