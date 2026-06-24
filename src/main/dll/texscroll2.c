/*
 * kaldachom (DLL 0x00D5) attack/movement state handlers, table A.
 *
 * These seven functions provide gKaldaChomStateHandlersA[0..6]; the table runs
 * [0..7] (A07 is defined in dll_00D5_kaldachom.c), which also registers them.
 * Handlers are stepped one per frame while the baddie is active. Each (a) on the
 * first frame of a move (moveJustStartedA) selects the anim move via
 * ObjAnim_SetCurrentMove and may play an attack sfx / toggle the hit volume, and
 * (b) every frame writes the per-mode movement speed and the unk34D mode tag back
 * into the GroundBaddieState. A05/A02 index the move/speed tables (lbl_803203F8
 * move ids, lbl_80320404 speeds) by the control record's climbFxIndex. A00/A01
 * raise/clear gameBitB and drive the linked-mouth mode.
 */
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/dll/kaldachom_state.h"
#include "main/dll/wallanimator.h"
#include "main/objhits.h"

#define KALDACHOM_EVENT_MOUTH_LINK 0x1000

int kaldachom_stateHandlerA06(int obj, int statePtr)
{
    extern f32 lbl_803E3060;
    extern f32 lbl_803E3090;

    if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
    {
        if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 8, lbl_803E3060, 0);
            ((GroundBaddieState*)statePtr)->baddie.moveDone = 0;
        }
        Sfx_PlayFromObject(obj, SFXsc_attack01);
    }
    ((GameObject*)obj)->anim.rotX += 546;
    ((GroundBaddieState*)statePtr)->baddie.unk34D = 1;
    ((GroundBaddieState*)statePtr)->baddie.moveSpeed = lbl_803E3090;
    ((GroundBaddieState*)statePtr)->baddie.animSpeedA = lbl_803E3060;
    return 0;
}

int kaldachom_stateHandlerA05(int obj, int statePtr)
{
    extern char lbl_803203F8[]; /* char[] for pointer-arithmetic *(s16*) access */
    extern f32 lbl_80320404[];
    extern f32 lbl_803E3060;
    KaldaChomControl* control = ((GroundBaddieState*)((GameObject*)obj)->extra)->control;

    if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
    {
        if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, *(s16*)(lbl_803203F8 + 8), lbl_803E3060, 0);
            ((GroundBaddieState*)statePtr)->baddie.moveDone = 0;
        }
        control->climbFxIndex = 4;
    }
    ((GroundBaddieState*)statePtr)->baddie.moveSpeed = lbl_80320404[control->climbFxIndex];
    ((GroundBaddieState*)statePtr)->baddie.unk34D = 1;
    return 0;
}

int kaldachom_stateHandlerA04(int obj, int statePtr)
{
    extern f32 lbl_803E3060;
    extern f32 lbl_803E3090;

    if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
    {
        if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 3, lbl_803E3060, 0);
            ((GroundBaddieState*)statePtr)->baddie.moveDone = 0;
        }
        Sfx_PlayFromObject(obj, SFXsc_attack01);
    }
    ((GroundBaddieState*)statePtr)->baddie.unk34D = 3;
    ((GroundBaddieState*)statePtr)->baddie.moveSpeed = lbl_803E3090;
    ((GroundBaddieState*)statePtr)->baddie.animSpeedA = lbl_803E3060;
    return 0;
}

int kaldachom_stateHandlerA03(int obj, int statePtr)
{
    extern f32 lbl_803E3060;
    extern f32 lbl_803E3094;

    if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
    {
        ObjHits_EnableObject((u32)obj);
        if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, randomGetRange(6, 7), lbl_803E3060, 0);
            ((GroundBaddieState*)statePtr)->baddie.moveDone = 0;
        }
    }
    ((GroundBaddieState*)statePtr)->baddie.moveSpeed = lbl_803E3094;
    ((GroundBaddieState*)statePtr)->baddie.unk34D = 1;
    return 0;
}

int kaldachom_stateHandlerA02(int obj, int statePtr)
{
    extern s16 lbl_803203F8[]; /* s16[] for direct index access */
    extern f32 lbl_80320404[];
    extern f32 lbl_803E3060;
    KaldaChomControl* control = ((GroundBaddieState*)((GameObject*)obj)->extra)->control;

    if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
    {
        if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, lbl_803203F8[randomGetRange(0, 4)], lbl_803E3060, 0);
            ((GroundBaddieState*)statePtr)->baddie.moveDone = 0;
        }
        ObjHits_EnableObject((u32)obj);
        control->climbFxIndex = 4;
    }
    ((GroundBaddieState*)statePtr)->baddie.moveSpeed = lbl_80320404[control->climbFxIndex];
    ((GroundBaddieState*)statePtr)->baddie.unk34D = 1;
    return 0;
}

int kaldachom_stateHandlerA01(int obj, int statePtr)
{
    extern f32 lbl_803E3060;
    extern f32 lbl_803E307C;
    GroundBaddieState* state = ((GameObject*)obj)->extra;

    if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
    {
        if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 5, lbl_803E3060, 0);
            ((GroundBaddieState*)statePtr)->baddie.moveDone = 0;
        }
        ObjHits_DisableObject((u32)obj);
        ((GroundBaddieState*)statePtr)->baddie.moveSpeed = lbl_803E307C;
        ((GroundBaddieState*)statePtr)->baddie.animSpeedA = lbl_803E3060;
    }
    else if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveDone != 0)
    {
        GameBit_Set(state->gameBitB, 0);
        if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 4, lbl_803E3060, 0);
            ((GroundBaddieState*)statePtr)->baddie.moveDone = 0;
        }
        state->targetState = 0;
    }
    if ((s32)(((GroundBaddieState*)statePtr)->baddie.eventFlags & KALDACHOM_EVENT_MOUTH_LINK) != 0)
    {
        ((GroundBaddieState*)statePtr)->baddie.eventFlags &= ~KALDACHOM_EVENT_MOUTH_LINK;
        kaldachompme_setLinkedMouthMode((u8*)obj, 2);
    }
    return 0;
}

int kaldachom_stateHandlerA00(int obj, int statePtr)
{
    extern f32 lbl_803E3060;
    extern f32 lbl_803E3098;
    extern f32 lbl_803E309C;
    GroundBaddieState* state = ((GameObject*)obj)->extra;

    if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
    {
        if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 4, lbl_803E3060, 0);
            ((GroundBaddieState*)statePtr)->baddie.moveDone = 0;
        }
        kaldachompme_setLinkedMouthMode((u8*)obj, 1);
        ((GroundBaddieState*)statePtr)->baddie.physicsActive = 1;
        GameBit_Set(state->gameBitB, 1);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        ((GameObject*)obj)->anim.alpha = 0xff;
        ((GroundBaddieState*)statePtr)->baddie.unk34D = 1;
        ((GroundBaddieState*)statePtr)->baddie.moveSpeed =
            lbl_803E3098 + ((f32)(u32)state->aggression / lbl_803E309C);
        ObjHits_EnableObject((u32)obj);
    }
    else if ((s32)(s8)((GroundBaddieState*)statePtr)->baddie.moveDone != 0)
    {
        state->targetState = 1;
    }
    return 0;
}
