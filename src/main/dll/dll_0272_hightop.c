/*
 * hightop (DLL 0x272) - the "HighTop" rideable/escortable dinosaur baddie
 * (object type 0x43).
 *
 * Runs as a BaddieState-driven object with an 11-entry state-handler
 * table (gHighTopStateHandlers, installed in HighTop_initialise) plus a
 * default handler. States cover idle/wander (04), locomotion (02),
 * follow/turn (01), the air-meter ride sequence (07/08), reset/death (09),
 * and a scripted progress state (10). It owns a path-control walker
 * (gPathControlInterface) for ground motion, a look-controller from
 * dll_2E, eye animation, movement SFX, and the on-screen air meter
 * (gGameUIInterface). Hits drain the air meter; emptying it shuts the
 * meter down, spawns a follow-up object and sets GameBit 0xB48.
 *
 * Interaction is gated through trigger sequences (gObjectTriggerInterface)
 * and a set of GameBits (e.g. 0x631/0x632/0x634, the 0x9C7.. progress
 * quartet, and the 0x3F0.. counters).
 */
#include "main/dll/dll_0272_hightop.h"

void* gHighTopDefaultStateHandler;
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/maketex_random_api.h"
#include "main/maketex_timer_api.h"
#include "main/vecmath.h"
#include "main/pad.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/tricky_api.h"
#include "main/dll/objfx_api.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/game_ui_interface.h"
#include "main/object.h"
#include "main/object_render.h"
#include "main/obj_group.h"
#include "main/obj_path.h"
#include "main/obj_trigger.h"
#include "main/objanim.h"
#include "main/objseq.h"
#include "main/objprint_api.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_sound_api.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/object_api.h"
#include "main/dll/baddie_state.h"
#include "main/obj_placement.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx_play_api.h"
#include "main/gamebit_ids.h"
#include "main/player_control_interface.h"
#include "main/object_descriptor.h"

const HtInitData gHighTopLookInitData1 = {{5, 5, 0, 0, 0, 0, 0, 0, 0}};
const HtInitData gHighTopLookInitData2 = {{8, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF}};

typedef struct HighTopPathParams
{
    u8 values[4];
} HighTopPathParams;

static const HighTopPathParams sHighTopPathParams = {{1, 1, 1, 1}};

#define PAD_BUTTON_A 0x100

/* Death follow-up spawn (docblock: "Obj_AllocObjectSetup(0x2C, 0xD4)"): object id
   (retail OBJECTS.bin name "FXEmit", DLL 0x12B) and effect id. */
#define HIGHTOP_DEATH_SPAWN_OBJ_ID 0xd4
#define HIGHTOP_DEATH_EFFECT_ID    0x675
#define HIGHTOP_AIRMETER_BGTEXTURE 0x5ce

/* HighTopRuntime.flagsC40 bits (0x140 clear = CURVE_FOLLOW + bit 0x100 together) */
#define HIGHTOP_FLAG_CURVE_ARMED  0x20 /* curve-follow armed (set with CURVE_FOLLOW) */
#define HIGHTOP_FLAG_CURVE_FOLLOW 0x40 /* running Obj_UpdateRomCurveFollowVelocity */

#define HIGHTOP_OBJECT_TYPE_ID 0x43
#define HIGHTOP_OBJGROUP       0xa
#define ARWARWING_OBJGROUP     0x26


int hightop_stateHandler10(GameObject* obj, HighTopRuntime* stateArg)
{
    HighTopRuntime* rt = obj->extra;
    int* weight;
    int roll;
    int i;
    if ((s8)stateArg->baddie.moveJustStartedA != 0)
    {
        rt->substate = 3;
        *(int*)((char*)stateArg + 0) |= 0x1000000;
    }
    if (mainGetBit(GAMEBIT_ITEM_NWKey_Got2) != 0)
    {
        if ((int)mainGetBit(GAMEBIT_CC_ActNo) == 2)
        {
            rt->substate = 7;
        }
        else
        {
            rt->substate = 9;
        }
    }
    else
    {
        rt->substate = 3;
    }
    if (Vec_distance((f32*)((char*)Obj_GetPlayerObject() + 0x18), &obj->anim.worldPosX) > 700.0f)
    {
        if (randFn_80080100(500) != 0)
        {
            roll = randomGetRange(0, 100);
            i = 0;
            weight = gHighTopIdleSequenceWeights;
            while (*weight < roll)
            {
                weight++;
                roll -= gHighTopIdleSequenceWeights[i++];
            }
            (*gObjectTriggerInterface)->runSequence(gHighTopIdleSequenceIds[i], (void*)obj, -1);
        }
    }
    return 0;
}

int hightop_stateHandler09(GameObject* obj, HighTopRuntime* stateArg)
{
    HighTopRuntime* state = (obj)->extra;
    HighTopPlacement* placement = (HighTopPlacement*)obj->anim.placementData;
    int i;
    int prevCount;
    int* weight;
    int roll;
    int idx;
    if ((s8)stateArg->baddie.moveJustStartedA != 0 || state->flagsC49.b6 != 0)
    {
        if (state->flagsC4A.b0 == 0)
        {
            state->substate = 0;
        }
        else
        {
            state->substate = 9;
        }
        state->flags &= ~1;
        state->flagsC49.b1 = 0;
        state->idleSeqIndex = 0;
        state->flagsC49.b6 = 0;
        *(u32*)stateArg |= 0x1000000;
        storeZeroToFloatParam(&state->transitionTimer);
        ObjHits_EnableObject(obj);
        if ((obj)->anim.currentMove != 2)
        {
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x78);
            ObjAnim_SetCurrentMove((int)obj, 2, 0.0f, 0);
            stateArg->baddie.moveSpeed = 0.004f;
        }
        stateArg->baddie.moveSpeed = 0.004f;
        prevCount = mainGetBit(GAMEBIT_ITEM_CCGoldBar_Used) - 1;
        state->savedControlMode = 9;
        for (i = 0; i < 4; i++)
        {
            mainSetBits(gHighTopProgressGameBitIds[i], i > prevCount);
        }
        if (prevCount == 3)
        {
            mainSetBits(GAMEBIT_ITEM_HighTopGold_Found, 1);
            return 0xb;
        }
    }
    if (mainGetBit(placement->gameBitId) == 0)
    {
        *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        if (randFn_80080100(0x64) != 0)
        {
            objSoundFn_800392f0(obj, &state->modelSoundState,
                                (ObjSoundDef*)(&lbl_803DC308 + randomGetRange(0, 0) * 6), 1);
        }
        if ((s8)stateArg->baddie.moveDone != 0)
        {
            if (randFn_80080100(2) != 0)
            {
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x78);
                ObjAnim_SetCurrentMove((int)obj, 9, 0.0f, 0);
                stateArg->baddie.moveSpeed = 0.006f;
            }
            else
            {
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x78);
                ObjAnim_SetCurrentMove((int)obj, 2, 0.0f, 0);
                stateArg->baddie.moveSpeed = 0.004f;
            }
        }
        return 0;
    }
    {
        s16 yItem;
        getYButtonItem(&yItem);
        if ((mainGetBit(GAMEBIT_ITEM_CCGoldBar_Count) != 0 && cMenuGetSelectedItem() != -1) || yItem == 0xaf7)
        {
            Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 4);
        }
        else
        {
            Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 2);
        }
    }
    if (ObjTrigger_IsSetById((int)obj, 0xaf7) != 0)
    {
        int total = mainGetBit(GAMEBIT_ITEM_CCGoldBar_Used);
        total = total + mainGetBit(GAMEBIT_ITEM_CCGoldBar_Count);
        mainSetBits(GAMEBIT_ITEM_CCGoldBar_Used, total);
        mainSetBits(GAMEBIT_ITEM_CCGoldBar_Count, 0);
        if (randFn_80080100(5 - total) != 0)
        {
            state->substate = 2;
        }
        else
        {
            state->substate = 9;
        }
        objModelClearVecFn_8003aa40(obj);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0);
        ObjAnim_SetCurrentMove((int)obj, 0, 0.0f, 0);
        ObjHits_DisableObject(obj);
        Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 2);
        (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        return 0;
    }
    if ((s8)stateArg->baddie.moveDone != 0)
    {
        if ((obj)->anim.currentMove != 2)
        {
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x78);
            ObjAnim_SetCurrentMove((int)obj, 2, 0.0f, 0);
            stateArg->baddie.moveSpeed = 0.004f;
        }
    }
    if (timerIsActive(&state->transitionTimer) != 0)
    {
        if (timerCountDown(&state->transitionTimer) != 0)
        {
            *(s8*)&state->substate = -1;
            (*gObjectTriggerInterface)->runSequence(gHighTopIdleSequenceIds[state->idleSeqIndex], (void*)obj, -1);
        }
    }
    else
    {
        if (Vec_distance((f32*)((char*)Obj_GetPlayerObject() + 0x18), &(obj)->anim.worldPosX) > 700.0f)
        {
            if (randFn_80080100(0x1f4) != 0)
            {
                roll = randomGetRange(0, 0x64);
                idx = 0;
                weight = gHighTopIdleSequenceWeights;
                while (*weight < roll)
                {
                    weight++;
                    roll -= gHighTopIdleSequenceWeights[idx++];
                }
                state->idleSeqIndex = idx;
                state->flags |= 1;
                s16toFloat(&state->transitionTimer, 0x14);
            }
        }
    }
    return 0;
}

int hightop_stateHandler08(GameObject* obj, HighTopRuntime* stateArg)
{
    HighTopRuntime* state = (obj)->extra;
    if ((s8)stateArg->baddie.moveJustStartedA != 0)
    {
        f32 zero;
        state->stateTimer = 400.0f;
        zero = 0.0f;
        stateArg->baddie.animSpeedC = zero;
        stateArg->baddie.animSpeedB = zero;
        stateArg->baddie.animSpeedA = zero;
        (obj)->anim.velocityX = zero;
        (obj)->anim.velocityY = zero;
        (obj)->anim.velocityZ = zero;
    }
    if ((s8)stateArg->baddie.moveDone != 0)
    {
        s16 cur = (obj)->anim.currentMove;
        switch (cur)
        {
        case 10:
            if (stateArg->baddie.moveSpeed > 0.0f)
            {
                ObjAnim_SetCurrentMove((int)obj, 5, 0.0f, 0);
            }
            else
            {
                return 8;
            }
            break;
        case 5:
            if (state->stateTimer < 0.0f)
            {
                ObjAnim_SetCurrentMove((int)obj, 10, 1.0f, 0);
                stateArg->baddie.moveSpeed = -0.01f;
            }
            break;
        default:
            ObjAnim_SetCurrentMove((int)obj, 10, 0.0f, 0);
            stateArg->baddie.moveSpeed = 0.01f;
            break;
        }
    }
    if ((obj)->anim.currentMove == 10)
    {
        if (stateArg->baddie.moveSpeed < 0.0f)
        {
            if ((obj)->anim.currentMoveProgress < 0.03f)
            {
                ObjAnim_SetCurrentMove((int)obj, 0, 0.0f, 0);
                stateArg->baddie.moveSpeed = 0.008f;
                return 8;
            }
        }
    }
    state->stateTimer -= (f32)(u32)framesThisStep;
    return 0;
}

int hightop_stateHandler07(GameObject* obj, HighTopRuntime* stateArg)
{
    HighTopRuntime* rt = (obj)->extra;
    f32 zero;
    if ((s8)stateArg->baddie.moveJustStartedA != 0)
    {
        zero = 0.0f;
        stateArg->baddie.animSpeedC = zero;
        stateArg->baddie.animSpeedB = zero;
        stateArg->baddie.animSpeedA = zero;
        (obj)->anim.velocityX = zero;
        (obj)->anim.velocityY = zero;
        (obj)->anim.velocityZ = zero;
        ObjHits_SyncObjectPositionIfDirty((GameObject*)obj);
        (*gGameUIInterface)->airMeterSetShutdown();
        rt->flagsC49.b7 = 0;
        rt->flagsC49.b1 = 0;
        rt->substate = 5;
        stateArg->baddie.moveSpeed = 0.004f;
        rt->flags &= ~1;
        ObjGroup_RemoveObject((int)obj, HIGHTOP_OBJGROUP);
    }
    if ((s8)stateArg->baddie.moveDone != 0)
    {
        if ((obj)->anim.currentMove != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0, 0.0f, 0);
            stateArg->baddie.moveSpeed = 0.008f;
        }
    }
    if ((s32)randomGetRange(0, 1000) != 0)
    {
        return 0;
    }
    return 9;
}

int hightop_stateHandler06(GameObject* obj, HighTopRuntime* state)
{
    HighTopRuntime* runtime = obj->extra;
    if ((s8)state->baddie.moveJustStartedA != 0)
    {
        runtime->flags |= 1;
    }
    if (mainGetBit(GAMEBIT_DR_RescuedHighTop) != 0)
    {
        return 8;
    }
    return 2;
}

int hightop_stateHandler05(GameObject* obj, HighTopRuntime* state)
{
    HighTopRuntime* runtime = obj->extra;
    if ((s8)state->baddie.moveJustStartedA != 0)
    {
        runtime->flagsC49.b1 = 0;
        runtime->substate = 0xa;
    }
    switch ((s8)runtime->substate)
    {
    case 1:
        if (mainGetBit(0x62c) != 0)
        {
            runtime->substate = 2;
        }
        break;
    case 0xa:
        if (mainGetBit(0x630) != 0)
        {
            return 7;
        }
        break;
    }
    return 0;
}

int hightop_stateHandler04(int obj, HighTopRuntime* stateArg)
{
    HighTopRuntime* state = ((GameObject*)obj)->extra;
    int move = -1;
    int count;
    int* player;
    f32 dy;
    if ((s8)stateArg->baddie.moveJustStartedA != 0)
    {
        state->flagsC49.b1 = 1;
        state->stateTimer = (f32)(int)randomGetRange(0x1f4, 0x3e8);
        state->substate = 0;
        if (((GameObject*)obj)->anim.currentMove != 2)
        {
            move = 2;
            stateArg->baddie.moveSpeed = 0.004f;
        }
        fn_80039264((s32*)((char*)state + 0xb48));
    }
    count = mainGetBit(GAMEBIT_DR_HighTopSwitch1) + mainGetBit(GAMEBIT_DR_HighTopSwitch2) +
            mainGetBit(GAMEBIT_DR_HighTopSwitch3) + mainGetBit(GAMEBIT_DR_HighTopSwitch4);
    if (mainGetBit(0x62b) != 0)
    {
        HighTopRuntime* state2;
        RomCurveInterface* curve;
        mainSetBits(0x62f, 1);
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
        ObjHits_ClearSourceMask((ObjAnimComponent*)obj, 1);
        ((GameObject*)obj)->anim.modelInstance->runtimeSourceHitMask &= ~1;
        *(s8*)&state->substate = -1;
        state->flagsC40 |= HIGHTOP_FLAG_CURVE_FOLLOW;
        state->flagsC40 |= HIGHTOP_FLAG_CURVE_ARMED;
        state->flagsC49.b1 = 0;
        curve->initFromCurveId((RomCurveWalker*)((char*)state + 0xa10), (GameObject*)obj, 0x3463a,
                               (curve = *gRomCurveInterface));
        state2 = ((GameObject*)obj)->extra;
        state2->flagsC49.b7 = 1;
        (*gGameUIInterface)->initAirMeter(gHighTopAirMeterInitValue, HIGHTOP_AIRMETER_BGTEXTURE);
        (*gGameUIInterface)->runAirMeter(state2->airMeterRemaining);
        fn_80039264((s32*)((char*)state + 0xb48));
        return 7;
    }
    if (count == 4)
    {
        mainSetBits(0x62a, 1);
        return 0;
    }
    objModelAndSoundFn_80039118(obj, (int)((char*)state + 0xb48));
    state->stateTimer -= (f32)(u32)framesThisStep;
    if (((GameObject*)obj)->anim.currentMove != 9 && ((GameObject*)obj)->anim.currentMove != 0x11)
    {
        RandomTimer_UpdateRangeTrigger((char*)state + 0xc34, 4.0f, 8.0f);
        if (count == 0)
        {
            if (state->stateTimer < 0.0f)
            {
                stateArg->baddie.moveSpeed = 0.002f * count + 0.006f;
                move = 9;
                state->stateTimer = (f32)(int)(randomGetRange(0x2bc, 0x3e8) - count * 0x12c);
            }
        }
        else
        {
            if (randFn_80080100((4 - count) * 0xa) != 0)
            {
                stateArg->baddie.moveSpeed = 0.0005f * count + 0.007f;
                move = 9;
                state->stateTimer = (f32)(int)(randomGetRange(0x2bc, 0x3e8) - count * 0x12c);
            }
        }
    }
    if ((s8)stateArg->baddie.moveDone != 0)
    {
        if (((GameObject*)obj)->anim.currentMove != 2)
        {
            move = 2;
            stateArg->baddie.moveSpeed = 0.004f;
        }
    }
    if (move != -1)
    {
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x78);
        ObjAnim_SetCurrentMove(obj, move, 0.0f, 0);
    }
    player = (int*)Obj_GetPlayerObject();
    if (player != 0 &&
        (((dy = ((GameObject*)player)->anim.localPosY - ((GameObject*)obj)->anim.localPosY) >= 0.0f
              ? dy
              : -dy) < 30.0f ||
         (dy >= 0.0f ? dy : -dy) > 300.0f))
    {
        state->flags |= 1;
        if ((int)randomGetRange(0, 0x64) == 0 && ((GameObject*)obj)->anim.currentMove != 9)
        {
            f32 deltaY = ((GameObject*)player)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
            f32 ac = deltaY >= 0.0f ? deltaY : -deltaY;
            if (ac < 30.0f)
            {
                (*gObjectTriggerInterface)->runSequence(9, (void*)obj, -1);
            }
        }
    }
    else
    {
        state->flags &= ~1;
    }
    return 0;
}
int gHighTopIdleSequenceIds[3] = {0x4, 0x5, 0x6};
int gHighTopIdleSequenceWeights[3] = {0x32, 0x19, 0x19};
HighTopTuning lbl_8032AB48 = {
    {8, 9, 7, 10},
    {-25.0f, 0.0f, -60.0f, 25.0f, 0.0f, -60.0f, 25.0f, 0.0f, 60.0f, -25.0f, 0.0f,
     60.0f,  0.0f, 0.0f,   0.0f,  0.0f, 0.0f,   0.0f,  35.0f, 0.0f, 0.0f,  -35.0f},
};
f32 gHighTopBandSpeedThresholds[4] = {0.0f, 0.03f, 0.05f, 8.0f};
ObjectDescriptor24 gHighTopObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_24_SLOTS,
    (ObjectDescriptorCallback)HighTop_initialise,
    (ObjectDescriptorCallback)HighTop_release,
    0,
    (ObjectDescriptorCallback)HighTop_init,
    (ObjectDescriptorCallback)HighTop_update,
    (ObjectDescriptorCallback)HighTop_hitDetect,
    (ObjectDescriptorCallback)HighTop_render,
    (ObjectDescriptorCallback)HighTop_free,
    (ObjectDescriptorCallback)HighTop_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)HighTop_getExtraSize,
    (ObjectDescriptorCallback)HighTop_setScale,
    (ObjectDescriptorCallback)hightop_func0B,
    (ObjectDescriptorCallback)HighTop_modelMtxFn,
    (ObjectDescriptorCallback)HighTop_render2,
    (ObjectDescriptorCallback)hightop_func0E,
    (ObjectDescriptorCallback)HighTop_func0F,
    (ObjectDescriptorCallback)hightop_func10,
    (ObjectDescriptorCallback)hightop_func11,
    (ObjectDescriptorCallback)hightop_func12,
    (ObjectDescriptorCallback)hightop_func13,
    (ObjectDescriptorCallback)hightop_func14,
    (ObjectDescriptorCallback)hightop_func15,
    (ObjectDescriptorCallback)HighTop_renderGroundMarker,
    (ObjectDescriptorCallback)HighTop_getLookTargetYaw,
};

int hightop_handleMotionEvent(int obj, u8 event)
{
    HighTopRuntime* runtime = ((GameObject*)obj)->extra;
    switch (event)
    {
    case 0:
        break;
    case 5:
        (*gPlayerInterface)->setState((void*)obj, runtime, 8);
        break;
    case 6:
        mainSetBits(0x634, 1);
        (*gObjectTriggerInterface)->runSequence(4, (void*)obj, -1);
        break;
    case 7:
        mainSetBits(0x634, 0);
        mainSetBits(0x631, 1);
        ((GameObject*)obj)->anim.modelInstance->runtimeSourceHitMask |= 1;
        runtime->flagsC40 &= ~0x140;
        runtime->flags &= ~2;
        (*gPlayerInterface)->setState((void*)obj, runtime, 7);
        break;
    case 8:
        (*gObjectTriggerInterface)->runSequence(7, (void*)obj, -1);
        break;
    case 9:
        (*gPlayerInterface)->setState((void*)obj, runtime, 7);
        break;
    }
    return 0;
}

int hightop_defaultStateHandler(void)
{
    return 0x0;
}

int hightop_stateHandler03(GameObject* obj, HighTopRuntime* state)
{
    HighTopRuntime* runtime = (obj)->extra;
    f32 zero = 0.0f;
    state->baddie.animSpeedC = zero;
    state->baddie.animSpeedB = zero;
    state->baddie.animSpeedA = zero;
    (obj)->anim.velocityX = zero;
    (obj)->anim.velocityY = zero;
    (obj)->anim.velocityZ = zero;
    if ((s8)state->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x78);
        if (*(u32*)&runtime->savedControlMode == 4)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x13, 0.0f, 0);
            state->baddie.moveSpeed = 0.008f;
        }
        else
        {
            ObjAnim_SetCurrentMove((int)obj, 0x13, 0.0f, 0);
            state->baddie.moveSpeed = 0.008f;
        }
    }
    if ((obj)->anim.currentMoveProgress > 0.95f)
    {
        return runtime->savedControlMode + 1;
    }
    return 0;
}

int hightop_stateHandler02(GameObject* obj, HighTopRuntime* stateArg, f32 dt)
{
    s16 d336;
    HighTopRuntime* state = (obj)->extra;
    int cont = 1;
    int conv;
    u32 band;
    int idx;
    int changed;
    f32 inputMag;
    f32 lateralSpeed;
    f32 ang;
    f32 moveSpeed;
    s16* vec;
    *(u32*)stateArg = *(u32*)stateArg | 0x200000;
    if (stateArg->baddie.inputMagnitude < 0.05f)
    {
        *(s16*)((char*)stateArg + 0x334) = 0;
        stateArg->baddie.turnRate = 0;
        stateArg->baddie.inputMagnitude = 0.0f;
    }
    d336 = stateArg->baddie.turnRate;
    if ((d336 >= 0 ? d336 : -d336) > state->turnRateThreshold)
    {
        conv = (int)(182.04445f * ((f32)d336 * dt));
        (obj)->anim.rotX = (s16)((obj)->anim.rotX + ((s16)conv >> 5));
    }
    else
    {
        (obj)->anim.rotX = (182.0f * (((f32)d336 * dt) / 36.0f) + (f32) * (s16*)obj);
    }
    conv = (int)(182.04445f * ((f32) * (s16*)((char*)stateArg + 0x336) * dt));
    vec = (s16*)objModelGetVecFn_800395d8(obj, 9);
    if (vec != 0)
    {
        vec[1] = (s16)(vec[1] + (((s16)conv - vec[1]) >> 3));
        vec[0] = (s16)(vec[0] + ((-vec[0]) >> 3));
        vec[1] = (vec[1] < -0x1555) ? -0x1555 : ((vec[1] > 0x1555) ? 0x1555 : vec[1]);
        vec[1] = (vec[1] < -0x1555) ? -0x1555 : ((vec[1] > 0x1555) ? 0x1555 : vec[1]);
    }
    inputMag = stateArg->baddie.inputMagnitude;
    if (inputMag < 0.0f)
    {
        inputMag = 0.0f;
    }
    if (inputMag > 1.0f)
    {
        inputMag = 1.0f;
    }
    lateralSpeed = 8.0f * inputMag;
    if (lateralSpeed < 0.0f)
    {
        lateralSpeed = 0.0f;
    }
    stateArg->baddie.animSpeedC =
        dt * ((lateralSpeed - stateArg->baddie.animSpeedC) /
              stateArg->baddie.velSmoothTime) +
        stateArg->baddie.animSpeedC;
    if ((obj)->anim.rotY > 0)
    {
        ang = lateralSpeed - 0.3f * mathSinf(3.1415927f * (f32)(obj)->anim.rotY / 32768.0f);
    }
    else
    {
        ang = lateralSpeed - 0.15f * mathSinf(3.1415927f * (f32)(obj)->anim.rotY / 32768.0f);
    }
    stateArg->baddie.animSpeedA = dt * ((ang - stateArg->baddie.animSpeedA) /
                                                           stateArg->baddie.velSmoothTime) +
                                                     stateArg->baddie.animSpeedA;
    changed = 0;
    moveSpeed = (obj)->anim.currentMoveProgress;
    band = 0;
    while (gHighTopBandMoveIds[band] != (obj)->anim.currentMove && band < 2)
    {
        band++;
    }
    if (band >= 2)
    {
        band = 0;
    }
    idx = band * 2;
    while (cont != 0)
    {
        f32 spd = stateArg->baddie.animSpeedC;
        if (spd < gHighTopBandSpeedThresholds[idx])
        {
            if ((int)band == 1)
            {
                return 2;
            }
            band -= 1;
            idx -= 2;
            changed = 1;
        }
        else if (spd >= gHighTopBandSpeedThresholds[idx + 1])
        {
            if ((int)band == 0)
            {
                moveSpeed = 0.0f;
            }
            band += 1;
            idx += 2;
            changed = 1;
        }
        else
        {
            cont = 0;
        }
    }
    if (changed != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, gHighTopBandMoveIds[band], moveSpeed, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xa);
    }
    ObjAnim_SampleRootCurvePhase((ObjAnimComponent*)obj, stateArg->baddie.animSpeedA,
                                 (f32*)((char*)stateArg + 0x2a0));
    return 0;
}

int hightop_stateHandler01(GameObject* obj, HighTopRuntime* stateArg)
{
    f32 zero;
    zero = 0.0f;
    stateArg->baddie.animSpeedC = zero;
    stateArg->baddie.animSpeedB = zero;
    stateArg->baddie.animSpeedA = zero;
    (obj)->anim.velocityX = zero;
    (obj)->anim.velocityY = zero;
    (obj)->anim.velocityZ = zero;
    *(int*)((char*)stateArg + 0) |= 0x200000;
    if ((s8)stateArg->baddie.moveJustStartedA != 0)
    {
        *(s16*)((char*)stateArg + 0x338) = 0;
        stateArg->baddie.moveSpeed = 0.005f;
        stateArg->baddie.velSmoothTime = 18.0f;
        if ((obj)->anim.currentMove != gHighTopBandMoveIds[0])
        {
            ObjAnim_SetCurrentMove((int)obj, gHighTopBandMoveIds[0], zero, 0);
        }
    }
    if (stateArg->baddie.inputMagnitude < 0.1f)
    {
        *(s16*)((char*)stateArg + 0x334) = 0;
        stateArg->baddie.turnRate = 0;
        stateArg->baddie.inputMagnitude = 0.0f;
    }
    if (*(f32*)&stateArg->baddie.trackedObj > 0.0f &&
        stateArg->baddie.inputMagnitude > 0.0f)
    {
        return 3;
    }
    return 0;
}

int hightop_stateHandler00(GameObject* obj)
{
    HighTopPlacement* placement = (HighTopPlacement*)obj->anim.placementData;
    if (placement->spawnVariant != 0)
    {
        return 0xa;
    }
    if (mainGetBit(0x631) != 0)
    {
        return 8;
    }
    return 5;
}

int HighTop_seqFn(GameObject* obj)
{
    HighTopRuntime* runtime;
    seqFn_800394a0();
    runtime = (obj)->extra;
    runtime->flags &= ~1;
    runtime->flagsC49.b4 = 0;
    runtime->flagsC49.b6 = 1;
    if ((s8)runtime->substate == 0)
    {
        runtime->flagsC4A.b0 = 1;
    }
    return 0;
}

void hightop_playMovementSfx(GameObject* obj, HighTopRuntime* state2, HighTopRuntime* state)
{
    int flags = state->baddie.eventFlags;
    int idx;
    if ((flags & 0x81) != 0)
    {
        if (flags & 1)
        {
            idx = 0;
        }
        if (flags & 0x80)
        {
            idx = 1;
        }
        Sfx_PlayFromObject((u32)obj, (u16)gHighTopMovementSfxIds[idx]);
    }
    if ((s32)state->baddie.eventFlags & 0x100)
    {
        fn_8009A8C8(obj, 1000.0f);
        Sfx_PlayFromObject((u32)obj, gHighTopMovementSfxIds[0]);
    }
}

void HighTop_getLookTargetYaw(GameObject* obj, int mode, int* out)
{
    MoveLibTarget target;
    HighTopRuntime* runtime;
    int yaw;
    switch (mode)
    {
    case 2:
        if (dll_2E_func0A(0x11, &target) != 0)
        {
            yaw = (s16)getAngle(target.x - obj->anim.localPosX, target.z - obj->anim.localPosZ);
            *out = yaw + gHighTopLookYawOffset;
            runtime = obj->extra;
            runtime->lookTargetX = target.x;
            runtime->lookTargetY = target.y;
            runtime->lookTargetZ = target.z;
        }
        else
        {
            *out = obj->anim.rotX + 0x4000;
        }
        break;
    case 3:
        *out = 1;
        break;
    case 4:
        *out = 0;
        break;
    }
}

void HighTop_renderGroundMarker(GameObject* obj, f32 scale)
{
    f32* mtx;
    f32 lx, ly, lz;
    MatrixTransform pos;
    mtx = (f32*)ObjPath_GetPointModelMtx(obj, 2);
    ObjPath_GetPointLocalPosition(obj, 2, &lx, &ly, &lz);
    pos.x = lx;
    pos.y = ly;
    pos.z = lz;
    pos.rotX = -0x8000;
    pos.rotY = 0;
    pos.rotZ = 0;
    pos.scale = scale / (obj)->anim.modelInstance->rootMotionScaleBase;
    setMatrixFromObjectPos(gHighTopGroundMarkerMtx, &pos);
    mtx44_mult(gHighTopGroundMarkerMtx, mtx, gHighTopGroundMarkerMtx);
    objSetModelMatrixOverride(gHighTopGroundMarkerMtx);
}

void hightop_func15(void)
{
}

int hightop_func14(void)
{
    return 0x0;
}

f32 hightop_func13(int obj, f32* out)
{
    *out = 5.0f;
    return 0.0f;
}

void hightop_func12(int obj, f32* a, int* b)
{
    *a = 0.0f;
    *b = 0;
}

void hightop_func11(GameObject* obj, int val)
{
    u8 v = val;
    HighTopRuntime* state = obj->extra;
    state->unkC43 = v;
}

int hightop_func10(void)
{
    return 0x0;
}

void HighTop_func0F(int obj, f32* ox, f32* oy, f32* oz)
{
    GameObject* player;
    MatrixTransform pos;
    f32 mtx[16];
    player = Obj_GetPlayerObject();
    pos.x = player->anim.localPosX;
    pos.y = player->anim.localPosY;
    pos.z = player->anim.localPosZ;
    pos.rotX = ((GameObject*)player)->anim.rotX;
    pos.rotY = ((GameObject*)player)->anim.rotY;
    pos.rotZ = ((GameObject*)player)->anim.rotZ;
    pos.scale = 1.0f;
    setMatrixFromObjectPos(mtx, &pos);
    Matrix_TransformPoint(mtx, 0.0f, 16.0f, -16.0f, ox, oy, oz);
}

int hightop_func0E(void)
{
    return 0x1;
}

int HighTop_render2(void)
{
    return 0x0;
}

void HighTop_modelMtxFn(int obj, f32* a, f32* b, f32* c)
{
    HighTopRuntime* runtime = ((HighTopObject*)obj)->runtime;
    *a = runtime->pathPoint2X;
    *b = runtime->pathPoint2Y;
    *c = runtime->pathPoint2Z;
}

int hightop_func0B(void)
{
    return 0x1;
}

int HighTop_setScale(void)
{
    return 0x0;
}
int HighTop_getExtraSize(void)
{
    return sizeof(HighTopRuntime);
}

int HighTop_getObjectTypeId(void)
{
    return HIGHTOP_OBJECT_TYPE_ID;
}

void HighTop_free(int obj)
{
    ObjGroup_RemoveObject(obj, ARWARWING_OBJGROUP);
    ObjGroup_RemoveObject(obj, HIGHTOP_OBJGROUP);
    (*gGameUIInterface)->airMeterSetShutdown();
}

void HighTop_render(void* obj, int p2, int p3, int p4, int p5, char visible)
{
    HighTopRuntime* runtime = ((HighTopObject*)obj)->runtime;
    f32 scale = 1.0f;
    if (visible != 0)
    {
        int count;
        int** list;
        int i;
        objRenderModelAndHitVolumes((GameObject*)obj, p2, p3, p4, p5, scale);
        ObjPath_GetPointWorldPosition((GameObject*)obj, 2, &runtime->pathPoint2X, &runtime->pathPoint2Y, &runtime->pathPoint2Z,
                                      0);
        ObjPath_GetPointWorldPositionArray((GameObject*)obj, 3, 4, runtime->pathPointWorldPositions);
        ObjPath_GetPointWorldPosition((GameObject*)obj, 0, &runtime->pathPoint0X, &runtime->pathPoint0Y, &runtime->pathPoint0Z,
                                      0);
        runtime->flagsC49.b5 = 1;
        dll_2E_func06((GameObject*)obj, (MoveLibState*)runtime->lookController, 0);
        if (runtime->flagsC49.b1 != 0)
        {
            int** t = (int**)ObjGroup_GetObjects(55, &count);
            for (i = 0, list = t; i < count; i++)
            {
                int idx = (*(int (**)(int*))((char*)**(int***)((char*)*list + 0x68) + 0x24))(*list);
                void (*dispatch)(int*, void*, int, int, int, int, int) =
                    *(void (**)(int*, void*, int, int, int, int, int))((char*)**(int***)((char*)*list + 0x68) + 0x20);
                dispatch(*list, obj, lbl_8032AB48.dispatchArgs[idx], p2, p3, p4, p5);
                list++;
            }
        }
    }
    else
    {
        runtime->flagsC49.b5 = 0;
    }
}

void HighTop_hitDetect(GameObject* obj)
{
    HighTopRuntime* runtime = (obj)->extra;
    f32 l10;
    f32 lc;
    f32 l8;
    int hit;
    s16 st;
    hit = ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &l8, &lc, &l10);
    if (hit == 0)
    {
        return;
    }
    st = runtime->baddie.controlMode;
    if (st != 4 && (u16)(st - 9) > 1)
    {
        if (hit == 0xf || hit == 0xe)
        {
            return;
        }
    }
    if (runtime->airMeterRemaining == 0)
    {
        return;
    }
    Obj_SpawnHitLightAndFade(obj, (const Vec3f*)&l8, 20.0f);
    objSoundFn_800392f0(obj, &runtime->modelSoundState,
                        (ObjSoundDef*)(&lbl_803DC308 + randomGetRange(0, 0) * 6), 1);
    st = runtime->baddie.controlMode;
    if (st != 3)
    {
        runtime->savedControlMode = st;
    }
    st = runtime->baddie.controlMode;
    if (st == 2 || st == 8)
    {
        runtime->airMeterRemaining -= 1;
        fn_8009A8C8(obj, 1000.0f);
        if (runtime->airMeterRemaining <= 0)
        {
            (*gGameUIInterface)->airMeterSetShutdown();
            runtime->flagsC49.b7 = 0;
            mainSetBits(0x634, 0);
            if (Obj_IsLoadingLocked() != 0)
            {
                HighTopDeathSpawn* spawn = (HighTopDeathSpawn*)Obj_AllocObjectSetup(0x2c, HIGHTOP_DEATH_SPAWN_OBJ_ID);
                spawn->base.color[0] = 2;
                spawn->base.posX = (obj)->anim.localPosX;
                spawn->base.posY = (obj)->anim.localPosY;
                spawn->base.posZ = (obj)->anim.localPosZ;
                spawn->effectId = HIGHTOP_DEATH_EFFECT_ID;
                spawn->unk1C = 0;
                spawn->gameBit = -1;
                Obj_SetupObject(&spawn->base, 5, (obj)->anim.mapEventSlot, -1, (obj)->anim.parent);
            }
            (obj)->anim.rotY = 0;
            (obj)->anim.rotZ = 0;
            runtime->baddie.physicsActive = 0;
            *(int*)runtime |= 0x1000000;
            mainSetBits(0xb48, 1);
            (*gGameUIInterface)->airMeterSetShutdown();
        }
    }
    else
    {
        (*gPlayerInterface)->setState(obj, runtime, 3);
    }
}

void HighTop_update(GameObject* obj)
{
    HighTopRuntime* runtime;
    char* state;
    register int self = (int)obj;
    state = ((GameObject*)self)->extra;
    runtime = (HighTopRuntime*)state;
    runtime->turnRateThreshold = 5;
    *(u8*)&((GameObject*)self)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    *(s8*)&runtime->baddie.physicsActive = !runtime->flagsC49.b4;
    runtime->baddie.hitPoints = 0;
    *(int*)state &= ~0x8000;
    if ((runtime->flagsC40 & HIGHTOP_FLAG_CURVE_FOLLOW) != 0)
    {
        int ev = Obj_UpdateRomCurveFollowVelocity((GameObject*)self, (RomCurveWalker*)(state + 0xa10),
                                                  lbl_803DC324 *
                                                      (runtime->curveFollowSpeedScale * timeDelta),
                                                  70.0f, 8.0f * timeDelta, 0);
        if (ev != 0)
        {
            if (ev == -1)
            {
                runtime->flagsC40 &= ~0x140;
                runtime->flags &= ~2;
            }
            else
            {
                hightop_handleMotionEvent(self, ev);
            }
        }
    }
    else
    {
        f32 zero = 0.0f;
        runtime->baddie.moveInputX = zero;
        runtime->baddie.moveInputZ = zero;
    }
    *(int*)&runtime->baddie.unk31C = 0;
    *(int*)&runtime->baddie.unk318 = 0;
    runtime->baddie.cameraYaw = 0;
    *(int*)state &= ~0x400000;
    (*gPlayerInterface)->update((void*)self, state, (f32)(u32)framesThisStep, timeDelta, gHighTopStateHandlers,
                                &gHighTopDefaultStateHandler);
    hightop_playMovementSfx((GameObject*)self, runtime, runtime);
    characterDoEyeAnims((GameObject*)self, state + 0x38c);
    objAnimFn_80038f38((GameObject*)(self), (char*)(state + 0x3bc));
    dll_2E_func03((GameObject*)self, (MoveLibState*)(state + 0x3ec));
    if (ObjTrigger_IsSet(self) != 0)
    {
        s8 substate;
        buttonDisable(0, PAD_BUTTON_A);
        substate = (s8)runtime->substate;
        if (substate != -1)
        {
            if (substate < 0xa)
            {
                (*gObjectTriggerInterface)->runSequence(substate, (void*)self, -1);
            }
            else
            {
                mainSetBits(((s16*)((char*)&lbl_803DC314 - 0x14))[substate], 1);
            }
        }
    }
    if ((int)randomGetRange(0, 0x64) == 0)
    {
        objSoundFn_800392f0((GameObject*)self, &((HighTopRuntime*)state)->modelSoundState,
                            (ObjSoundDef*)&lbl_8032AAB0[randomGetRange(0, 2) * 6], 0);
    }
    if (runtime->flagsC49.b7 != 0)
    {
        (*gGameUIInterface)->runAirMeter(runtime->airMeterRemaining);
        runtime->sfxIntervalTimer += timeDelta;
        if (runtime->sfxIntervalTimer > 60.0f)
        {
            runtime->sfxIntervalTimer -= 60.0f;
            Sfx_PlayFromObject((u32)self, SFXTRIG_hightop_fstep);
        }
    }
}


void HighTop_init(GameObject* obj, HighTopPlacement* placement)
{
    u8* base = lbl_8032AAB0;
    HighTopRuntime* runtime = (obj)->extra;
    u8* pathState;
    int* node;
    HtInitData local1;
    HtInitData local2;
    HighTopPathParams pathParam = sHighTopPathParams;
    local1 = gHighTopLookInitData1;
    local2 = gHighTopLookInitData2;
    (obj)->anim.rotX = (s16)(placement->rotByte << 8);
    (obj)->animEventCallback = HighTop_seqFn;
    runtime->unkC45 = placement->spawnVariant;
    runtime->turnRateThreshold = 5;
    *(s8*)&runtime->substate = -1;
    node = *(int**)&(obj)->anim.modelState;
    if (node != 0)
    {
        *(int*)&((ObjModelState*)node)->flags |= 0xa10;
    }
    ObjGroup_AddObject((int)obj, ARWARWING_OBJGROUP);
    ObjGroup_AddObject((int)obj, HIGHTOP_OBJGROUP);
    (*gPlayerInterface)->init(obj, runtime, 11, 1);
    runtime->baddie.gravity = 0.17f;
    pathState = (u8*)&runtime->baddie + 4;
    pathState[0x25b] = 1;
    (*gPathControlInterface)->init(pathState, 3, 1024, 0);
    (*gPathControlInterface)->setLocalPointCollision(pathState, 2, &base[0xe8], &lbl_803DC318, 8);
    (*gPathControlInterface)->setup(pathState, 4, &base[0xa8], &base[0xd8], pathParam.values);
    (*gPathControlInterface)->attachObject(obj, pathState);
    dll_2E_func05(obj, (MoveLibState*)runtime->lookController, -4551, 23665, 6);
    dll_2E_func08((MoveLibState*)runtime->lookController, 300, 120);
    dll_2E_func09((MoveLibState*)runtime->lookController, &local2, &local1, 6);
    runtime->flags |= 2;
    runtime->flags |= 8;
    runtime->airMeterRemaining = placement->airMeterParam;
    runtime->flags |= 1;
    (obj)->anim.modelInstance->runtimeSourceHitMask = 127;
    runtime->flagsC49.b4 = 0;
    runtime->flagsC49.b7 = 0;
    gHighTopAirMeterInitValue = placement->airMeterParam;
    if (placement->curveScaleParam == 0)
    {
        runtime->curveFollowSpeedScale = 1.9f;
    }
    else
    {
        runtime->curveFollowSpeedScale = (f32)placement->curveScaleParam / 10.0f;
    }
    runtime->flagsC49.b6 = 0;
    runtime->flagsC4A.b0 = 0;
}

void HighTop_release(void)
{
}

void HighTop_initialise(void)
{
    void** t = gHighTopStateHandlers;
    t[0] = hightop_stateHandler00;
    t[1] = hightop_stateHandler01;
    t[2] = hightop_stateHandler02;
    t[3] = hightop_stateHandler03;
    t[4] = hightop_stateHandler04;
    t[5] = hightop_stateHandler05;
    t[6] = hightop_stateHandler06;
    t[7] = hightop_stateHandler07;
    t[8] = hightop_stateHandler08;
    t[9] = hightop_stateHandler09;
    t[10] = hightop_stateHandler10;
    gHighTopDefaultStateHandler = hightop_defaultStateHandler;
}
