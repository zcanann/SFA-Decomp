#include "dlls/objects/599_DR_EarthWar.h"
#include "dlls/objects/common/vehicle.h"

#include "main/dll/partfx_interface.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "game/objects/object_setup.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/game_ui_interface.h"
#include "main/model.h"
#include "main/objhits.h"
#include "main/objanim.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "main/dll/path_control_interface.h"
#include "main/objtype.h"
#include "main/obj_link.h"
#include "main/obj_path.h"
#include "main/frame_timing.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "dlls/object_descriptor.h"
#include "main/dll/tricky_api.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/camera.h"
#include "main/byte_flags.h"
#include "main/gamebit_ids.h"
#include "game/objects/object.h"
#include "main/object_render.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_sound_api.h"
#include "main/objprint_api.h"
#include "main/pad.h"
#include "main/dll/baddie_state.h"
#include "main/dll/player_api.h"
#include "main/dll/player_motion_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/player_control_interface.h"
#include "main/maketex_timer_api.h"
#include "main/vecmath.h"
#include "dlls/objects/473_DIM2PrisonM.h"
#include "main/newshadows_audio_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/dll_005A_staffcollision.h"

#define PAD_BUTTON_A 0x100

#define DREARTHWARRIOR_PARTFX             0x7e6
#define DREARTHWARRIOR_AIRMETER_BGTEXTURE 0x5cf /* HUD air-meter background texture id */

#define DREARTHWARRIOR_OBJFLAG_PARENT_SLACK 0x1000

#define DREARTHWARRIOR_CHILD_OBJ_HELPER 0x6f5
/* attacker romDefNo whose hits are ignored here (retail OBJECTS.bin). */
#define DREARTHWARRIOR_ATTACKER_SEQID_SWORD 0x23 /* "sword" (DLL 0xE2) */
#define DREARTHWARRIOR_EFFECT_RESOURCE_ID   0x5a /* shared effect resource -> gEarthWarriorResource */

#define CLAMP_EXPR(value, low, high) ((value) < (low) ? (low) : ((value) > (high) ? (high) : (value)))

f32 gEarthWarriorMatrix[16];
void* gDREarthWarriorStateHandlers[4];
void* gDREarthWarriorDefaultStateHandler;
StaffCollisionInterface** gEarthWarriorResource;

const EWPathRange gDREarthWarriorLookInitData1 = {{10, 10, 0, 0, 0}};
const EWPathRange gDREarthWarriorLookInitData2 = {{20, 20, 0, 0, 0}};
const EWColorTable gDREarthWarriorColors = {
    {{8, 255, 190, 120}, {8, 255, 255, 120}, {8, 180, 240, 255}, {8, 170, 255, 170}}
};
static const u8 gDREarthWarriorPathSetupParam[4] = {1, 1, 1, 1};

static void DR_EarthWarrior_setupPathState(u8* pathState, DREarthWarriorInitData* base, EarthWarriorSub* warrior)
{
    (*gPathControlInterface)->setup(pathState, 4, base->segmentLocalPoints, base->segmentRadii, (void*)gDREarthWarriorPathSetupParam);
    warrior->aimAccumY = 0.0f;
    warrior->aimHalfY = (f32)warrior->yawTurnDir;
}

void DR_EarthWarrior_feed(GameObject* obj, int mode)
{
    EarthWarriorState* state = obj->extra;
    switch (mode)
    {
    case 1:
        state->sub.energy += 4;
        objSoundStartTimed(obj, &state->modelSoundState, 0x291, 0x1000, -1, 1);
        state->sub.maxSpeed = 4.32f;
        gDREarthWarriorSpeedRows[4].maxSpeed = state->sub.maxSpeed;
        break;
    default:
        break;
    }
}

int DR_EarthWarrior_updateLeap(GameObject* obj, EarthWarriorSub* warrior, BaddieState* baddie)
{
    warrior->unk360 |= 0x1000000LL;
    baddie->moveSpeed = 0.035f;
    if (obj->anim.currentMoveProgress > 0.1f && obj->anim.currentMoveProgress < 0.25f &&
        baddie->animSpeedC > warrior->configRow[3].maxSpeed - 0.4f && baddie->inputMagnitude > 0.8f &&
        warrior->frameCounter >= 0x96)
    {
        warrior->flags3F0.b40 = 1;
        warrior->flags3F0.b80 = 0;
        warrior->soundId = warrior->soundIdReload;
        baddie->moveSpeed = 0.0165f;
        ObjAnim_SetCurrentMove(obj, warrior->moveTable[0x1D], 0.0f, 0);
        ObjAnim_SetCurrentEventStepFrames(&obj->anim, 0x10);
        warrior->leapStartYaw = warrior->currentYaw;
        warrior->animSpeedRate = (0.2f + (warrior->configRow[2].maxSpeed + baddie->animSpeedC)) / 60.0f;
        warrior->appliedYaw = warrior->currentYaw;
        warrior->currentYaw += 0x8000;
        baddie->animSpeedC = -baddie->animSpeedC;
        baddie->animSpeedA = -baddie->animSpeedA;
    }
    if (warrior->flags3F0.b80 != 0)
    {
        f32 lim;
        if (baddie->animSpeedC <= (lim = warrior->configRow[2].minSpeed) && baddie->animSpeedA <= lim)
        {
            warrior->savedYaw = warrior->currentYaw;
            warrior->flags3F0.b40 = 0;
            warrior->flags3F0.b80 = 0;
            return 1;
        }
        warrior->targetAnimSpeed = 0.0f;
        warrior->animSpeedSmoothing = warrior->animSpeedSmoothingReload;
        warrior->flags8D8 |= 8;
    }
    return 0;
}

static void DR_EarthWarrior_applySlowTurn(GameObject* obj, EarthWarriorSub* warrior, BaddieState* baddie)
{
    baddie->moveSpeed = 0.02f;
    warrior->yawSmoothDivisor *= 2.0f;
    warrior->yawStepScale *= 0.5f;
    warrior->targetAnimSpeed *= 0.75f;
    warrior->appliedYaw = (s16)(32768.0f * obj->anim.currentMoveProgress);
}

static inline void DR_EarthWarrior_updateAim(EarthWarriorSub* warrior, BaddieState* baddie, int targetAngle)
{
    int angleDelta;
    int horizontalDelta;
    f32 responseScale;

    angleDelta = CLAMP_EXPR(targetAngle, -0x41, 0x41);
    angleDelta = angleDelta * 0xb6;
    angleDelta -= (u16)warrior->aimAccumY;
    if (angleDelta > 0x8000)
    {
        angleDelta = angleDelta - 0xffff;
    }
    if (angleDelta < -0x8000)
    {
        angleDelta = angleDelta + 0xffff;
    }
    responseScale = 0.15f;
    angleDelta *= responseScale;
    angleDelta = CLAMP_EXPR(angleDelta, -0x16c, 0x16c);
    warrior->aimAccumY += angleDelta * timeDelta;
    warrior->aimHalfY = warrior->aimAccumY / 2;
    {
        f32 step;
        f32 scale;
        f32 ph;

        ph = (f32)(s32)baddie->spawnRotY / 8192.0f;
        scale = 182.0f;
        step = 10.0f;
        horizontalDelta = (int)(scale * (step * -((ph < -1.0f) ? -1.0f : ((ph > 1.0f) ? 1.0f : ph))));
        horizontalDelta -= (u16)warrior->aimAccumX;
    }
    if (horizontalDelta > 0x8000)
    {
        horizontalDelta = horizontalDelta - 0xffff;
    }
    if (horizontalDelta < -0x8000)
    {
        horizontalDelta = horizontalDelta + 0xffff;
    }
    warrior->aimAccumX += horizontalDelta;
}

static void DR_EarthWarrior_updateSteeringPose(GameObject* obj, EarthWarriorSub* warrior, BaddieState* baddie)
{
    int targetAngle;
    s16* primaryLookBone;
    s16* secondaryLookBone;

    targetAngle = warrior->yawTurnDir << 1;
    DR_EarthWarrior_updateAim(warrior, baddie, targetAngle);
    primaryLookBone = objFindJointPoseVector(obj, 0);
    secondaryLookBone = objFindJointPoseVector(obj, 9);
    objFindJointPoseVector(obj, 4);
    objFindJointPoseVector(obj, 5);
    if (primaryLookBone != NULL)
    {
        int clampedY;
        primaryLookBone[0] = -warrior->aimAccumX;
        primaryLookBone[1] = warrior->aimAccumY / 2;
        clampedY = primaryLookBone[1];
        clampedY = (clampedY < -4000) ? -4000 : ((clampedY > 4000) ? 4000 : clampedY);
        primaryLookBone[1] = clampedY;
        primaryLookBone[2] = 0;
    }
    if (secondaryLookBone != NULL)
    {
        int clampedY;
        int absoluteHalfY;
        secondaryLookBone[1] = warrior->aimHalfY;
        clampedY = secondaryLookBone[1];
        clampedY = (clampedY < -3000) ? -3000 : ((clampedY > 3000) ? 3000 : clampedY);
        secondaryLookBone[1] = clampedY;
        absoluteHalfY = warrior->aimHalfY;
        if (absoluteHalfY < 0)
        {
            absoluteHalfY = -absoluteHalfY;
        }
        secondaryLookBone[0] = (s16)(absoluteHalfY >> 1);
    }
}

int DR_EarthWarrior_defaultStateHandler(void)
{
    return 0x0;
}

int DR_EarthWarrior_stateHandler03(GameObject* obj, BaddieState* baddie)
{
    EarthWarriorState* state = obj->extra;
    f32 fz;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    fz = 0.0f;
    baddie->animSpeedC = fz;
    baddie->animSpeedB = fz;
    baddie->animSpeedA = fz;
    obj->anim.velocityX = fz;
    obj->anim.velocityY = fz;
    obj->anim.velocityZ = fz;
    if (baddie->moveJustStartedA != 0)
    {
        if (state->sub.flags994.b80)
        {
            ObjAnim_SetCurrentMove(obj, 7, fz, 0);
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, 8, fz, 0);
        }
        baddie->moveSpeed = 0.02f;
    }
    if (baddie->moveDone != 0)
    {
        if (state->sub.mountState == VEHICLE_Mounted)
        {
            state->sub.energy -= 1;
            if (state->sub.energy <= 0)
            {
                state->sub.maxSpeed = lbl_803DC76C;
                CameraShake_Enable();
                CameraShake_SetOffset(1.0f);
                playerAddHealth(Obj_GetPlayerObject(), -1);
                state->sub.energy = 0;
            }
            return state->sub.savedControlMode + 1;
        }
    }
    return 0;
}

int DR_EarthWarrior_stateHandler02(GameObject* obj, EarthWarriorState* controllerState)
{
    EarthWarriorState* state = obj->extra;
    EarthWarriorSub* warrior = &state->sub;
    warrior->flags3F1.b04 = 0;
    warrior->flags3F1.b08 = 0;
    warrior->flags3F2.b10 = 0;
    if (controllerState->baddie.moveJustStartedA != 0)
    {
        warrior->flags3F0.b80 = 0;
        warrior->flags3F0.b40 = 0;
        warrior->attackPhase = 0;
        warrior->flags3F2.b10 = 1;
    }
    if (!warrior->flags3F0.b80 && !warrior->flags3F0.b40 && !state->sub.flags994.b01 &&
        controllerState->baddie.pressedButtons & 0x100)
    {
        buttonDisable(0, PAD_BUTTON_A);
        state->sub.flags994.b01 = 1;
        ObjAnim_GetPriorityHitState(&obj->anim)->suppressOutgoingHits = 0;
        ObjAnim_SetCurrentMove(obj, 0x14, 0.0f, 0);
        controllerState->baddie.moveDone = 0;
        Sfx_PlayFromObject(obj, SFXTRIG_earthhuff);
    }
    controllerState->baddie.flags0 |= 0x800000;
    controllerState->baddie.stateId = 0;
    warrior->animSpeedMax = 4.32f;
    if (controllerState->baddie.moveJustStartedA != 0)
    {
        warrior->currentYaw += warrior->turnDegrees * 0xb6;
        warrior->frameCounter = 0;
        warrior->turnDegrees = 0;
    }
    {
        f32 a;
        f32 ph = (controllerState->baddie.inputMagnitude - 0.2f) / 0.8f;
        f32 t;
        a = warrior->animSpeedMax - 0.05f;
        t = (ph < 0.0f) ? 0.0f : ((ph > 1.0f) ? 1.0f : ph);
        warrior->targetAnimSpeed = a * (t * warrior->animSpeedScale);
    }
    if (warrior->flags3F0.b40)
    {
        warrior->unk360 |= 0x1000000LL;
        controllerState->baddie.moveSpeed = 0.0165f;
        {
            s16 yaw = (32768.0f * obj->anim.currentMoveProgress + (f32)warrior->leapStartYaw);
            warrior->appliedYaw = yaw;
            warrior->savedYaw = yaw;
        }
        if (controllerState->baddie.moveDone != 0)
        {
            s16 sw;
            warrior->flags3F0.b40 = 0;
            sw = warrior->currentYaw;
            warrior->appliedYaw = sw;
            warrior->savedYaw = sw;
            warrior->attackPhase = 0xc;
            warrior->flags3F1.b04 = 1;
            warrior->flags3F1.b08 = 1;
        }
        controllerState->baddie.animSpeedC = warrior->animSpeedRate * timeDelta + controllerState->baddie.animSpeedC;
        warrior->targetAnimSpeed = 0.0f;
        if (obj->anim.currentMoveProgress > 0.1f && obj->anim.currentMoveProgress < 0.5f)
        {
            warrior->flags8D8 |= 8;
        }
    }
    else if (warrior->flags3F0.b80)
    {
        if (DR_EarthWarrior_updateLeap(obj, warrior, &controllerState->baddie) != 0)
        {
            return 2;
        }
    }
    else if (state->sub.flags994.b01)
    {
        controllerState->baddie.moveSpeed = 0.02f;
        if (controllerState->baddie.moveDone != 0)
        {
            state->sub.flags994.b01 = 0;
            warrior->flags3F1.b08 = 1;
            ObjAnim_GetPriorityHitState(&obj->anim)->suppressOutgoingHits = 0;
        }
        {
            f32 m2;
            f32 m1;
            warrior->yawSmoothDivisor *= (m1 = 2.0f);
            warrior->yawStepScale *= (m2 = 0.5f);
            warrior->currentYawSmoothDivisor *= m1;
            warrior->currentYawStepRate *= m2;
        }
        warrior->targetAnimSpeed *= 0.75f;
        if (warrior->targetAnimSpeed < warrior->configRow[1].maxSpeed)
        {
            warrior->targetAnimSpeed = warrior->configRow[1].maxSpeed;
        }
        ObjAnim_GetPriorityHitState(&obj->anim)->hitVolumePriority = 0x15;
        ObjAnim_GetPriorityHitState(&obj->anim)->hitVolumeId = 2;
    }
    if (!state->sub.flags994.b01 && !warrior->flags3F0.b40 && !warrior->flags3F0.b80 &&
        controllerState->baddie.animSpeedC > 0.3f + warrior->configRow[2].maxSpeed &&
        (warrior->unk470 < -0.3f || warrior->frameCounter >= 0x96))
    {
        warrior->flags3F0.b80 = 1;
        warrior->unk360 |= 0x1000000LL;
        warrior->animSpeedRate = controllerState->baddie.animSpeedA;
        ObjAnim_SetCurrentMove(obj, warrior->moveTable[0x1E], 0.0f, 0);
        controllerState->baddie.moveSpeed = 0.035f;
    }
    if (!warrior->flags3F0.b80 && !warrior->flags3F0.b40)
    {
        if (warrior->frameCounter < 0x96)
        {
            f32 v = interpolate((f32)warrior->yawTurnProgress, 1.0f / warrior->yawSmoothDivisor, timeDelta);
            f32 cap = timeDelta * (warrior->yawStepScale * warrior->yawStepRate);
            if (v > cap)
            {
                v = cap;
            }
            if (warrior->yawTurnDir < 0)
            {
                v = -v;
            }
            warrior->appliedYaw = (182.044f * v + (f32)warrior->appliedYaw);
        }
        if (warrior->frameCounter < 0x96)
        {
            f32 v = interpolate((f32)warrior->frameCounter, 1.0f / warrior->currentYawSmoothDivisor, timeDelta);
            f32 cap = warrior->currentYawStepRate * timeDelta;
            if (v > cap)
            {
                v = cap;
            }
            if (warrior->turnDegrees < 0)
            {
                v = -v;
            }
            warrior->currentYaw = (182.044f * v + (f32)warrior->currentYaw);
        }
        else if (controllerState->baddie.animSpeedC <= warrior->configRow[0].maxSpeed &&
            controllerState->baddie.animSpeedA <= warrior->configRow[1].maxSpeed)
        {
            warrior->currentYaw += warrior->turnDegrees * 0xb6;
        }
    }
    if (!warrior->flags3F0.b40 && !warrior->flags3F1.b04)
    {
        f32 r = interpolate(warrior->targetAnimSpeed - controllerState->baddie.animSpeedC, warrior->animSpeedSmoothing,
                            timeDelta);
        r = r < -0.1f * timeDelta ? -0.1f * timeDelta : r > 0.1f * timeDelta ? 0.1f * timeDelta : r;
        if (warrior->frameCounter >= 0x96 && r > 0.0f)
        {
            r = 2.0f * -r;
        }
        controllerState->baddie.animSpeedC += r;
        controllerState->baddie.animSpeedC =
            (controllerState->baddie.animSpeedC < warrior->configRow[0].minSpeed)
                ? warrior->configRow[0].minSpeed
                : ((controllerState->baddie.animSpeedC > warrior->animSpeedMax)
                       ? warrior->animSpeedMax
                       : controllerState->baddie.animSpeedC);
        controllerState->baddie.animSpeedB = 0.0f;
    }
    else
    {
        controllerState->baddie.animSpeedC =
            (controllerState->baddie.animSpeedC < -warrior->animSpeedMax)
                ? -warrior->animSpeedMax
                : ((controllerState->baddie.animSpeedC > warrior->animSpeedMax)
                       ? warrior->animSpeedMax
                       : controllerState->baddie.animSpeedC);
    }
    controllerState->baddie.animSpeedA +=
        interpolate(controllerState->baddie.animSpeedC - controllerState->baddie.animSpeedA,
                    warrior->animSpeedASmoothing, timeDelta);
    if (!warrior->flags3F0.b80 && !warrior->flags3F0.b40 && !state->sub.flags994.b01)
    {
        f32 blend;
        int i2;
        int skip = 0;
        if (warrior->flags3F1.b08)
        {
            skip = 1;
            blend = 0.0f;
        }
        else
        {
            blend = obj->anim.currentMoveProgress;
        }
        i2 = (warrior->attackPhase / 4) << 1;
        warrior->attackStage = (i2 >> 1) + 1;
        if (warrior->attackStage > 4)
        {
            warrior->attackStage = 4;
        }
        warrior->soundId = (warrior->attackStage > 3) ? 0xa : 8;
        {
            f32 animSpeedC = controllerState->baddie.animSpeedC;
            if (animSpeedC < (&warrior->configRow[0].minSpeed)[i2])
            {
                if (warrior->attackPhase == 4)
                {
                    if (controllerState->baddie.animSpeedA < warrior->configRow[2].minSpeed &&
                        controllerState->baddie.inputMagnitude < 0.2f)
                    {
                        return 2;
                    }
                }
                else
                {
                    warrior->attackPhase -= 4;
                }
            }
            else if (animSpeedC >= (&warrior->configRow[0].maxSpeed)[i2])
            {
                if (warrior->attackPhase < 0x14)
                {
                    if (warrior->attackPhase == 0)
                    {
                        blend = 0.85f;
                    }
                    if (animSpeedC < warrior->animSpeedMax)
                    {
                        warrior->attackPhase += 4;
                    }
                }
            }
        }
        if ((skip != 0 || warrior->prevMoveTable != warrior->moveTable ||
                obj->anim.currentMove != warrior->moveTable[warrior->attackPhase]) &&
            (ObjAnim_GetCurrentEventCountdown(&obj->anim) == 0 || warrior->flags3F2.b10 != 0))
        {
            if ((obj)->anim.currentMove == 0x14)
            {
                blend = 0.85f;
            }
            ObjAnim_SetCurrentMove(obj, warrior->moveTable[warrior->attackPhase], blend, 0);
        }
    }
    if (!warrior->flags3F0.b80 && !warrior->flags3F0.b40 && !state->sub.flags994.b01)
    {
        if (ObjAnim_SampleRootCurvePhase(&obj->anim, controllerState->baddie.animSpeedC,
                                         &controllerState->baddie.moveSpeed) == 0)
        {
            controllerState->baddie.moveSpeed = 0.005f;
        }
    }
    DR_EarthWarrior_updateSteeringPose(obj, warrior, &controllerState->baddie);
    return 0;
}

int DR_EarthWarrior_stateHandler01(GameObject* obj, BaddieState* baddie)
{
    EarthWarriorState* state = obj->extra;
    EarthWarriorSub* warrior = &state->sub;
    int moveId;
    if (baddie->moveJustStartedA != 0)
    {
        baddie->animSpeedC = 0.0f;
    }
    baddie->animSpeedA -= interpolate(baddie->animSpeedA, warrior->animSpeedASmoothing, timeDelta);
    if (baddie->animSpeedA <= gDREarthWarriorSpeedRows[1].minSpeed)
    {
        baddie->animSpeedA = 0.0f;
    }
    {
        f32 z = 0.0f;
        baddie->animSpeedB = z;
        obj->anim.velocityX = z;
        obj->anim.velocityZ = z;
    }
    if (!warrior->flags3F0.b80 && !warrior->flags3F0.b40 && !state->sub.flags994.b01 &&
        (baddie->pressedButtons & 0x100))
    {
        buttonDisable(0, PAD_BUTTON_A);
        state->sub.flags994.b01 = 1;
        ObjAnim_GetPriorityHitState(&obj->anim)->suppressOutgoingHits = 0;
        ObjAnim_SetCurrentMove(obj, 0x14, 0.0f, 0);
        baddie->moveDone = 0;
        return 3;
    }
    if (baddie->previousInputMagnitude >= 0.22f && baddie->inputMagnitude >= 0.22f &&
        baddie->animSpeedC >= warrior->configRow[0].maxSpeed)
    {
        return 3;
    }
    moveId = warrior->moveTable[0];
    baddie->stateId = 0;
    warrior->animSpeedMax = 4.32f;
    {
        f32 a;
        f32 ph = (baddie->inputMagnitude - 0.2f) / 0.8f;
        f32 t;
        a = warrior->animSpeedMax - 0.05f;
        t = (ph < 0.0f) ? 0.0f : ((ph > 1.0f) ? 1.0f : ph);
        warrior->targetAnimSpeed = a * (t * warrior->animSpeedScale);
    }
    baddie->animSpeedC +=
        interpolate(warrior->targetAnimSpeed - baddie->animSpeedC, warrior->animSpeedSmoothing, timeDelta);
    if (baddie->moveJustStartedA != 0)
    {
        warrior->yawTurnProgress = 0;
        warrior->yawTurnDir = 0;
        warrior->frameCounter = 0;
        warrior->turnDegrees = 0;
        warrior->soundId = 8;
        warrior->attackStage = 0;
        baddie->velSmoothTime = 8.0f;
        baddie->moveSpeed = 0.005f;
    }
    if ((obj)->anim.currentMove == warrior->moveTable[0x18] || obj->anim.currentMove == warrior->moveTable[0x19])
    {
        if (baddie->moveDone != 0 && ObjAnim_GetCurrentEventCountdown(&obj->anim) == 0 && !state->sub.flags994.b01)
        {
            ObjAnim_SetCurrentMove(obj, moveId, 0.0f, 0);
            baddie->moveSpeed = 0.005f;
        }
    }
    else if (!state->sub.flags994.b01)
    {
        ObjAnim_SetCurrentMove(obj, moveId, 0.0f, 0);
        baddie->moveSpeed = 0.005f;
    }
    {
        f32 v = interpolate((f32)warrior->yawTurnProgress, 1.0f / warrior->yawSmoothDivisor, timeDelta);
        f32 cap = timeDelta * (warrior->yawStepScale * warrior->yawStepRate);
        v = (v < cap) ? v : cap;
        if (warrior->yawTurnDir < 0)
        {
            v = -v;
        }
        warrior->appliedYaw = (182.044f * v + (f32)warrior->appliedYaw);
    }
    {
        f32 v = interpolate((f32)warrior->frameCounter, 1.0f / warrior->currentYawSmoothDivisor, timeDelta);
        f32 cap = warrior->currentYawStepRate * timeDelta;
        v = (v < cap) ? v : cap;
        if (warrior->turnDegrees < 0)
        {
            v = -v;
        }
        warrior->currentYaw = (182.044f * v + (f32)warrior->currentYaw);
    }
    DR_EarthWarrior_updateSteeringPose(obj, warrior, baddie);
    return 0;
}

int DR_EarthWarrior_stateHandler00(GameObject* obj)
{
    EarthWarriorState* state = obj->extra;
    state->sub.flags98C |= 0x20;
    return 2;
}

int DR_EarthWarrior_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate)
{
    EarthWarriorState* state = obj->extra;
    int i;
    f32 fz;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    if (dll_2E_updateSequenceTurn(obj, animUpdate, &state->moveLib, 0, 0) != 0)
    {
        return 1;
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        int eventId = animUpdate->eventIds[i];
        switch (eventId)
        {
        case 0xa:
            break;
        case 0xe:
        case 0xf:
            state->moveLib.modeBits |= 1;
            ObjAnim_GetPriorityHitState(&obj->anim)->shapeFlags &= ~0x20;
            break;
        case 0x10:
            state->moveLib.modeBits &= ~1;
            ObjAnim_GetPriorityHitState(&obj->anim)->shapeFlags |= 0x20;
            break;
        }
    }
    state->sub.unk360 |= 0x800000LL;
    (*gPathControlInterface)->attachObject(obj, &state->baddie.flags4);
    fz = 0.0f;
    state->baddie.animSpeedC = fz;
    state->baddie.animSpeedB = fz;
    state->baddie.animSpeedA = fz;
    obj->anim.velocityX = fz;
    obj->anim.velocityY = fz;
    obj->anim.velocityZ = fz;
    return 0;
}

void DR_EarthWarrior_handleRiderScale(GameObject* obj, f32 scale)
{
    MatrixTransform v;
    f32 lp0, lp1, lp2;
    ObjModelJointMatrix* mtx = ObjPath_GetPointModelMtx(obj, 2);
    ObjPath_GetPointLocalPosition(obj, 2, &lp0, &lp1, &lp2);
    v.x = lp0;
    v.y = lp1;
    v.z = lp2;
    v.rotX = 0;
    v.rotY = 0;
    v.rotZ = 0;
    v.scale = scale / obj->anim.modelInstance->rootMotionScaleBase;
    setMatrixFromObjectPos(gEarthWarriorMatrix, &v);
    mtx44_mult(gEarthWarriorMatrix, (void*)mtx, gEarthWarriorMatrix);
    objSetModelMatrixOverride(gEarthWarriorMatrix);
}

void DR_EarthWarrior_resetToRomListPosition(void)
{
}

int DR_EarthWarrior_getRacePosition(void)
{
    return 0x0;
}

f32 DR_EarthWarrior_func19(GameObject* obj, f32* out)
{
    EarthWarriorState* state = obj->extra;
    f32 animSpeed;
    animSpeed = 0.001f * state->baddie.animSpeedC + 0.005f;
    *out = -(animSpeed < 0.005f ? 0.005f : animSpeed > 0.01f ? 0.01f : animSpeed);
    return 0.0f;
}

void DR_EarthWarrior_getPlayerAnim(GameObject* obj, f32* steeringAngle, int* leanAngle)
{
    EarthWarriorState* state = obj->extra;
    *steeringAngle = (f32)state->sub.aimAccumY;
    *leanAngle = state->sub.aimAccumX;
}

void DR_EarthWarrior_setMountState(GameObject* obj, enum VehicleMountState mountState)
{
    EarthWarriorState* state = obj->extra;
    state->sub.mountState = mountState;
    if (mountState == VEHICLE_NoRider)
    {
        mainSetBits(GAMEBIT_DR_EarthWarriorUnknown_2, 0);
        mainSetBits(GAMEBIT_DR_EarthWarriorUnknown_3, 1);
        state->moveLib.modeBits &= ~1;
        state->sub.flags994.b02 = 0;
        (*gGameUIInterface)->airMeterShutdown();
    }
    else
    {
        EarthWarriorState* reloadedState = obj->extra;
        DREarthWarriorPlacement* placement = (DREarthWarriorPlacement*)obj->anim.placementData;
        reloadedState->sub.flags994.b02 = 1;
        (*gGameUIInterface)->initAirMeter(placement->energyCapacity, DREARTHWARRIOR_AIRMETER_BGTEXTURE);
        (*gGameUIInterface)->runAirMeter(reloadedState->sub.energy);
        mainSetBits(GAMEBIT_DR_EarthWarriorUnknown_2, 1);
        mainSetBits(GAMEBIT_DR_EarthWarriorUnknown_3, 0);
    }
}

int DR_EarthWarrior_getMountState(void)
{
    return 0x0;
}

void DR_EarthWarrior_getCameraPosition(GameObject* obj, f32* x, f32* y, f32* z)
{
    *x = obj->anim.localPosX;
    *y = obj->anim.localPosY;
    *z = obj->anim.localPosZ;
}

int DR_EarthWarrior_getDismountSide(GameObject* obj)
{
    EarthWarriorState* state = obj->extra;
    if (state->sub.dismountSide != 0)
    {
        return 2;
    }
    return 1;
}

int DR_EarthWarrior_canDismount(void)
{
    return 0x0;
}

void DR_EarthWarrior_getRiderPosition(GameObject* obj, f32* x, f32* y, f32* z)
{
    EarthWarriorState* state = obj->extra;
    *x = state->sub.riderPosX;
    *y = state->sub.riderPosY;
    *z = state->sub.riderPosZ;
}

int DR_EarthWarrior_getMountSide(GameObject* obj)
{
    EarthWarriorState* state = obj->extra;
    if (state->sub.mountSide != 0)
    {
        return 1;
    }
    return 2;
}

int DR_EarthWarrior_canMount(void)
{
    return 0x0;
}

int DR_EarthWarrior_getExtraSize(void)
{
    return sizeof(EarthWarriorState);
}

int DR_EarthWarrior_getObjectTypeId(void)
{
    return 0x43;
}

void DR_EarthWarrior_free(GameObject* obj)
{
    EarthWarriorState* state = obj->extra;
    if (state->sub.modelChain != NULL)
    {
        ObjModelChain_Free(state->sub.modelChain);
    }
    objFreeObjectType(obj, VEHICLE_OBJECT_GROUP);
    if (state->sub.flags994.b02)
    {
        (*gGameUIInterface)->airMeterShutdown();
    }
    if (state->helperObj != NULL)
    {
        ObjLink_DetachChild(obj, state->helperObj);
        Obj_FreeObject(state->helperObj);
    }
}

void DR_EarthWarrior_render(GameObject* obj, int gdl, int mtxs, int vtxs, int pols, s8 visibility) {
    EarthWarriorState* state = obj->extra;
    if (visibility == -1) {
        objRenderModelAndHitVolumes(obj, gdl, mtxs, vtxs, pols, 1.0f);
        ObjPath_GetPointWorldPosition(obj, 0xb, &state->sub.riderPosX, &state->sub.riderPosY, &state->sub.riderPosZ, 0);
        ObjPath_GetPointWorldPositionArray(obj, 3, 4, (f32*)state->pathPoints);
    } else if (visibility != 0) {
        objRenderModelAndHitVolumes(obj, gdl, mtxs, vtxs, pols, 1.0f);
        ObjPath_GetPointWorldPosition(obj, 0xb, &state->sub.riderPosX, &state->sub.riderPosY, &state->sub.riderPosZ, 0);
        ObjPath_GetPointWorldPositionArray(obj, 3, 4, (f32*)state->pathPoints);
        dll_2E_setTargetFromPathPoint(obj, &state->moveLib, 0);
    }
}

void DR_EarthWarrior_hitDetect(GameObject* obj) {
    f32 hz;
    f32 hy;
    f32 hx;
    GameObject* hitObj;
    PartFxSpawnParams spawnParams;
    EarthWarriorState* state = obj->extra;
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    EWColorTable rows = gDREarthWarriorColors;

    if (obj->objectFlags & DREARTHWARRIOR_OBJFLAG_PARENT_SLACK) {
        return;
    }

    if (hitState->contactFlags != 0) {
        int i = hitState->contactHitVolume;
        i = i < 0 ? 0 : i > 0x23 ? 0x23 : i;
        spawnParams.scale = 1.0f;
        spawnParams.rotZ = 0;
        spawnParams.rotY = 0;
        spawnParams.rotX = 0;
        spawnParams.posX = hitState->contactPosX;
        spawnParams.posY = hitState->contactPosY;
        spawnParams.posZ = hitState->contactPosZ;
        (*gEarthWarriorResource)->spawn(NULL, 1, &spawnParams, 0x401, -1, &rows.rows[gDREarthWarriorRowIndices[i]]);
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->suppressOutgoingHits = 1;
        doRumble(10.0f);
    }

    if (hitState->lastHitObject != 0) {
        doRumble(10.0f);
    }

    obj->anim.rotX = state->sub.appliedYaw;
    if (state->baddie.controlMode != 3) {
        int hit = ObjHits_GetPriorityHitWithPosition(obj, &hitObj, 0, 0, &hx, &hy, &hz);
        if (hit != 0) {
            if (objGetFlagsE5_2((u8*)obj) != 0 && state->sub.mountState == VEHICLE_Mounted) {
                return;
            }
            Obj_SpawnHitLightAndFade(obj, (const Vec3f*)&hx, 5.0f);
            if (hit == 0x1a || hitObj == Obj_GetPlayerObject() ||
                hitObj->anim.romDefNo == DREARTHWARRIOR_ATTACKER_SEQID_SWORD) {
                return;
            }
            {
                objSoundStartTimed(obj, &state->modelSoundState, 0x28e, 0x1000, -1, 1);
                {
                    s16 d = obj->anim.rotX - (u16)hitObj->anim.rotX;
                    if (d > 0x8000) {
                        d = (s16)(d - 0xffff);
                    }
                    if (d < -0x8000) {
                        d += 0xffff;
                    }
                    if (d > 0x4000 || d < -0x4000) {
                        state->sub.flags994.b80 = 0;
                    } else {
                        state->sub.flags994.b80 = 1;
                    }
                }

                state->sub.savedControlMode = state->baddie.controlMode;
                (*gPlayerInterface)->setState(obj, state, 3);
            }
        }
    }

    if (state->baddie.flags0 & 0x800000) {
        if ((state->baddie.groundContact != 0 || state->baddie.surfaceFlags & 0xf0) &&
            state->sub.footstepCooldown <= 0.0f && state->baddie.animSpeedA > 3.408f) {
            doRumble((f32)randomGetRange(2, 5));
            state->sub.footstepCooldown = 30.0f;
            Sfx_PlayFromObject(obj, SFXTRIG_foot_run_jingle4);
        }

        if (state->baddie.groundContact != 0 || ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags & 8) {
            f32 spd;
            f32 vcos;
            f32 vsin;
            spd = sqrtf(obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityZ * obj->anim.velocityZ);
            obj->anim.velocityX = oneOverTimeDelta * (obj->anim.worldPosX - obj->anim.previousWorldPosX);
            obj->anim.velocityZ = oneOverTimeDelta * (obj->anim.worldPosZ - obj->anim.previousWorldPosZ);
            vcos = mathSinf(3.1415927f * state->sub.currentYaw / 32768.0f);
            vsin = mathCosf(3.1415927f * state->sub.currentYaw / 32768.0f);
            state->baddie.animSpeedA = -obj->anim.velocityZ * vsin - obj->anim.velocityX * vcos;
            state->baddie.animSpeedA *= 2.0f;
            state->baddie.animSpeedA = state->baddie.animSpeedA < 1.2960001f                ? 1.2960001f
                                       : state->baddie.animSpeedA > state->sub.animSpeedMax ? state->sub.animSpeedMax
                                                                                            : state->baddie.animSpeedA;
            state->baddie.animSpeedA = state->baddie.animSpeedA < 0.0f  ? 0.0f
                                       : state->baddie.animSpeedA > spd ? spd
                                                                        : state->baddie.animSpeedA;

            if (!state->sub.flags3F0.b40) {
                state->baddie.animSpeedC = state->baddie.animSpeedA;
            }
        }

        state->baddie.flags0 &= ~0x800000;
    }

    state->sub.footstepCooldown -= timeDelta;
    if (state->sub.footstepCooldown < 0.0f) {
        state->sub.footstepCooldown = 0.0f;
    }

    if (state != NULL) {
        ObjModelChain_AdvancePhase(state->sub.modelChain);
    }
}

void DR_EarthWarrior_runController(GameObject* obj, int updateRate, int frameIndex)
{
    EarthWarriorState* state = obj->extra;
    // Dinosaur Planet fossil: the earth warrior used to follow the player, but
    // that code was stripped but they left in the call to get the player.
    GameObject* player = Obj_GetPlayerObject();
    EarthWarriorSub* sub = &state->sub;
    Camera* camera = Camera_GetCurrent();
    state->baddie.hitPoints = 0;
    state->baddie.flags0 &= ~0x8000;

    if (state->sub.mountState == VEHICLE_Mounted)
    {
        state->baddie.moveInputX = padGetStickX(0);
        state->baddie.moveInputZ = padGetStickY(0);
        state->baddie.pressedButtons = getButtonsJustPressed(0);
        state->baddie.heldButtons = getButtonsHeld(0);
        state->baddie.cameraYaw = camera->yaw;
    }
    else
    {
        state->baddie.moveInputX = 0.0f;
        state->baddie.moveInputZ = 0.0f;
        state->baddie.pressedButtons = 0;
        state->baddie.heldButtons = 0;
        state->baddie.cameraYaw = 0;
    }

    state->baddie.flags0 |= 0x1000000;
    playerUpdateMotionState(obj, sub, &state->baddie);
    (*gPlayerInterface)
        ->update(obj, (void*)state, timeDelta, timeDelta, gDREarthWarriorStateHandlers,
                 &gDREarthWarriorDefaultStateHandler);
    obj->anim.rotY += state->baddie.spawnRotY >> 2;
    obj->anim.rotZ += state->baddie.spawnRotZ >> 2;

    if (state->sub.flags994.b02)
    {
        (*gGameUIInterface)->runAirMeter(state->sub.energy);
    }

    playerUpdateVelocityFromMotion(obj, sub, &state->baddie, timeDelta);
    playerClampVelocityAndMove(obj, timeDelta);

    (*gPathControlInterface)->update(obj, &state->baddie.flags4, timeDelta);
    (*gPathControlInterface)->apply(obj, &state->baddie.flags4);
    (*gPathControlInterface)->advance(obj, &state->baddie.flags4, timeDelta);

    obj->anim.rotX = sub->appliedYaw;
}

void DR_EarthWarrior_update(GameObject* obj)
{
    EarthWarriorState* state = obj->extra;
    int j;
    int i;
    Obj_GetPlayerObject();
    ObjAnim_GetPriorityHitState(&obj->anim)->hitVolumePriority = 0;
    ObjAnim_GetPriorityHitState(&obj->anim)->hitVolumeId = 0;
    if (state->helperObj == NULL && (u8)Obj_CanSetupObject() != 0)
    {
        ObjPlacement* setup = Obj_AllocObjectSetup(0x18, DREARTHWARRIOR_CHILD_OBJ_HELPER);
        GameObject* newObj = objSetupObject(setup, 4, obj->anim.mapEventSlot, -1, obj->anim.parent);
        ObjLink_AttachChild(obj, newObj, 2);
        state->helperObj = newObj;
    }
    state->sub.turnThreshold = 5;
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    if (state->sub.mountState == VEHICLE_Mounted)
    {
        setAButtonIcon(0x13);
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        ObjAnim_GetPriorityHitState(&obj->anim)->lateralResponseWeight = 0xf4;
        ObjAnim_GetPriorityHitState(&obj->anim)->axialResponseWeight = 0xf4;
        DR_EarthWarrior_runController(obj, timeDelta, -1);
    }
    else
    {
        f32 z;
        ObjAnim_GetPriorityHitState(&obj->anim)->lateralResponseWeight = 0;
        ObjAnim_GetPriorityHitState(&obj->anim)->axialResponseWeight = 0;
        z = 0.0f;
        state->baddie.animSpeedC = z;
        state->baddie.animSpeedB = z;
        state->baddie.animSpeedA = z;
        obj->anim.velocityX = z;
        obj->anim.velocityY = z;
        obj->anim.velocityZ = z;
        DR_EarthWarrior_runController(obj, framesThisStep, -1);
    }
    characterDoEyeAnims(obj, &state->eyeAnimState);
    objSoundUpdateMouth(obj, &state->modelSoundState);
    dll_2E_updateLookAt(obj, &state->moveLib);
    if ((obj)->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED)
    {
        state->sub.flags994.b10 = 1;
        if ((*gGameUIInterface)->isItemBeingUsed(GAMEBIT_ITEM_TrickyFood_Count) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            buttonDisable(0, PAD_BUTTON_A);
            state->sub.energy += 4;
            mainSetBits(GAMEBIT_ITEM_TrickyFood_Count, mainGetBit(GAMEBIT_ITEM_TrickyFood_Count) - 1);
        }
        else if (state->sub.talkSequenceId != -1)
        {
            if ((*gGameUIInterface)->isAnyItemBeingUsed() == 0)
            {
                if (state->sub.flags994.b08 == 0)
                {
                    (*gObjectTriggerInterface)->runSequence(state->sub.talkSequenceId, obj, -1);
                    buttonDisable(0, PAD_BUTTON_A);
                }
                else
                {
                    state->sub.flags994.b10 = 1;
                }
            }
        }
    }
    state->baddie.surfaceFlags |= 0x10;
    {
        f32 saved = obj->anim.velocityY;
        obj->anim.velocityY = 0.0f;
        state->baddie.eventFlags &= ~7;
        objAudioDispatchEventMask(obj, state->baddie.eventFlags, state->sub.soundId, state->pathPoints,
                                  &state->baddie.curvesCollision, state->baddie.animSpeedA,
                                  (state->sub.soundId == 8) ? 2.5f : 2.75f);
        obj->anim.velocityY = saved;
    }
    if (state->sub.flags8D8 & 8)
    {
        f32 vecA[3];
        struct
        {
            s16 angles[4];
            f32 mat[4];
        } w;
        vecA[0] = 0.05f * obj->anim.velocityX;
        vecA[1] = 0.0f;
        vecA[2] = 0.05f * obj->anim.velocityZ;
        for (i = 0; i < 4; i++)
        {
            w.mat[1] = 8.0f * obj->anim.velocityX + state->pathPoints[i].x;
            w.mat[2] = state->pathPoints[i].y;
            w.mat[3] = 8.0f * obj->anim.velocityZ + state->pathPoints[i].z;
            w.mat[0] = 1.0f;
            w.angles[0] = 2;
            for (j = 2; j != 0; j--)
            {
                (*gPartfxInterface)->spawnObject(obj, DREARTHWARRIOR_PARTFX, &w, 0x200001, -1, vecA);
            }
        }
        state->sub.flags8D8 &= ~8;
    }
}

void DR_EarthWarrior_init(GameObject* obj, DREarthWarriorPlacement* def)
{
    DREarthWarriorInitData* base = (DREarthWarriorInitData*)gDREarthWarriorInitData;
    EarthWarriorState* state = obj->extra;
    u32 stk = *(const u32*)gDREarthWarriorPathSetupParam;
    EWPathRange r2 = gDREarthWarriorLookInitData1;
    EWPathRange r1 = gDREarthWarriorLookInitData2;
    u8* pathState;
    obj->anim.rotX = (s16)(def->spawnYaw << 8);
    obj->animEventCallback = DR_EarthWarrior_SeqFn;
    objAddObjectType(obj, VEHICLE_OBJECT_GROUP);
    state->sub.setupVariant = def->setupVariant;
    state->sub.turnThreshold = 5;
    state->sub.talkSequenceId = -1;
    (*gPlayerInterface)->init(obj, state, 4, 1);
    state->baddie.flags0 |= 0x4000;
    state->baddie.gravity = 0.17f;
    pathState = (u8*)&state->baddie + 4;
    (*gPathControlInterface)->init(pathState, 0, 0x48683, 1);
    (*gPathControlInterface)->setup(pathState, 4, base->segmentLocalPoints, base->segmentRadii, &stk);
    (*gPathControlInterface)->setLocalPointCollision(pathState, 1, base->localPointPositions, base->localPointRadii, 8);
    pathState[0x264] = 0x28;
    (*gPathControlInterface)->attachObject(obj, pathState);
    ObjHits_EnableObject(obj);
    ObjAnim_GetPriorityHitState(&obj->anim)->trackContactMask = 9;
    dll_2E_initState(obj, &state->moveLib, -0x2000, 0x31c7, 2);
    dll_2E_setMoveTables(&state->moveLib, &r1, &r2, 2);
    dll_2E_setLookAtMaxDistance(&state->moveLib, 150.0f);
    state->moveLib.modeBits |= 2;
    state->sub.maxSpeed = 4.32f;
    state->sub.energy = def->energyCapacity;
    state->sub.moveTable = (const s16*)base->moveTable;
    state->sub.configRow = base->configRow;
    {
        f32 v = 1.0f;
        state->sub.unk834 = v;
        state->sub.animSpeedASmoothing = v;
    }
    state->sub.animSpeedSmoothingReload = 0.06f;
    state->sub.paramCurve0 = base->paramCurve0Data;
    state->sub.paramCurve0Count = 0x29;
    state->sub.paramCurve1 = base->paramCurve1Data;
    state->sub.paramCurve1Count = 0x29;
    state->sub.paramCurve2 = base->paramCurve2Data;
    state->sub.paramCurve2Count = 0x2e;
    state->sub.paramCurve3 = base->paramCurve1Data;
    state->sub.paramCurve3Count = 0x29;
    state->sub.paramCurve4 = base->paramCurve2Data;
    state->sub.paramCurve4Count = 0x2e;
    state->sub.unk7E0 = 5.555f;
    {
        s16 h = obj->anim.rotX;
        state->sub.savedYaw = h;
        state->sub.unk474 = h;
        state->sub.currentYaw = h;
        state->sub.appliedYaw = h;
    }
    state->sub.flags994.b08 = 0;
    state->sub.talkSequenceId = 2;
    storeZeroToFloatParam(&state->sub.airMeterTimer);
    s16toFloat(&state->sub.airMeterTimer, 0x1e);
    state->sub.flags994.b02 = 0;
    state->sub.unk99D = 1;
    state->helperObj = NULL;
    if (mainGetBit(GAMEBIT_DR_EarthWarriorUnknown_1) != 0)
    {
        state->sub.unk995 = 1;
    }
    state->sub.modelChain = ObjModelChain_Alloc(&gEarthWarriorTailChainDesc, 1);
    ObjModelChain_SetOrigin(state->sub.modelChain, 0.15f, 0.75f, -0.05f);
    obj->afterBonesCallback = dim2prisonmammoth_updateModelChain;
    ObjModelChain_SetEnabled(state->sub.modelChain, 1);
}

void DR_EarthWarrior_release(void)
{
    if (gEarthWarriorResource != NULL)
    {
        Resource_Release(gEarthWarriorResource);
        gEarthWarriorResource = NULL;
    }
}

void DR_EarthWarrior_initialise(void)
{
    gDREarthWarriorStateHandlers[0] = DR_EarthWarrior_stateHandler00;
    gDREarthWarriorStateHandlers[1] = DR_EarthWarrior_stateHandler01;
    gDREarthWarriorStateHandlers[2] = DR_EarthWarrior_stateHandler02;
    gDREarthWarriorStateHandlers[3] = DR_EarthWarrior_stateHandler03;
    gDREarthWarriorDefaultStateHandler = DR_EarthWarrior_defaultStateHandler;
    if (gEarthWarriorResource == NULL)
    {
        gEarthWarriorResource = Resource_Acquire(DREARTHWARRIOR_EFFECT_RESOURCE_ID, 1);
    }
}

u8 gDREarthWarriorInitData[132] = {
    0x02, 0x8F, 0x08, 0x00, 0x01, 0x00, 0x02, 0x90, 0x10, 0x00, 0x03, 0x00, 0xC1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xC1, 0x40, 0x00, 0x00, 0x41, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC1, 0x40, 0x00, 0x00, 0x41, 0x10,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x40, 0x00, 0x00, 0xC1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41,
    0x40, 0x00, 0x00, 0x3D, 0xCC, 0xCC, 0xCD, 0x3D, 0xCC, 0xCC, 0xCD, 0x3D, 0xCC, 0xCC, 0xCD, 0x3D, 0xCC, 0xCC, 0xCD,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xC2, 0x0C, 0x00, 0x00, 0x42, 0x0C, 0x00, 0x00, 0x40, 0xA0, 0x00, 0x00, 0x40, 0xA0, 0x00, 0x00, 0x40, 0xA0,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x0A,
};

EWSpeedRange gDREarthWarriorSpeedRows[6] = {
    {0.005f, 0.24000001f}, {0.192f, 1.2960001f}, {1.248f, 2.256f},
    {2.2080002f, 3.408f},  {3.3600001f, 4.32f},  {4.3f, 4.32f},
};

u8 gDREarthWarriorRowIndices[36] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

u16 lbl_803352D0[32] = {
    2, 2, 2, 2, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22,
    4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 28, 27, 2,
};

f32 lbl_80335310[215] = {
    12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 12.0f,
    12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 13.0f, 16.0f,
    32.0f, 32.0f, 32.0f, 32.0f, 32.0f, 32.0f, 32.0f, 32.0f, 32.0f, 32.0f,
    32.0f, 32.0f, 32.0f, 32.0f, 32.0f, 32.0f, 32.0f, 32.0f, 32.0f, 32.0f,
    32.0f, 16.0f, 16.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f,
    10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f,
    10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f,
    10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f, 10.0f,
    10.0f, 10.0f, 7.0f, 7.0f, 7.0f, 7.0f, 7.0f, 7.0f, 7.0f, 7.0f,
    7.0f, 7.0f, 7.0f, 7.0f, 7.0f, 6.5f, 6.0f, 5.5f, 5.0f, 4.8f,
    4.0f, 3.6f, 3.4f, 3.4f, 3.4f, 3.4f, 3.4f, 3.4f, 3.4f, 3.4f,
    3.4f, 3.4f, 3.4f, 3.4f, 3.4f, 3.4f, 3.4f, 3.4f, 3.4f, 3.4f,
    3.4f, 3.4f, 3.4f, 3.4f, 3.4f, 3.4f, 3.4f, 3.4f, 8.0f, 8.0f,
    5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f,
    5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f,
    5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f,
    5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 14.0f,
    14.0f, 14.0f, 14.0f, 14.0f, 14.0f, 14.0f, 14.0f, 14.0f, 14.0f, 14.0f,
    14.0f, 14.0f, 13.0f, 12.0f, 11.0f, 10.0f, 9.6f, 8.0f, 7.2f, 6.8f,
    6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f,
    6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f,
    6.8f, 6.8f, 6.8f, 6.8f, 6.8f,
};

s32 gEarthWarriorTailChainJointIndices[4] = {0x17, 0x18, 0x19, 0x1A};

ObjModelChainDesc gEarthWarriorTailChain = {gEarthWarriorTailChainJointIndices, 4};
ObjModelChainDesc* gEarthWarriorTailChainDesc = &gEarthWarriorTailChain;

ObjectDescriptor24WithPadding gDR_EarthWarriorObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_24_SLOTS,
        (ObjectDescriptorCallback)DR_EarthWarrior_initialise,
        (ObjectDescriptorCallback)DR_EarthWarrior_release,
        0,
        (ObjectDescriptorCallback)DR_EarthWarrior_init,
        (ObjectDescriptorCallback)DR_EarthWarrior_update,
        (ObjectDescriptorCallback)DR_EarthWarrior_hitDetect,
        (ObjectDescriptorCallback)DR_EarthWarrior_render,
        (ObjectDescriptorCallback)DR_EarthWarrior_free,
        (ObjectDescriptorCallback)DR_EarthWarrior_getObjectTypeId,
        (ObjectDescriptorExtraSizeCallback)DR_EarthWarrior_getExtraSize,
        (ObjectDescriptorCallback)DR_EarthWarrior_canMount,
        (ObjectDescriptorCallback)DR_EarthWarrior_getMountSide,
        (ObjectDescriptorCallback)DR_EarthWarrior_getRiderPosition,
        (ObjectDescriptorCallback)DR_EarthWarrior_canDismount,
        (ObjectDescriptorCallback)DR_EarthWarrior_getDismountSide,
        (ObjectDescriptorCallback)DR_EarthWarrior_getCameraPosition,
        (ObjectDescriptorCallback)DR_EarthWarrior_getMountState,
        (ObjectDescriptorCallback)DR_EarthWarrior_setMountState,
        (ObjectDescriptorCallback)DR_EarthWarrior_getPlayerAnim,
        (ObjectDescriptorCallback)DR_EarthWarrior_func19,
        (ObjectDescriptorCallback)DR_EarthWarrior_getRacePosition,
        (ObjectDescriptorCallback)DR_EarthWarrior_resetToRomListPosition,
        (ObjectDescriptorCallback)DR_EarthWarrior_handleRiderScale,
        (ObjectDescriptorCallback)DR_EarthWarrior_feed,
    },
    0,
};
