/*
 * DIMSnowHorn (DLL 0x256) - the rideable SnowHorn mammoth found in
 * DIM (Dinosaur InfernoMountain).  Fox can mount the mammoth and use it to
 * clear puzzle obstacles.  The object runs a 12-state BaddieState machine
 * (stateHandler00-0B); the riding sub-loop (DIMSnowHorn1_ridingUpdate) handles stick/button
 * input and the air-meter while mounted, and DIMSnowHorn1_update coordinates
 * the full per-frame tick.
 */
#include "dlls/objects/598_DIMSnowHorn.h"
#include "dlls/objects/common/vehicle.h"
#include "dlls/objects/457_DIMDismount.h"
#include "main/dll/partfx_interface.h"
#include "main/obj_path.h"
#include "main/texture.h"
#include "main/objHitReact.h"
#include "main/vecmath.h"
#include "main/newclouds.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/game_ui_interface.h"
#include "main/mapEventTypes.h"
#include "main/newshadows_audio_api.h"
#include "main/object_render.h"
#include "main/pad_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/shader_api.h"
#include "sys/objects.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/tricky_api.h"
#include "main/gamebit_ids.h"
#include "main/dll/baddie_state.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/player_control_interface.h"
#include "dlls/object_descriptor.h"
#include "main/objprint_api.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "dlls/objects/201_Baddie.h"
#include "main/pad.h"
#include "main/objtype.h"
#include "dolphin/pad.h"
#include "main/camera.h"
#include "main/objseq.h"

f32 gDIMSnowHorn1ModelMtx[16];
void* gDIMSnowHorn1StateHandlers[12];
void* gDIMSnowHorn1DefaultStateHandler;
void* gDIMSnowHorn1Texture;

s16 gDIMSnowHorn1TextureId = 0x1C8;
f32 gDIMSnowHorn1PathCollisionData[2] = {25.0f, 25.0f};
s16 gDIMSnowHorn1MoveIds[2] = {0x103, 0xB};
f32 gDIMSnowHorn1MoveSpeeds[2] = {0.0031f, 0.005f};
s16 gDIMSnowHorn1LocomotionMoveIds[4] = {0, 3, 0, 0};

#define DIMSNOWHORN1_AIRMETER_BGTEXTURE 0x5d0 /* HUD air-meter background texture id */

/* DIMSnowHorn1State.flags bits */
#define SNOWHORN1_FLAG_RIDING        0x2  /* GAMEBIT_NW_SnowHorn03E3 active (set cross-DLL) */
#define SNOWHORN1_FLAG_HITVOL_PRIO   0x8  /* suppress hit-volume priority this frame */
#define SNOWHORN1_FLAG_SEQ_TRIGGERED 0x20 /* interaction sequence armed */

static const DIMSnowHorn1PieceCounts sDIMSnowHorn1DefaultPieceCounts = {{1, 1, 1, 1}};

void DIMSnowHorn1_func23(void) {
}

int DIMSnowHorn1_defaultStateHandler(void) {
    return 0x0;
}

int DIMSnowHorn1_stateHandler0B(GameObject* obj, DIMSnowHorn1State* state) {
    ObjHitsPriorityState* sub;
    DIMSnowHorn1State* inner;
    f32 k;

    inner = obj->extra;
    sub = (ObjHitsPriorityState*)obj->anim.hitReactState;
    state->baddie.flags0 |= 0x200000;
    k = 0.0f;
    state->baddie.animSpeedC = k;
    state->baddie.animSpeedB = k;
    state->baddie.animSpeedA = k;
    obj->anim.velocityX = k;
    obj->anim.velocityY = k;
    obj->anim.velocityZ = k;

    if (state->baddie.moveJustStartedA != 0) {
        inner->flags &= ~SNOWHORN1_FLAG_HITVOL_PRIO;
        sub->flags |= OBJHITS_PRIORITY_STATE_TRACK_CONTACT;
        ObjAnim_SetCurrentMove(obj, 0x204, k, 0);
        state->baddie.moveSpeed = 0.013f;
        Sfx_PlayFromObject(obj, SFXTRIG_thorntail_chew2);
    }
    if ((sub->flags & OBJHITS_PRIORITY_STATE_TRACK_CONTACT) &&
        (sub->contactFlags & OBJHITS_CONTACT_FLAG_KIND_NONZERO)) {
        inner->flags |= SNOWHORN1_FLAG_HITVOL_PRIO;
    }
    if (inner->flags & SNOWHORN1_FLAG_HITVOL_PRIO) {
        sub->hitVolumePriority = 0;
        sub->hitVolumeId = 0;
        sub->flags &= ~OBJHITS_PRIORITY_STATE_TRACK_CONTACT;
    } else {
        sub->hitVolumePriority = 0xb;
        sub->hitVolumeId = 1;
        sub->flags |= OBJHITS_PRIORITY_STATE_TRACK_CONTACT;
    }
    if (obj->anim.currentMoveProgress > 0.9f) {
        return 8;
    }
    return 0;
}

int DIMSnowHorn1_stateHandler0A(GameObject* obj, DIMSnowHorn1State* state, f32 t) {
    GameObject* near;
    DIMSnowHorn1State* inner;
    int phase;
    int moveIdx;
    int changed;
    int useNormal;
    f32 speed;
    f32 target;
    f32 animSpeedC;
    f32 blend;
    f32 nearDist;

    nearDist = 300.0f;
    near = objGetNearestTypeTo(DIM_DISMOUNT_POINT_OBJECT_GROUP, obj, &nearDist);
    inner = obj->extra;
    if (mainGetBit(GAMEBIT_NW_SnowHorn03E3) != 0) {
        if (RandomTimer_UpdateRangeTrigger(&inner->randomTimerD04, 3.0f, 6.0f) != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_hightop_call1);
        }
    }
    state->baddie.flags0 |= 0x200000;
    if (state->baddie.inputMagnitude < 0.05f) {
        state->baddie.turnRateAbs = 0;
        state->baddie.turnRate = 0;
        state->baddie.inputMagnitude = 0.0f;
    }
    if (state->baddie.turnRateAbs < 0x5a) {
        obj->anim.rotX = 182.0f * ((f32)(s16) * &state->baddie.turnRate * t / 36.0f) + (f32)(s16) * &obj->anim.rotX;
    } else {
        return 8;
    }

    speed = state->baddie.inputMagnitude;
    if (speed < 0.0f) {
        speed = 0.0f;
    }
    if (speed > 1.0f) {
        speed = 1.0f;
    }
    if (inner->airMeterValue == 0) {
        speed = 0.0f;
    }
    target = 0.85f * speed;
    if (target < 0.0f) {
        target = 0.0f;
    }
    state->baddie.animSpeedC =
        t * ((target - state->baddie.animSpeedC) / state->baddie.velSmoothTime) + state->baddie.animSpeedC;

    if (obj->anim.rotY > 0) {
        target = target - 0.3f * mathSinf(3.1415927f * (f32)(s16) * &obj->anim.rotY / 32768.0f);
    } else {
        target = target - 0.15f * mathSinf(3.1415927f * (f32)(s16) * &obj->anim.rotY / 32768.0f);
    }
    if (target < gDIMSnowHorn1LocomotionSpeedRanges[2]) {
        target = gDIMSnowHorn1LocomotionSpeedRanges[2];
    }
    state->baddie.animSpeedA =
        t * ((target - state->baddie.animSpeedA) / state->baddie.velSmoothTime) + state->baddie.animSpeedA;

    changed = 0;
    blend = obj->anim.currentMoveProgress;
    phase = 0;
    while (gDIMSnowHorn1LocomotionMoveIds[phase] != obj->anim.currentMove && phase < 2) {
        phase++;
    }
    if (phase >= 2) {
        phase = 0;
    }
    if (obj->anim.currentMove == 0x208) {
        phase = 1;
    }

    animSpeedC = state->baddie.animSpeedC;
    moveIdx = phase * 2;
    if (animSpeedC < gDIMSnowHorn1LocomotionSpeedRanges[moveIdx]) {
        if (phase == 1) {
            return 8;
        }
        phase--;
        changed = 1;
    } else if (animSpeedC >= gDIMSnowHorn1LocomotionSpeedRanges[moveIdx + 1]) {
        if (phase == 0) {
            blend = 0.0f;
        }
        phase++;
        changed = 1;
    }

    useNormal = 1;
    if (state->baddie.moveDone != 0 && obj->anim.currentMove == 0x208) {
        changed = 1;
        useNormal = 0;
    }
    if (changed != 0) {
        if (phase == 1 && useNormal != 0) {
            ObjAnim_SetCurrentMove(obj, 0x208, blend, 0);
        } else {
            ObjAnim_SetCurrentMove(obj, gDIMSnowHorn1LocomotionMoveIds[phase], blend, 0);
        }
    }

    ObjAnim_SampleRootCurvePhase(&obj->anim, state->baddie.animSpeedA, &state->baddie.moveSpeed);
    if ((state->baddie.pressedButtons & PAD_BUTTON_A) != 0) {
        if (near == NULL || ((near)->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) == 0) {
            return 0xc;
        }
    }
    return 0;
}

int DIMSnowHorn1_stateHandler09(GameObject* obj, DIMSnowHorn1State* state, f32 fv) {
    GameObject* near;
    DIMSnowHorn1State* inner;
    f32 sp = 300.0f;
    s16 turnRate;

    near = (objGetNearestTypeTo(DIM_DISMOUNT_POINT_OBJECT_GROUP, obj, &sp));
    inner = obj->extra;
    state->baddie.flags0 |= 0x200000;

    if (state->baddie.turnRateAbs < inner->advanceCountThreshold || 0.0f == state->baddie.inputMagnitude) {
        return 8;
    }

    if (state->baddie.turnRate < -0xaf) {
        state->baddie.turnRate = -state->baddie.turnRate;
    }
    turnRate = state->baddie.turnRate;
    if (turnRate > 0 && obj->anim.currentMove != 0x201) {
        ObjAnim_SetCurrentMove(obj, 0x201, 0.0f, 0);
    } else if (turnRate <= 0) {
        if (obj->anim.currentMove != 0x200) {
            ObjAnim_SetCurrentMove(obj, 0x200, 0.0f, 0);
        }
    }
    state->baddie.moveSpeed = 0.012f;
    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 8);

    if (state->baddie.pressedButtons & PAD_BUTTON_A) {
        if (near == NULL || (near->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) == 0) {
            return 0xc;
        }
    }
    return 0;
}

int DIMSnowHorn1_stateHandler08(GameObject* obj, DIMSnowHorn1State* state) {
    DIMSnowHorn1State* inner = obj->extra;

    state->baddie.flags0 |= 0x200000;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;

    switch (obj->anim.currentMove) {
    case 0x206:
        if (state->baddie.moveDone != 0) {
            if (state->baddie.moveSpeed > 0.0f) {
                ObjAnim_SetCurrentMove(obj, 0x205, 0.0f, 0);
                state->baddie.moveSpeed = 0.005f;
            } else {
                return 8;
            }
        }
        if (inner->airMeterValue != 0 && state->baddie.moveSpeed > 0.0f) {
            if (state->baddie.pressedButtons != 0 || state->baddie.moveInputX != 0.0f ||
                0.0f != state->baddie.moveInputZ) {
                state->baddie.moveSpeed = -state->baddie.moveSpeed;
            }
        }
        break;
    case 0x205:
        if (inner->airMeterValue != 0) {
            if (state->baddie.pressedButtons != 0 || state->baddie.moveInputX != 0.0f ||
                0.0f != state->baddie.moveInputZ) {
                ObjAnim_SetCurrentMove(obj, 0x207, 0.0f, 0);
                state->baddie.moveSpeed = 0.014f;
            }
        }
        break;
    case 0x207:
        if (state->baddie.moveDone != 0) {
            return 8;
        }
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0x206, 0.0f, 0);
        state->baddie.moveSpeed = 0.014f;
        break;
    }
    return 0;
}

int DIMSnowHorn1_stateHandler07(GameObject* obj, DIMSnowHorn1State* state) {
    GameObject* near;
    DIMSnowHorn1State* inner;
    f32 sp = 300.0f;
    f32 fz;

    near = objGetNearestTypeTo(DIM_DISMOUNT_POINT_OBJECT_GROUP, obj, &sp);
    inner = obj->extra;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    fz = 0.0f;
    state->baddie.animSpeedC = fz;
    state->baddie.animSpeedB = fz;
    state->baddie.animSpeedA = fz;
    obj->anim.velocityX = fz;
    obj->anim.velocityY = fz;
    obj->anim.velocityZ = fz;
    state->baddie.flags0 |= 0x200000;
    if (state->baddie.moveJustStartedA != 0) {
        state->baddie.controlTimer = 0;
        state->baddie.moveSpeed = 0.005f;
        state->baddie.velSmoothTime = 8.0f;
        if (obj->anim.currentMove != gDIMSnowHorn1LocomotionMoveIds[0]) {
            ObjAnim_SetCurrentMove(obj, gDIMSnowHorn1LocomotionMoveIds[0], fz, 0);
        }
    }
    switch (obj->anim.currentMove) {
    case 0x209:
    case 0x20a:
        if (state->baddie.moveDone != 0) {
            ObjAnim_SetCurrentMove(obj, gDIMSnowHorn1LocomotionMoveIds[0], 0.0f, 0);
            state->baddie.moveSpeed = 0.005f;
        }
        break;
    }
    if (state->baddie.inputMagnitude < 0.05f) {
        state->baddie.turnRateAbs = 0;
        state->baddie.turnRate = 0;
        state->baddie.inputMagnitude = 0.0f;
    }
    {
        f32 v = *(f32*)&state->baddie.trackedObj;
        if (v > 0.0f && state->baddie.inputMagnitude > 0.0f &&
            state->baddie.turnRateAbs >= inner->advanceCountThreshold) {
            return 0xa;
        }
        if (v > 0.1f && state->baddie.inputMagnitude > 0.1f &&
            state->baddie.turnRateAbs < inner->advanceCountThreshold) {
            return 0xb;
        }
    }
    if (state->baddie.pressedButtons & PAD_BUTTON_A) {
        if (near == NULL || (near->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) == 0) {
            return 0xc;
        }
    }
    if (mainGetBit(GAMEBIT_NW_SnowHorn03E3) != 0) {
        if (RandomTimer_UpdateRangeTrigger(&inner->randomTimerD04, 3.0f, 6.0f) != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_hightop_call1);
        }
    }
    return 0;
}

int DIMSnowHorn1_stateHandler06(GameObject* obj, DIMSnowHorn1State* state) {
    DIMSnowHorn1State* inner;
    f32 fz;

    fz = 0.0f;
    state->baddie.animSpeedC = fz;
    state->baddie.animSpeedB = fz;
    state->baddie.animSpeedA = fz;
    obj->anim.velocityX = fz;
    obj->anim.velocityY = fz;
    obj->anim.velocityZ = fz;
    state->baddie.flags0 |= 0x200000;
    inner = obj->extra;
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    obj->hitVolumeIndex = mainGetBit(GAMEBIT_ITEM_DIMAlpineRoot_Count) != 0;
    if (state->baddie.moveJustStartedA != 0) {
        state->baddie.moveSpeed = 0.005f;
        if (obj->anim.currentMove != 0x13) {
            ObjAnim_SetCurrentMove(obj, 0x13, 0.0f, 0);
        }
    }
    if (obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) {
        if ((*gGameUIInterface)->isItemBeingUsed(GAMEBIT_ITEM_DIMAlpineRoot_Count) != 0) {
            u8 bit170 = mainGetBit(GAMEBIT_ITEM_DIMAlpineRoot_Count);
            if (mainGetBit(GAMEBIT_ITEM_AlpineRoot_028) == 0) {
                switch (bit170) {
                case 1:
                    mainSetBits(GAMEBIT_ITEM_AlpineRoot_028, 1);
                    inner->triggerMode = 2;
                    break;
                case 2:
                    inner->triggerMode = 4;
                    mainSetBits(GAMEBIT_ITEM_DIMAlpineRoot_16F, 1);
                    break;
                }
            } else {
                inner->triggerMode = 4;
                mainSetBits(GAMEBIT_ITEM_DIMAlpineRoot_16F, 1);
            }
            (*gObjectTriggerInterface)->runSequence(inner->triggerMode, (void*)obj, -1);
            mainSetBits(GAMEBIT_ITEM_DIMAlpineRoot_Count, mainGetBit(GAMEBIT_ITEM_DIMAlpineRoot_Count) - bit170);
            buttonDisable(0, PAD_BUTTON_A);
        } else {
            if (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
                if (mainGetBit(GAMEBIT_ITEM_AlpineRoot_028) != 0) {
                    inner->triggerMode = 3;
                } else {
                    inner->triggerMode = 1;
                }
                (*gObjectTriggerInterface)->runSequence(inner->triggerMode, (void*)obj, -1);
                buttonDisable(0, PAD_BUTTON_A);
            }
        }
    }
    return 0;
}

int DIMSnowHorn1_stateHandler05(GameObject* obj, DIMSnowHorn1State* state) {
    GameObject* player;
    DIMSnowHorn1State* inner;
    int bit_a, bit_b;
    int id_a, id_b, id_c, id_d;
    GameObject* o1;
    int* o2;
    int phase;
    f32 resetValue;

    resetValue = 0.0f;
    state->baddie.animSpeedC = resetValue;
    state->baddie.animSpeedB = resetValue;
    state->baddie.animSpeedA = resetValue;
    obj->anim.velocityX = resetValue;
    obj->anim.velocityY = resetValue;
    obj->anim.velocityZ = resetValue;
    *(int*)state |= 0x200000;

    inner = obj->extra;
    player = Obj_GetPlayerObject();
    switch (inner->mode) {
    case 1:
        id_a = 0x1602;
        id_b = 0x454bc;
        id_c = 0x454b8;
        id_d = 0x454b9;
        bit_a = 0x172;
        bit_b = 0x9ed;
        break;
    case 4:
        id_a = 0x4963b;
        id_b = 0x4963c;
        id_c = 0x4963d;
        id_d = 0x4963e;
        bit_a = 0x8f9;
        bit_b = 0x85d;
        break;
    }

    if (state->baddie.moveJustStartedA != 0) {
        state->baddie.moveSpeed = 0.005f;
        if (obj->anim.currentMove != 0x13) {
            ObjAnim_SetCurrentMove(obj, 0x13, 0.0f, 0);
        }
    }

    if (mainGetBit(bit_a) != 0 && mainGetBit(bit_b) != 0 && player != NULL &&
        Vec_distance(&player->anim.worldPosX, &obj->anim.worldPosX) < 150.0f) {
        switch (inner->mode) {
        case 1:
            inner->triggerMode = 0;
            mainSetBits(GAMEBIT_ITEM_TrickyFlame_Got, 1);
            mainSetBits(GAMEBIT_DIM_FoundInjuredSnowHorn, 1);
            break;
        case 4:
            inner->triggerMode = 9;
            mainSetBits(0x1db, 1);
            break;
        }
        (*gObjectTriggerInterface)->runSequence(inner->triggerMode, (void*)obj, -1);
        buttonDisable(0, PAD_BUTTON_A);
    } else {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        phase = inner->proximityPhase;
        switch (phase) {
        case 1:
            if (Vec_distance(&player->anim.worldPosX, &obj->anim.worldPosX) < 200.0f) {
                o1 = ObjList_FindObjectById(id_a);
                if (o1 != NULL) {
                    enemy_trackPlayer(o1);
                }
                o1 = ObjList_FindObjectById(id_b);
                if (o1 != NULL) {
                    enemy_trackPlayer(o1);
                }
                inner->proximityPhase = 2;
            }
            break;
        case 0:
        case 2:
            if ((u32)phase == 0 || Vec_distance(&player->anim.worldPosX, &obj->anim.worldPosX) > 300.0f) {
                o1 = ObjList_FindObjectById(id_a);
                o2 = (int*)ObjList_FindObjectById(id_c);
                if (o1 != NULL && o2 != NULL) {
                    enemy_setTrackedObj(o1, (GameObject*)o2);
                }
                o1 = ObjList_FindObjectById(id_b);
                o2 = (int*)ObjList_FindObjectById(id_d);
                if (o1 != NULL && o2 != NULL) {
                    enemy_setTrackedObj(o1, (GameObject*)o2);
                }
                inner->proximityPhase = 1;
            } else {
                if (RandomTimer_UpdateRangeTrigger(&inner->randomTimerD08, 4.0f, 8.0f) != 0) {
                    Sfx_PlayFromObject(obj, SFXTRIG_thorntail_chew1);
                }
            }
            break;
        }
    }
    return 0;
}

int DIMSnowHorn1_stateHandler04(GameObject* obj, DIMSnowHorn1State* state) {
    f32 k = 0.0f;
    int idx;

    state->baddie.animSpeedC = k;
    state->baddie.animSpeedB = k;
    state->baddie.animSpeedA = k;
    obj->anim.velocityX = k;
    obj->anim.velocityY = k;
    obj->anim.velocityZ = k;
    state->baddie.flags0 |= 0x200000;

    if (state->baddie.moveJustStartedA != 0) {
        idx = randomGetRange(0, 1);
        state->baddie.moveSpeed = gDIMSnowHorn1MoveSpeeds[idx];
        ObjAnim_SetCurrentMove(obj, gDIMSnowHorn1MoveIds[idx], 0.0f, 0);
    }
    if (state->baddie.moveDone != 0) {
        return -2;
    }
    if (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
        (*gObjectTriggerInterface)->runSequence(randomGetRange(0, 2) + 6, (void*)obj, -1);
        buttonDisable(0, PAD_BUTTON_A);
    }
    return 0;
}

int DIMSnowHorn1_stateHandler03(GameObject* obj, DIMSnowHorn1State* state) {
    DIMSnowHorn1State* inner = obj->extra;
    f32 k = 0.0f;
    int idx;

    state->baddie.animSpeedC = k;
    state->baddie.animSpeedB = k;
    state->baddie.animSpeedA = k;
    obj->anim.velocityX = k;
    obj->anim.velocityY = k;
    obj->anim.velocityZ = k;
    state->baddie.flags0 |= 0x200000;

    if (state->baddie.moveJustStartedA != 0) {
        idx = randomGetRange(0, 1);
        state->baddie.moveSpeed = gDIMSnowHorn1MoveSpeeds[idx];
        ObjAnim_SetCurrentMove(obj, gDIMSnowHorn1MoveIds[idx], 0.0f, 0);
    }
    if (state->baddie.moveDone != 0) {
        return -1;
    }
    if (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
        if (inner->flags & SNOWHORN1_FLAG_SEQ_TRIGGERED) {
            (*gObjectTriggerInterface)->runSequence(randomGetRange(0, 2) + 6, (void*)obj, -1);
        } else {
            (*gObjectTriggerInterface)->runSequence(5, (void*)obj, -1);
        }
        buttonDisable(0, PAD_BUTTON_A);
    }
    return 0;
}

int DIMSnowHorn1_stateHandler02(GameObject* obj, DIMSnowHorn1State* state, f32 fv) {
    DIMSnowHorn1State* inner = obj->extra;
    f32 k = 0.0f;
    s16 timer;

    state->baddie.animSpeedC = k;
    state->baddie.animSpeedB = k;
    state->baddie.animSpeedA = k;
    obj->anim.velocityX = k;
    obj->anim.velocityY = k;
    obj->anim.velocityZ = k;
    state->baddie.flags0 |= 0x200000;
    state->baddie.moveSpeed = 0.005f;

    if (obj->anim.currentMove != gDIMSnowHorn1LocomotionMoveIds[0]) {
        ObjAnim_SetCurrentMove(obj, gDIMSnowHorn1LocomotionMoveIds[0], k, 0);
    }

    inner->countdownTimer = randomGetRange(0x4b0, 0x960);
    timer = inner->countdownTimer - (int)fv;
    inner->countdownTimer = timer;
    if (timer <= 0) {
        return -4;
    }
    if (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
        (*gObjectTriggerInterface)->runSequence(randomGetRange(0, 2) + 6, (void*)obj, -1);
        buttonDisable(0, PAD_BUTTON_A);
    }
    return 0;
}

int DIMSnowHorn1_stateHandler01(GameObject* obj, DIMSnowHorn1State* state, f32 fv) {
    DIMSnowHorn1State* inner = obj->extra;
    f32 k = 0.0f;
    s16 timer;

    state->baddie.animSpeedC = k;
    state->baddie.animSpeedB = k;
    state->baddie.animSpeedA = k;
    obj->anim.velocityX = k;
    obj->anim.velocityY = k;
    obj->anim.velocityZ = k;
    state->baddie.flags0 |= 0x200000;

    if (state->baddie.moveJustStartedA != 0) {
        state->baddie.moveSpeed = 0.005f;
        if (obj->anim.currentMove != gDIMSnowHorn1LocomotionMoveIds[0]) {
            ObjAnim_SetCurrentMove(obj, gDIMSnowHorn1LocomotionMoveIds[0], k, 0);
        }
        inner->countdownTimer = randomGetRange(0x4b0, 0x960);
    }

    timer = inner->countdownTimer - (int)fv;
    inner->countdownTimer = timer;
    if (timer <= 0) {
        return -3;
    }
    if (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
        if (inner->flags & SNOWHORN1_FLAG_SEQ_TRIGGERED) {
            (*gObjectTriggerInterface)->runSequence(randomGetRange(0, 2) + 6, (void*)obj, -1);
        } else {
            (*gObjectTriggerInterface)->runSequence(5, (void*)obj, -1);
        }
        buttonDisable(0, PAD_BUTTON_A);
    }
    return 0;
}

int DIMSnowHorn1_stateHandler00(GameObject* obj) {
    DIMSnowHorn1State* inner = obj->extra;

    switch (inner->mode) {
    case 0:
        if (mainGetBit(0xf3)) {
            inner->flags |= SNOWHORN1_FLAG_SEQ_TRIGGERED;
        }
        return 2;
    case 5:
        return 3;
    case 4:
        if (mainGetBit(0x1db)) {
            return 8;
        }
        return 6;
    case 1:
        if (mainGetBit(GAMEBIT_ITEM_DIMAlpineRoot_16F)) {
            return 8;
        }
        if (mainGetBit(GAMEBIT_ITEM_AlpineRoot_028)) {
            return 7;
        }
        if (mainGetBit(GAMEBIT_DIM_FoundInjuredSnowHorn)) {
            return 7;
        }
        return 6;
    case 3:
        return 8;
    default:
        return 8;
    }
}

int DIMSnowHorn1_animEventCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    DIMSnowHorn1State* state;
    int animState;
    int i;
    f32 fz;

    (void)unused;
    state = obj->extra;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;

    switch (state->mode) {
    case 0:
        animUpdate->movementState = 0;
        if (obj->seqIndex == -1) {
            for (i = 0; i < (int)(u32)animUpdate->eventCount; i++) {
                mainSetBits(GAMEBIT_ITEM_DIMCog1_Got, 1);
                state->flags |= SNOWHORN1_FLAG_SEQ_TRIGGERED;
            }
        }
        (*gPlayerInterface)->setState((void*)obj, state, 1);
        break;
    case 5:
        animUpdate->movementState = 0;
        (*gPlayerInterface)->setState((void*)obj, state, 2);
        break;
    case 4:
        animUpdate->movementState = 0;
        (*gPlayerInterface)->setState((void*)obj, state, 7);
        break;
    case 1:
        animUpdate->movementState = 0;
        if (obj->seqIndex != -1) {
            switch (state->triggerMode) {
            case 0:
            case 1:
            case 2:
            case 3:
                animState = 6;
                break;
            case 4:
            default:
                animState = 7;
                break;
            }
        } else {
            animState = 7;
        }
        (*gPlayerInterface)->setState((void*)obj, state, animState);
        break;
    case 3:
        animUpdate->movementState = 0;
        state->baddie.moveJustStartedA = 1;
        (*gPlayerInterface)->setState((void*)obj, state, 7);
        break;
    default:
        break;
    }

    (*gPathControlInterface)->attachObject((void*)obj, (u8*)&state->baddie + 4);
    fz = 0.0f;
    state->baddie.animSpeedC = fz;
    state->baddie.animSpeedB = fz;
    state->baddie.animSpeedA = fz;
    obj->anim.velocityX = fz;
    obj->anim.velocityY = fz;
    obj->anim.velocityZ = fz;
    return (u32)(-(s8)animUpdate->movementState | (s8)animUpdate->movementState) >> 0x1f;
}

void DIMSnowHorn1_handleRiderScale(GameObject* obj, f32 scale) {
    void* pathMtx;
    MatrixTransform transform;
    f32 x;
    f32 y;
    f32 z;

    pathMtx = (void*)ObjPath_GetPointModelMtx(obj, 1);
    ObjPath_GetPointLocalPosition(obj, 1, &x, &y, &z);
    transform.x = x;
    transform.y = y;
    transform.z = z;
    transform.rotX = 0;
    transform.rotY = 0;
    transform.rotZ = 0;
    transform.scale = scale / obj->anim.modelInstance->rootMotionScaleBase;
    setMatrixFromObjectPos((f32*)gDIMSnowHorn1ModelMtx, &transform);
    mtx44_mult(gDIMSnowHorn1ModelMtx, (f32*)pathMtx, gDIMSnowHorn1ModelMtx);
    objSetModelMatrixOverride(gDIMSnowHorn1ModelMtx);
}

void DIMSnowHorn1_func21(void) {
}

int DIMSnowHorn1_getRacePosition(void) {
    return 0;
}

f32 DIMSnowHorn1_func19(GameObject* obj, f32* out) {
    DIMSnowHorn1State* state = obj->extra;
    if (state->baddie.controlMode == 0xa) {
        *out = -state->baddie.moveSpeed;
    } else {
        *out = 0.005f;
    }
    return 0.0f;
}

void DIMSnowHorn1_getPlayerAnim(void* unused, f32* out_f, int* out_i) {
    (void)unused;
    *out_f = 0.0f;
    *out_i = 0;
}

void DIMSnowHorn1_setMountState(GameObject* obj, int value) {
    u8 mode = (u8)value;
    ((DIMSnowHorn1State*)obj->extra)->mountMode = mode;
}

int DIMSnowHorn1_getMountState(void) {
    return 0;
}

void DIMSnowHorn1_getCameraPosition(GameObject* obj, f32* outX, f32* outY, f32* outZ) {
    MatrixTransform transform;
    f32 matrix[16];

    transform.x = obj->anim.localPosX;
    transform.y = obj->anim.localPosY;
    transform.z = obj->anim.localPosZ;
    transform.rotX = obj->anim.rotX;
    transform.rotY = obj->anim.rotY;
    transform.rotZ = obj->anim.rotZ;
    transform.scale = 1.0f;
    setMatrixFromObjectPos(matrix, &transform);
    Matrix_TransformPoint(matrix, 0.0f, 80.0f, -25.0f, outX, outY, outZ);
}

int DIMSnowHorn1_getDismountSide(GameObject* obj) {
    if (((DIMSnowHorn1State*)obj->extra)->dismountSide != 0) {
        return 2;
    }
    return 1;
}

int DIMSnowHorn1_canDismount(GameObject* obj) {
    DIMSnowHorn1State* state = obj->extra;
    if ((state->flags & SNOWHORN1_FLAG_RIDING) != 0) {
        mainSetBits(GAMEBIT_NW_SnowHorn03E3, 0);
        state->flags = (u8)(state->flags & ~SNOWHORN1_FLAG_RIDING);
        return 1;
    }
    return 0;
}

void DIMSnowHorn1_getRiderPosition(GameObject* obj, f32* out_x, f32* out_y, f32* out_z) {
    DIMSnowHorn1State* state = obj->extra;
    *out_x = state->pathPosX;
    *out_y = state->pathPosY;
    *out_z = state->pathPosZ;
}

int DIMSnowHorn1_getMountSide(GameObject* obj) {
    if (((DIMSnowHorn1State*)obj->extra)->mountSide != 0) {
        return 1;
    }
    return 2;
}

int DIMSnowHorn1_canMount(GameObject* obj) {
    DIMSnowHorn1State* state;
    f32 range;
    GameObject* nearest;

    state = obj->extra;
    range = 300.0f;

    switch (state->mode) {
    case 0:
    case 5:
        return 0;
    }
    if (state->baddie.controlMode != 7) {
        return 0;
    }
    if (obj->pendingParentObj != NULL) {
        return 0;
    }

    nearest = objGetNearestTypeTo(DIM_DISMOUNT_POINT_OBJECT_GROUP, obj, &range);
    if ((nearest != NULL) && ((nearest->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)) {
        buttonDisable(0, PAD_BUTTON_A);
        return 1;
    }
    return 0;
}

void DIMSnowHorn1_spawnFootstepEffects(void* obj, DIMSnowHorn1State* pointState, DIMSnowHorn1State* inputState) {
    u8 flags;
    u8 pointIndex;
    u8 count;
    s32 inputFlags;
    struct {
        u32 unk0;
        u32 unk4;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } args;

    flags = 0;
    inputFlags = inputState->baddie.eventFlags;
    if ((inputFlags & 2) != 0) {
        flags |= 1;
    }
    if ((inputFlags & 4) != 0) {
        flags |= 2;
    }

    pointIndex = 0;
    while (flags != 0) {
        if ((flags & 1) != 0) {
            args.x = pointState->pathPointArray[pointIndex * 3];
            args.y = pointState->pathPointArray[pointIndex * 3 + 1];
            args.z = pointState->pathPointArray[pointIndex * 3 + 2];
            args.scale = 0.004f;

            count = (u8)randomGetRange(2, 6);
            while (count != 0) {
                ((EffectInterface*)*gPartfxInterface)
                    ->spawnObject(obj, randomGetRange(0, 1) + 0x1f9, &args, 0x10001, -1, NULL);
                count--;
            }

            Sfx_PlayFromObject(obj, surfaceSfxSelectTrigger((u8)(s8) * (s8*)&inputState->baddie.paletteSlot, 9));
            doRumble(3.0f);
        }
        flags >>= 1;
        pointIndex++;
    }
}

int DIMSnowHorn1_getExtraSize(void) {
    return sizeof(DIMSnowHorn1State);
}

int DIMSnowHorn1_getObjectTypeId(void) {
    return 0x43;
}

void DIMSnowHorn1_free(GameObject* obj) {
    objFreeObjectType(obj, VEHICLE_OBJECT_GROUP);
}

void DIMSnowHorn1_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) {
    DIMSnowHorn1State* state = obj->extra;

    if (visible == -1) {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        ObjPath_GetPointWorldPosition(obj, 1, &state->pathPosX, &state->pathPosY, &state->pathPosZ, 0);
        ObjPath_GetPointWorldPositionArray(obj, 2, 4, state->pathPointArray);
    }

    if ((state->mountMode != 2) && (visible != 0)) {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        ObjPath_GetPointWorldPosition(obj, 1, &state->pathPosX, &state->pathPosY, &state->pathPosZ, 0);
        ObjPath_GetPointWorldPositionArray(obj, 2, 4, state->pathPointArray);
    }
}

void DIMSnowHorn1_hitDetect(void) {
}

void DIMSnowHorn1_ridingUpdate(GameObject* obj, int frameStep, int slot) {
    DIMSnowHorn1State* state;
    Camera* viewSlot;
    int matchFrame;

    if (slot != -1) {
        matchFrame = ((framesThisStep - 1 - slot) == 0);
    } else {
        matchFrame = 1;
    }
    viewSlot = Camera_GetCurrent();
    state = obj->extra;

    state->baddie.hitPoints = 0;
    state->baddie.flags0 &= ~0x8000;

    if (state->mountMode == 2) {
        if (mainGetBit(GAMEBIT_DIM_TriggerLostInBlizzard) != 0) {
            state->airMeterValue -= 1;
        } else {
            state->airMeterValue = 0x3e8;
        }
        (*gGameUIInterface)->runAirMeter(state->airMeterValue);
        if (mainGetBit(GAMEBIT_ITEM_NWFood_Got) != 0) {
            mainSetBits(GAMEBIT_ITEM_NWFood_Got, 0);
            state->airMeterValue = 0x3e8;
        }
        if (state->airMeterValue < 0) {
            state->airMeterValue = 0;
            (*gMapEventInterface)->gotoRestartPoint();
        }
        state->baddie.moveInputX = (f32)(s8)padGetStickX(0);
        state->baddie.moveInputZ = (f32)(s8)padGetStickY(0);
        state->baddie.pressedButtons = getButtonsJustPressed(0);
        state->baddie.heldButtons = getButtonsHeld(0);
        state->baddie.cameraYaw = viewSlot->yaw;
    } else {
        f32 zero = 0.0f;
        state->baddie.moveInputX = zero;
        state->baddie.moveInputZ = zero;
        state->baddie.pressedButtons = 0;
        state->baddie.heldButtons = 0;
        state->baddie.cameraYaw = 0;
    }

    state->baddie.flags0 |= 0x00400000;
    if (matchFrame != 0) {
        state->baddie.flags0 &= ~0x00400000;
    }

    if (state->baddie.physicsActive != 0) {
        obj->anim.velocityY = obj->anim.velocityY - 0.14f * (f32)frameStep;
    }

    {
        f32 cur = obj->anim.velocityY;
        obj->anim.velocityY = (cur < -4.0f) ? -4.0f : ((cur > 0.0f) ? 0.0f : cur);
    }

    (*gPlayerInterface)
        ->update(obj, (void*)state, timeDelta, timeDelta, gDIMSnowHorn1StateHandlers,
                 &gDIMSnowHorn1DefaultStateHandler);
    DIMSnowHorn1_spawnFootstepEffects(obj, state, state);
}

static inline s16 DIMSnowHorn1_angleTo(GameObject* obj, GameObject* found) {
    s16 angleDelta = obj->anim.rotX - (u16)(found)->anim.rotX;
    if (angleDelta > 0x8000) {
        angleDelta = angleDelta - 0xffff;
    }
    if (angleDelta < -0x8000) {
        angleDelta += 0xffff;
    }
    return angleDelta;
}

const f32 gDIMSnowHorn1OverrideOffsetY[] = {-30.0f};
const f32 gDIMSnowHorn1OverrideOffsetZ[] = {-20.0f};

void DIMSnowHorn1_update(GameObject* obj) {
    f32 nearDist;
    u8* base = (u8*)gDIMSnowHorn1ConfigTable;
    GameObject* player = Obj_GetPlayerObject();
    DIMSnowHorn1State* data;
    s8 modeIndex = -1;
    s16 angleDelta;
    GameObject* found;
    DIMSnowHorn1State* statePtr;
    GameObject* playerObj;
    u32 flip;
    int flags;

    data = obj->extra;
    data->advanceCountThreshold = 5;
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->trackContactMask = 9;
    {
        u8* fp = base + 0x94;
        flags = fp[data->baddie.controlMode];
    }
    if (!(flags & 8)) {
        ObjHitReactEntry* arm;
        if (flags & 2) {
            arm = (ObjHitReactEntry*)(base + 0x80);
        } else {
            arm = (ObjHitReactEntry*)(base + 0x6c);
        }
        data->hitReactState = ObjHitReact_Update(obj, arm, 1, data->hitReactState, &data->hitReactStepScale);
        if (data->hitReactState != 0) {
            characterHeadLookRelax(obj, &data->eyeAnimState);
            characterDoEyeAnims(obj, &data->eyeAnimState);
            return;
        }
    }
    if (data->mountMode == 2) {
        data->baddie.physicsActive = 1;
        DIMSnowHorn1_ridingUpdate(obj, framesThisStep, -1);
    } else {
        f32 fz;
        data->baddie.physicsActive = 0;
        fz = 0.0f;
        data->baddie.animSpeedC = fz;
        data->baddie.animSpeedB = fz;
        data->baddie.animSpeedA = fz;
        obj->anim.velocityX = fz;
        obj->anim.velocityY = fz;
        obj->anim.velocityZ = fz;
        (*gPathControlInterface)->attachObject((void*)obj, (u8*)&data->baddie + 4);
        DIMSnowHorn1_ridingUpdate(obj, framesThisStep, -1);
    }
    if (data->mountMode == 0) {
        (*gNewCloudsInterface)->func0ANop(0);
    } else {
        (*gNewCloudsInterface)->func0ANop(1);
    }
    switch (data->mode) {
    case 0:
    case 5:
        statePtr = obj->extra;
        playerObj = Obj_GetPlayerObject();
        if (playerObj != NULL && Vec_distance(&playerObj->anim.worldPosX, &obj->anim.worldPosX) < 300.0f &&
            statePtr->mountMode == 0) {
            statePtr->eyeAnimState.lookAtActive = 1;
            statePtr->eyeAnimState.lookAtPosX = playerObj->anim.localPosX;
            statePtr->eyeAnimState.lookAtPosY = playerObj->anim.localPosY;
            statePtr->eyeAnimState.lookAtPosZ = playerObj->anim.localPosZ;
        } else {
            statePtr->eyeAnimState.lookAtActive = 0;
        }
        characterHeadLookCalm(obj, (s16*)&data->eyeAnimState, 0.0f);
        break;
    }
    switch (data->mode) {
    case 1:
    case 3:
    case 4:
        nearDist = 300.0f;
        found = objGetNearestTypeTo(DIM_DISMOUNT_POINT_OBJECT_GROUP, obj, &nearDist);
        if (data->mountMode == 0 && data->baddie.controlMode == 7 &&
            getXZDistanceSquared(&player->anim.worldPosX, &obj->anim.worldPosX) < 10000.0f) {
            if (found != NULL && ((found)->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE)) {
                setAButtonIcon(0x14);
                if ((found)->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
                    int layer = getCurMapLayer();
                    (*gMapEventInterface)->restartPoint(&player->anim.localPosX, 0x584, layer, 0);
                    buttonDisable(0, PAD_BUTTON_A);
                    mainSetBits(GAMEBIT_NW_SnowHorn03E3, 1);
                    angleDelta = DIMSnowHorn1_angleTo(obj, found);
                    if (angleDelta > 0x4000 || angleDelta < -0x4000) {
                        mainSetBits(GAMEBIT_NW_ClimbOnSnowHorn, 1);
                    } else {
                        mainSetBits(GAMEBIT_NW_SnowHown05BA, 1);
                    }
                    if (data->mode == 3) {
                        data->airMeterValue = 1000;
                        (*gGameUIInterface)->initAirMeter(1000, DIMSNOWHORN1_AIRMETER_BGTEXTURE);
                    }
                }
            }
        } else if (data->mountMode == 2) {
            if (found != NULL && ((found)->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE)) {
                setAButtonIcon(0x15);
                if ((found)->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
                    buttonDisable(0, PAD_BUTTON_A);
                    mainSetBits(GAMEBIT_NW_SnowHorn03E3, 0);
                    switch (data->mode) {
                    case 1:
                        modeIndex = 0;
                        break;
                    case 3:
                        modeIndex = 1;
                        break;
                    case 4:
                        modeIndex = 2;
                        break;
                    }
                    angleDelta = DIMSnowHorn1_angleTo(obj, found);
                    if (modeIndex >= 0) {
                        SnowHornEntry* tbl = (SnowHornEntry*)base;
                        int bit2;
                        int cc;
                        mainSetBits(tbl[modeIndex].altPoseGameBit, (found)->anim.placementData[0xd]);
                        bit2 = tbl[modeIndex].flipRotGameBit;
                        cc = modeIndex;
                        flip = 0;
                        if (angleDelta > 0x4000 || angleDelta < -0x4000) {
                            flip = 1;
                        }
                        mainSetBits(bit2, cc ^ flip);
                    }
                    if (angleDelta > 0x4000 || angleDelta < -0x4000) {
                        mainSetBits(GAMEBIT_NW_ClimbOffSnowHorn, 1);
                    } else {
                        mainSetBits(GAMEBIT_NW_SnowHown05BB, 1);
                    }
                    data->baddie.pressedButtons = 0;
                    (*gGameUIInterface)->airMeterShutdown();
                    (*gMapEventInterface)->clearRestartPoint();
                }
            } else {
                setAButtonIcon(0x13);
            }
        }
        break;
    }
    characterDoEyeAnims(obj, &data->eyeAnimState);
    {
        MatrixTransform v;
        f32 matrix[16];

        v.x = obj->anim.localPosX;
        v.y = obj->anim.localPosY;
        v.z = obj->anim.localPosZ;
        v.rotX = obj->anim.rotX;
        v.rotY = obj->anim.rotY;
        v.rotZ = obj->anim.rotZ;
        v.scale = 1.0f;
        setMatrixFromObjectPos(matrix, &v);
        Matrix_TransformPoint(matrix, 0.0f, gDIMSnowHorn1OverrideOffsetY[0], gDIMSnowHorn1OverrideOffsetZ[0],
                              &obj->anim.modelState->overrideWorldPosX, &obj->anim.modelState->overrideWorldPosY,
                              &obj->anim.modelState->overrideWorldPosZ);
    }
}

void DIMSnowHorn1_init(GameObject* obj, DIMSnowHorn1Placement* def, int spawnFlag) {
    u8* base = gDIMSnowHorn1ConfigTable;
    DIMSnowHorn1PieceCounts stk = sDIMSnowHorn1DefaultPieceCounts;
    DIMSnowHorn1State* inner;
    u8* pathState;
    s8 idx;
    obj->anim.rotX = (s16)(def->spawnRot << 8);
    obj->animEventCallback = (void*)DIMSnowHorn1_animEventCallback;
    objAddObjectType(obj, VEHICLE_OBJECT_GROUP);
    inner = obj->extra;
    inner->mode = def->spawnVariant;
    inner->advanceCountThreshold = 5;
    inner->airMeterValue = 0x3e8;
    if (obj->anim.modelState != NULL) {
        obj->anim.modelState->flags |= 0xa10;
    }
    if (obj->anim.hitReactState != NULL) {
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->trackContactMask = 9;
    }
    (*gPlayerInterface)->init(obj, inner, 0xc, 1);
    inner->baddie.gravity = 0.17f;
    pathState = (u8*)&inner->baddie + 4;
    pathState[0x25b] = 0;
    switch (inner->mode) {
    case 1:
    case 3:
    case 4:
        (*gPathControlInterface)->init(pathState, 3, 0x200020, 1);
        (*gPathControlInterface)->setLocalPointCollision(pathState, 2, base + 0xe0, &gDIMSnowHorn1PathCollisionData, 8);
        (*gPathControlInterface)->setup(pathState, 4, base + 0xa0, base + 0xd0, stk.counts);
        (*gPathControlInterface)->attachObject((void*)obj, pathState);
        break;
    case 2:
        break;
    }
    dll_2E_initState(obj, &inner->lookController, -0x2000, 0x2aaa, 3);
    inner->lookController.modeBits |= 8;
    if (spawnFlag == 0) {
        idx = -1;
        switch (inner->mode) {
        case 1:
            if (mainGetBit(GAMEBIT_ITEM_DIMAlpineRoot_16F)) {
                idx = 0;
            }
            break;
        case 3:
            idx = 1;
            break;
        case 4:
            if (mainGetBit(0x1db)) {
                idx = 2;
            }
            break;
        }
        if (idx >= 0) {
            SnowHornEntry* tbl = (SnowHornEntry*)base;
            if (mainGetBit(tbl[idx].altPoseGameBit)) {
                obj->anim.localPosX = tbl[idx].altPosX;
                obj->anim.localPosY = tbl[idx].altPosY;
                obj->anim.localPosZ = tbl[idx].altPosZ;
                obj->anim.rotX = tbl[idx].altRotX;
            } else {
                SnowHornEntry* e = &tbl[idx];
                obj->anim.localPosX = e->posX;
                obj->anim.localPosY = e->posY;
                obj->anim.localPosZ = e->posZ;
                obj->anim.rotX = e->rotX;
            }
            if (mainGetBit(tbl[idx].flipRotGameBit)) {
                obj->anim.rotX += 0x8000;
            }
        }
    }
}

void DIMSnowHorn1_release(void) {
    void** p;
    int i;
    p = &gDIMSnowHorn1Texture;
    for (i = 0; i < 1; i++) {
        if (p[i] != NULL) {
            textureFree((Texture*)p[i]);
        }
        p[i] = NULL;
    }
}

void DIMSnowHorn1_initialise(void) {
    s16* src;
    void** dst;
    int i;
    gDIMSnowHorn1StateHandlers[0] = DIMSnowHorn1_stateHandler00;
    gDIMSnowHorn1StateHandlers[1] = DIMSnowHorn1_stateHandler01;
    gDIMSnowHorn1StateHandlers[2] = DIMSnowHorn1_stateHandler02;
    gDIMSnowHorn1StateHandlers[3] = DIMSnowHorn1_stateHandler03;
    gDIMSnowHorn1StateHandlers[4] = DIMSnowHorn1_stateHandler04;
    gDIMSnowHorn1StateHandlers[5] = DIMSnowHorn1_stateHandler05;
    gDIMSnowHorn1StateHandlers[6] = DIMSnowHorn1_stateHandler06;
    gDIMSnowHorn1StateHandlers[7] = DIMSnowHorn1_stateHandler07;
    gDIMSnowHorn1StateHandlers[8] = DIMSnowHorn1_stateHandler08;
    gDIMSnowHorn1StateHandlers[9] = DIMSnowHorn1_stateHandler09;
    gDIMSnowHorn1StateHandlers[10] = DIMSnowHorn1_stateHandler0A;
    gDIMSnowHorn1StateHandlers[11] = DIMSnowHorn1_stateHandler0B;
    gDIMSnowHorn1DefaultStateHandler = (void*)DIMSnowHorn1_defaultStateHandler;
    src = &gDIMSnowHorn1TextureId;
    dst = &gDIMSnowHorn1Texture;
    for (i = 0; i < 1; i++) {
        dst[i] = (void*)textureLoad(src[i], 0);
    }
}

u8 gDIMSnowHorn1ConfigTable[] = {
    0xC5, 0xE0, 0xD0, 0x00, 0xC4, 0x9E, 0xA0, 0x00, 0x46, 0x49, 0xC4, 0x00, 0x81, 0x10, 0x00, 0x00, 0xC5, 0xFD,
    0xB8, 0x00, 0xC4, 0x97, 0x00, 0x00, 0x46, 0x54, 0x7C, 0x00, 0xBD, 0x00, 0x01, 0x00, 0x01, 0x05, 0x00, 0x00,
    0xC5, 0xFA, 0x50, 0x00, 0xC4, 0x8F, 0xE0, 0x00, 0x46, 0x68, 0x88, 0x00, 0x85, 0xAC, 0x00, 0x00, 0xC6, 0x1E,
    0x14, 0x00, 0xC4, 0x40, 0xC0, 0x00, 0x46, 0x6A, 0xBC, 0x00, 0x80, 0x9D, 0x01, 0x01, 0x01, 0x06, 0x00, 0x00,
    0xC6, 0x13, 0xB0, 0x00, 0xC5, 0x24, 0x30, 0x00, 0x46, 0x7E, 0x50, 0x00, 0xBD, 0x36, 0x00, 0x00, 0xC6, 0x13,
    0xB0, 0x00, 0xC5, 0x24, 0x30, 0x00, 0x46, 0x7E, 0x50, 0x00, 0xBD, 0x36, 0x01, 0x01, 0x06, 0x43, 0x00, 0x00,
    0x02, 0xDA, 0x03, 0x75, 0x00, 0x30, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x44, 0x9B, 0xA6, 0x00, 0x00,
    0x00, 0x00, 0x02, 0xDA, 0x03, 0x75, 0x00, 0x2F, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x44, 0x9B, 0xA6,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x08, 0x08, 0x08, 0x08, 0xC1, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC1, 0xA0, 0x00, 0x00, 0x41, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC1, 0xA0, 0x00, 0x00, 0x41, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xA0, 0x00, 0x00, 0xC1, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x0C,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x0C, 0x00, 0x00,
};

f32 gDIMSnowHorn1LocomotionSpeedRanges[] = {0.0f, 0.05f, 0.03f, 0.85f};

ObjectDescriptor24 gDIMSnowHorn1ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_24_SLOTS,
    (ObjectDescriptorCallback)DIMSnowHorn1_initialise,
    (ObjectDescriptorCallback)DIMSnowHorn1_release,
    0,
    (ObjectDescriptorCallback)DIMSnowHorn1_init,
    (ObjectDescriptorCallback)DIMSnowHorn1_update,
    (ObjectDescriptorCallback)DIMSnowHorn1_hitDetect,
    (ObjectDescriptorCallback)DIMSnowHorn1_render,
    (ObjectDescriptorCallback)DIMSnowHorn1_free,
    (ObjectDescriptorCallback)DIMSnowHorn1_getObjectTypeId,
    DIMSnowHorn1_getExtraSize,
    (ObjectDescriptorCallback)DIMSnowHorn1_canMount,
    (ObjectDescriptorCallback)DIMSnowHorn1_getMountSide,
    (ObjectDescriptorCallback)DIMSnowHorn1_getRiderPosition,
    (ObjectDescriptorCallback)DIMSnowHorn1_canDismount,
    (ObjectDescriptorCallback)DIMSnowHorn1_getDismountSide,
    (ObjectDescriptorCallback)DIMSnowHorn1_getCameraPosition,
    (ObjectDescriptorCallback)DIMSnowHorn1_getMountState,
    (ObjectDescriptorCallback)DIMSnowHorn1_setMountState,
    (ObjectDescriptorCallback)DIMSnowHorn1_getPlayerAnim,
    (ObjectDescriptorCallback)DIMSnowHorn1_func19,
    (ObjectDescriptorCallback)DIMSnowHorn1_getRacePosition,
    (ObjectDescriptorCallback)DIMSnowHorn1_func21,
    (ObjectDescriptorCallback)DIMSnowHorn1_handleRiderScale,
    (ObjectDescriptorCallback)DIMSnowHorn1_func23,
};

const f32 gDIMSnowHorn1ZeroOffset = 0.0f;
