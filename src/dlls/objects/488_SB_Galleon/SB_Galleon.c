/*
 * SB_Galleon (DLL 0x1E8) - General Scales' galleon in the ShipBattle
 * prologue.
 */
#include "dlls/objects/488_SB_Galleon.h"

#include "main/render_envfx_api.h"
#include "main/camera_interface.h"
#include "main/dll/cloudaction_interface.h"
#include "game/objects/object_setup.h"
#include "sys/objects.h"
#include "main/obj_list.h"

#include "main/frame_timing.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/screen_transition.h"
#include "main/gamebits.h"
#include "main/gamebit_ids.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/ship_battle_api.h"
#include "main/dll/partfx_interface.h"
#include "main/gametext_show_api.h"
#include "main/textrender_api.h"
#include "main/lightmap_render_control_api.h"
#include "main/audio/music_api.h"
#include "main/object_render.h"
#include "main/pi_dolphin_api.h"
#include "main/map_load.h"
#include "main/sky.h"
#include "main/model.h"
#include "main/render_lactions_api.h"
#include "main/objtype.h"
#include "dlls/objects/430_SH_LevelCon.h"
#include "main/texture.h"
#include "main/gametext_color_api.h"
#include "dlls/objects/489_SB_Propelle.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/sky_api.h"

#define DBPROTECTION_GAMEBIT_CYCLE_A_PENDING  0xa3c
#define DBPROTECTION_GAMEBIT_CYCLE_B_PENDING  0xa3d
#define DBPROTECTION_GAMEBIT_CYCLE_A_DONE     0xa3e
#define DBPROTECTION_GAMEBIT_CYCLE_B_DONE     0xa3f
#define DBPROTECTION_GAMEBIT_TRANSITION_ARMED 0x9f
#define DBPROTECTION_GAMEBIT_TRANSITION_USED  0xa0
#define DBPROTECTION_GAMEBIT_MUTE_SFX         0xa71
#define DBPROTECTION_ENVFX_A                  0x467e7
#define DBPROTECTION_ENVFX_B                  0x467e8
#define DBPROTECTION_PLAYER_ENVFX_FLASH       0x96
#define DBPROTECTION_PLAYER_ENVFX_SWAP        0x8a
/* Tricky's sequence ID. */
#define DBPROTECTION_TRICKY_TARGET_SEQID 0x8c
#define DBPROTECTION_GAMEBIT_DIVE_ACTIVE 0xf1e

extern s8 gSB_GalleonTransitionPending;

ObjectDescriptor15 gSB_GalleonObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_15_SLOTS,
    (ObjectDescriptorCallback)SB_Galleon_initialise,
    (ObjectDescriptorCallback)SB_Galleon_release,
    0,
    (ObjectDescriptorCallback)SB_Galleon_init,
    (ObjectDescriptorCallback)SB_Galleon_update,
    (ObjectDescriptorCallback)SB_Galleon_hitDetect,
    (ObjectDescriptorCallback)SB_Galleon_render,
    (ObjectDescriptorCallback)SB_Galleon_free,
    (ObjectDescriptorCallback)SB_Galleon_getObjectTypeId,
    SB_Galleon_getExtraSize,
    (ObjectDescriptorCallback)SB_Galleon_onPartDestroyed,
    (ObjectDescriptorCallback)SB_Galleon_getStage,
    (ObjectDescriptorCallback)SB_Galleon_getPhase,
    (ObjectDescriptorCallback)SB_Galleon_getDamagePhase,
    (ObjectDescriptorCallback)SB_Galleon_func0E,
};

void SB_Galleon_updateFlight(GameObject* obj) {
    ObjPlacement* spawnData;
    SBGalleonState* state;
    f32 tx;
    GameObject** objects;
    GameObject* otherObj;
    s8 c;
    int t;
    int wrap;
    int diff;
    u32 angY;
    int iv;
    int dv;
    f32 amp;
    f32 limit;
    f32 negLimit;
    f32 blendK;
    f32 lerpD;
    f32 zRatio;
    f32 ty;
    GameObject* tricky;
    f32 tz;
    f32 ambA;
    f32 dy;
    f32 dz;
    f32 dist;
    f32 ambC;
    f32 ambB;
    f32 threshold;
    f32 dx;
    f32 wander;
    f32 speedTarget;
    f32 zero;
    f32 mtx[17];
    MatrixTransform objPos;
    int objIndex;
    int objCount;
    f32 camShake;

    spawnData = obj->anim.placement;
    state = obj->extra;
    camShake = 120.0f;
    obj->anim.mapEventSlot = -1;
    if ((state->targetObj != NULL) && ((state->targetObj->anim.flags & 0x40) != 0)) {
        state->targetObj = NULL;
    }
    if (state->targetObj == NULL) {
        objects = ObjList_GetObjects(&objIndex, &objCount);
        for (t = objIndex; t < objCount; t++) {
            otherObj = objects[t];
            if (otherObj->anim.romDefNo == DBPROTECTION_TRICKY_TARGET_SEQID) {
                state->targetObj = otherObj;
                t = objCount;
            }
        }
    }
    if (state->phase >= 2) {
        Sfx_PlayFromObject(obj, SFXTRIG_tr_gal_lightning);
    } else {
        Sfx_StopFromObject(obj, SFXTRIG_tr_gal_lightning);
    }
    tricky = state->targetObj;
    if (tricky == NULL) {
        return;
    }
    if ((tricky != NULL) && (tricky->userData1 == 0)) {
        SB_CloudRunner_getSpawnPos(tricky, &state->homeX, &state->homeY, &state->homeZ);
    }
    state->timer26 -= framesThisStep;
    if (state->timer26 < 0) {
        state->timer26 = 0;
    }
    c = state->stage;
    if (c == 7) {
        state->damagePhase = 3;
    } else if (c == 8) {
        state->damagePhase = 4;
    } else if (c == 9) {
        state->damagePhase = 5;
    }
    if (state->phase < 2) {
        state->wanderTimerA -= timeDelta;
        if (state->wanderTimerA <= 0.0f) {
            state->wanderFlagA ^= 1;
            state->wanderTimerA = (f32)randomGetRange(0xB4, 300);
        }
        if (state->wanderFlagA != 0) {
            state->wanderA = 4.0f * timeDelta + state->wanderA;
        } else {
            state->wanderA -= timeDelta;
        }
        state->wanderTimerB -= timeDelta;
        if (state->wanderTimerB <= 0.0f) {
            state->wanderFlagB ^= 1;
            state->wanderTimerB = (f32)randomGetRange(0xB4, 300);
        }
        if (state->wanderFlagB != 0) {
            state->wanderB = 4.0f * timeDelta + state->wanderB;
        } else {
            state->wanderB -= timeDelta;
        }
    } else {
        amp = 2.0f;
        state->wanderA = -(amp * timeDelta - state->wanderA);
        state->wanderB = -(amp * timeDelta - state->wanderB);
    }
    wander = state->wanderA;
    state->wanderA = (wander < 0.0f) ? 0.0f : (wander > 35.0f) ? 35.0f : wander;
    wander = state->wanderB;
    state->wanderB = (wander < 0.0f) ? 0.0f : (wander > 35.0f) ? 35.0f : wander;
    switch (state->phase) {
    case 0:
        camShake = 120.0f;
        Sfx_StopObjectChannel(obj, 1);
        (*gCameraInterface)->releaseAction(&camShake, 0);
        obj->userData1 = 1;
        tx = state->homeX - 1600.0f;
        tz = 150.0f * mathCosf((3.14159265f * (f32)state->bobPhase) / 32768.0f) +
             state->homeZ;
        ty = 60.0f * mathSinf((3.14159265f * (f32)state->bobPhase) / 32768.0f) +
             (state->homeY - 300.0f);
        state->bobPhase = state->bobPhase + framesThisStep * 0xB6;
        dx = tx - obj->anim.localPosX;
        dy = ty - obj->anim.localPosY;
        dz = tz - obj->anim.localPosZ;
        state->speed = 3.0f;
        dx *= 0.03125f;
        dy *= 0.03125f;
        dz *= 0.03125f;
        limit = state->speed;
        if (dx > limit) {
            dx = limit;
        }
        negLimit = -limit;
        if (dx < negLimit) {
            dx = negLimit;
        }
        if (dy > limit) {
            dy = limit;
        }
        if (dy < negLimit) {
            dy = negLimit;
        }
        if (dz > limit) {
            dz = limit;
        }
        if (dz < negLimit) {
            dz = negLimit;
        }
        t = state->phaseTimer;
        if (t < 0x78) {
            dy = 0.0f;
        } else if (t < 0xB4) {
            dy = dy * ((f32)(t - 0x78) / 60.0f);
        }
        state->phaseTimer += framesThisStep;
        lerpD = dx - state->driftX;
        state->driftX += lerpD * (blendK = 0.0625f);
        state->driftY += (dy - state->driftY) * (blendK = blendK);
        state->driftZ += (dz - state->driftZ) * (blendK = blendK);
        ambA = 50.0f;
        ambB = 0.001f;
        ambC = 10.0f;
        if (state->cycleKind == 0) {
            switch (state->stage) {
            case 0:
            case 1:
                if (state->headingLatch != 0) {
                    state->headingLatch -= 1;
                    if (state->headingLatch <= 0) {
                        state->headingLatch = 200;
                    }
                }
                break;
            default:
                state->stage = 2;
                state->phaseTimer = 0;
                state->phase = 1;
                state->cycleKind = 1;
                state->phaseCounter = 0;
                state->flightPattern = 0;
                state->headingLatch = 200;
                mainSetBits(DBPROTECTION_GAMEBIT_DIVE_ACTIVE, 1);
                break;
            }
        } else {
            switch (state->stage) {
            case 3:
            case 4:
                if (state->headingLatch != 0) {
                    state->headingLatch -= 1;
                    if (state->headingLatch <= 0) {
                        state->headingLatch = 200;
                    }
                }
                break;
            default:
                state->stage = 5;
                state->phaseTimer = 0;
                state->phase = 1;
                state->cycleKind = 2;
                state->flightPattern = 0;
                state->headingLatch = 200;
                break;
            }
        }
        break;
    case 1:
        obj->userData1 = 2;
        camShake = 120.0f;
        (*gCameraInterface)->releaseAction(&camShake, 0);
        if (state->headingLatch != 0) {
            state->headingLatch -= 1;
        }
        switch (state->flightPattern) {
        case 0:
            tx = state->homeX - 1700.0f;
            tz = state->homeZ;
            ty = 300.0f + tricky->anim.localPosY;
            if ((state->headingLatch <= 0) &&
                ((state->phaseCounter == 0) || (state->phaseCounter == 5))) {
                state->headingLatch = 200;
            }
            Sfx_IsPlayingFromObjectChannel(obj, 2); /* The result is intentionally unused. */
            break;
        case 1:
            tx = state->homeX - 800.0f;
            tz = state->homeZ;
            ty = 300.0f + tricky->anim.localPosY;
            break;
        case 2:
            tx = tricky->anim.localPosX - 500.0f;
            tz = state->homeZ;
            ty = 250.0f + tricky->anim.localPosY;
            break;
        case 3:
            tx = tricky->anim.localPosX - 535.0f;
            tz = 220.0f + state->homeZ;
            ty = 250.0f + tricky->anim.localPosY;
            tz = tz + (tricky->anim.localPosZ - state->posZ);
            state->unk7B = 0;
            break;
        case 4:
            tx = tricky->anim.localPosX - 535.0f;
            tz = 100.0f + state->homeZ;
            ty = 250.0f + tricky->anim.localPosY;
            state->unk7B = 0;
            break;
        case 5:
            tx = tricky->anim.localPosX - 535.0f;
            tz = state->homeZ - 220.0f;
            ty = 250.0f + tricky->anim.localPosY;
            tz = tz + (tricky->anim.localPosZ - state->posZ);
            state->unk7B = 0;
            break;
        default:
            state->unk7B = 0;
            tx = state->homeX - 880.0f;
            tz = state->homeZ;
            ty = 260.0f + tricky->anim.localPosY;
            break;
        }
        tx = tx - obj->anim.localPosX;
        dy = ty - obj->anim.localPosY;
        tz = tz - obj->anim.localPosZ;
        state->speed = 3.0f;
        dist = sqrtf(tz * tz + (tx * tx + dy * dy));
        tx *= 0.0625f;
        dy *= 0.03125f;
        tz *= 0.03125f;
        if (tx > 6.0f) {
            tx = 6.0f;
        }
        if (tx < -6.0f) {
            tx = -6.0f;
        }
        if (dy > 1.5f) {
            dy = 1.5f;
        }
        if (dy < -1.5f) {
            dy = -1.5f;
        }
        if (tz > 3.5f) {
            tz = 3.5f;
        }
        if (tz < -3.5f) {
            tz = -3.5f;
        }
        state->phaseTimer += framesThisStep;
        lerpD = tx - state->driftX;
        blendK = 0.125f;
        state->driftX += lerpD * blendK;
        state->driftY += (dy - state->driftY) / 14.0f;
        state->driftZ += (tz - state->driftZ) / 24.0f;
        ambA = 1911.0f;
        ambB = 0.005f;
        ambC = 0.0f;
        switch (state->flightPattern) {
        case 0:
            if (dist < 15.0f) {
                state->flightPattern = 1;
                state->phaseTimer = 0;
            }
            break;
        case 1:
            if (dist < 10.0f) {
                state->flightPattern = 2;
                state->phaseTimer = 0;
            }
            break;
        case 2:
            if ((state->phaseTimer > 0xF0) || (dist < 10.0f)) {
                state->flightPattern = 0;
                state->phaseTimer = 0;
            }
            break;
        case 3:
            if ((dist < 10.0f) || (state->phaseTimer > 0x78)) {
                state->flightPattern = 0;
                state->phaseTimer = 0;
            }
            break;
        case 4:
            if ((dist < 10.0f) || (state->phaseTimer > 0x78)) {
                state->flightPattern = 5;
                state->phaseTimer = 3;
            }
            break;
        case 5:
            if ((dist < 10.0f) || (state->phaseTimer > 0x78)) {
                state->flightPattern = 0;
                state->phaseTimer = 0;
            }
            break;
        default:
            if (dist < 25.0f) {
                if (state->stage == 2) {
                    state->phaseTimer = 0;
                    state->phase = 0;
                    state->stage = 3;
                } else if (state->stage == 5) {
                    state->phase = 2;
                    state->stage = 6;
                }
            }
            break;
        }
        state->timer26 = 300;
        if ((state->phaseCounter >= 4) && (state->stage < 3)) {
            state->phase = 0;
            state->cycleKind = 1;
            state->stage = 3;
            state->phaseCounter = 5;
            state->headingLatch = 200;
            {
                GameObject* sfxObj = sbGetPropeller();
                Sfx_StopFromObject(sfxObj, SFXTRIG_swtst1_c);
                Sfx_PlayFromObject(sfxObj, SFXTRIG_mv_curtainloop16);
            }
            mainSetBits(DBPROTECTION_GAMEBIT_DIVE_ACTIVE, 0);
        } else if (state->phaseCounter >= 4) {
            state->phase = 2;
            state->cycleKind = 3;
            state->stage = 6;
            state->headingLatch = 200;
            state->refZ = tricky->anim.localPosZ;
        }
        break;
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8: {
        int nextState;
        camShake = 120.0f;
        Sfx_StopObjectChannel((int)obj, 2);
        (*gCameraInterface)->releaseAction(&camShake, 0);
        obj->userData1 = 3;
        if (state->headingLatch != 0) {
            state->headingLatch -= 1;
        }
        switch (state->phase) {
        case 2:
            speedTarget = 20.0f;
            tx = state->homeX - 4700.0f;
            tz = -(1500.0f * (f32)state->sweepDir - state->homeZ);
            ty = state->homeY;
            threshold = 1000.0f;
            nextState = 3;
            break;
        case 3:
            speedTarget = 12.0f;
            tx = state->homeX - 5000.0f;
            tz = -(1000.0f * (f32)state->sweepDir - state->homeZ);
            ty = 100.0f + state->homeY;
            nextState = 4;
            threshold = 700.0f;
            break;
        case 4:
            speedTarget = 12.0f;
            tx = state->homeX - 4700.0f;
            tz = -(10.0f * (f32)state->sweepDir - state->homeZ);
            ty = 100.0f + state->homeY;
            nextState = 5;
            threshold = 700.0f;
            break;
        case 5:
            speedTarget = 10.0f;
            obj->userData1 = 4;
            tx = state->homeX - 1100.0f;
            tz = state->homeZ;
            ty = state->homeY - 100.0f;
            nextState = 6;
            threshold = 700.0f;
            if ((state->headingLatch <= 0) && (state->stage == 6)) {
                state->headingLatch = 200;
            }
            break;
        case 6:
            speedTarget = 4.0f;
            tx = 200.0f + state->homeX;
            tz = -(1500.0f * (f32)state->sweepDir - state->homeZ);
            ty = 250.0f + state->homeY;
            nextState = 7;
            threshold = 100.0f;
            break;
        case 7:
            speedTarget = 4.0f;
            tx = 1400.0f + state->homeX;
            tz = state->homeZ;
            ty = 280.0f + tricky->anim.localPosY;
            nextState = 8;
            threshold = 100.0f;
            break;
        case 8:
            speedTarget = 8.0f;
            tx = state->homeX - 1200.0f;
            tz = state->homeZ;
            ty = 100.0f + tricky->anim.localPosY;
            nextState = 2;
            threshold = 200.0f;
            break;
        }
        dx = tx - state->posX;
        dy = ty - state->posY;
        dz = tz - state->posZ;
        state->speed =
            state->speed + (speedTarget - state->speed) / 30.0f;
        dist = sqrtf(dx * dx + dz * dz);
        if ((state->phase == 5) && (dist < 3000.0f)) {
            obj->userData1 = 5;
        }
        if (dist < threshold) {
            if (state->phase == 5) {
                state->sweepDir = -state->sweepDir;
            }
            state->phase = nextState;
        }
        wrap = (getAngle(dx, dz) & 0xFFFF) + 0x8000;
        angY = getAngle(dy, dist) & 0xFFFF;
        diff = wrap - (obj->anim.rotX & 0xFFFF);
        if (diff > 0x8000) {
            diff = diff - 0xFFFF;
        }
        if (diff < -0x8000) {
            diff = diff + 0xFFFF;
        }
        state->turnRate =
            state->turnRate + ((framesThisStep * (diff - state->turnRate)) >> 4);
        c = state->phase;
        if ((c == 3) || (c == 4)) {
            obj->anim.rotX = obj->anim.rotX + (state->turnRate * framesThisStep) / 0x3C;
        } else if ((c == 6) || (c == 2)) {
            obj->anim.rotX = obj->anim.rotX + (state->turnRate * framesThisStep) / 0x78;
        } else {
            obj->anim.rotX = obj->anim.rotX + (state->turnRate * framesThisStep) / 0x3C;
        }
        wrap = angY - (((GameObject*)obj)->anim.rotY & 0xFFFF);
        if (wrap > 0x8000) {
            wrap = wrap - 0xFFFF;
        }
        if (wrap < -0x8000) {
            wrap = wrap + 0xFFFF;
        }
        obj->anim.rotY = obj->anim.rotY + ((wrap * framesThisStep) >> 6);
        dx = state->homeX - obj->anim.localPosX;
        dz = state->homeZ - obj->anim.localPosZ;
        sqrtf(dx * dx + dz * dz); /* The result is intentionally unused. */
        t = ((GameObject*)obj)->anim.rotZ;
        iv = (int)(0.45f * (f32)state->turnRate);
        dv = (iv - t) >> 3;
        if (dv > 0x3C) {
            dv = 0x3C;
        }
        if (dv < -0x3C) {
            dv = -0x3C;
        }
        obj->anim.rotZ = dv * timeDelta + (f32)obj->anim.rotZ;
        objPos.x = 0.0f;
        objPos.y = 0.0f;
        objPos.z = 0.0f;
        objPos.scale = 1.0f;
        objPos.rotX = obj->anim.rotX;
        objPos.rotY = obj->anim.rotY;
        objPos.rotZ = obj->anim.rotZ;
        setMatrixFromObjectPos(mtx, &objPos);
        Matrix_TransformPoint(mtx, 0.0f, 0.0f, -state->speed * timeDelta,
                              &state->driftX, &state->driftY, &state->driftZ);
        if (state->phase == 7) {
            state->posX = tx;
            state->posY = ty;
            state->posZ = tz;
            zero = 0.0f;
            state->swayX = zero;
            state->swayY = zero;
            state->swayZ = zero;
        } else {
            state->posX = state->posX + state->driftX;
            state->posY = state->posY + state->driftY;
            state->posZ = state->posZ + state->driftZ;
        }
        ambB = 0.17f;
        obj->anim.localPosX = state->posX + state->swayX;
        obj->anim.localPosY = state->posY + state->swayY;
        obj->anim.localPosZ =
            state->posZ + state->swayZ + (tricky->anim.localPosZ - state->refZ);
        if (state->stage >= 7) {
            if (state->fadeTimer == 0) {
                ObjHits_DisableObject(obj);
                (*gScreenTransitionInterface)->start(0x41, SCREEN_TRANSITION_BLACK);
            }
            state->fadeTimer += framesThisStep;
            if (state->fadeTimer > 0x41) {
                obj->anim.rotX = 0;
                state->phase = 6;
                (*gCloudActionInterface)->func10Nop(0);
                (*gCloudActionInterface)->func11Nop(0);
                (*gCloudActionInterface)->func12Nop(0.0f, 25.0f);
                if (state->musicLatch == 0) {
                    state->musicLatch = 1;
                }
                state->cameraState = 1;
                obj->anim.localPosX = spawnData->posX;
                obj->anim.localPosY = -1.0f;
                obj->anim.localPosZ = spawnData->posZ;
                Sfx_StopObjectChannel((int)obj, 1);
                (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, 2, 1);
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                return;
            }
        }
        break;
    }
    default:
        obj->userData1 = 7;
        break;
    }

    /* Integrate the current drift while the Galleon is in a flight phase. */
    if (state->phase < 2) {
        state->posX =
            state->moveScale * (state->driftX * timeDelta) +
            state->posX;
        state->posY =
            state->moveScale * (state->driftY * timeDelta) +
            state->posY;
        state->posZ =
            state->moveScale * (state->driftZ * timeDelta) +
            state->posZ;
        state->moveScale += 0.004166667f;
        if (state->moveScale > 1.0f) {
            state->moveScale = 1.0f;
        }
        blendK = 0.02f;
        state->swayScaleSmooth +=
            blendK * (timeDelta * (ambA - state->swayScaleSmooth));
        state->rollScaleSmooth +=
            blendK * (timeDelta * (ambC - state->rollScaleSmooth));
        state->swayResponseSmooth +=
            blendK * (timeDelta * (ambB - state->swayResponseSmooth));
        if (state->phase == 0) {
            zRatio = (f32)tricky->anim.rotY / state->swayScaleSmooth;
            state->swayZ +=
                timeDelta * (state->swayResponseSmooth *
                             ((f32)-tricky->anim.rotZ / state->swayScaleSmooth -
                              state->swayZ));
            state->swayY +=
                timeDelta * (state->swayResponseSmooth * (zRatio - state->swayY));
            zero = 0.0f;
            state->swayX = zero;
            state->swayY = zero;
            t = (s16)(-state->swayZ * state->rollScaleSmooth);
            wrap = (s16)(0.5f * (-state->swayY * state->rollScaleSmooth));
        } else {
            state->swayZ -=
                timeDelta * (state->swayZ * state->swayResponseSmooth);
            state->swayY -=
                timeDelta * (state->swayY * state->swayResponseSmooth);
            t = 0;
            wrap = t;
        }
        obj->anim.localPosX = state->swayX * state->moveScale + state->posX;
        obj->anim.localPosY = state->swayY * state->moveScale + state->posY;
        obj->anim.localPosZ = state->swayZ * state->moveScale + state->posZ;
        state->rollLatch =
            state->rollLatch + ((framesThisStep * (t - state->rollLatch)) >> 5);
        obj->anim.rotY = obj->anim.rotY + ((framesThisStep * (wrap - obj->anim.rotY)) >> 5);
        obj->anim.rotX = state->rollLatch + 0x4000;
        obj->anim.rotZ = obj->anim.rotX - 0x4000;
    }
}

void SB_Galleon_updateEnvfxGameBits(SBGalleonState* state) {
    GameObject* player;
    GameObject* effectObj;

    player = Obj_GetPlayerObject();
    if (mainGetBit(DBPROTECTION_GAMEBIT_CYCLE_A_PENDING) != 0) {
        effectObj = ObjList_FindObjectById(DBPROTECTION_ENVFX_B);
        getEnvfxAct(effectObj, player, state->envfxActs[state->envfxIndex + 4], 0);
        effectObj = ObjList_FindObjectById(DBPROTECTION_ENVFX_A);
        getEnvfxAct(effectObj, player, state->envfxActs[(state->envfxIndex ^ 1) + 2], 0);
        getEnvfxAct(player, player, DBPROTECTION_PLAYER_ENVFX_FLASH, 0);
        mainSetBits(DBPROTECTION_GAMEBIT_CYCLE_A_PENDING, 0);
        state->envfxCycle = DBPROTECTION_GAMEBIT_CYCLE_A_DONE;
    }

    if (mainGetBit(DBPROTECTION_GAMEBIT_CYCLE_B_PENDING) != 0) {
        effectObj = ObjList_FindObjectById(DBPROTECTION_ENVFX_A);
        getEnvfxAct(effectObj, player, state->envfxActs[state->envfxIndex + 4], 0);
        effectObj = ObjList_FindObjectById(DBPROTECTION_ENVFX_B);
        getEnvfxAct(effectObj, player, state->envfxActs[(state->envfxIndex ^ 1) + 2], 0);
        getEnvfxAct(player, player, DBPROTECTION_PLAYER_ENVFX_FLASH, 0);
        mainSetBits(DBPROTECTION_GAMEBIT_CYCLE_B_PENDING, 0);
        state->envfxCycle = DBPROTECTION_GAMEBIT_CYCLE_B_DONE;
    }

    if (mainGetBit(DBPROTECTION_GAMEBIT_CYCLE_A_DONE) != 0) {
        if (state->envfxCycle != DBPROTECTION_GAMEBIT_CYCLE_A_DONE) {
            state->envfxIndex = state->envfxIndex ^ 1;
        }
        getEnvfxAct(player, player, state->envfxActs[state->envfxIndex ^ 1], 0);
        getEnvfxAct(player, player, state->envfxActs[state->envfxIndex + 4], 0);
        getEnvfxAct(player, player, DBPROTECTION_PLAYER_ENVFX_SWAP, 0);
        mainSetBits(DBPROTECTION_GAMEBIT_CYCLE_A_DONE, 0);
    }

    if (mainGetBit(DBPROTECTION_GAMEBIT_CYCLE_B_DONE) != 0) {
        if (state->envfxCycle != DBPROTECTION_GAMEBIT_CYCLE_B_DONE) {
            state->envfxIndex = state->envfxIndex ^ 1;
        }
        getEnvfxAct(player, player, state->envfxActs[state->envfxIndex ^ 1], 0);
        getEnvfxAct(player, player, state->envfxActs[state->envfxIndex + 4], 0);
        getEnvfxAct(player, player, DBPROTECTION_PLAYER_ENVFX_SWAP, 0);
        mainSetBits(DBPROTECTION_GAMEBIT_CYCLE_B_DONE, 0);
    }
}

int SB_Galleon_getCameraState(GameObject* obj) {
    return ((SBGalleonState*)obj->extra)->cameraState;
}

void SB_Galleon_updateShield(GameObject* obj) {
    SBGalleonState* state;
    f32 angleSin;

    state = obj->extra;
    obj->userData1 = 7;

    if (mainGetBit(DBPROTECTION_GAMEBIT_TRANSITION_ARMED) != 0 &&
        mainGetBit(DBPROTECTION_GAMEBIT_TRANSITION_USED) == 0 &&
        mainGetBit(GAMEBIT_ITEM_WMGoldKey_Got) != 0) {
        gSB_GalleonTransitionPending = 1;
        mainSetBits(DBPROTECTION_GAMEBIT_TRANSITION_USED, 1);
        (*gScreenTransitionInterface)->start(0xa, SCREEN_TRANSITION_BLACK);
    }

    SB_Galleon_updateEnvfxGameBits(state);

    if (gSB_GalleonTransitionPending != 0 && (*gScreenTransitionInterface)->isFinished() != 0) {
        (*gScreenTransitionInterface)->step(0x50, SCREEN_TRANSITION_BLACK);
        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
        state->cameraState = 3;
        gSB_GalleonTransitionPending = 0;
    }

    (*gCloudActionInterface)->func12Nop(-25.0f, 0.0f);
    (*gCloudActionInterface)->func10Nop(0);

    angleSin = mathSinf((3.14159265f * state->shieldAngle) / 32768.0f);
    if (state->shieldSfxLatch == 0) {
        if (angleSin < -0.9f) {
            if (mainGetBit(DBPROTECTION_GAMEBIT_MUTE_SFX) == 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_tr_gal_crateslide);
            }
            state->shieldSfxLatch = 1;
        } else if (angleSin > 0.9f) {
            if (mainGetBit(DBPROTECTION_GAMEBIT_MUTE_SFX) == 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_tr_gal_sailflap3);
            }
            state->shieldSfxLatch = 1;
        }
    } else if (angleSin > -0.1f && angleSin < 0.1f) {
        state->shieldSfxLatch = 0;
    }

    obj->anim.rotZ = 432.0f * angleSin;
    state->shieldAngle = (u16)(s32)(128.0f * timeDelta + state->shieldAngle);
}

void SB_Galleon_onSeqFree(GameObject* obj) {
    SBGalleonState* state = obj->extra;
    state->posX = obj->anim.localPosX;
    state->posY = obj->anim.localPosY;
    state->posZ = obj->anim.localPosZ;
}

u8 gSbGalleonSkyColorBStart[4] = {0x0A, 0x10, 0x1F, 0};
u8 gSbGalleonSkyColorBEnd[4] = {9, 0x0F, 0x1E, 0};
u8 gSbGalleonSkyColorAStart[4] = {0x3E, 0x52, 0x64, 0};
u8 gSbGalleonSkyColorAEnd[4] = {0xC8, 0xE7, 0xFF, 0};
u8 gSbGalleonSkyColorCStart[4] = {0x3E, 0x52, 0x66, 0};
u8 gSbGalleonSkyColorCEnd[4] = {0x13, 0x23, 0x36, 0};

#define SBGALLEON_OBJGROUP 3

const Vec gSbGalleonSkyLightVecs[4] = {
    {-1.0f, -2.0f, -1.0f}, {1.0f, -2.0f, 1.0f}, {1.0f, -2.0f, 1.0f}, {1.0f, -0.25f, 1.0f}};
u32 sSbGalleonUnused0;
u8 gSbGalleonSkyColorA[4];
u8 gSbGalleonSkyColorB[4];
u8 gSbGalleonSkyColorC[4];
u8 gSbGalleonSkyLightIntensity;
s8 gSB_GalleonTransitionPending;
f32 gSbGalleonSkyBlendFactor;
f32 gSbGalleonSkyBlendHold;
GameObject* gSbGalleon;
Texture* gSbGalleonSkyTexB;
Texture* gSbGalleonSkyTexA;

static inline void SB_Galleon_blendSkyColorChannel(u8* color, int start, int end, f32 blendFactor) {
    *color = start + blendFactor * (end - start);
}

/* Sequence-event opcodes consumed by SB_Galleon_SeqFn. */
enum SbGalleonSeqEvent {
    SBGALLEON_SEQEV_TOGGLE_DAMAGE_PHASE_1 = 2, /* toggle damagePhase to 1 */
    SBGALLEON_SEQEV_SPRAY_ON = 3,
    SBGALLEON_SEQEV_SPRAY_OFF = 4,
    SBGALLEON_SEQEV_TOGGLE_DAMAGE_PHASE_2 = 5, /* toggle damagePhase to 2 */
    SBGALLEON_SEQEV_SFX_ON = 6,
    SBGALLEON_SEQEV_SFX_OFF = 7,
    SBGALLEON_SEQEV_TOGGLE_DAMAGE_PHASE_8 = 8, /* toggle damagePhase to 8 */
    SBGALLEON_SEQEV_SKY_ON = 9,
    SBGALLEON_SEQEV_SKY_OFF = 10,
    SBGALLEON_SEQEV_SPLASH_SFX = 0xb,
    SBGALLEON_SEQEV_MUSIC = 0xc,
    SBGALLEON_SEQEV_TEXT = 0xd
};

/* SBGalleonState.cameraState - protection-spirit encounter state machine
   stepped in SB_Galleon_update. */
enum SbGalleonCameraState {
    SBGALLEON_CAM_APPROACH = 0,
    SBGALLEON_CAM_START_INTRO = 1,
    SBGALLEON_CAM_SHIELD = 2,
    SBGALLEON_CAM_END = 3,
    SBGALLEON_CAM_DONE = 4
};

#define SBGALLEON_FX_SPRAY         0x7aa /* water-spray particle fx */
#define SBGALLEON_FX_WANDER        0xa3  /* wandering particle fx */
#define SBGALLEON_ROMLIST_LINKED   0xf7  /* romlist type of the linked spray actor */
#define SBGALLEON_GAMETEXT         0x4b1 /* on-screen gameText id */
#define SBGALLEON_GAMEBIT_INTRO    0x75  /* gates the intro map-event setup */
#define SBGALLEON_GAMEBIT_DEFEATED 0xac8 /* set on free */
#define SBGALLEON_SFX_SPLASH       0x143
#define SBGALLEON_SFX_SPRAY        0x2c6
#define SBGALLEON_TEXTURE_SKY_A    0x16d /* gSbGalleonSkyTexA */
#define SBGALLEON_TEXTURE_SKY_B    0x89  /* gSbGalleonSkyTexB */
#define SBGALLEON_MUSIC_INTRO      0xa3
#define SBGALLEON_MAP_PALACE       0xb /* map-event/dir id this boss locks */
#define SBGALLEON_SKY_LIGHT_SLOT   7   /* sky override light slot SB_Galleon_updateSkyLighting drives */

void SB_Galleon_updateSkyLighting(GameObject* obj, SBGalleonState* state) {
    ObjModel* activeModel;
    int renderOpIndex;
    Shader* renderOp;
    Vec primaryLightDirection;
    Vec alternateLightDirection;
    Vec overrideDirectionStart;
    Vec overrideDirectionEnd;
    primaryLightDirection = gSbGalleonSkyLightVecs[0];
    alternateLightDirection = gSbGalleonSkyLightVecs[1];
    overrideDirectionStart = gSbGalleonSkyLightVecs[2];
    overrideDirectionEnd = gSbGalleonSkyLightVecs[3];
    setDrawLights(0);
    skySetOverrideLightColorEnabled(1);
    skySetOverrideLightColor(0x29, 0x4b, 0xa9);
    skySetLightsEnabled(SBGALLEON_SKY_LIGHT_SLOT, 1, 0);
    if (lightningGetRemainingFraction() > 0.0f) {
        gSbGalleonSkyBlendHold = 1.0f;
        gSbGalleonSkyBlendFactor = 1.0f;
    }
    {
        f32 blendFactor = -(0.02f * timeDelta - gSbGalleonSkyBlendFactor);
        gSbGalleonSkyBlendFactor = blendFactor;
        if (blendFactor < 0.0f) {
            gSbGalleonSkyBlendFactor = 0.0f;
        }
    }
    SB_Galleon_blendSkyColorChannel(&gSbGalleonSkyColorA[0], gSbGalleonSkyColorAStart[0], gSbGalleonSkyColorAEnd[0],
                                    gSbGalleonSkyBlendFactor);
    SB_Galleon_blendSkyColorChannel(&gSbGalleonSkyColorA[1], gSbGalleonSkyColorAStart[1], gSbGalleonSkyColorAEnd[1],
                                    gSbGalleonSkyBlendFactor);
    SB_Galleon_blendSkyColorChannel(&gSbGalleonSkyColorA[2], gSbGalleonSkyColorAStart[2], gSbGalleonSkyColorAEnd[2],
                                    gSbGalleonSkyBlendFactor);
    skySetBaseColor(SBGALLEON_SKY_LIGHT_SLOT, gSbGalleonSkyColorA[0], gSbGalleonSkyColorA[1], gSbGalleonSkyColorA[2],
                    0x40, 0x40);
    SB_Galleon_blendSkyColorChannel(&gSbGalleonSkyColorB[0], gSbGalleonSkyColorBStart[0], gSbGalleonSkyColorBEnd[0],
                                    gSbGalleonSkyBlendFactor);
    SB_Galleon_blendSkyColorChannel(&gSbGalleonSkyColorB[1], gSbGalleonSkyColorBStart[1], gSbGalleonSkyColorBEnd[1],
                                    gSbGalleonSkyBlendFactor);
    SB_Galleon_blendSkyColorChannel(&gSbGalleonSkyColorB[2], gSbGalleonSkyColorBStart[2], gSbGalleonSkyColorBEnd[2],
                                    gSbGalleonSkyBlendFactor);
    skySetAmbientColor(SBGALLEON_SKY_LIGHT_SLOT, gSbGalleonSkyColorB[0], gSbGalleonSkyColorB[1],
                       gSbGalleonSkyColorB[2]);
    SB_Galleon_blendSkyColorChannel(&gSbGalleonSkyColorC[0], gSbGalleonSkyColorCStart[0], gSbGalleonSkyColorCEnd[0],
                                    gSbGalleonSkyBlendFactor);
    SB_Galleon_blendSkyColorChannel(&gSbGalleonSkyColorC[1], gSbGalleonSkyColorCStart[1], gSbGalleonSkyColorCEnd[1],
                                    gSbGalleonSkyBlendFactor);
    SB_Galleon_blendSkyColorChannel(&gSbGalleonSkyColorC[2], gSbGalleonSkyColorCStart[2], gSbGalleonSkyColorCEnd[2],
                                    gSbGalleonSkyBlendFactor);
    skySetMoonColor(SBGALLEON_SKY_LIGHT_SLOT, gSbGalleonSkyColorC[0], gSbGalleonSkyColorC[1], gSbGalleonSkyColorC[2]);
    gSbGalleonSkyLightIntensity = gSbGalleonSkyBlendFactor * 128.0f + 32.0f;
    skySetOverrideLightDirectionEnabled(1);
    skySetOverrideLightDirection(
        gSbGalleonSkyBlendFactor * (overrideDirectionEnd.x - overrideDirectionStart.x) + overrideDirectionStart.x,
        gSbGalleonSkyBlendFactor * (overrideDirectionEnd.y - overrideDirectionStart.y) + overrideDirectionStart.y,
        gSbGalleonSkyBlendFactor * (overrideDirectionEnd.z - overrideDirectionStart.z) + overrideDirectionStart.z,
        100.0f);
    if (state->skyFlag == 0) {
        skySetLightDirection(SBGALLEON_SKY_LIGHT_SLOT, primaryLightDirection.x, primaryLightDirection.y,
                             primaryLightDirection.z);
    } else {
        skySetLightDirection(SBGALLEON_SKY_LIGHT_SLOT, alternateLightDirection.x, alternateLightDirection.y,
                             alternateLightDirection.z);
    }
    activeModel = Obj_GetActiveModel(obj);
    renderOpIndex = 0;
    {
        f32 alphaScale = 255.0f;
        for (; renderOpIndex < activeModel->file->renderOpCount; renderOpIndex++) {
            renderOp = ObjModel_GetRenderOp(activeModel->file, renderOpIndex);
            if (renderOp->layers[0].materialId == 1) {
                renderOp->alpha = alphaScale * gSbGalleonSkyBlendFactor;
            }
        }
    }
}

int SB_Galleon_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    SBGalleonState* state = obj->extra;
    int i;

    obj->anim.mapEventSlot = -1;
    SB_Galleon_updateSkyLighting(obj, state);
    {
        f32 z = 0.0f;
        state->moveScale = 0.0f;
        state->swayX = z;
        state->swayY = z;
        state->swayZ = z;
    }
    animUpdate->freeCallback = (ObjAnimSequenceFreeCallback)SB_Galleon_onSeqFree;
    for (i = 0; i < animUpdate->eventCount; i++) {
        switch (animUpdate->eventIds[i]) {
        case SBGALLEON_SEQEV_TOGGLE_DAMAGE_PHASE_1:
            if (state->damagePhase == 1) {
                state->damagePhase = 0;
            } else {
                state->damagePhase = 1;
            }
            break;
        case SBGALLEON_SEQEV_SPRAY_ON: {
            int start;
            int end;
            GameObject** arr = ObjList_GetObjects(&start, &end);
            for (i = start; i < end; i++) {
                if ((arr[i])->anim.romDefNo == SBGALLEON_ROMLIST_LINKED) {
                    state->linkedActor = arr[i];
                    i = end;
                }
            }
            state->sprayActive = 1;
            break;
        }
        case SBGALLEON_SEQEV_SPRAY_OFF:
            state->sprayActive = 0;
            break;
        case SBGALLEON_SEQEV_TOGGLE_DAMAGE_PHASE_2:
            if (state->damagePhase == 2) {
                state->damagePhase = 0;
            } else {
                state->damagePhase = 2;
            }
            break;
        case SBGALLEON_SEQEV_SFX_ON:
            Sfx_PlayFromObject(obj, SBGALLEON_SFX_SPLASH);
            break;
        case SBGALLEON_SEQEV_SFX_OFF:
            Sfx_StopFromObject(obj, SBGALLEON_SFX_SPLASH);
            break;
        case SBGALLEON_SEQEV_TOGGLE_DAMAGE_PHASE_8:
            if (state->damagePhase == 8) {
                state->damagePhase = 1;
            } else {
                state->damagePhase = 8;
            }
            break;
        case SBGALLEON_SEQEV_SKY_ON:
            state->skyFlag = 1;
            break;
        case SBGALLEON_SEQEV_SKY_OFF:
            state->skyFlag = 0;
            break;
        case SBGALLEON_SEQEV_SPLASH_SFX:
            Sfx_PlayFromObject(sbGetPropeller(), SBGALLEON_SFX_SPRAY);
            break;
        case SBGALLEON_SEQEV_MUSIC:
            state->musicIdB = SBGALLEON_MUSIC_INTRO;
            Music_Trigger(state->musicIdB, 1);
            Music_Trigger(state->musicIdA, 0);
            break;
        case SBGALLEON_SEQEV_TEXT:
            state->textTimer = 600.0f;
            state->textRising = 1;
            state->textAlpha = 0.0f;
            break;
        }
    }
    if (state->textTimer >= 0.0f) {
        state->textTimer = state->textTimer - timeDelta;
        if (state->textTimer < 0.0f) {
            state->textTimer = 0.0f;
            state->textRising = 0;
        }
    }
    if (state->textRising != 0) {
        state->textAlpha = 8.0f * timeDelta + state->textAlpha;
    } else {
        state->textAlpha = -(8.0f * timeDelta - state->textAlpha);
    }
    {
        f32 v = state->textAlpha;
        state->textAlpha = (v < 0.0f) ? 0.0f : ((v > 255.0f) ? 255.0f : v);
    }
    if (state->textAlpha > 0.0f) {
        gameTextSetColor(0xff, 0xff, 0xff, state->textAlpha);
        gameTextShow(SBGALLEON_GAMETEXT);
    }
    state->posX = obj->anim.localPosX;
    state->posY = obj->anim.localPosY;
    state->posZ = obj->anim.localPosZ;
    animUpdate->flags = animUpdate->savedFlags;
    animUpdate->movementState = 0;
    return 0;
}

GameObject* getSbGalleon(void) {
    return gSbGalleon;
}

int SB_Galleon_func0E(GameObject* obj) {
    SBGalleonState* state = (SBGalleonState*)obj->extra;
    if ((s8)(u8)state->phase == 1) {
        int wrapped;
        if ((s8)(u8)state->phaseCounter >= 5) {
            wrapped = (s8)(u8)state->phaseCounter - 5;
        } else {
            wrapped = (s8)(u8)state->phaseCounter;
        }
        return (6 - wrapped) * 0x5a;
    }
    return 0x640;
}

u8 SB_Galleon_getDamagePhase(GameObject* obj) {
    return ((SBGalleonState*)obj->extra)->damagePhase;
}

int SB_Galleon_getPhase(GameObject* obj) {
    int phase;
    SBGalleonState* state = (SBGalleonState*)obj->extra;
    int pattern;
    phase = (u8)state->phase;
    if ((s8)phase == 0) {
        if (state->timer26 > 0) {
            return -2;
        }
    }
    if ((s8)phase == 1) {
        if ((pattern = state->flightPattern) == 2 || pattern == 3 || pattern == 5) {
            return -1;
        }
    }
    return (s8)phase;
}

s32 SB_Galleon_getStage(GameObject* obj) {
    return ((SBGalleonState*)obj->extra)->stage;
}

/*
 * A destructible gun, propeller blade, or ship head reports its destruction
 * through the Galleon's callback at offset 0x20.
 */
int SB_Galleon_onPartDestroyed(GameObject* obj) {
    SBGalleonState* state = (SBGalleonState*)obj->extra;
    int phase = state->phase;
    if (phase != 1) {
        if (phase >= 2) {
            Sfx_PlayFromObject(obj, SFXTRIG_sc_npu_216_3f);
        }
        state->stage += 1;
        return 1;
    }
    {
        int pattern;
        if ((pattern = state->flightPattern) == 0 || pattern == 1 || pattern == 2) {
            state->phaseCounter += 1;
            return 1;
        }
    }
    return 0;
}

int SB_Galleon_getExtraSize(void) {
    return sizeof(SBGalleonState);
}

int SB_Galleon_getObjectTypeId(void) {
    return 0x0;
}

void SB_Galleon_free(GameObject* obj, int leavingMap) {
    SBGalleonState* state = (SBGalleonState*)obj->extra;
    if (gSbGalleonSkyTexA != NULL) {
        textureFree(gSbGalleonSkyTexA);
        gSbGalleonSkyTexA = NULL;
    }
    if (gSbGalleonSkyTexB != NULL) {
        textureFree(gSbGalleonSkyTexB);
        gSbGalleonSkyTexB = NULL;
    }
    objFreeObjectType(obj, SBGALLEON_OBJGROUP);
    if (state->musicLatch != 0 && leavingMap == 0) {
        state->musicLatch = 0;
    }
    gSbGalleon = NULL;
    Music_Trigger(state->musicIdB, 0);
    Music_Trigger(state->musicIdA, 0);
    mainSetBits(SBGALLEON_GAMEBIT_DEFEATED, 1);
}

void SB_Galleon_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) {
    SBGalleonState* state = (SBGalleonState*)obj->extra;
    struct {
        u8 pad[6];
        u16 mode;
        f32 unused;
        f32 a;
        f32 b;
        f32 c;
    } stk;
    if (visible != 0) {
        if (state->cameraState < 2) {
            stk.mode = state->wanderA;
            stk.c = 570.0f;
            stk.b = 85.0f;
            stk.a = 217.0f;
            (*gPartfxInterface)->spawnObject((void*)obj, SBGALLEON_FX_WANDER, stk.pad, 2, -1, NULL);
            stk.mode = state->wanderB;
            stk.a = -217.0f;
            (*gPartfxInterface)->spawnObject((void*)obj, SBGALLEON_FX_WANDER, stk.pad, 2, -1, NULL);
        }
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void SB_Galleon_hitDetect(GameObject* obj) {
    SBGalleonState* state = (SBGalleonState*)obj->extra;
    u8 i;
    struct {
        u8 pad[6];
        u16 mode;
        f32 a;
        f32 b;
        f32 c;
        f32 d;
    } stk;
    if (state->sprayActive != 0 && state->linkedActor != NULL) {
        stk.a = 1.5f;
        stk.mode = 0xc0a;
        stk.b = 0.0f;
        stk.c = 60.0f;
        stk.d = 120.0f;
        for (i = 0; i < framesThisStep; i++) {
            (*gPartfxInterface)->spawnObject(state->linkedActor, SBGALLEON_FX_SPRAY, stk.pad, 2, -1, 0);
        }
    }
}

void SB_Galleon_update(GameObject* obj) {
    SBGalleonState* state = (SBGalleonState*)obj->extra;
    obj->anim.mapEventSlot = state->mapLayer;
    SB_Galleon_updateSkyLighting(obj, state);
    if (mainGetBit(SBGALLEON_GAMEBIT_INTRO) == 0) {
        (*gMapEventInterface)->setMapAct(SBGALLEON_MAP_PALACE, 1);
        (*gMapEventInterface)->setObjGroupStatus(SBGALLEON_MAP_PALACE, 0, 1);
        (*gMapEventInterface)->setObjGroupStatus(SBGALLEON_MAP_PALACE, 1, 1);
        (*gMapEventInterface)->setObjGroupStatus(SBGALLEON_MAP_PALACE, 5, 1);
        lockLevel(mapGetDirIdx(SBGALLEON_MAP_PALACE), 0);
        if ((*gMapEventInterface)->getObjGroupStatus(obj->anim.hostedMapSlot, 1) == 0) {
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, 1, 1);
        }
        obj->userData1 = 0;
    } else {
        if ((state->musicLatch == 0) && (state->cameraState > 0)) {
            state->musicLatch = 1;
        }
        switch (state->cameraState) {
        case SBGALLEON_CAM_APPROACH:
            SB_Galleon_updateFlight(obj);
            break;
        case SBGALLEON_CAM_START_INTRO:
            (*gObjectTriggerInterface)->runSequence(3, obj, -1);
            state->cameraState = SBGALLEON_CAM_SHIELD;
            break;
        case SBGALLEON_CAM_SHIELD:
            SB_Galleon_updateShield(obj);
            break;
        case SBGALLEON_CAM_END:
            (*gMapEventInterface)->setMapAct(SBGALLEON_MAP_PALACE, 1);
            obj->anim.mapEventSlot = -1;
            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
            state->cameraState = SBGALLEON_CAM_DONE;
            break;
        }
        GameBitLatch_Update((GameBitLatchState*)state->gameBitLatch, 1, -1, -1, 0xa71, 0xa4);
    }
}

void SB_Galleon_init(GameObject* obj) {
    SBGalleonState* state = (SBGalleonState*)obj->extra;
    ObjHitsPriorityState* hitState;
    gSbGalleon = obj;
    objAddObjectType(obj, SBGALLEON_OBJGROUP);
    objSetSlot(obj, 0x5a);
    obj->animEventCallback = SB_Galleon_SeqFn;
    state->posX = obj->anim.localPosX;
    state->posY = obj->anim.localPosY;
    state->posZ = obj->anim.localPosZ;
    state->sweepDir = 1;
    state->timer26 = 0xf0;
    state->phaseTimer = 0xf0;
    state->damagePhase = 0;
    state->headingLatch = 200;
    state->envfxActs[2] = 0x89;
    state->envfxActs[3] = 0x95;
    state->envfxActs[4] = 0x86;
    state->envfxActs[5] = 0x88;
    state->envfxActs[0] = 0x87;
    state->envfxActs[1] = 0x97;
    state->mapLayer = obj->anim.mapEventSlot;
    obj->anim.rotX = 0x4000;
    obj->anim.rotY = 0;
    obj->anim.rotZ = 0;
    gSbGalleonSkyTexA = textureLoadAsset(SBGALLEON_TEXTURE_SKY_A);
    gSbGalleonSkyTexB = textureLoadAsset(SBGALLEON_TEXTURE_SKY_B);
    state->unk84 = 100;
    (*gMapEventInterface)->setMapAct(obj->anim.mapEventSlot, 1);
    getLActions(obj, obj, 0x58, 0, 0, 0);
    state->wanderTimerA = 0.0f;
    state->wanderTimerB = 180.0f;
    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    hitState->flags |= 0x1800;
    setDrawLights(0);
    state->musicIdA = 0x92;
    state->musicIdB = 0x91;
    Music_Trigger(state->musicIdB, 1);
}

void SB_Galleon_release(void) {
}

void SB_Galleon_initialise(void) {
}
