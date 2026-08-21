/*
 * DIMCannon (DLL 0x1C6) - DIM lava cannon; a stationary turret that tracks
 * and fires cannonballs at the player, with a manned-control mode (mode 3)
 * in which the player aims with the stick, charges with A, and fires on release.
 * The 0x1D6 sub-variant is its falling-debris cannonball.
 */
#include "dlls/objects/454_DIMCannon.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/pad.h"
#include "game/objects/object.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_interface.h"
#include "main/dll/dll_0051_cameramodecannon.h"
#include "main/dll/player_api.h"
#include "main/dll/player_status.h"
#include "main/dll/tricky_api.h"
#include "main/frame_timing.h"
#include "main/game_ui_interface.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/objanim.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/object_render.h"
#include "main/pad.h"
#include "main/resource.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define DIM_CANNON_BALL_HIT_VOLUME_SLOT             5
#define DIM_CANNON_OBJECT_GROUP                     3
#define DIM_CANNON_AIR_METER_BACKGROUND_TEXTURE     0x5d5
#define DIM_CANNON_RELEASE_CAMERA_MODE              0x42 /* default gameplay camera */
#define DIM_CANNON_PLAYER_CONTROLLED_MAP_EVENT_SLOT 0x13

extern s16 lbl_803DBF02;
extern s16 lbl_803DBF04;
extern f32 gDimCannonBallGravity;
extern f32 lbl_803DBF14;

/* Integrate a cannonball under gravity and explode it on contact or a scripted trigger. */

static void DIMCannon_explodeBall(GameObject* obj, DimCannonBallState* state) {
    ObjHitbox_SetSphereRadius(&obj->anim, state->hitboxRadius);
    spawnExplosion(obj, 50.0f, 2, 1, 0, 1, 1, 1, 0);
    obj->userData1 = 1180;
    state->mode = DIM_CANNON_BALL_MODE_EXPLODED;
    obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
}

void DIMCannon_updateBall(GameObject* obj) {
    DimCannonBallState* state = obj->extra;
    switch (state->mode) {
    case DIM_CANNON_BALL_MODE_FALLING: {
        f32 previousVelocityY = obj->anim.velocityY;
        f32 gravity = 0.01f * -gDimCannonBallGravity;
        f32 averageVelocityY;
        ObjHitsPriorityState* hitState;
        obj->anim.velocityY = gravity * timeDelta + previousVelocityY;
        averageVelocityY = 0.5f * (previousVelocityY + obj->anim.velocityY);
        objMove(obj, obj->anim.velocityX * timeDelta, averageVelocityY * timeDelta, obj->anim.velocityZ * timeDelta);
        obj->anim.rotZ = obj->anim.rotZ + state->rotationZRate * 10;
        obj->anim.rotY = obj->anim.rotY + state->rotationYRate * 10;
        obj->anim.rotX = obj->anim.rotX + state->rotationXRate * 10;
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        if (hitState != NULL) {
            int* lastHitObject;
            ObjHits_SetHitVolumeSlot(&obj->anim, DIM_CANNON_BALL_HIT_VOLUME_SLOT, state->hitType, 0);
            lastHitObject = (int*)hitState->lastHitObject;
            if (lastHitObject != NULL && lastHitObject != *(int**)state) {
                DIMCannon_explodeBall(obj, state);
            }
        }
        if ((mainGetBit(GAMEBIT_DIM2_CannonRelated085E) != 0 && mainGetBit(GAMEBIT_CannonRelated0C2D) == 0) ||
            (mainGetBit(GAMEBIT_DIM2_CannonRelated0874) != 0 && mainGetBit(GAMEBIT_CannonRelated0C2E) == 0)) {
            obj->userData1 = 1200;
        }
        if (((ObjHitsPriorityState*)obj->anim.hitReactState)->contactFlags != 0) {
            DIMCannon_explodeBall(obj, state);
        }
        break;
    }
    case DIM_CANNON_BALL_MODE_EXPLODED:
        break;
    }
    obj->userData1 = obj->userData1 + framesThisStep;
    if (obj->userData1 > 1200) {
        Obj_FreeObject(obj);
    } else if (state->clearLatch != 0) {
        state->clearLatch = 0;
    }
}

void DIMCannon_spawnBall(GameObject* obj, u8 variant) {
    DimCannonPlacement* placement;
    DimCannonState* state;
    DimCannonBallState* ballState;
    s16* modelRotation;
    DimCannonBallPlacement* ballPlacement;
    GameObject* ball;
    f32 launchSpeed;
    f32 launchScale;
    f32 angle;
    GameObject* objHandle = obj;
    u8 canSetupObject;

    placement = *(DimCannonPlacement**)&obj->anim.placementData;
    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject == 0 || (state = obj->extra)->shouldSpawnProjectile == 0 || state->launchDelay > 0) {
        return;
    }

    modelRotation = objFindJointPoseVector(obj, 0);
    ballPlacement =
        (DimCannonBallPlacement*)Obj_AllocObjectSetup(sizeof(DimCannonBallPlacement), DIM_CANNON_BALL_SEQUENCE_ID);
    ballPlacement->base.color[0] = placement->base.color[0];
    ballPlacement->base.color[2] = placement->base.color[2];
    ballPlacement->base.color[1] = placement->base.color[1];
    ballPlacement->base.color[3] = placement->base.color[3];
    ballPlacement->base.posX = state->launchOriginX;
    ballPlacement->base.posY = state->launchOriginY;
    ballPlacement->base.posZ = state->launchOriginZ;

    ball = objSetupObject(&ballPlacement->base, 5, obj->anim.mapEventSlot, -1, 0);
    ballState = ball->extra;
    ballState->parent = obj;
    ballState->variant = variant;
    if (variant != 0) {
        if (obj->anim.mapEventSlot == 0x1b) {
            ballState->hitboxRadius = 100;
        } else {
            ballState->hitboxRadius = 60;
        }
        ballState->hitType = 100;
    } else {
        ballState->hitboxRadius = 20;
        ballState->hitType = 1;
    }

    launchSpeed = state->launchSpeed;
    launchScale = 2.0f * launchSpeed;
    ball->anim.rotX = obj->anim.rotX + modelRotation[1];
    angle = (3.1415927f * (f32)(s32) * (s16*)ball) / 32768.0f;
    ball->anim.velocityX = launchScale * -mathSinf(angle);
    ball->anim.velocityY = launchSpeed;
    angle = (3.1415927f * (f32)(s32) * (s16*)ball) / 32768.0f;
    ball->anim.velocityZ = launchScale * -mathCosf(angle);

    state->shouldSpawnProjectile = 0;
    state->shotCooldown = 50;
    if (state->mode == DIM_CANNON_MODE_PLAYER_CONTROLLED) {
        state->launchDelay = 50;
    } else {
        state->launchDelay = (s16)(randomGetRange(placement->launchDelayMin, placement->launchDelayMax) << 2);
    }

    ObjAnim_SetCurrentMove(objHandle, 0, 0.0f, 0);
    Sfx_PlayFromObject(objHandle, SFXTRIG_tr_jrumbalp);
}

void DIMCannon_updateAim(GameObject* obj, f32 targetX, f32 unusedTargetY, f32 targetZ, f32 unusedDistance) {
    DimCannonState* state;
    DimCannonPlacement* placement;
    s16* modelRotation;
    GameObject* player;
    f32 dx;
    f32 dz;
    f32 distSq;
    f32 dist;
    f32 heightDelta;
    f32 accel;
    f32 accelDenom;
    register int facingAngle;
    int angleDelta;
    int pitchSign;
    int turnSign;
    s16 pitch;
    int turnStep;
    s16 absPitch;

    (void)unusedTargetY;
    (void)unusedDistance;

    placement = *(DimCannonPlacement**)&(obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    state = (obj)->extra;
    if (state->shotCooldown <= 0) {
        f32 launchSpeed;
        modelRotation = objFindJointPoseVector(obj, 0);
        facingAngle = modelRotation[1] + ((s32)placement->rotationXByte << 8);
        targetX -= (obj)->anim.localPosX;
        targetZ -= (obj)->anim.localPosZ;
        angleDelta = ((u16)getAngle(targetX, targetZ) + 0x8000);
        angleDelta = angleDelta - (u16)facingAngle;
        if (angleDelta > 0x8000) {
            angleDelta -= 0xffff;
        }
        if (angleDelta < -0x8000) {
            angleDelta += 0xffff;
        }
        if ((angleDelta < 0x1200) && (angleDelta > -0x1200)) {
            state->shouldSpawnProjectile = 1;
        }
        if (angleDelta > 0x800) {
            angleDelta = 0x800;
        }
        if (angleDelta < -0x800) {
            angleDelta = -0x800;
        }
        turnStep = angleDelta >> 3;
        if (turnStep != 0) {
            pitch = modelRotation[1];
            absPitch = (pitch < 0) ? -pitch : pitch;
            if ((s32)absPitch > (s32)lbl_803DBF02 - lbl_803DBF04) {
                turnSign = (turnStep < 0) ? -1 : ((turnStep > 0) ? 1 : 0);
                pitchSign = (modelRotation[1] < 0) ? -1 : ((modelRotation[1] > 0) ? 1 : 0);
                if (pitchSign == turnSign) {
                    turnStep *= lbl_803DBF02 - (s32)absPitch;
                    turnStep /= lbl_803DBF04;
                }
            }
            modelRotation[1] = (s16)(*(s16*)((char*)modelRotation + 2) + turnStep);
        }

        dx = state->launchOriginX - state->aimTargetX;
        dz = state->launchOriginZ - state->aimTargetZ;
        distSq = dx * dx + dz * dz;
        dist = sqrtf(distSq);
        heightDelta = (10.0f + state->aimTargetY) - state->launchOriginY;
        distSq = (distSq > 10.0f) ? (dx * dx + dz * dz) : 10.0f;
        if ((distSq < (f32)((s32)(placement->targetRadius * 2) * (s32)(placement->targetRadius * 2))) ||
            (heightDelta < lbl_803DBF14) || ((player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0)) {
            state->shouldSpawnProjectile = 0;
        }
        distSq = (distSq > (f32)((s32)(placement->targetRadius * 2) * (s32)(placement->targetRadius * 2)))
                     ? distSq
                     : (f32)((s32)(placement->targetRadius * 2) * (s32)(placement->targetRadius * 2));

        accel = (0.01f * -gDimCannonBallGravity) * distSq;
        accelDenom = 8.0f * heightDelta - 4.0f * dist;
        launchSpeed = accel / ((accelDenom < -1.0f) ? accelDenom : -1.0f);
        launchSpeed = (launchSpeed > 0.0f) ? launchSpeed : 0.0f;
        launchSpeed = sqrtf(launchSpeed);
        state->launchSpeed += (launchSpeed - state->launchSpeed) / 80.0f;
    }
}

f32 gDimCannonBallGravity = 6.0f;
f32 gDimCannonAnimAdvanceSpeedCur = 0.025f;
f32 gDimCannonLaunchSpeedBase = 1.0f;
f32 gDimCannonLaunchSpeedPerCharge = 0.04f;
u8 gDimCannonMaxCharge = 100;
s16 lbl_803DBF02 = 14000;
s16 lbl_803DBF04 = 1000;
f32 gDimCannonAimStickScale = 2.5f;
int lbl_803DBF0C = 164025;
int lbl_803DBF10 = 152100;
f32 lbl_803DBF14 = -300.0f;

int lbl_803DDB54;
void* gDimCannonResource;

int DIMCannon_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    DimCannonState* state;
    DimCannonPlacement* placement = *(DimCannonPlacement**)&obj->anim.placementData;
    int aimDelta;
    u8 shouldExit = 0;
    int cameraMode;

    (void)unused;

    animUpdate->movementState = 0;
    animUpdate->flags &= ~0x608;
    state = obj->extra;

    if (state->mode == DIM_CANNON_MODE_PLAYER_CONTROLLED) {
        s16* modelRotation;
        s8 timer;
        GameObject* player;

        player = Obj_GetPlayerObject();
        setAButtonIcon(0x16);
        setBButtonIcon(0x17);
        setHudForceShowMask(1);
        cameraMode = (*gCameraInterface)->getMode();
        if (cameraMode != CAMERA_MODE_CANNON_RESOURCE_ID && cameraMode != 0x4c) {
            CameraModeCannonInitParams cameraParams;
            cameraParams.target = obj;
            (*gCameraInterface)
                ->setMode(CAMERA_MODE_CANNON_RESOURCE_ID, 1, 0, sizeof(cameraParams), &cameraParams, 0x32, 0xff);
        }
        if (cameraMode != CAMERA_MODE_CANNON_RESOURCE_ID) {
            return 0;
        }
        modelRotation = objFindJointPoseVector(obj, 0);
        timer = state->chargeTimer;
        if (timer > 0) {
            state->chargeTimer = (s8)(timer - framesThisStep);
            if (state->chargeTimer <= 0) {
                (*gGameUIInterface)->initAirMeter(gDimCannonMaxCharge, DIM_CANNON_AIR_METER_BACKGROUND_TEXTURE);
            }
        } else {
            if (!mainGetBit(0xdb)) {
                (*gGameUIInterface)->showNpcDialogue(0x4b9, 0x14, 0x8c, 1);
                mainSetBits(0xdb, 1);
            }
            aimDelta = (int)(-gDimCannonAimStickScale * padGetStickX(0));
            if (aimDelta != 0) {
                s16 angleMagnitude = *(s16*)((char*)modelRotation + 0x2) < 0 ? -*(s16*)((char*)modelRotation + 0x2)
                                                                             : *(s16*)((char*)modelRotation + 0x2);
                if (angleMagnitude > lbl_803DBF02 - lbl_803DBF04) {
                    int rotationSign, deltaSign;
                    deltaSign = aimDelta < 0 ? -1 : (aimDelta > 0 ? 1 : 0);
                    rotationSign = *(s16*)((char*)modelRotation + 0x2) < 0
                                       ? -1
                                       : (*(s16*)((char*)modelRotation + 0x2) > 0 ? 1 : 0);
                    if (rotationSign == deltaSign) {
                        aimDelta = aimDelta * (lbl_803DBF02 - angleMagnitude);
                        aimDelta = aimDelta / lbl_803DBF04;
                    }
                }
                modelRotation[1] = (s16)(modelRotation[1] + aimDelta);
                Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_gal_sailflap2);
            } else if (state->previousAimDelta != 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_cnplarlp);
            }
            state->previousAimDelta = aimDelta;
            if (state->launchDelay > 0) {
                state->launchDelay -= framesThisStep;
            }
            if (state->shotCooldown > 0) {
                state->shotCooldown -= framesThisStep;
            }
            if ((getButtonsHeld(0) & PAD_BUTTON_A) && state->launchDelay <= 0) {
                buttonDisable(0, PAD_BUTTON_A);
                if (Player_GetCurrentMagic((int)player) >= 1) {
                    state->airMeterCharge += framesThisStep;
                    if (Sfx_IsPlayingFromObjectChannel(obj, 2) == 0) {
                        Sfx_PlayFromObject(obj, SFXTRIG_gal_sailflap1);
                        Sfx_PlayFromObject(obj, SFXTRIG_tr_cnplarlp);
                    }
                } else {
                    Sfx_PlayFromObject(obj, SFXTRIG_staff_swipes_long);
                }
            } else {
                Sfx_StopObjectChannel(obj, 2);
            }
            if (state->airMeterCharge > gDimCannonMaxCharge) {
                state->airMeterCharge = gDimCannonMaxCharge;
            }
            (*gGameUIInterface)->runAirMeter(state->airMeterCharge);
            state->launchSpeed =
                (f32)state->airMeterCharge * gDimCannonLaunchSpeedPerCharge + gDimCannonLaunchSpeedBase;
            if ((getButtonsJustPressedIfNotBusy(0) & PAD_BUTTON_A) || state->airMeterCharge == gDimCannonMaxCharge) {
                if (state->launchDelay <= 0 && Player_GetCurrentMagic((int)player) >= 1) {
                    buttonDisable(0, PAD_BUTTON_A);
                    playerAddRemoveMagic(player, -1);
                    state->shouldSpawnProjectile = 1;
                    state->airMeterCharge = 0;
                }
            }
            DIMCannon_spawnBall(obj, 1);
            if (obj->anim.mapEventSlot == DIM_CANNON_PLAYER_CONTROLLED_MAP_EVENT_SLOT && state->hasActivated == 0 &&
                mainGetBit(GAMEBIT_DIM_CannonRelated0C17) && mainGetBit(GAMEBIT_DIM_CannonRelated0A21)) {
                state->hasActivated = 1;
                state->shutdownTimer = 1;
            }
            {
                u8 shutdownTimer = state->shutdownTimer;
                if (shutdownTimer != 0) {
                    state->shutdownTimer += framesThisStep;
                    if (state->shutdownTimer > 0x3c) {
                        shouldExit = 1;
                    }
                }
            }
            if (shouldExit != 0 || (getButtonsJustPressed(0) & PAD_BUTTON_B)) {
                buttonDisable(0, PAD_BUTTON_B);
                setHudForceShowMask(0);
                (*gGameUIInterface)->airMeterShutdown();
                (*gCameraInterface)->setMode(DIM_CANNON_RELEASE_CAMERA_MODE, 0, 1, 0, NULL, 0, 0xff);
                state->mode = DIM_CANNON_MODE_WAIT_FOR_RESET;
                *(u8*)&state->chargeTimer = 0x3c;
                animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
                obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED;
                if (Sfx_IsPlayingFromObjectChannel(obj, 8) != 0) {
                    Sfx_IsPlayingFromObjectChannel(obj, 0);
                }
                Sfx_StopObjectChannel(obj, 2);
            }
            ObjAnim_AdvanceCurrentMove(obj, gDimCannonAnimAdvanceSpeedCur, timeDelta, NULL);
        }
    } else {
        s16* modelRotation;
        obj->anim.flags = (s16)(obj->anim.flags & ~OBJANIM_FLAG_HIDDEN);
        modelRotation = objFindJointPoseVector(obj, 0);
        modelRotation[1] = (s16)(obj->anim.rotX - (placement->rotationXByte << 8));
        obj->anim.rotX = (s16)(placement->rotationXByte << 8);
        state->mode = DIM_CANNON_MODE_ARMED;
    }

    return 0;
}

int DIMCannon_getExtraSize(GameObject* obj) {
    if (obj->anim.romDefNo == DIM_CANNON_BALL_SEQUENCE_ID) {
        return sizeof(DimCannonBallState);
    }
    return sizeof(DimCannonState);
}

int DIMCannon_getObjectTypeId(GameObject* obj) {
    if (obj->anim.romDefNo == DIM_CANNON_BALL_SEQUENCE_ID) {
        return 0x0;
    }
    return 0x0;
}

void DIMCannon_free(GameObject* obj) {
    if (obj->anim.romDefNo != DIM_CANNON_BALL_SEQUENCE_ID) {
        ((void (*)(void))((int**)*gGameUIInterface)[0x18])();
        Resource_Release(gDimCannonResource);
        gDimCannonResource = NULL;
    }
    objFreeObjectType(obj, DIM_CANNON_OBJECT_GROUP);
}

void DIMCannon_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                      s8 unusedVisible) {
    DimCannonPlacement* placement;
    DimCannonState* state;
    s16 savedRotationX;

    (void)unusedVisible;

    placement = *(DimCannonPlacement**)&obj->anim.placementData;
    if (obj->anim.romDefNo != DIM_CANNON_BALL_SEQUENCE_ID) {
        state = obj->extra;
        savedRotationX = obj->anim.rotX;
        obj->anim.rotX = (s16)(placement->rotationXByte << 8);
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        obj->anim.rotX = savedRotationX;
        ObjPath_GetPointWorldPosition(obj, 0, &state->launchOriginX, &state->launchOriginY, &state->launchOriginZ, 0);
    } else {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void DIMCannon_hitDetect(void) {
}

void DIMCannon_update(GameObject* obj) {
    DimCannonState* state;
    GameObject* player;
    DimCannonPlacement* placement = *(DimCannonPlacement**)&obj->anim.placementData;

    if (obj->anim.romDefNo == DIM_CANNON_BALL_SEQUENCE_ID) {
        DIMCannon_updateBall(obj);
        return;
    }

    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_DISABLED) && mainGetBit(placement->resetGameBit)) {
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED;
    }

    state = obj->extra;
    player = Obj_GetPlayerObject();
    if (playerGetFocusObject(player) != NULL) {
        state->targetPlayer = 0;
    } else {
        state->targetPlayer = player;
    }

    obj->anim.flags = (s16)(obj->anim.flags & ~OBJANIM_FLAG_HIDDEN);

    switch (state->mode) {
    case DIM_CANNON_MODE_WAIT_FOR_ARM:
        if (mainGetBit(placement->armGameBit)) {
            state->mode = DIM_CANNON_MODE_ARMED;
        }
        break;
    case DIM_CANNON_MODE_WAIT_FOR_RESET: {
        s8 chargeTimer = state->chargeTimer;
        if (chargeTimer > 0) {
            state->chargeTimer = (s8)(chargeTimer - framesThisStep);
        } else if (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
            CameraModeCannonInitParams cameraParams;
            state->airMeterCharge = 0;
            state->shutdownTimer = 0;
            cameraParams.target = obj;
            (*gCameraInterface)
                ->setMode(CAMERA_MODE_CANNON_RESOURCE_ID, 1, 0, sizeof(cameraParams), &cameraParams, 0x32, 0xff);
            buttonDisable(0, PAD_BUTTON_A);
            state->mode = DIM_CANNON_MODE_PLAYER_CONTROLLED;
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
            *(u8*)&state->chargeTimer = 0x3c;
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        }
        state->shouldSpawnProjectile = 0;
        state->launchDelay = 0;
        state->shotCooldown = 0;
        break;
    }
    case DIM_CANNON_MODE_ARMED:
        DIMCannon_updateAim(obj, state->aimTargetX, state->aimTargetY, state->aimTargetZ,
                            state->targetDistance);
        if (mainGetBit(placement->resetGameBit)) {
            state->mode = DIM_CANNON_MODE_WAIT_FOR_RESET;
        } else if (state->targetPlayer != 0 && !mainGetBit(placement->holdGameBit)) {
            f32 playerDistance =
                getXZDistanceSquared(&obj->anim.worldPosX, &((GameObject*)state->targetPlayer)->anim.worldPosX);
            int triggerDistance = placement->triggerRange * lbl_803DBF10;
            if (playerDistance < triggerDistance / 100.0f) {
                state->mode = DIM_CANNON_MODE_AUTO_FIRE;
            }
        }
        state->shouldSpawnProjectile = 0;
        state->launchDelay = 0;
        state->shotCooldown = 0;
        break;
    case DIM_CANNON_MODE_AUTO_FIRE:
        if (mainGetBit(placement->resetGameBit)) {
            state->mode = DIM_CANNON_MODE_WAIT_FOR_RESET;
            break;
        }
        if (mainGetBit(placement->holdGameBit)) {
            state->mode = DIM_CANNON_MODE_ARMED;
            break;
        }
        if (state->targetPlayer != 0) {
            state->aimRefreshTimer += framesThisStep;
            if (state->aimRefreshTimer > 0xa) {
                u8 j;
                state->aimRefreshTimer = 0;
                for (j = 0; j < 9; j++) {
                    state->aimHistoryX[j] = state->aimHistoryX[j + 1];
                    state->aimHistoryY[j] = state->aimHistoryY[j + 1];
                    state->aimHistoryZ[j] = state->aimHistoryZ[j + 1];
                    if (j == 0 || state->aimHistoryY[j] > state->aimTargetY) {
                        state->aimTargetY = state->aimHistoryY[j];
                    }
                }
                state->aimHistoryX[9] = ((GameObject*)state->targetPlayer)->anim.localPosX;
                state->aimHistoryY[9] = ((GameObject*)state->targetPlayer)->anim.localPosY;
                state->aimHistoryZ[9] = ((GameObject*)state->targetPlayer)->anim.localPosZ;
                state->aimTargetX = state->aimHistoryX[0];
                state->aimTargetZ = state->aimHistoryZ[0];
            }
            if (state->launchDelay > 0) {
                state->launchDelay -= framesThisStep;
            }
            if (state->shotCooldown > 0) {
                state->shotCooldown -= framesThisStep;
            }
            state->targetDistance =
                getXZDistanceSquared(&obj->anim.worldPosX, &((GameObject*)state->targetPlayer)->anim.worldPosX);
            DIMCannon_updateAim(obj, state->aimTargetX, state->aimTargetY, state->aimTargetZ,
                                state->targetDistance);
            DIMCannon_spawnBall(obj, 0);
            {
                f32 playerDistance = state->targetDistance;
                int triggerDistance = placement->triggerRange * lbl_803DBF0C;
                if (playerDistance > triggerDistance / 100.0f) {
                    state->mode = DIM_CANNON_MODE_ARMED;
                }
            }
        } else {
            state->mode = DIM_CANNON_MODE_ARMED;
        }
        break;
    }

    gDimCannonAnimAdvanceSpeedCur = 0.025f;
    ObjAnim_AdvanceCurrentMove(obj, 0.025f, timeDelta, NULL);
}

void DIMCannon_init(GameObject* obj, DimCannonPlacement* placement) {
    ObjMsg_AllocQueue(obj, 4);

    if (obj->anim.romDefNo == DIM_CANNON_BALL_SEQUENCE_ID) {
        DimCannonBallState* state;
        ObjHitsPriorityState* hitState;
        ObjModelState* modelState;
        obj->userData1 = 0;
        modelState = obj->anim.modelState;
        if (modelState != 0) {
            modelState->flags |= 0xc10;
            modelState = obj->anim.modelState;
            modelState->flags |= 0x8000LL;
        }
        state = obj->extra;
        state->rotationZRate = randomGetRange(-0x64, 0x64);
        state->rotationYRate = randomGetRange(-0x64, 0x64);
        state->rotationXRate = randomGetRange(-0x64, 0x64);
        state->clearLatch = 1;
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        if (hitState != 0) {
            hitState->trackContactMask = 1;
        }
        obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
    } else {
        DimCannonState* state = obj->extra;
        u8 i;

        if (obj->anim.mapEventSlot == DIM_CANNON_PLAYER_CONTROLLED_MAP_EVENT_SLOT) {
            int hasActivated = 0;
            if (mainGetBit(GAMEBIT_DIM_CannonRelated0C17) && mainGetBit(GAMEBIT_DIM_CannonRelated0A21)) {
                hasActivated = 1;
            }
            state->hasActivated = hasActivated;
        }

        for (i = 0; i < 0xa; i += 5) {
            state->aimHistoryX[i + 0] = obj->anim.localPosX;
            state->aimHistoryY[i + 0] = obj->anim.localPosY;
            state->aimHistoryZ[i + 0] = obj->anim.localPosZ;
            state->aimHistoryX[i + 1] = obj->anim.localPosX;
            state->aimHistoryY[i + 1] = obj->anim.localPosY;
            state->aimHistoryZ[i + 1] = obj->anim.localPosZ;
            state->aimHistoryX[i + 2] = obj->anim.localPosX;
            state->aimHistoryY[i + 2] = obj->anim.localPosY;
            state->aimHistoryZ[i + 2] = obj->anim.localPosZ;
            state->aimHistoryX[i + 3] = obj->anim.localPosX;
            state->aimHistoryY[i + 3] = obj->anim.localPosY;
            state->aimHistoryZ[i + 3] = obj->anim.localPosZ;
            state->aimHistoryX[i + 4] = obj->anim.localPosX;
            state->aimHistoryY[i + 4] = obj->anim.localPosY;
            state->aimHistoryZ[i + 4] = obj->anim.localPosZ;
        }

        state->aimRefreshTimer = 0x80;
        state->launchSpeed = 0.0f;
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        obj->animEventCallback = DIMCannon_SeqFn;
        obj->anim.rotX = (s16)(placement->rotationXByte << 8);
        gDimCannonResource = Resource_Acquire(0x79, 1);
        if (mainGetBit(placement->resetGameBit)) {
            *(u8*)&state->chargeTimer = 0x3c;
            state->mode = DIM_CANNON_MODE_WAIT_FOR_RESET;
        }
        state->launchOriginX = obj->anim.localPosX;
        state->launchOriginY = obj->anim.localPosY;
        state->launchOriginZ = obj->anim.localPosZ;
    }

    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void DIMCannon_release(void) {
}

void DIMCannon_initialise(void) {
}

ObjectDescriptor gDIMCannonObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DIMCannon_initialise,
    (ObjectDescriptorCallback)DIMCannon_release,
    0,
    (ObjectDescriptorCallback)DIMCannon_init,
    (ObjectDescriptorCallback)DIMCannon_update,
    (ObjectDescriptorCallback)DIMCannon_hitDetect,
    (ObjectDescriptorCallback)DIMCannon_render,
    (ObjectDescriptorCallback)DIMCannon_free,
    (ObjectDescriptorCallback)DIMCannon_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)DIMCannon_getExtraSize,
};
