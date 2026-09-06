#include "dlls/objects/423.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "dlls/objects/196_Tricky.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/sky_interface.h"
#include "main/track_bbox_api.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/curve.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/gameloop_gamebit_api.h"
#include "main/obj_message.h"
#include "main/objtype.h"

/* EdibleMushroomState::flags bits */
#define EDIBLE_MUSHROOM_FLAG_ANIM_DONE 0x1  /* current move finished this frame */
#define EDIBLE_MUSHROOM_FLAG_ON_CURVE  0x2  /* follows a rom-curve path (type 4/5) */
#define EDIBLE_MUSHROOM_FLAG_GROUNDED  0x4  /* landed on a floor hit */
#define EDIBLE_MUSHROOM_FLAG_MOVING    0x8  /* nonzero root speed this frame */
#define EDIBLE_MUSHROOM_FLAG_STRUCK    0x10 /* hit by the player this cycle */

#define EDIBLE_MUSHROOM_MESSAGE_IN_RANGE 0x7000A

#define EDIBLE_MUSHROOM_GROUP_ID           0x47
#define EDIBLE_MUSHROOM_SECONDARY_GROUP_ID 0x31

/* Retail OBJECTS.bin remap alias for SH_whitemus (object definition 0x02B0). */
#define EDIBLE_MUSHROOM_WHITE_ALIAS_ID 0x658
/* Retail OBJECTS.bin remap alias for DR_EarthWar (object definition 0x0431). */
#define EDIBLE_MUSHROOM_EARTH_WARRIOR_ALIAS_ID 0x416

/* Effect emitted on the tailSwingFxTimer tick while idle and rendered. */
#define EDIBLE_MUSHROOM_PARTFX_TAIL_SWING 0x7F0
/* Spore puff emitted on the sporePuffTimer tick during the burrow/attack state. */
#define EDIBLE_MUSHROOM_PARTFX_SPORE_PUFF 0x51D

s16 gEdibleMushroomStateMoveIds[12] = {0, 1, 6, 2, 3, 4, 0, 5, 6, 7, -1, 0};

f32 gEdibleMushroomAnimStepScaleTable[] = {0.005f, 0.01f, 0.005f, 0.01f,  0.01f, 0.015f,
                                           0.005f, 0.01f, 0.005f, 0.012f, 0.0f};

ObjectDescriptor gEdibleMushroomObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)EdibleMushroom_init,
    (ObjectDescriptorCallback)EdibleMushroom_update,
    (ObjectDescriptorCallback)EdibleMushroom_hitDetect,
    0,
    (ObjectDescriptorCallback)EdibleMushroom_free,
    0,
    EdibleMushroom_getExtraSize,
};

int EdibleMushroom_animEventCallback(GameObject* obj) {
    ((EdibleMushroomState*)obj->extra)->seqResetPending = 1;
    return 0;
}

void EdibleMushroom_updateBehavior(GameObject* obj, EdibleMushroomState* state, EdibleMushroomPlacement* placement) {
    GameObject* player;
    int sval;
    u32 animState;
    int curMove;
    int moveId;
    int bit;
    f32 dz;
    f32 dx;
    f32 speed;
    f32 rangeSq;
    f32 timer;
    s16 ang;
    ObjAnimEventList animEvents;
    PartFxSpawnParams partfxBlock;
    f32 sunTime;

    player = Obj_GetPlayerObject();

    if (state->flags & EDIBLE_MUSHROOM_FLAG_GROUNDED) {
        state->animState = 6;
    }

    speed = oneOverTimeDelta * (state->previousTargetDistance - state->currentTargetDistance);

    sval = state->animState;
    switch (sval) {
    case 0:
        if (state->flags & EDIBLE_MUSHROOM_FLAG_STRUCK) {
            state->animState = 9;
        } else if ((*gSkyInterface)->getSunPosition(&sunTime) == 0) {
            if (state->currentTargetDistance < placement->lungeTriggerDistance) {
                if (state->flags & EDIBLE_MUSHROOM_FLAG_ON_CURVE) {
                    rangeSq = state->lungeRange * state->lungeRange;
                    while (1) {
                        dx = state->curve.posX - obj->anim.localPosX;
                        dz = state->curve.posZ - obj->anim.localPosZ;
                        if (!(dx * dx + dz * dz < rangeSq)) {
                            break;
                        }
                        if (Curve_AdvanceAlongPath(&state->curve.curve, state->curveAdvanceStep) != 0 ||
                            state->curve.atSegmentEnd != 0) {
                            (*gRomCurveInterface)->goNextPoint(&state->curve);
                        }
                    }
                    ang = getAngle(-dx, -dz);
                    state->moveAngle = ang;
                } else {
                    state->moveAngle = EdibleMushroom_findClearApproachAngle(obj, player, state, state->lungeRange);
                }
                state->animState = 1;
                Sfx_PlayFromObject(obj, SFXTRIG_mushrele16);
                obj->anim.rotX = (s16)(state->moveAngle - 0x4000);
            } else if (state->currentTargetDistance < placement->retreatTriggerDistance) {
                state->animState = 3;
            }
        } else {
            timer = (state->tailSwingFxTimer -= timeDelta);
            if (timer <= 0.0f) {
                if (obj->objectFlags & OBJECT_OBJFLAG_RENDERED) {
                    partfxBlock.posX = obj->anim.worldPosX;
                    partfxBlock.posY = 18.0f + obj->anim.worldPosY;
                    partfxBlock.posZ = obj->anim.worldPosZ;
                    (*gPartfxInterface)
                        ->spawnObject(obj, EDIBLE_MUSHROOM_PARTFX_TAIL_SWING, &partfxBlock, 0x200001, -1, NULL);
                }
                state->tailSwingFxTimer = 30.0f;
            }
        }
        break;
    case 1:
        if (state->flags & EDIBLE_MUSHROOM_FLAG_STRUCK) {
            state->animState = 9;
        } else if (state->flags & EDIBLE_MUSHROOM_FLAG_ANIM_DONE) {
            state->animState = 0;
        }
        break;
    case 3:
    case 7:
        if (state->flags & EDIBLE_MUSHROOM_FLAG_STRUCK) {
            state->animState = 9;
            break;
        }
        if (state->flags & EDIBLE_MUSHROOM_FLAG_ANIM_DONE) {
            if (sval == 3u) {
                state->animState = 4;
            } else {
                state->animState = 0;
            }
            break;
        }
        /* fall through */
    case 4:
        if (state->flags & EDIBLE_MUSHROOM_FLAG_STRUCK) {
            state->animState = 9;
        } else {
            ang = getAngle(-(obj->anim.localPosX - player->anim.localPosX),
                           -(obj->anim.localPosZ - player->anim.localPosZ));
            obj->anim.rotX = ang;
            if (state->currentTargetDistance > 10.0f + placement->retreatTriggerDistance) {
                state->animState = 7;
            } else if (state->currentTargetDistance < placement->lungeTriggerDistance) {
                Sfx_PlayFromObject(obj, SFXTRIG_mushrele16);
                if (speed >= 0.54f) {
                    if (state->flags & EDIBLE_MUSHROOM_FLAG_ON_CURVE) {
                        rangeSq = state->lungeRange * state->lungeRange;
                        while (1) {
                            dx = state->curve.posX - obj->anim.localPosX;
                            dz = state->curve.posZ - obj->anim.localPosZ;
                            if (!(dx * dx + dz * dz < rangeSq)) {
                                break;
                            }
                            if (Curve_AdvanceAlongPath(&state->curve.curve, state->curveAdvanceStep) != 0 ||
                                state->curve.atSegmentEnd != 0) {
                                (*gRomCurveInterface)->goNextPoint(&state->curve);
                            }
                        }
                        ang = getAngle(-dx, -dz);
                        state->moveAngle = ang;
                    } else {
                        state->moveAngle = EdibleMushroom_findClearApproachAngle(obj, player, state, state->lungeRange);
                    }
                    state->animState = 1;
                    obj->anim.rotX = (s16)(state->moveAngle - 0x4000);
                } else {
                    if (state->flags & EDIBLE_MUSHROOM_FLAG_ON_CURVE) {
                        rangeSq = state->retreatRange * state->retreatRange;
                        while (1) {
                            dx = state->curve.posX - obj->anim.localPosX;
                            dz = state->curve.posZ - obj->anim.localPosZ;
                            if (!(dx * dx + dz * dz < rangeSq)) {
                                break;
                            }
                            if (Curve_AdvanceAlongPath(&state->curve.curve, state->curveAdvanceStep) != 0 ||
                                state->curve.atSegmentEnd != 0) {
                                (*gRomCurveInterface)->goNextPoint(&state->curve);
                            }
                        }
                        ang = getAngle(-dx, -dz);
                        state->moveAngle = ang;
                    } else {
                        state->moveAngle =
                            EdibleMushroom_findClearApproachAngle(obj, player, state, state->retreatRange);
                    }
                    state->animState = 5;
                    obj->anim.rotX = state->moveAngle;
                }
            }
        }
        break;
    case 5:
        if ((state->flags & (EDIBLE_MUSHROOM_FLAG_STRUCK | EDIBLE_MUSHROOM_FLAG_ANIM_DONE)) ==
            (EDIBLE_MUSHROOM_FLAG_STRUCK | EDIBLE_MUSHROOM_FLAG_ANIM_DONE)) {
            state->animState = 9;
        }
        if (state->currentTargetDistance > 10.0f + placement->lungeTriggerDistance &&
            (state->flags & EDIBLE_MUSHROOM_FLAG_ANIM_DONE)) {
            state->animState = 4;
        } else if (speed >= 0.54f) {
            if (state->flags & EDIBLE_MUSHROOM_FLAG_ON_CURVE) {
                rangeSq = state->lungeRange * state->lungeRange;
                while (1) {
                    dx = state->curve.posX - obj->anim.localPosX;
                    dz = state->curve.posZ - obj->anim.localPosZ;
                    if (!(dx * dx + dz * dz < rangeSq)) {
                        break;
                    }
                    if (Curve_AdvanceAlongPath(&state->curve.curve, state->curveAdvanceStep) != 0 ||
                        state->curve.atSegmentEnd != 0) {
                        (*gRomCurveInterface)->goNextPoint(&state->curve);
                    }
                }
                ang = getAngle(-dx, -dz);
                state->moveAngle = ang;
            } else {
                state->moveAngle = EdibleMushroom_findClearApproachAngle(obj, player, state, state->lungeRange);
            }
            state->animState = 1;
            Sfx_PlayFromObject(obj, SFXTRIG_mushrele16);
            obj->anim.rotX = (s16)(state->moveAngle - 0x4000);
        }
        break;
    case 9:
        ObjHits_ClearSourceMask((ObjAnimComponent*)obj, 1);
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_cagelp_c);
        if (state->burrowAttackTimer <= 0.0f) {
            state->burrowAttackTimer = randomGetRange(0xF0, 0x12C);
        }
        timer = state->burrowAttackTimer - timeDelta;
        state->burrowAttackTimer = timer;
        if (timer <= 0.0f) {
            ObjHits_SetSourceMask((ObjAnimComponent*)obj, 1);
            (*gExpgfxInterface)->freeSource((int)obj);
            state->animState = 0;
            state->flags &= ~EDIBLE_MUSHROOM_FLAG_STRUCK;
        } else {
            timer = state->sporePuffTimer - timeDelta;
            state->sporePuffTimer = timer;
            if (timer <= 0.0f) {
                partfxBlock.posX = 10.0f;
                partfxBlock.posY = 12.0f;
                if (obj->objectFlags & OBJECT_OBJFLAG_RENDERED) {
                    (*gPartfxInterface)->spawnObject(obj, EDIBLE_MUSHROOM_PARTFX_SPORE_PUFF, &partfxBlock, 2, -1, NULL);
                }
                state->sporePuffTimer = 20.0f;
            }
            if (mainGetBit(GAMEBIT_ITEM_TrickyFood_GrabInProgress) == 0) {
                if (!(player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK)) {
                    if (Vec_xzDistance(&player->anim.worldPosX, &obj->anim.worldPosX) < 25.0f) {
                        (*gExpgfxInterface)->freeSource((int)obj);
                        if (obj->anim.romDefNo == EDIBLE_MUSHROOM_WHITE_ALIAS_ID) {
                            state->pickupMsgBitId = 0x18A;
                            itemPickupDoParticleFx(obj, 1.0f, 0xFF, 0x28);
                        } else {
                            state->pickupMsgBitId = 0x119;
                            itemPickupDoParticleFx(obj, 1.0f, 6, 0x28);
                        }
                        state->pickupMsgValue = 0;
                        state->pickupMsgDelay = 0.4f;
                        ObjMsg_SendToObject(player, EDIBLE_MUSHROOM_MESSAGE_IN_RANGE, obj, (u32)&state->pickupMsgBitId);
                        bit = placement->gameBitId;
                        if (bit != -1) {
                            mainSetBits(bit, 1);
                        }
                        state->animState = 8;
                        mainSetBits(GAMEBIT_ITEM_TrickyFood_GrabInProgress, 1);
                    }
                }
            }
        }
        break;
    case 6:
        if (state->flags & EDIBLE_MUSHROOM_FLAG_STRUCK) {
            state->animState = 9;
        }
        break;
    case 2:
    case 8:
    case 10:
        break;
    }

    curMove = obj->anim.currentMove;
    moveId = gEdibleMushroomStateMoveIds[state->animState];
    if (curMove != moveId && moveId != -1) {
        ObjAnim_SetCurrentMove(obj, moveId, 0.25f, 0);
    }

    if (ObjAnim_AdvanceCurrentMove(obj, gEdibleMushroomAnimStepScaleTable[state->animState], timeDelta,
                                   &animEvents) != 0) {
        state->flags |= EDIBLE_MUSHROOM_FLAG_ANIM_DONE;
    } else {
        state->flags &= ~EDIBLE_MUSHROOM_FLAG_ANIM_DONE;
    }

    animState = state->animState;
    if (animState == 1) {
        speed = state->lungeRootSpeedScale * (animEvents.rootDeltaX * oneOverTimeDelta);
    } else if (animState == 5) {
        speed = animEvents.rootDeltaZ * oneOverTimeDelta;
    } else {
        speed = 0.0f;
    }

    if (speed != 0.0f) {
        state->flags |= EDIBLE_MUSHROOM_FLAG_MOVING;
    } else {
        state->flags &= ~EDIBLE_MUSHROOM_FLAG_MOVING;
    }

    obj->anim.velocityX = speed * mathSinf((3.1415927f * (f32)state->moveAngle) / 32768.0f);
    obj->anim.velocityZ = speed * mathCosf((3.1415927f * (f32)state->moveAngle) / 32768.0f);

    objMove(obj, obj->anim.velocityX * timeDelta, 0.0f, obj->anim.velocityZ * timeDelta);
}

s16 EdibleMushroom_findClearApproachAngle(GameObject* obj, GameObject* player, EdibleMushroomState* state, f32 dist) {
    s16 angle;
    s16 anglePlus;
    s16 angleMinus;
    int i;
    f32 rad;
    f32 sin0;
    f32 cos0;
    f32 sinM;
    f32 sinP;
    f32 cosM;
    f32 cosP;
    f32 sinStepP;
    f32 sinStepM;
    f32 cosStepP;
    f32 cosStepM;
    f32 vec[3];

    angle = getAngle(-(obj->anim.localPosX - player->anim.localPosX), -(obj->anim.localPosZ - player->anim.localPosZ));
    rad = (3.1415927f * angle) / 32768.0f;
    sin0 = mathSinf(rad);
    cos0 = mathCosf(rad);
    vec[0] = obj->anim.localPosX - dist * sin0;
    vec[1] = obj->anim.localPosY;
    vec[2] = obj->anim.localPosZ - dist * cos0;
    if (trackGetLineIntersect(&obj->anim.localPosX, vec, 0.1f, 3, NULL, obj, 8, -1, 0xFF, 0) != 0) {
        anglePlus = angle;
        angleMinus = angle;
        sinM = sin0;
        sinP = sin0;
        sinStepP = mathSinf(0.34898064f);
        sinStepM = mathSinf(-0.34898064f);
        cosP = cos0;
        cosM = cos0;
        cosStepP = mathCosf(0.34898064f);
        cosStepM = mathCosf(-0.34898064f);
        for (i = 0; i < 8; i++) {
            f32 sinNext;

            anglePlus += 0xE38;
            sinNext = sinP * cosStepP + cosP * sinStepP;
            cosP = cosP * cosStepP - sinP * sinStepP;
            sinP = sinNext;
            vec[0] = obj->anim.localPosX - dist * sinNext;
            vec[2] = obj->anim.localPosZ - dist * cosP;
            if (trackGetLineIntersect(&obj->anim.localPosX, vec, 0.1f, 1, NULL, obj, 8, -1, 0xFF, 0) == 0) {
                return anglePlus;
            }
            angleMinus -= 0xE38;
            sinNext = sinM * cosStepM + cosM * sinStepM;
            cosM = cosM * cosStepM - sinM * sinStepM;
            sinM = sinNext;
            vec[0] = obj->anim.localPosX - dist * sinNext;
            vec[2] = obj->anim.localPosZ - dist * cosM;
            if (trackGetLineIntersect(&obj->anim.localPosX, vec, 0.1f, 1, NULL, obj, 8, -1, 0xFF, 0) == 0) {
                return angleMinus;
            }
        }
    }
    return angle;
}

int EdibleMushroom_getExtraSize(void) {
    return sizeof(EdibleMushroomState);
}

void EdibleMushroom_free(GameObject* obj) {
    objFreeObjectType(obj, EDIBLE_MUSHROOM_GROUP_ID);
    objFreeObjectType(obj, EDIBLE_MUSHROOM_SECONDARY_GROUP_ID);
}

void EdibleMushroom_hitDetect(GameObject* obj) {
    EdibleMushroomState* state;
    EdibleMushroomPlacement* placement;
    int hitCount;
    TrackGroundHit** hits;
    int i;
    TrackLineIntersectResult bboxHit;

    state = obj->extra;
    placement = (EdibleMushroomPlacement*)obj->anim.placementData;

    if (((obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) &&
        (((state->flags & EDIBLE_MUSHROOM_FLAG_MOVING) != 0) ||
         ((((ObjHitsPriorityState*)obj->anim.hitReactState)->flags & OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED) !=
          0))) {
        hitCount =
            trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &hits, 0, 0);
        for (i = 0; i < hitCount; i++) {
            if (hits[i]->height < 10.0f + obj->anim.localPosY) {
                obj->anim.localPosY = hits[i]->height;
                break;
            }
        }

        hitCount = trackGetLineIntersect(&obj->anim.previousLocalPosX, &obj->anim.localPosX, 6.0f, 2, &bboxHit, obj, 8, -1,
                                      0xFF, 0x14);
        if ((placement->objectType == 4) && (hitCount != 0) && (bboxHit.surfaceType == 13)) {
            state->flags |= EDIBLE_MUSHROOM_FLAG_GROUNDED;
        }
    }
}

void EdibleMushroom_update(GameObject* obj) {
    EdibleMushroomState* state;
    EdibleMushroomPlacement* placement;
    GameObject* player;
    GameObject* enemy;
    GameObject* hitObj;
    int msg;
    int hitKind;
    f32 distState;
    f32 distEnemy;

    state = obj->extra;
    placement = (EdibleMushroomPlacement*)obj->anim.placementData;
    player = Obj_GetPlayerObject();
    enemy = getTrickyObject();

    if (objIsFrozen(obj) != 0) {
        return;
    }

    if (state->animState == 8) {
        while (ObjMsg_Pop(obj, (u32*)&msg, 0, 0) != 0) {
            if (((u32)msg - 0x70000) != 0xB) {
                continue;
            }
            obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
            ObjHits_DisableObject(obj);
            gameBitIncrement(state->collectedGameBitId);
            mainSetBits(GAMEBIT_ITEM_TrickyFood_GrabInProgress, 0);
            if (obj->anim.romDefNo == EDIBLE_MUSHROOM_WHITE_ALIAS_ID) {
                itemPickupDoParticleFx(obj, 1.0f, 0xFF, 0x28);
            } else {
                itemPickupDoParticleFx(obj, 1.0f, 6, 0x28);
            }
            Sfx_PlayFromObject(obj, SFXTRIG_cam90_c);
        }
        return;
    }

    if (state->seqResetPending != 0) {
        obj->anim.localPosX = placement->base.posX;
        obj->anim.localPosY = placement->base.posY;
        obj->anim.localPosZ = placement->base.posZ;
        obj->anim.alpha = 0xFF;
        state->seqResetPending = 0;
    }

    state->previousTargetDistance = state->currentTargetDistance;
    distState = vec3f_distanceSquared(&player->anim.worldPosX, &obj->anim.worldPosX);
    if (enemy == NULL) {
        state->currentTargetDistance = sqrtf(distState);
    } else {
        distEnemy = vec3f_distanceSquared(&enemy->anim.worldPosX, &obj->anim.worldPosX);
        if (distState < distEnemy) {
            state->currentTargetDistance = sqrtf(distState);
        } else {
            state->currentTargetDistance = sqrtf(distEnemy);
        }
        if (state->currentTargetDistance < (f32)(u32)placement->retreatTriggerDistance) {
            TRICKY_INTERFACE(enemy)->sideCommandEnable(enemy, obj, TRICKY_COMMAND_KIND_NORMAL,
                                                       TRICKY_COMMAND_TYPE_FIND_SECRET);
        }
    }

    hitKind = ObjHits_GetPriorityHit(obj, &hitObj, 0, 0);
    if (hitKind != 0) {
        if (hitKind == 0x10) {
            Obj_StartModelFadeIn(obj, 0x12C);
        } else {
            Obj_SetModelColorFadeRecursive(obj, 0xF, 0xC8, 0, 0, 1);
            if (hitObj->anim.romDefNo != EDIBLE_MUSHROOM_EARTH_WARRIOR_ALIAS_ID) {
                if ((state->flags & EDIBLE_MUSHROOM_FLAG_STRUCK) == 0) {
                    Sfx_PlayFromObject(obj, SFXTRIG_mv_ladderslide16);
                }
                state->flags = (u8)(state->flags | EDIBLE_MUSHROOM_FLAG_STRUCK);
            }
        }
    }
    EdibleMushroom_updateBehavior(obj, state, placement);
}

void EdibleMushroom_init(GameObject* obj, EdibleMushroomPlacement* placement) {
    EdibleMushroomState* state;
    GameObject* player;
    int curveInitParam;
    ObjAnimEventList animEvents;
    f32 dist;

    state = obj->extra;
    curveInitParam = 0x19;
    player = Obj_GetPlayerObject();

    obj->animEventCallback = EdibleMushroom_animEventCallback;
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HIDDEN);

    if (mainGetBit(placement->gameBitId) != 0) {
        state->animState = 8;
        ObjHits_DisableObject(obj);
        obj->anim.flags = (short)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
    }

    obj->anim.modelState->flags |= 0x810;

    state->lungeRootSpeedScale = 0.5f;
    state->mapParamScale = 0.2f * ((f32)placement->scaleParam / 255.0f);

    ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
    ObjAnim_AdvanceCurrentMove(obj, 1.0f, 1.0f, &animEvents);
    state->lungeRange = animEvents.rootDeltaX;
    if (state->lungeRange < 0.0f) {
        state->lungeRange = -state->lungeRange;
    }
    state->lungeRange = state->lungeRange * state->lungeRootSpeedScale;
    state->lungeRange += 20.0f;

    ObjAnim_SetCurrentMove(obj, 4, 0.0f, 0);
    ObjAnim_AdvanceCurrentMove(obj, 1.0f, 1.0f, &animEvents);
    state->retreatRange = animEvents.rootDeltaZ;
    if (state->retreatRange < 0.0f) {
        state->retreatRange = -state->retreatRange;
    }
    state->retreatRange += 20.0f;

    ObjMsg_AllocQueue(obj, 1);

    {
        int v = placement->objectType;
        switch (v) {
        case 4:
        case 5:
            state->flags |= EDIBLE_MUSHROOM_FLAG_ON_CURVE;
            (*gRomCurveInterface)->initCurve((void*)state, (void*)obj, 1000.0f, &curveInitParam, -1);
            obj->anim.localPosX = state->curve.posX;
            obj->anim.localPosZ = state->curve.posZ;
            break;
        }
    }

    state->curveAdvanceStep = 5.0f;

    if (player != NULL) {
        dist = Vec_distance(&player->anim.worldPosX, &obj->anim.worldPosX);
        state->currentTargetDistance = dist;
        state->previousTargetDistance = dist;
    } else {
        f32 z = 200.0f;
        state->currentTargetDistance = z;
        state->previousTargetDistance = z;
    }

    objAddObjectType(obj, EDIBLE_MUSHROOM_SECONDARY_GROUP_ID);
    objAddObjectType(obj, EDIBLE_MUSHROOM_GROUP_ID);

    if (obj->anim.romDefNo == EDIBLE_MUSHROOM_WHITE_ALIAS_ID) {
        state->collectedGameBitId = GAMEBIT_ITEM_WhiteShroom_Count;
    } else {
        state->collectedGameBitId = GAMEBIT_ITEM_TrickyFood_Count;
    }
}
