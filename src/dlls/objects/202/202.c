/*
 * Unused GroundBaddie-derived enemy in the ChukChuk/IceBall family.
 *
 * Slot 202 has no retail object name; the iceBaddie namespace is descriptive.
 */
#include "dlls/objects/202.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/camera_shake_api.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"
#include "main/vecmath.h"
#include "main/voxmaps.h"
#include "string.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/dll/baddie_state.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/wispbaddie_baddie.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/baddie_setmove.h"
#include "main/pad_api.h"
#include "main/dll/seqobj11d_ext.h"
#include "main/dll/wispbaddieseq_ext.h"
#include "main/gameloop_api.h"
#include "main/audio/sfx.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/gamebits.h"
#include "main/dll/objfsa.h"
#include "main/dll/newseqobj_baddie.h"
#include "main/dll/baddie_frozen.h"
#include "main/game_ui_interface.h"
#include "main/dll/tricky_api.h"
#include "main/model.h"
#include "main/object_transform.h"
#include "main/dll/player_target.h"
#include "main/dll/player_api.h"
#include "dlls/objects/225_WispBaddie.h"
#include "main/trig_float_helpers.h"
#include "main/obj_link.h"
#include "main/objfx.h"
#include "main/objtexture.h"
#include "main/dll/seqObj11E.h"
#include "main/dll/groundbaddiepush_ext.h"
#include "main/dll/dll_00C9_enemy_ext.h"
#include "dlls/objects/336_GCRobotLigh.h"
#include "dolphin/mtx.h"
#include "main/dll/mikaladon.h"
#include "main/dll/magicPlant.h"
#include "main/dll/kooshy.h"
#include "main/dll/weevil.h"
#include "main/trig.h"
#include "main/dll/waterfx_interface.h"
#include "main/dll/fall_ladders.h"
#include "main/dll/fireflyLantern.h"
#include "main/dll/duster_api.h"
#include "main/track_bbox_api.h"
#include "main/sky_interface.h"
#include "main/dll/duster.h"
#include "dlls/objects/216_PinPonSpike.h"
#include "main/dll/duster_wb.h"
#include "main/obj_query.h"
#include "main/dll/hoodedzyck.h"
#include "main/camera_interface.h"
#include "main/model_light.h"
#include "main/dll/firecrawler.h"
#include "main/dll/dll_0273_firepipe.h"
#include "main/dll/hagabon_mk2.h"
#include "main/dll/snowworm.h"
#include "main/dll/baddiewhirlpool.h"

/* Baddie-family animation data shared with the sequence-driver TUs. */

typedef struct IceBaddieControl {
    f32 hitTimer;               /* 0x00 */
    s16 attackPatternIndex;     /* 0x04 */
    s16 consecutiveHitCount;    /* 0x06 */
    f32 projectileTransform[6]; /* 0x08 */
    f32 particlePositionX;      /* 0x20 */
    f32 particlePositionY;      /* 0x24 */
    f32 fxScale;                /* 0x28 */
    f32 effectPosition[3];      /* 0x2C */
    f32 projectileVelocity[3];  /* 0x38 */
    u8 effectFlags;             /* 0x44 */
    u8 pad45;                   /* 0x45 */
    u16 ambientSfxTimer;        /* 0x46 */
} IceBaddieControl;

typedef struct IceBallSetup {
    ObjPlacement base; /* 0x00 */
    u8 pad18[0x1e - 0x18];
    s16 gameBit;          /* 0x1E */
    s16 secondaryGameBit; /* 0x20 */
    u8 pad22[0x24 - 0x22];
} IceBallSetup;

STATIC_ASSERT(offsetof(IceBaddieControl, attackPatternIndex) == 0x4);

STATIC_ASSERT(offsetof(IceBaddieControl, particlePositionX) == 0x20);

STATIC_ASSERT(offsetof(IceBaddieControl, effectPosition) == 0x2C);

STATIC_ASSERT(offsetof(IceBaddieControl, projectileVelocity) == 0x38);

STATIC_ASSERT(offsetof(IceBaddieControl, effectFlags) == 0x44);

STATIC_ASSERT(sizeof(IceBaddieControl) == 0x48);

STATIC_ASSERT(offsetof(IceBallSetup, gameBit) == 0x1E);

STATIC_ASSERT(offsetof(IceBallSetup, secondaryGameBit) == 0x20);

STATIC_ASSERT(sizeof(IceBallSetup) == 0x24);

#define ICEBADDIE_OBJGROUP 3

#define ICEBADDIE_FX_SPAWN_ICEBALL 0x01 /* fire the armed ice-ball projectile */

#define ICEBADDIE_FX_ARM_ICEBALL   0x02 /* stash spawn transform, then request SPAWN_ICEBALL */

#define ICEBADDIE_FX_BURST         0x04 /* 4x contact particle (obj 0x56) */

#define ICEBADDIE_FX_PUFF          0x08 /* one puff particle (obj 0x57) */

#define ICEBADDIE_FX_IMPACT        0x10 /* camera shake + 0x28x particle 0x57 */

#define ICEBADDIE_FX_LANDING       0x20 /* bigger shake + 0x57 burst + 0x58 debris (anim event 0x200) */

#define ICEBADDIE_CHILD_OBJ_ICEBALL 100

#define ICEBADDIE_PARTICLE_CONTACT 0x56 /* 4x contact particle */

#define ICEBADDIE_PARTICLE_PUFF    0x57 /* puff / impact burst particle */

#define ICEBADDIE_PARTICLE_DEBRIS  0x58 /* landing debris particle */

void iceBaddie_spawnIceBall(GameObject* obj, IceBaddieControl* control);

void iceBaddie_updateControlEffects(GameObject* obj, GroundBaddieState* state);

void iceBaddie_tryAcquireTarget(GameObject* obj, GroundBaddieState* objectState, GroundBaddieState* state);

void iceBaddie_updateTargetMotion(GameObject* obj, GroundBaddieState* objectState, GroundBaddieState* state);

void iceBaddie_updateTargetCollision(GameObject* obj, int stateAddress, GroundBaddieState* state);

u8 gIceBaddieA06MoveVariant;

u8 gIceBaddieA05MoveVariant;

s16 gIceBaddieAttackMoves[8] = {5, 6, 8, 6, 5, 8, 6, 0};

s16 gIceBaddieAttackMovesAlt[8] = {8, 6, 9, 8, 6, 9, 9, 0};

int gIceBaddieHitReactionMoves[30] = {
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 12,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
};

u8 gIceBaddieHitReactionDamage[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
};

u8 gIceBaddieParticleArgsTable[16] = {
    0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0xC0, 0x96, 0x5A, 0x5A, 0x64, 0xFF, 0x5A, 0x00, 0x00,
};

u8 gIceBaddiePaletteIndexTable[32] = {
    0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
};

int iceBaddie_stateHandlerB07(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;

    if ((s8)state->baddie.moveJustStartedB != 0) {
        if ((s32)state->baddie.targetDistance > 0x37) {
            if ((objectState->configFlags & 2) == 0) {
                (*gPlayerInterface)->setState(obj, state, 7);
            } else {
                IceBaddieControl* control = (IceBaddieControl*)objectState->control;
                if ((objectState->configFlags & 0x10) != 0) {
                    (*gPlayerInterface)->setState(obj, state, gIceBaddieAttackMovesAlt[control->attackPatternIndex++]);
                } else {
                    (*gPlayerInterface)->setState(obj, state, gIceBaddieAttackMoves[control->attackPatternIndex++]);
                }
                if (control->attackPatternIndex >= 7) {
                    control->attackPatternIndex = 0;
                }
            }
        } else {
            if (state->baddie.controlMode == 6) {
                (*gPlayerInterface)->setState(obj, state, 5);
            } else {
                (*gPlayerInterface)->setState(obj, state, 6);
            }
        }
    } else if (state->baddie.moveDone != 0) {
        if (((*gBaddieControlInterface)->getClearDirectionMask(obj, state, 75.0f) & 1) == 0) {
            return 5;
        }
        if ((*gBaddieControlInterface)->shouldDropTarget(obj, state, objectState->aggroRange, 1) != 0) {
            return 5;
        }
        if ((s32)state->baddie.targetDistance > 0x37) {
            if ((objectState->configFlags & 2) == 0) {
                (*gPlayerInterface)->setState(obj, state, 7);
            } else {
                IceBaddieControl* control = (IceBaddieControl*)objectState->control;
                if ((objectState->configFlags & 0x10) != 0) {
                    (*gPlayerInterface)->setState(obj, state, gIceBaddieAttackMovesAlt[control->attackPatternIndex++]);
                } else {
                    (*gPlayerInterface)->setState(obj, state, gIceBaddieAttackMoves[control->attackPatternIndex++]);
                }
                if (control->attackPatternIndex >= 7) {
                    control->attackPatternIndex = 0;
                }
            }
        } else {
            if (state->baddie.controlMode == 6) {
                (*gPlayerInterface)->setState(obj, state, 5);
            } else {
                (*gPlayerInterface)->setState(obj, state, 6);
            }
        }
    } else if (state->baddie.controlMode == 7 && (s32)state->baddie.targetDistance < 0x37) {
        if (state->baddie.controlMode == 6) {
            (*gPlayerInterface)->setState(obj, state, 5);
        } else {
            (*gPlayerInterface)->setState(obj, state, 6);
        }
    }
    return 0;
}

int iceBaddie_stateHandlerB06(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;
    RouteNav* route;
    f32 neutralBlend;

    if (state->baddie.moveDone != 0 &&
        (((*gBaddieControlInterface)->getClearDirectionMask(obj, state, 75.0f) & 1) == 0)) {
        return 5;
    }
    if ((s8)state->baddie.moveJustStartedB != 0) {
        (*gPlayerInterface)->setState(obj, state, 0xb);
    } else if (objectState->targetState == 3) {
        (*gPlayerInterface)->setState(obj, state, 4);
    } else if (objectState->targetState == 4) {
        if (state->baddie.targetDistance < 110.0f && state->baddie.moveDone != 0) {
            if (objectState->aggression > 50) {
                (*gPlayerInterface)->setState(obj, state, 0);
            } else {
                (*gPlayerInterface)->setState(obj, state, 1);
            }
        }
    } else if (objectState->targetState == 1) {
        return 8;
    }
    route = &objectState->routeNav;
    neutralBlend = 0.0f;
    state->baddie.moveInputX = neutralBlend;
    state->baddie.moveInputZ = neutralBlend;
    memcpy(route, &obj->anim.localPosX, 0xc);
    memcpy((void*)objectState->routeNav.curPos, (void*)&((GameObject*)state->baddie.targetObj)->anim.localPosX, 0xc);
    voxmaps_updateRoutePath(&objectState->routeNav, &objectState->routeState);
    if (route->flag25 == 0) {
        (*gPlayerInterface)->moveTowardPoint(obj, state, route->tgtPos[0], route->tgtPos[2], 0.0f, 0.0f, 60.0f);
    } else {
        (*gPlayerInterface)->moveTowardPoint(obj, state, route->tgtPos[0], route->tgtPos[2], 15.0f, 30.0f, 60.0f);
    }
    if (state->baddie.stateTimer > 0x78 &&
        (*gBaddieControlInterface)->shouldDropTarget(obj, state, objectState->aggroRange, 1) != 0) {
        return 5;
    }
    return 0;
}

int iceBaddie_stateHandlerB05(GameObject* obj, GroundBaddieState* state) {
    if ((s8)state->baddie.moveJustStartedB != 0) {
        (*gPlayerInterface)->setState(obj, state, 3);
    }
    if (state->baddie.moveDone != 0) {
        if (state->baddie.controlMode == 3) {
            (*gPlayerInterface)->setState(obj, state, 0);
        } else {
            return 8;
        }
    }
    return 0;
}

int iceBaddie_stateHandlerB04(GameObject* obj, GroundBaddieState* state) {
    if ((s8)state->baddie.moveJustStartedB != 0) {
        (*gPlayerInterface)->setState(obj, state, 2);
    }
    return 0;
}

int iceBaddie_stateHandlerB03(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState;

    if ((s8)state->baddie.moveJustStartedB != 0) {
        objectState = obj->extra;
        objectState->subMode = 0;
        mainSetBits((s32)objectState->gameBitB, 0);
        mainSetBits((s32)objectState->gameBitA, 1);
    }
    return 0;
}

int iceBaddie_stateHandlerB02(GameObject* obj, GroundBaddieState* state) {
    if ((s8)state->baddie.moveJustStartedB != 0) {
        (*gPlayerInterface)->setState(obj, state, 0xd);
        state->baddie.targetObj = NULL;
        state->baddie.physicsActive = 0;
        state->baddie.hasTarget = 0;
        ObjHits_DisableObject(obj);
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    } else if (state->baddie.moveDone != 0) {
        ObjMsg_SendToObjects(0, 3, obj, 0xe0000, (int)obj);
        if (obj->anim.placementData == NULL) {
            Obj_FreeObject(obj);
            return 0;
        }
        return 4;
    }
    return 0;
}

int iceBaddie_stateHandlerB01(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;

    if (state->baddie.hitPoints < 1) {
        return 3;
    }
    if (state->baddie.moveDone != 0) {
        if (state->baddie.controlMode == 12) {
            if (objectState->aggression > 50) {
                (*gPlayerInterface)->setState(obj, state, 0);
            } else {
                (*gPlayerInterface)->setState(obj, state, 1);
            }
        } else {
            return 8;
        }
    }
    return 0;
}

int iceBaddie_checkTargetState(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;
    f32 neutralBlend;

    if (state->baddie.targetObj != NULL) {
        if ((s32)(s8)state->baddie.moveJustStartedB != 0) {
            neutralBlend = 0.0f;
            state->baddie.animSpeedB = neutralBlend;
            state->baddie.animSpeedA = neutralBlend;
            if ((u32)objectState->aggression > 50) {
                if (state->baddie.targetDistance < 0.5f * (f32)(u32)objectState->aggroRange ||
                    (objectState->configFlags & 0x2) != 0) {
                    (*gPlayerInterface)->setState(obj, state, 0);
                } else {
                    (*gPlayerInterface)->setState(obj, state, 1);
                }
            } else {
                (*gPlayerInterface)->setState(obj, state, 1);
            }
        }

        if ((s32)state->baddie.moveDone != 0) {
            (*gPlayerInterface)->rotateTowardTarget(obj, state, timeDelta, 4);
            if (((*gBaddieControlInterface)->getClearDirectionMask(obj, state, 75.0f) & 1) == 0) {
                return 5;
            }

            if (state->baddie.targetDistance < 0.5f * (f32)(u32)objectState->aggroRange ||
                (objectState->configFlags & 0x2) != 0) {
                return 8;
            }
            return 7;
        }
    }
    return 0;
}

int iceBaddie_updateLandingState(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;
    GameObject* player;
    f32 noBlend;

    state->baddie.stateTag = 3;
    state->baddie.moveSpeed = 0.008f;
    noBlend = 0.0f;
    state->baddie.animSpeedA = noBlend;
    state->baddie.animSpeedB = noBlend;
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 1, noBlend, 0);
        state->baddie.moveDone = 0;
    }
    if ((state->baddie.moveEventFlags & 1) == 0) {
        player = Obj_GetPlayerObject();
        if (player->anim.romDefNo != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_wp_stftest122_1f2);
        } else {
            Sfx_PlayFromObject(obj, SFXTRIG_swd);
        }
        Sfx_PlayFromObject(obj, SFXTRIG_en_rfall5_c);
        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_26f);
        state->baddie.moveEventFlags |= 1;
    }
    if ((state->baddie.moveEventFlags & 2) == 0 && obj->anim.currentMoveProgress > 0.3f) {
        Sfx_PlayFromObject(obj, SFXTRIG_wp_iceywindlp16_233);
        state->baddie.moveEventFlags |= 2;
        (*gBaddieControlInterface)->spawnChild(obj, objectState->triggerId, -1, 0);
    }
    return 0;
}

int iceBaddie_updateContactHitState(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;
    IceBaddieControl* control;
    f32 noBlend;

    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (objectState->aggression > 0x32) {
        if (state->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 4, 0.0f, 0);
            state->baddie.moveDone = 0;
        }
    } else if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0xe, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.stateTag = 3;
    state->baddie.moveSpeed = 0.008f;
    control = (IceBaddieControl*)objectState->control;
    control->effectFlags |= (ICEBADDIE_FX_BURST | ICEBADDIE_FX_PUFF);
    noBlend = 0.0f;
    state->baddie.animSpeedA = noBlend;
    state->baddie.animSpeedB = noBlend;
    if ((objectState->configFlags & 2) == 0) {
        state->baddie.animSpeedA = -1.0f + obj->anim.currentMoveProgress;
    }
    return 0;
}

int iceBaddie_stateHandlerA0B(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;
    IceBaddieControl* control;

    if (state->baddie.moveJustStartedA != 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        if (state->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 2, 0.0f, 0);
            state->baddie.moveDone = 0;
        }
        objectState->targetState = 2;
        state->baddie.stateTag = 1;
        state->baddie.moveSpeed = 0.015f;
    } else {
        if (state->baddie.moveDone != 0) {
            objectState->targetState = 3;
        }
    }
    control = (IceBaddieControl*)objectState->control;
    control->effectFlags |= ICEBADDIE_FX_BURST;
    if ((s32)(state->baddie.eventFlags & BADDIE_EVENT_LANDING) != 0) {
        state->baddie.eventFlags &= ~BADDIE_EVENT_LANDING;
        control->effectFlags |= ICEBADDIE_FX_IMPACT;
    }
    control->effectFlags |= (ICEBADDIE_FX_BURST | ICEBADDIE_FX_PUFF);
    state->baddie.animSpeedA = obj->anim.currentMoveProgress;
    return 0;
}

int iceBaddie_updateDropState(GameObject* obj, GroundBaddieState* state) {
    IceBaddieControl* control = (IceBaddieControl*)((GroundBaddieState*)obj->extra)->control;
    GameObject* player;

    control->effectFlags |= ICEBADDIE_FX_BURST;
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    if (state->baddie.moveJustStartedA != 0) {
        Obj_GetPlayerObject();
        player = Obj_GetPlayerObject();
        if (player->anim.romDefNo != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_wp_stftest122_1f2);
        } else {
            Sfx_PlayFromObject(obj, SFXTRIG_swd);
        }
        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_26e);
    }
    state->baddie.stateTag = 3;
    state->baddie.moveSpeed = 0.015f;
    state->baddie.animSpeedA = 0.0f;
    return 0;
}

int iceBaddie_updateCommDownState(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;
    IceBaddieControl* control = (IceBaddieControl*)objectState->control;

    control->effectFlags |= ICEBADDIE_FX_BURST;
    state->baddie.moveSpeed = 0.01f;
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 10, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.stateTag = 1;
    if ((state->baddie.eventFlags & BADDIE_EVENT_FOOTSTEP) != 0) {
        control = (IceBaddieControl*)objectState->control;
        state->baddie.eventFlags &= ~BADDIE_EVENT_FOOTSTEP;
        control->effectFlags |= ICEBADDIE_FX_ARM_ICEBALL;
        Sfx_PlayFromObject(obj, SFXTRIG_wp_dsmk2_c_cf);
    }
    (*gPlayerInterface)->rotateTowardTarget(obj, state, timeDelta, 4);
    return 0;
}

int iceBaddie_updateControlMove5State(GameObject* obj, GroundBaddieState* state) {
    IceBaddieControl* control = (IceBaddieControl*)((GroundBaddieState*)obj->extra)->control;
    control->effectFlags |= ICEBADDIE_FX_BURST;
    state->baddie.moveSpeed = 0.01f;
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 5, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.stateTag = 1;
    (*gPlayerInterface)->rotateTowardTarget(obj, state, timeDelta, 4);
    return 0;
}

int iceBaddie_updateHeightBlendState(GameObject* obj, GroundBaddieState* state) {
    IceBaddieControl* control = (IceBaddieControl*)((GroundBaddieState*)obj->extra)->control;
    f32 height;

    control->effectFlags |= (ICEBADDIE_FX_BURST | ICEBADDIE_FX_PUFF);
    if (state->baddie.moveJustStartedA != 0) {
        if (state->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 0xf, 0.0f, 0);
            state->baddie.moveDone = 0;
        }
        state->baddie.stateTag = 1;
    }
    state->baddie.moveSpeed = state->baddie.targetDistance / 5000.0f;
    if (state->baddie.moveSpeed > 0.02f) {
        state->baddie.moveSpeed = 0.02f;
    } else if (state->baddie.moveSpeed < 0.01f) {
        state->baddie.moveSpeed = 0.01f;
    }
    height = obj->anim.currentMoveProgress;
    if (height < 0.5f) {
        state->baddie.animSpeedA = 4.0f * height;
    } else {
        state->baddie.animSpeedA = 4.0f * (1.0f - height);
    }
    (*gPlayerInterface)->rotateTowardTarget(obj, state, timeDelta, 4);
    return 0;
}

int iceBaddie_stateHandlerA06(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;
    int moveChoice;

    ((IceBaddieControl*)objectState->control)->effectFlags |= ICEBADDIE_FX_BURST;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (state->baddie.moveJustStartedA != 0) {
        gIceBaddieA06MoveVariant = randomGetRange(0, 2);
        moveChoice = randomGetRange(0, 1);
        if (moveChoice != 0) {
            if (state->baddie.moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 7, 0.0f, 0);
                state->baddie.moveDone = 0;
            }
        } else {
            if (state->baddie.moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 3, 0.0f, 0);
                state->baddie.moveDone = 0;
            }
        }
        state->baddie.stateTag = 1;
        state->baddie.moveSpeed = 0.005f + objectState->aggression / 20000.0f;
    }
    if (objectState->aggression > 50 && (objectState->configFlags & 2) == 0) {
        if (state->baddie.targetDistance > 55.0f && state->baddie.moveDone == 0) {
            state->baddie.animSpeedA = state->baddie.targetDistance / 55.0f - 1.0f;
            state->baddie.animSpeedA = state->baddie.animSpeedA * ((f32)objectState->aggression / 50.0f);
        } else {
            state->baddie.animSpeedA = 0.0f;
        }
    } else {
        state->baddie.animSpeedA = 0.0f;
    }
    (*gPlayerInterface)->rotateTowardTarget(obj, state, timeDelta, 4);
    return 0;
}

int iceBaddie_stateHandlerA05(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;
    int moveChoice;

    ((IceBaddieControl*)objectState->control)->effectFlags |= ICEBADDIE_FX_BURST;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (state->baddie.moveJustStartedA != 0) {
        moveChoice = randomGetRange(0, 1);
        if (moveChoice != 0) {
            gIceBaddieA05MoveVariant = randomGetRange(0, 2);
            if (state->baddie.moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 6, 0.0f, 0);
                state->baddie.moveDone = 0;
            }
        } else {
            gIceBaddieA05MoveVariant = 3;
            if (state->baddie.moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 10, 0.0f, 0);
                state->baddie.moveDone = 0;
            }
        }
        state->baddie.stateTag = 1;
        state->baddie.moveSpeed = 0.005f + objectState->aggression / 20000.0f;
    }
    if (objectState->aggression > 50 && (objectState->configFlags & 2) == 0) {
        if (state->baddie.targetDistance > 55.0f && state->baddie.moveDone == 0) {
            state->baddie.animSpeedA = state->baddie.targetDistance / 55.0f - 1.0f;
            state->baddie.animSpeedA = state->baddie.animSpeedA * ((f32)objectState->aggression / 50.0f);
        } else {
            state->baddie.animSpeedA = 0.0f;
        }
    } else {
        state->baddie.animSpeedA = 0.0f;
    }
    (*gPlayerInterface)->rotateTowardTarget(obj, state, timeDelta, 4);
    return 0;
}

int iceBaddie_updateSpinState(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;
    IceBaddieControl* control;

    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 9, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    control = (IceBaddieControl*)objectState->control;
    control->effectFlags |= (ICEBADDIE_FX_BURST | ICEBADDIE_FX_PUFF);
    if (state->baddie.moveJustStartedA != 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        objectState->targetState = 4;
    }
    obj->anim.rotX = (s16)(182.0f * (((f32)state->baddie.turnRate * timeDelta) / 12.0f) + (f32) * (s16*)obj);
    state->baddie.moveSpeed = 0.01f;
    state->baddie.animSpeedA = 1.0f;
    return 0;
}

int iceBaddie_updateImpactHitState(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;
    IceBaddieControl* control = (IceBaddieControl*)objectState->control;

    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (state->baddie.moveJustStartedA != 0) {
        state->baddie.moveDone = 0;
    }
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 4, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.stateTag = 3;
    state->baddie.moveSpeed = 0.008f;
    if ((s32)(state->baddie.eventFlags & BADDIE_EVENT_LANDING) != 0) {
        state->baddie.eventFlags &= ~BADDIE_EVENT_LANDING;
        control->effectFlags |= ICEBADDIE_FX_IMPACT;
    }
    control->effectFlags |= (ICEBADDIE_FX_BURST | ICEBADDIE_FX_PUFF);
    return 0;
}

int iceBaddie_updateHideResetState(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;
    ObjHitsPriorityState* hitState;

    if (state->baddie.prevControlMode != 4 && state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0xe, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    ((IceBaddieControl*)objectState->control)->effectFlags |= (ICEBADDIE_FX_BURST | ICEBADDIE_FX_PUFF);
    if (state->baddie.moveJustStartedA != 0) {
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags &= ~1;
        state->baddie.moveSpeed = 0.01f;
        state->baddie.animSpeedA = 0.0f;
    }
    if (state->baddie.moveDone != 0) {
        mainSetBits((s32)objectState->gameBitB, 0);
        ObjAnim_SetCurrentMove(obj, 8, 0.0f, 0);
        state->baddie.targetObj = NULL;
        state->baddie.physicsActive = 0;
        state->baddie.hasTarget = 0;
        objectState->targetState = 0;
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
    return 0;
}

int iceBaddie_updateOpenState(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState;
    IceBaddieControl* control;
    ObjHitsPriorityState* hitState;

    objectState = obj->extra;
    control = (IceBaddieControl*)objectState->control;
    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    hitState->flags |= 1;
    state->baddie.physicsActive = 1;
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 11, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    if (state->baddie.moveJustStartedA != 0) {
        mainSetBits(objectState->gameBitB, 1);
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        obj->anim.alpha = 0xff;
        state->baddie.stateTag = 1;
        state->baddie.moveSpeed = 0.012f + (f32)(u32)objectState->aggression / 10000.0f;
    }
    if (state->baddie.moveDone != 0) {
        objectState->targetState = 1;
    }
    {
        int eventFlags = state->baddie.eventFlags;
        if ((eventFlags & BADDIE_EVENT_LANDING) != 0) {
            state->baddie.eventFlags = eventFlags & ~BADDIE_EVENT_LANDING;
            control->effectFlags |= ICEBADDIE_FX_LANDING;
        }
    }
    control->effectFlags |= ICEBADDIE_FX_BURST;
    if (obj->anim.currentMoveProgress < 0.4f) {
        control->effectFlags |= ICEBADDIE_FX_PUFF;
    }
    (*gPlayerInterface)->rotateTowardTarget(obj, state, timeDelta, 4);
    return 0;
}

int iceBaddie_updateOpenHitState(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState;
    IceBaddieControl* control;

    objectState = obj->extra;
    control = (IceBaddieControl*)objectState->control;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
    state->baddie.physicsActive = 1;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = 9;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 8, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    if (state->baddie.moveJustStartedA != 0) {
        mainSetBits(objectState->gameBitB, 1);
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        obj->anim.alpha = 0xff;
        state->baddie.stateTag = 1;
        state->baddie.moveSpeed = 0.0025f + (f32)(u32)objectState->aggression / 50000.0f;
    }
    if (state->baddie.moveDone != 0) {
        objectState->targetState = 1;
    }
    {
        int eventFlags = state->baddie.eventFlags;
        if ((eventFlags & BADDIE_EVENT_LANDING) != 0) {
            state->baddie.eventFlags = eventFlags & ~BADDIE_EVENT_LANDING;
            control->effectFlags |= ICEBADDIE_FX_LANDING;
        }
    }
    control->effectFlags |= ICEBADDIE_FX_BURST;
    if (obj->anim.currentMoveProgress < 0.4f) {
        control->effectFlags |= ICEBADDIE_FX_PUFF;
    }
    (*gPlayerInterface)->rotateTowardTarget(obj, state, timeDelta, 4);
    return 0;
}

void iceBaddie_spawnIceBall(GameObject* obj, IceBaddieControl* control) {
    IceBallSetup* setup;
    GameObject* projectile;
    if ((u8)Obj_IsLoadingLocked() != 0) {
        setup = (IceBallSetup*)Obj_AllocObjectSetup(36, ICEBADDIE_CHILD_OBJ_ICEBALL);
        setup->base.posX = control->projectileTransform[3];
        setup->base.posY = control->projectileTransform[4];
        setup->base.posZ = control->projectileTransform[5];
        setup->base.color[0] = 1;
        setup->base.color[1] = 1;
        setup->base.color[2] = 255;
        setup->base.color[3] = 255;
        setup->gameBit = -1;
        setup->secondaryGameBit = -1;
        projectile = objSetupObject(&setup->base, 5, -1, -1, NULL);
        if (projectile != NULL) {
            projectile->anim.velocityX = control->projectileVelocity[0];
            projectile->anim.velocityY = control->projectileVelocity[1];
            projectile->anim.velocityZ = control->projectileVelocity[2];
            projectile->ownerObj = obj;
        }
    }
}

void iceBaddie_updateControlEffects(GameObject* obj, GroundBaddieState* state) {
    IceBaddieControl* controlAddress = state->control;
    int paletteIndex;
    u8* particleArgs;
    int i;
    f32 shakeScale;
    f32 contactScale;

    if (obj->anim.romDefNo == 99) {
        controlAddress->fxScale = 1.7f;
        shakeScale = 2.0f;
    } else {
        contactScale = 1.0f;
        controlAddress->fxScale = contactScale;
        shakeScale = contactScale;
    }
    paletteIndex = 0;
    if ((s8)state->baddie.physicsActive != 0) {
        paletteIndex = gIceBaddiePaletteIndexTable[(s8)state->baddie.paletteSlot];
        if (paletteIndex > 0x1e) {
            paletteIndex = 0;
        }
    }
    particleArgs = &gIceBaddieParticleArgsTable[paletteIndex * 3];
    if ((controlAddress->effectFlags & ICEBADDIE_FX_SPAWN_ICEBALL) != 0) {
        iceBaddie_spawnIceBall(obj, controlAddress);
        controlAddress->effectFlags &= ~ICEBADDIE_FX_SPAWN_ICEBALL;
    }
    if ((controlAddress->effectFlags & ICEBADDIE_FX_BURST) != 0 &&
        (state->configFlags & 0x40) == 0) {
        for (i = 0; i < 4; i++) {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, ICEBADDIE_PARTICLE_CONTACT, &controlAddress->particlePositionX, 0x200001, -1,
                              particleArgs);
        }
    }
    if ((controlAddress->effectFlags & ICEBADDIE_FX_PUFF) != 0 &&
        (state->configFlags & 0x40) == 0) {
        (*gPartfxInterface)
            ->spawnObject((void*)obj, ICEBADDIE_PARTICLE_PUFF, &controlAddress->particlePositionX, 0x200001, -1,
                          particleArgs);
    }
    if ((controlAddress->effectFlags & ICEBADDIE_FX_IMPACT) != 0) {
        CameraShake_Enable();
        CameraShake_SetOffset(2.0f * shakeScale);
        for (i = 0; i < 0x28; i++) {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, ICEBADDIE_PARTICLE_PUFF, &controlAddress->particlePositionX, 0x200001, -1,
                              particleArgs);
        }
    }
    if ((controlAddress->effectFlags & ICEBADDIE_FX_LANDING) != 0) {
        CameraShake_Enable();
        CameraShake_SetOffset(3.0f * shakeScale);
        for (i = 0; i < 0x28; i++) {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, ICEBADDIE_PARTICLE_PUFF, &controlAddress->particlePositionX, 0x200001, -1,
                              particleArgs);
        }
        for (i = 0; i < 10; i++) {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, ICEBADDIE_PARTICLE_DEBRIS, &controlAddress->particlePositionX, 0x200001, -1,
                              particleArgs);
        }
    }
    controlAddress->effectFlags = 0;
}

void iceBaddie_updateEffectAnchors(GameObject* obj, GroundBaddieState* state) {
    IceBaddieControl* control = (IceBaddieControl*)state->control;
    f32 transformed[3];
    f32 transformScratch[6];
    f32 pathMtx[16];
    f32 scale;
    f32 minScale;
    f32 angle;

    memcpy(pathMtx, (void*)ObjPath_GetPointModelMtx(obj, 1), 0x40);
    pathMtx[14] = 0.0f;
    pathMtx[13] = 0.0f;
    pathMtx[12] = 0.0f;
    if (obj->anim.romDefNo == 99) {
        minScale = 1.0f;
    } else {
        minScale = 0.3f;
    }
    if (state->baddie.animSpeedA < minScale) {
        scale = minScale;
    } else {
        scale = state->baddie.animSpeedA;
    }
    if (state->baddie.controlMode != 4) {
        ObjPath_GetPointWorldPosition(obj, 2, &control->effectPosition[0], &control->effectPosition[1],
                                      &control->effectPosition[2], 0);
    } else {
        ObjPath_GetPointWorldPosition(obj, 0, &control->effectPosition[0], &control->effectPosition[1],
                                      &control->effectPosition[2], 0);
    }
    control->effectPosition[1] = 8.0f + obj->anim.localPosY;
    angle = (3.1415927f * (f32) * (s16*)obj) / 32768.0f;
    control->effectPosition[0] = control->effectPosition[0] - scale * (10.0f * mathSinf(angle));
    angle = (3.1415927f * (f32) * (s16*)obj) / 32768.0f;
    control->effectPosition[2] = control->effectPosition[2] - scale * (10.0f * mathCosf(angle));
    transformScratch[3] = 0.0f;
    transformScratch[4] = -15.0f;
    transformScratch[5] = -20.0f;
    ObjPath_GetPointWorldPosition(obj, 0, &transformScratch[3], &transformScratch[4], &transformScratch[5], 1);
    if ((control->effectFlags & ICEBADDIE_FX_ARM_ICEBALL) != 0) {
        transformed[0] = -8.0f;
        transformed[1] = 40.0f;
        transformed[2] = -20.0f;
        Matrix_TransformPoint(pathMtx, transformed[0], transformed[1], transformed[2], &transformed[0], &transformed[1],
                              &transformed[2]);
        memcpy(control->projectileVelocity, transformed, sizeof(transformed));
        memcpy(control->projectileTransform, transformScratch, 0x18);
        control->effectFlags |= ICEBADDIE_FX_SPAWN_ICEBALL;
    }
}

void iceBaddie_tryAcquireTarget(GameObject* obj, GroundBaddieState* objectState, GroundBaddieState* state) {
    GameObject* acquired;

    ObjHits_DisableObject(obj);

    if ((objectState->configFlags & 0x4) != 0) {
        acquired = (*gBaddieControlInterface)->findAggroTarget(obj, state, 55.0f, 0x8000);
    } else if ((objectState->configFlags & 0x8) != 0) {
        acquired =
            (*gBaddieControlInterface)->findAggroTarget(obj, state, 0.5f * (f32)(u32)objectState->aggroRange, 0x8000);
    } else {
        acquired = (*gBaddieControlInterface)->findAggroTarget(obj, state, (f32)(u32)objectState->aggroRange, 0x8000);
    }

    if (acquired != 0) {
        (*gPlayerInterface)->rotateTowardTarget(obj, state, timeDelta, 4);
        if (((*gBaddieControlInterface)->getClearDirectionMask(obj, state, 75.0f) & 1) == 0) {
            acquired = 0;
        }
    }

    if (acquired != 0) {
        int physicsActive = -1;
        (*gBaddieControlInterface)
            ->startHitReaction(obj, state, &objectState->routeNav, objectState->gameBitB, NULL, 0, 0, 8,
                               physicsActive);
        state->baddie.targetObj = acquired;
        state->baddie.hasTarget = 0;
        objectState->targetState = 1;
    }
}

void iceBaddie_updateTargetMotion(GameObject* obj, GroundBaddieState* objectState, GroundBaddieState* state) {
    IceBaddieControl* control = (IceBaddieControl*)objectState->control;

    control->ambientSfxTimer += framesThisStep;
    if (control->ambientSfxTimer >= 300) {
        control->ambientSfxTimer = randomGetRange(0, 200);
        if (state->baddie.controlMode == 7 || state->baddie.controlMode == 8) {
            Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_26c);
        }
    }
    if ((objectState->configFlags & 2) != 0) {
        (*gBaddieControlInterface)->updateGravity(obj, state, 0.0f, -1);
    } else {
        (*gBaddieControlInterface)->updateGravity(obj, state, 0.17f, -1);
    }
    objectState->savedPendingParentObj = obj->pendingParentObj;
    obj->pendingParentObj = NULL;
    (*gPlayerInterface)->update(obj, state, timeDelta, timeDelta, gIceBaddieStateHandlersA, gIceBaddieStateHandlersB);
    obj->pendingParentObj = objectState->savedPendingParentObj;
}

void iceBaddie_updateTargetCollision(GameObject* obj, int stateAddress, GroundBaddieState* state) {
    IceBaddieControl* controlAddress = ((GroundBaddieState*)stateAddress)->control;
    GameObject* target;
    int hitInfo[7];
    f32 targetDelta[3];

    Obj_GetPlayerObject();
    target = state->baddie.targetObj;
    if (target != NULL) {
        f32* delta = targetDelta;
        delta[0] = target->anim.worldPosX - obj->anim.worldPosX;
        delta[1] = target->anim.worldPosY - obj->anim.worldPosY;
        delta[2] = target->anim.worldPosZ - obj->anim.worldPosZ;
        state->baddie.targetDistance = sqrtf(delta[2] * delta[2] + (delta[0] * delta[0] + delta[1] * delta[1]));
    }
    if ((((GroundBaddieState*)stateAddress)->configFlags & 0x20) == 0) {
        (*gBaddieControlInterface)
            ->pollCameraTarget(obj, state, &((GroundBaddieState*)stateAddress)->flags400, 2, 3,
                               ((GroundBaddieState*)stateAddress)->soundIdB,
                               ((GroundBaddieState*)stateAddress)->soundIdA);
    }
    (*gBaddieControlInterface)
        ->processMessages(obj, state, (void*)(stateAddress + 0x35c), ((GroundBaddieState*)stateAddress)->gameBitB, NULL,
                          0, 0, 8);
    controlAddress->hitTimer += timeDelta;
    if (state->baddie.controlMode != 3 &&
        (*gBaddieControlInterface)
                ->updateHitReaction(obj, state, &((GroundBaddieState*)stateAddress)->routeNav,
                                    ((GroundBaddieState*)stateAddress)->gameBitB, gIceBaddieHitReactionMoves,
                                    gIceBaddieHitReactionDamage, 1, hitInfo) != 0) {
        if (controlAddress->hitTimer < 240.0f) {
            controlAddress->consecutiveHitCount += 1;
        } else {
            controlAddress->consecutiveHitCount = 0;
        }
        controlAddress->hitTimer = 0.0f;
        if (state->baddie.hitPoints > 0 && controlAddress->consecutiveHitCount >= 2) {
            (*gPlayerInterface)->setState(obj, state, 3);
            controlAddress->consecutiveHitCount = 0;
            state->baddie.substate = 5;
        }
    }
}

void iceBaddie_handleMessage(GameObject* obj, int message) {
    GroundBaddieState* state = obj->extra;

    switch ((u8)message) {
    case 0x80:
        (*gPlayerInterface)->setState(obj, state, 2);
        state->baddie.substate = 4;
        state->baddie.moveJustStartedB = 1;
        break;
    }
}

s16 iceBaddie_getControlMode(GameObject* obj) {
    return ((GroundBaddieState*)obj->extra)->baddie.controlMode;
}

int iceBaddie_getExtraSize(void) {
    return sizeof(GroundBaddieState) + sizeof(IceBaddieControl);
}

int iceBaddie_getObjectTypeId(void) {
    return 0x49;
}

void iceBaddie_free(GameObject* obj) {
    GroundBaddieState* state = obj->extra;

    CameraShake_Disable();
    objFreeObjectType(obj, ICEBADDIE_OBJGROUP);
    {
        GameObject* child = (GameObject*)obj->childObjs[0];
        if (child != NULL) {
            Obj_FreeObject(child);
            obj->childObjs[0] = NULL;
        }
    }
    (*gBaddieControlInterface)->releaseState(obj, state, 0x20);
}

void iceBaddie_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    GroundBaddieState* state = obj->extra;
    f32 zero = 0.0f;

    if (visible == 0 || obj->userData1 != 0 || state->targetState == 0) {
        return;
    }

    if (state->glowAlpha != zero) {
        objSetGlowColor(0xc8, 0, 0, state->glowAlpha);
    }
    objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
    iceBaddie_updateEffectAnchors(obj, state);
}

void iceBaddie_hitDetect(GameObject* obj) {
    (*gPlayerInterface)->updateVelocityState(obj, obj->extra, gIceBaddieStateHandlersA);
}

void iceBaddie_update(GameObject* obj, int unusedA, int unusedB) {
    GroundBaddieState* objectState;
    GroundBaddiePlacement* placement;

    (void)unusedA;
    (void)unusedB;

    objectState = obj->extra;
    placement = (GroundBaddiePlacement*)obj->anim.placementData;
    if (obj->userData1 != 0) {
        if ((objectState->baddie.substate != 3 || (objectState->configFlags & 1) != 0) &&
            (*gMapEventInterface)->shouldNotSaveTime(placement->base.ident) != 0) {
            (*gBaddieControlInterface)
                ->initGroundBaddie(obj, (u8*)placement, (u8*)objectState, 14, 8, 0x102, 0x26, 20.0f);
            objectState->targetState = 0;
            Sfx_PlayFromObject(obj, SFXTRIG_dn_seal4_c_263);
            ObjAnim_SetCurrentMove(obj, 8, 0.0f, OBJANIM_MOVE_CONTROL_SKIP_EVENT_COUNTDOWN);
            objectState->baddie.moveDone = 0;
            obj->anim.alpha = 0xff;
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        }
    } else if (obj->userData2 == 0) {
        obj->anim.localPosX = placement->base.posX;
        obj->anim.localPosY = placement->base.posY;
        obj->anim.localPosZ = placement->base.posZ;
        (*gObjectTriggerInterface)->runSequence(placement->sequenceId, obj, -1);
        obj->userData2 = 1;
    } else {
        if ((*gBaddieControlInterface)->isObjectValid(obj, objectState, 0) == 0) {
            objectState->targetState = 0;
        } else {
            iceBaddie_updateTargetCollision(obj, (int)objectState, objectState);
            iceBaddie_updateControlEffects(obj, objectState);
            if (objectState->targetState == 0) {
                iceBaddie_tryAcquireTarget(obj, objectState, objectState);
            } else {
                iceBaddie_updateTargetMotion(obj, objectState, objectState);
            }
            if ((objectState->configFlags & 2) != 0) {
                obj->anim.localPosY = placement->base.posY - 8.0f;
            }
        }
    }
}

void iceBaddie_init(GameObject* obj, GroundBaddiePlacement* placement, int flags) {
    GroundBaddieState* objectState;
    u8 mode;

    objectState = obj->extra;
    mode = 6;
    if (flags != 0) {
        mode |= 1;
    }
    if ((placement->flags & 0x20) == 0) {
        mode |= 8;
    }
    (*gBaddieControlInterface)->initGroundBaddie(obj, (u8*)placement, (u8*)objectState, 14, 8, 0x102, mode, 20.0f);
    obj->animEventCallback = NULL;
    if (0.5f * (f32)(u32)objectState->aggroRange < 55.0f) {
        objectState->aggroRange = 0x6e;
    }
    ObjAnim_SetCurrentMove(obj, 8, 0.0f, 0);
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    (*gPlayerInterface)->setState(obj, objectState, 0);
    objectState->baddie.substate = 0;
    objectState->baddie.physicsActive = 0;
}

void iceBaddie_release(void) {
}

void iceBaddie_initialise(void) {
    iceBaddie_installStateHandlers();
}

IceBaddieStateHandler gIceBaddieStateHandlersA[14];

IceBaddieStateHandler gIceBaddieStateHandlersB[8];

ObjectDescriptor12 gIceBaddieObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)iceBaddie_initialise,
    (ObjectDescriptorCallback)iceBaddie_release,
    0,
    (ObjectDescriptorCallback)iceBaddie_init,
    (ObjectDescriptorCallback)iceBaddie_update,
    (ObjectDescriptorCallback)iceBaddie_hitDetect,
    (ObjectDescriptorCallback)iceBaddie_render,
    (ObjectDescriptorCallback)iceBaddie_free,
    (ObjectDescriptorCallback)iceBaddie_getObjectTypeId,
    iceBaddie_getExtraSize,
    (ObjectDescriptorCallback)iceBaddie_getControlMode,
    (ObjectDescriptorCallback)iceBaddie_handleMessage,
};
