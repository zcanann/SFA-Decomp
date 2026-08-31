/*
 * Unnamed GroundBaddie object in DLL slot 203.
 *
 * The object follows ROM curves and switches to target-tracking movement when
 * its sequence state requests it. No retail object name is known.
 */
#include "dlls/objects/203.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objseq_control.h"
#include "main/player_control_interface.h"
#include "main/vecmath.h"
#include "main/voxmaps.h"
#include "string.h"
#include "sys/objects.h"
#include "main/curve.h"
#include "main/obj_message.h"
#include "main/objtype.h"
#include "sys/objects/lifecycle.h"
#include "main/objprint_character_api.h"

#define DLL_CB_OBJGROUP                     3
#define DLL_CB_FLAG400_PENDING_HIT_REACTION 0x2
#define DLL_CB_SUBMODE_CURVE                0
#define DLL_CB_SUBMODE_SEQUENCE             1
#define DLL_CB_SUBMODE_TARGET               2

DllCBStateHandler gDllCBStateHandlers[6];

int dll_CB_stateHandler5(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState;
    RouteNav* routePath;
    f32 neutralInput;

    objectState = obj->extra;
    if (state->baddie.targetObj != NULL) {
        (*gPlayerInterface)->setState(obj, state, 1);
        routePath = &objectState->routeNav;
        neutralInput = 0.0f;
        state->baddie.moveInputX = neutralInput;
        state->baddie.moveInputZ = neutralInput;
        memcpy(routePath, &obj->anim.localPosX, sizeof(routePath->destPos));
        memcpy((void*)objectState->routeNav.curPos, &((GameObject*)state->baddie.targetObj)->anim.localPosX,
               sizeof(routePath->curPos));
        voxmaps_updateRoutePath(&objectState->routeNav, &objectState->routeState);
        if (state->baddie.targetDistance < 50.0f && objectState->subMode == DLL_CB_SUBMODE_TARGET) {
            return 5;
        }
        if (routePath->flag25 == 0) {
            (*gPlayerInterface)
                ->moveTowardPoint(obj, state, routePath->tgtPos[0], routePath->tgtPos[2], 0.0f, 0.0f, 60.0f);
        } else {
            (*gPlayerInterface)
                ->moveTowardPoint(obj, state, routePath->tgtPos[0], routePath->tgtPos[2], 15.0f, 30.0f, 60.0f);
        }
    } else {
        (*gPlayerInterface)->setState(obj, state, 0);
        state->baddie.moveDone = 0;
    }
    return 0;
}

int dll_CB_stateHandler4(GameObject* obj, GroundBaddieState* state) {
    if (state->baddie.moveJustStartedB != 0) {
        f32 initialVelocity;

        (*gPlayerInterface)->setState(obj, state, 0);
        initialVelocity = 5.0f;
        obj->anim.velocityY = initialVelocity;
        state->baddie.animSpeedA = initialVelocity;
        state->baddie.animSpeedC = initialVelocity;
    }
    if (obj->anim.velocityY < 0.25) {
        f32 zeroVelocity = 0.0f;

        obj->anim.velocityY = zeroVelocity;
        state->baddie.animSpeedA = zeroVelocity;
        state->baddie.animSpeedC = zeroVelocity;
        return 6;
    }
    {
        f32 slowdownDivisor = 1.1f;

        obj->anim.velocityY = obj->anim.velocityY / slowdownDivisor;
        state->baddie.animSpeedA = state->baddie.animSpeedA / slowdownDivisor;
        state->baddie.animSpeedC = state->baddie.animSpeedC / slowdownDivisor;
    }
    return 0;
}

int dll_CB_stateHandler3(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;

    if (state->baddie.moveJustStartedB != 0) {
        (*gBaddieControlInterface)->spawnChild(obj, objectState->triggerId, -1, 0);
    }
    return 0;
}

int dll_CB_stateHandler2(GameObject* obj, GroundBaddieState* state) {
    ObjHitsPriorityState* hitState;

    if (state->baddie.moveJustStartedB != 0) {
        (*gPlayerInterface)->setState(obj, state, 3);
        state->baddie.targetObj = NULL;
        state->baddie.physicsActive = 0;
        state->baddie.hasTarget = 0;
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags &= ~1;
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    } else {
        ObjMsg_SendToObject(Obj_GetPlayerObject(), 0xe0000, obj, 0);
        if (obj->anim.placementData == NULL) {
            Obj_FreeObject(obj);
            return 0;
        }
        return 4;
    }
    return 0;
}

int dll_CB_stateHandler1(GameObject* obj, GroundBaddieState* state) {
    (void)obj;

    if (state->baddie.hitPoints < 1) {
        return 3;
    }
    return 6;
}

int dll_CB_stateHandler0(GameObject* obj, GroundBaddieState* state) {
    (void)obj;
    (void)state;

    return 6;
}

int dll_CB_moveHandler3(GameObject* obj, GroundBaddieState* state, f32 timeDelta) {
    GroundBaddieState* objectState = obj->extra;
    u8 step;

    (void)state;
    (void)timeDelta;

    if (obj->anim.alpha >= (step = framesThisStep)) {
        obj->anim.alpha -= step;
    } else {
        obj->anim.alpha = 0;
    }
    if (obj->anim.alpha == 0) {
        mainSetBits(objectState->gameBitB, 0);
        mainSetBits(objectState->gameBitA, 1);
    }
    return 0;
}

int dll_CB_moveHandler2(GameObject* obj, GroundBaddieState* state, f32 timeDelta) {
    f32 zeroSpeed = 0.0f;

    (void)timeDelta;

    state->baddie.animSpeedA = zeroSpeed;
    state->baddie.animSpeedB = zeroSpeed;
    state->baddie.physicsActive = 1;
    obj->anim.rotZ = state->baddie.spawnRotZ;
    obj->anim.rotY = state->baddie.spawnRotY;
    return 0;
}

int dll_CB_moveHandler1(GameObject* obj, GroundBaddieState* state, f32 timeDelta) {
    GroundBaddieState* objectState = obj->extra;

    (void)timeDelta;

    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.physicsActive = 1;
    obj->anim.rotZ = state->baddie.spawnRotZ;
    obj->anim.rotY = state->baddie.spawnRotY;
    (*gBaddieControlInterface)->updateMovementBlend(obj, state, objectState, 1.0f, 12.0f);
    state->baddie.moveSpeed = 0.075f * state->baddie.animSpeedA;
    return 0;
}

int dll_CB_moveHandler0(GameObject* obj, GroundBaddieState* state, f32 timeDelta) {
    f32 zeroSpeed = 0.0f;

    state->baddie.animSpeedA = zeroSpeed;
    state->baddie.animSpeedB = zeroSpeed;
    state->baddie.moveSpeed = zeroSpeed;
    state->baddie.physicsActive = 1;
    obj->anim.rotZ = state->baddie.spawnRotZ;
    obj->anim.rotY = state->baddie.spawnRotY;
    (*gPlayerInterface)->rotateTowardTarget(obj, state, timeDelta, 5);
    return 0;
}

const f32 gDllCBDefaultAnimSpeed[] = {0.1f};

void dll_CB_seekAndUpdate(GameObject* obj, ObjSeqState* sequenceState, GroundBaddieState* objectState,
                          GroundBaddieState* state) {
    DllCBPlacement* placement;

    placement = (DllCBPlacement*)obj->anim.placementData;
    state->baddie.moveDone = 1;
    if ((*gBaddieControlInterface)->shouldDropTarget(obj, state, (f32)(u32)objectState->aggroRange, 1) != 0) {
        state->baddie.targetObj = objectState->savedPendingParentObj;
        state->baddie.hasTarget = 0;
        if (placement->trackYieldEnable != -1) {
            if (sequenceState != NULL) {
                (*gObjectTriggerInterface)->yield(sequenceState, placement->trackYieldId);
            }
            objectState->subMode = DLL_CB_SUBMODE_SEQUENCE;
        } else {
            state->baddie.targetObj = NULL;
        }
    }
    (*gBaddieControlInterface)->updateGravity(obj, state, 0.17f, 1);
    objectState->savedPendingParentObj = obj->pendingParentObj;
    obj->pendingParentObj = NULL;
    (*gPlayerInterface)->update(obj, state, timeDelta, timeDelta, gDllCBMoveHandlers, gDllCBStateHandlers);
    obj->pendingParentObj = objectState->savedPendingParentObj;
}

void dll_CB_advanceAI(GameObject* obj, GroundBaddieState* objectState, GroundBaddieState* state) {
    GameObject* targetObj;
    int hitReaction;
    f32 targetDelta[3];
    f32* delta = targetDelta;

    if (obj->childObjs[0] != NULL) {
        ((GameObject*)obj->childObjs[0])->anim.parent = obj->anim.parent;
    }
    targetObj = state->baddie.targetObj;
    if (targetObj != NULL) {
        delta[0] = targetObj->anim.worldPosX - obj->anim.worldPosX;
        delta[1] = targetObj->anim.worldPosY - obj->anim.worldPosY;
        delta[2] = targetObj->anim.worldPosZ - obj->anim.worldPosZ;
        state->baddie.targetDistance = sqrtf(delta[2] * delta[2] + (delta[0] * delta[0] + delta[1] * delta[1]));
    }
    characterDoEyeAnims(obj, &objectState->eyeAnimState);
    if ((objectState->configFlags & 1) == 0) {
        (*gBaddieControlInterface)
            ->pollCameraTarget(obj, state, &objectState->flags400, 2, 3, objectState->soundIdB, objectState->soundIdA);
    }
    (*gBaddieControlInterface)
        ->processMessages(obj, state, &objectState->routeNav, objectState->gameBitB, &objectState->subMode, 0, 0, 0);
    hitReaction = (*gBaddieControlInterface)
                      ->updateHitReaction(obj, state, &objectState->routeNav, objectState->gameBitB,
                                          gDllCBHitReactionMoves, gDllCBHitReactionDamage, 1, NULL);
    if (hitReaction >= 4) {
        objectState->subMode = DLL_CB_SUBMODE_TARGET;
        state->baddie.targetObj = Obj_GetPlayerObject();
    }
}

int dll_CB_seqFn(GameObject* obj, int unused, ObjSeqState* sequenceState) {
    DllCBPlacement* placement;
    RomCurveWalker* path;
    GroundBaddieState* state;

    (void)unused;

    placement = (DllCBPlacement*)obj->anim.placementData;
    state = obj->extra;
    if (obj->userData1 != 0) {
        return 0;
    }
    if (obj->seqIndex != -1) {
        if ((*gBaddieControlInterface)->isObjectValid(obj, state, 1) == 0) {
            return 1;
        }
        dll_CB_advanceAI(obj, state, state);
        if (state->gameBitC != -1 && mainGetBit(state->gameBitC) != 0) {
            (*gObjectTriggerInterface)->yield(sequenceState, placement->gameBitId);
            state->gameBitC = -1;
        }
        switch (state->subMode) {
        case DLL_CB_SUBMODE_TARGET:
            sequenceState->flags = 0;
            dll_CB_seekAndUpdate(obj, sequenceState, state, state);
            if (state->subMode == DLL_CB_SUBMODE_SEQUENCE) {
                state->baddie.substate = 5;
                (*gPlayerInterface)->update(obj, state, 1.0f, 1.0f, gDllCBMoveHandlers, gDllCBStateHandlers);
                sequenceState->movementState = 0;
            }
            break;
        case DLL_CB_SUBMODE_SEQUENCE:
            if ((*gBaddieControlInterface)
                    ->updateSequenceMovement(obj, sequenceState, (char*)state, gDllCBMoveHandlers, gDllCBStateHandlers,
                                             0) != 0) {
                (*gBaddieControlInterface)->updateGravity(obj, state, 0.17f, 1);
            }
            break;
        case DLL_CB_SUBMODE_CURVE:
        default:
            sequenceState->flags = -1;
            sequenceState->flags &= ~OBJSEQ_FLAG_TEXTURE_ANIM_TRACKS;
            path = (RomCurveWalker*)state->path;
            if ((state->flags400 & BADDIE_FLAG400_PATH_ACTIVE) != 0) {
                if ((Curve_AdvanceAlongPath((Curve*)path, state->baddie.animSpeedA) != 0 || path->atSegmentEnd != 0) &&
                    (*gRomCurveInterface)->goNextPoint(path) != 0) {
                    state->flags400 &= ~BADDIE_FLAG400_PATH_ACTIVE;
                }
                state->baddie.animSpeedA = gDllCBDefaultAnimSpeed[0];
                obj->anim.rotX = getAngle(path->tangentX, path->tangentZ) + 0x8000;
                obj->anim.rotY = getAngle(path->tangentZ, path->tangentY) + 0x4000;
                obj->anim.rotZ = getAngle(path->tangentY, path->tangentX) + 0x4000;
                obj->anim.localPosX = path->posX;
                obj->anim.localPosY = path->posY;
                obj->anim.localPosZ = path->posZ;
            }
            break;
        }
    }
    if (obj->seqIndex == -1) {
        state->flags400 |= DLL_CB_FLAG400_PENDING_HIT_REACTION;
        return 0;
    }
    return state->subMode != DLL_CB_SUBMODE_CURVE;
}

void dll_CB_handleMessage(GameObject* obj, int message) {
    (void)obj;
    (void)message;
}

s16 dll_CB_getControlMode(GameObject* obj) {
    return ((BaddieState*)obj->extra)->controlMode;
}

int dll_CB_getExtraSize(void) {
    return sizeof(GroundBaddieState);
}

int dll_CB_getObjectTypeId(void) {
    return 0x14b;
}

void dll_CB_free(GameObject* obj) {
    GroundBaddieState* state = obj->extra;

    objFreeObjectType(obj, DLL_CB_OBJGROUP);
    {
        GameObject* child = obj->childObjs[0];

        if (child != NULL) {
            Obj_FreeObject(child);
            obj->childObjs[0] = NULL;
        }
    }
    (*gBaddieControlInterface)->releaseState(obj, state, 1);
}

void dll_CB_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    s32 visible32 = visible;

    if (visible32 != 0) {
        switch (obj->userData1) {
        case 0:
            objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
            break;
        }
    }
}

void dll_CB_hitDetect(GameObject* obj) {
    GroundBaddieState* state = obj->extra;

    (*gPlayerInterface)->updateVelocityState(obj, state, gDllCBMoveHandlers);
}

void dll_CB_update(GameObject* obj) {
    RomCurveWalker* path;
    GroundBaddieState* state;
    DllCBPlacement* placement;

    state = obj->extra;
    placement = (DllCBPlacement*)obj->anim.placementData;
    if (obj->userData1 != 0) {
        return;
    }
    if (obj->userData2 == 0) {
        obj->anim.localPosX = placement->base.posX;
        obj->anim.localPosY = placement->base.posY;
        obj->anim.localPosZ = placement->base.posZ;
        obj->userData2 = 1;
        return;
    }
    if ((state->flags400 & DLL_CB_FLAG400_PENDING_HIT_REACTION) != 0) {
        (*gBaddieControlInterface)
            ->startHitReaction(obj, state, &state->routeNav, state->gameBitB, &state->subMode, 0, 0, 0, 1);
        state->flags400 = state->flags400 & ~DLL_CB_FLAG400_PENDING_HIT_REACTION;
    }
    if ((*gBaddieControlInterface)->isObjectValid(obj, state, 1) == 0) {
        return;
    }
    dll_CB_advanceAI(obj, state, state);
    path = (RomCurveWalker*)state->path;
    if ((state->flags400 & BADDIE_FLAG400_PATH_ACTIVE) == 0) {
        return;
    }
    if (Curve_AdvanceAlongPath((Curve*)path, state->baddie.animSpeedA) != 0 || path->atSegmentEnd != 0) {
        if ((*gRomCurveInterface)->goNextPoint(path) != 0) {
            state->flags400 = state->flags400 & ~BADDIE_FLAG400_PATH_ACTIVE;
        }
    }
    state->baddie.animSpeedA = gDllCBDefaultAnimSpeed[0];
    obj->anim.rotX = (s16)(getAngle(path->tangentX, path->tangentZ) + 0x8000);
    obj->anim.rotY = (s16)(getAngle(path->tangentZ, path->tangentY) + 0x4000);
    obj->anim.rotZ = (s16)(getAngle(path->tangentY, path->tangentX) + 0x4000);
    obj->anim.localPosX = path->posX;
    obj->anim.localPosY = path->posY;
    obj->anim.localPosZ = path->posZ;
}

void dll_CB_init(GameObject* obj, DllCBPlacement* placement, int flags) {
    GroundBaddieState* state;
    u8 initFlags;

    state = obj->extra;
    initFlags = 0x16;
    if (flags != 0) {
        initFlags |= 1;
    }
    if ((placement->flags & 1) == 0) {
        initFlags |= 8;
    }
    obj->anim.rotY = (s16)(placement->rotY << 8);
    obj->anim.rotZ = (s16)(placement->rotZ << 8);
    (*gBaddieControlInterface)->initGroundBaddie(obj, (u8*)placement, (u8*)state, 4, 6, 0x82, initFlags, 20.0f);
    obj->animEventCallback = dll_CB_seqFn;
    (*gPlayerInterface)->setState(obj, state, 0);
    state->baddie.substate = 0;
    if (state->aggroRange < 0x32) {
        state->aggroRange = 0x32;
    }
}

void dll_CB_release(void) {
}

void dll_CB_initialise(void) {
    gDllCBMoveHandlers[0] = dll_CB_moveHandler0;
    gDllCBMoveHandlers[1] = dll_CB_moveHandler1;
    gDllCBMoveHandlers[2] = dll_CB_moveHandler2;
    gDllCBMoveHandlers[3] = dll_CB_moveHandler3;
    gDllCBStateHandlers[0] = dll_CB_stateHandler0;
    gDllCBStateHandlers[1] = dll_CB_stateHandler1;
    gDllCBStateHandlers[2] = dll_CB_stateHandler2;
    gDllCBStateHandlers[3] = dll_CB_stateHandler3;
    gDllCBStateHandlers[4] = dll_CB_stateHandler4;
    gDllCBStateHandlers[5] = dll_CB_stateHandler5;
}

int gDllCBHitReactionMoves[30] = {
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
};

u8 gDllCBHitReactionDamage[32] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0,   0,
};



DllCBMoveHandler gDllCBMoveHandlers[4];

ObjectDescriptor12 gDllCBObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)dll_CB_initialise,
    (ObjectDescriptorCallback)dll_CB_release,
    0,
    (ObjectDescriptorCallback)dll_CB_init,
    (ObjectDescriptorCallback)dll_CB_update,
    (ObjectDescriptorCallback)dll_CB_hitDetect,
    (ObjectDescriptorCallback)dll_CB_render,
    (ObjectDescriptorCallback)dll_CB_free,
    (ObjectDescriptorCallback)dll_CB_getObjectTypeId,
    dll_CB_getExtraSize,
    (ObjectDescriptorCallback)dll_CB_getControlMode,
    (ObjectDescriptorCallback)dll_CB_handleMessage,
};
