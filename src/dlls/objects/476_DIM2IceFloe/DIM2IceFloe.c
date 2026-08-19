/*
 * DIM2IceFloe (DLL 0x1DC) - moving ice floes for the DarkIce Mines.
 * Each floe follows a curve supplied by another object, then sinks and is
 * freed after reaching the end of that path.
 */
#include "dlls/objects/476_DIM2IceFloe.h"

#include "dlls/objects/472_DIM2PathGen.h"
#include "main/curve.h"
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define DIM2_ICE_FLOE_FLAG_CURVE_READY   0x01
#define DIM2_ICE_FLOE_FADE_IN_RATE       4
#define DIM2_ICE_FLOE_MAX_ALPHA          0xFF
#define DIM2_ICE_FLOE_PATH_END_MARGIN    4
#define DIM2_ICE_FLOE_PATH_HEIGHT_OFFSET 5.0f
#define DIM2_ICE_FLOE_SINK_SPEED         0.3f
#define DIM2_ICE_FLOE_SINK_FREE_DISTANCE 50.0f
#define DIM2_ICE_FLOE_PATH_STEP_SCALE    100.0f

typedef enum Dim2IceFloeObjectId {
    DIM2_ICE_FLOE_OBJECT_ID_FLOE_1 = 0x109,
    DIM2_ICE_FLOE_OBJECT_ID_FLOE_2 = 0x10D,
    DIM2_ICE_FLOE_OBJECT_ID_FLOE = 0x111,
} Dim2IceFloeObjectId;

int dim2icefloe_getExtraSize(void) {
    return sizeof(Dim2IceFloeState);
}

int dim2icefloe_getObjectTypeId(void) {
    return 0;
}

void dim2icefloe_free(void) {
}

void dim2icefloe_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void dim2icefloe_hitDetect(void) {
}

void dim2icefloe_update(GameObject* obj) {
    Dim2IceFloeState* state = obj->extra;

    if (state->followedObject != NULL && (state->followedObject->objectFlags & OBJECT_OBJFLAG_FREED) != 0) {
        state->flags &= ~DIM2_ICE_FLOE_FLAG_CURVE_READY;
        state->followedObject = NULL;
    } else {
        int alpha;
        int reached;

        switch ((int)state->paused) {
        case 0:
            alpha = obj->anim.alpha + framesThisStep * DIM2_ICE_FLOE_FADE_IN_RATE;
            if (alpha > DIM2_ICE_FLOE_MAX_ALPHA) {
                alpha = DIM2_ICE_FLOE_MAX_ALPHA;
            }
            obj->anim.alpha = alpha;
            if ((state->flags & DIM2_ICE_FLOE_FLAG_CURVE_READY) == 0) {
                state->followedObject = ObjList_FindObjectById(state->targetObjectId);
                state->curve.count = DIM2_PATH_GENERATOR_INTERFACE(state->followedObject)
                                         ->getCurveVals(state->followedObject, &state->curve.px, &state->curve.py,
                                                        &state->curve.pz, NULL);
                state->curve.dir = 0;
                state->curve.eval = Curve_EvalHermite;
                state->curve.coeffFn = Curve_BuildHermiteCoeffs;
                curvesMove(&state->curve);
                state->flags |= DIM2_ICE_FLOE_FLAG_CURVE_READY;
            }
            Curve_AdvanceAlongPath(&state->curve, state->pathStep);
            reached = state->curve.idx >= state->curve.count - DIM2_ICE_FLOE_PATH_END_MARGIN;
            obj->anim.localPosX = state->curve.sample[0];
            if (!state->completion.finished) {
                obj->anim.localPosY = DIM2_ICE_FLOE_PATH_HEIGHT_OFFSET + state->curve.sample[1];
            }
            obj->anim.localPosZ = state->curve.sample[2];
            if (reached) {
                state->completion.finished = 1;
            }
            state->bobPhase = timeDelta * state->bobRate + (f32)state->bobPhase;
            if (state->completion.finished) {
                obj->anim.localPosY = -(DIM2_ICE_FLOE_SINK_SPEED * timeDelta - obj->anim.localPosY);
                if (obj->anim.localPosY < state->curve.sample[1]) {
                    ObjHits_DisableObject(obj);
                    obj->objectFlags |= 0x100;
                    playerReleaseLedgeGrabOn(Obj_GetPlayerObject(), obj);
                }
                if (obj->anim.localPosY < state->curve.sample[1] - DIM2_ICE_FLOE_SINK_FREE_DISTANCE) {
                    Obj_FreeObject(obj);
                }
            }
            break;
        default:
            break;
        }
    }
}

void dim2icefloe_init(GameObject* obj, Dim2IceFloePlacementView* placement) {
    Dim2IceFloeState* state = obj->extra;

    state->targetObjectId = placement->base.ident;
    state->pathStep = placement->pathStep / DIM2_ICE_FLOE_PATH_STEP_SCALE;
    state->yawJitter = (f32)(s32)randomGetRange(-0x1e, 0x1e);
    placement->base.ident = -1;
    obj->anim.bankIndex = randomGetRange(0, obj->anim.modelInstance->modelCount - 1);
    obj->anim.rotX = (s16)((s32)placement->initialRotationXByte << 8);
    obj->anim.rotX = randomGetRange(0, 0xffff);
    obj->anim.alpha = 0;
    switch (obj->anim.romDefNo) {
    case DIM2_ICE_FLOE_OBJECT_ID_FLOE_1:
        state->bobRate = 180.0f + (f32)(s32)randomGetRange(0, 0x28);
        state->bobBase = 2.0f;
        break;
    case DIM2_ICE_FLOE_OBJECT_ID_FLOE_2:
        state->bobRate = 200.0f + (f32)(s32)randomGetRange(0, 0x32);
        state->bobBase = 2.0f;
        break;
    case DIM2_ICE_FLOE_OBJECT_ID_FLOE:
    default:
        state->bobRate = 196.0f + (f32)(s32)randomGetRange(0, 0x28);
        state->bobBase = 2.0f;
        break;
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void dim2icefloe_release(void) {
}

void dim2icefloe_initialise(void) {
}

ObjectDescriptor gDIM2IceFloeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dim2icefloe_initialise,
    (ObjectDescriptorCallback)dim2icefloe_release,
    0,
    (ObjectDescriptorCallback)dim2icefloe_init,
    (ObjectDescriptorCallback)dim2icefloe_update,
    (ObjectDescriptorCallback)dim2icefloe_hitDetect,
    (ObjectDescriptorCallback)dim2icefloe_render,
    (ObjectDescriptorCallback)dim2icefloe_free,
    (ObjectDescriptorCallback)dim2icefloe_getObjectTypeId,
    dim2icefloe_getExtraSize,
};
