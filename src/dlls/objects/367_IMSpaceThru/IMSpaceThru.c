#include "dlls/objects/367_IMSpaceThru.h"

#include "main/asset_load.h"
#include "main/frame_timing.h"
#include "main/mldf_fileid.h"
#include "main/mm.h"
#include "main/model.h"
#include "main/object_render.h"
#include "main/objtexture.h"

#define IM_SPACE_THRUSTER_ROOT_MOTION_SCALE_KIND01 0.49f
#define IM_SPACE_THRUSTER_ROOT_MOTION_SCALE_KIND23 0.42f
#define IM_SPACE_THRUSTER_ROOT_MOTION_SCALE_KIND4  0.72f
#define IM_SPACE_THRUSTER_ROOT_MOTION_SCALE_KIND56 0.58f

#define IM_SPACE_THRUSTER_WEIGHT_MAX            1.0f
#define IM_SPACE_THRUSTER_ALPHA_TO_WEIGHT_SCALE 255.0f

s16 gIMSpaceThrusterKeyframeIndicesA[6] = {0x160, 0x161, 0x162, 0x163, 0x165, 0};
s16 gIMSpaceThrusterKeyframeIndicesB[6] = {3, 4, 5, 6, 7, 0};

static inline ObjModel* imSpaceThruster_getActiveModel(GameObject* obj) {
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;

    return (ObjModel*)objAnim->banks[objAnim->bankIndex];
}

int imSpaceThruster_getExtraSize(void) {
    return sizeof(IMSpaceThrusterState);
}

int imSpaceThruster_getObjectTypeId(void) {
    return 0;
}

void imSpaceThruster_free(GameObject* obj) {
    IMSpaceThrusterState* state = obj->extra;

    if (state->keyframesA != NULL) {
        mm_free(state->keyframesA);
    }
    if (state->keyframesB != NULL) {
        mm_free(state->keyframesB);
    }
}

void imSpaceThruster_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, IM_SPACE_THRUSTER_WEIGHT_MAX);
    }
}

void imSpaceThruster_hitDetect(void) {
}

void imSpaceThruster_update(GameObject* obj) {
    IMSpaceThrusterState* state;
    int thrusterMode;
    s16 textureOffset;
    ObjTextureRuntimeSlot* texture;

    state = obj->extra;
    if (obj->anim.parent != NULL) {
        thrusterMode = IM_SPACE_THRUSTER_PARENT_INTERFACE(obj->anim.parent)
                           ->getThrusterMode((GameObject*)obj->anim.parent, state->kind);
        switch (state->phase) {
        case IM_SPACE_THRUSTER_PHASE_OFF:
            if (thrusterMode == 1) {
                ObjModel_SetBlendChannelTargets(imSpaceThruster_getActiveModel(obj), 0, -1, 0, -0.2f,
                                                BLENDCHAN_FLAG_KEEP_WEIGHT);
                obj->anim.alpha = 0xFF;
                state->phase = IM_SPACE_THRUSTER_PHASE_ON;
            } else {
                int alpha = obj->anim.alpha - framesThisStep * 8;

                if (alpha < 0) {
                    alpha = 0;
                }
                obj->anim.alpha = alpha;
            }
            break;
        case IM_SPACE_THRUSTER_PHASE_ON:
            if (thrusterMode == 0) {
                ObjModel_SetBlendChannelTargets(imSpaceThruster_getActiveModel(obj), 0, -1, 0, 0.2f,
                                                BLENDCHAN_FLAG_KEEP_WEIGHT);
                state->blendTimer = 0xB4;
                obj->anim.alpha = 0xA4;
                state->phase = IM_SPACE_THRUSTER_PHASE_FADE_OUT;
            }
            break;
        case IM_SPACE_THRUSTER_PHASE_FADE_OUT:
            if (thrusterMode == 1) {
                state->phase = IM_SPACE_THRUSTER_PHASE_ON;
            } else if ((state->blendTimer -= framesThisStep) < 0) {
                state->phase = IM_SPACE_THRUSTER_PHASE_OFF;
            }
            break;
        }

        if (state->kind < 5) {
            f32 weight = obj->anim.alpha / IM_SPACE_THRUSTER_ALPHA_TO_WEIGHT_SCALE;

            if (weight > IM_SPACE_THRUSTER_WEIGHT_MAX) {
                weight = IM_SPACE_THRUSTER_WEIGHT_MAX;
            } else if (weight < 0.0f) {
                weight = 0.0f;
            }
            IM_SPACE_THRUSTER_PARENT_INTERFACE(obj->anim.parent)
                ->setThrusterWeight((GameObject*)obj->anim.parent, weight, state->kind);
        }

        texture = objFindTexture(obj, 0, 0);
        textureOffset = -texture->offsetT;
        textureOffset += 0x100;
        if (textureOffset > 0x800) {
            textureOffset -= 0x800;
        }
        texture->offsetT = -textureOffset;

        texture = objFindTexture(obj, 1, 0);
        textureOffset = -texture->offsetT;
        textureOffset += 0xA0;
        if (textureOffset > 0x800) {
            textureOffset -= 0x800;
        }
        texture->offsetT = -textureOffset;
    }
}

void imSpaceThruster_init(GameObject* obj, const IMSpaceThrusterPlacement* placement) {
    IMSpaceThrusterState* state = obj->extra;
    ObjModel* model;

    obj->anim.rotX = (s16)(placement->initialRotX << 8);
    obj->anim.rotY = placement->initialRotY;
    obj->anim.bankIndex = (s8)placement->bankIndex;
    state->kind = placement->kind;

    switch (state->kind) {
    case 0:
    case 1:
        obj->anim.rootMotionScale = IM_SPACE_THRUSTER_ROOT_MOTION_SCALE_KIND01;
        break;
    case 2:
    case 3:
        obj->anim.rootMotionScale = IM_SPACE_THRUSTER_ROOT_MOTION_SCALE_KIND23;
        break;
    case 5:
    case 6:
        obj->anim.rootMotionScale = IM_SPACE_THRUSTER_ROOT_MOTION_SCALE_KIND56;
        break;
    case 4:
        obj->anim.rootMotionScale = IM_SPACE_THRUSTER_ROOT_MOTION_SCALE_KIND4;
        break;
    }
    model = imSpaceThruster_getActiveModel(obj);
    ObjModel_SetBlendChannelTargets(model, 0, -1, 0, 0.0f, 0);
    ObjModel_SetBlendChannelWeight(model, 0, IM_SPACE_THRUSTER_WEIGHT_MAX);
    {
        u32 kind = state->kind;

        if (kind < 5) {
            state->keyframesA = mmAlloc(0x28, 0x12, 0);
            getTabEntry(state->keyframesA, MLDF_FILEID_LACTIONS_BIN, gIMSpaceThrusterKeyframeIndicesA[kind] * 0x28,
                        0x28);
            state->keyframesB = mmAlloc(0x28, 0x12, 0);
            getTabEntry(state->keyframesB, MLDF_FILEID_LACTIONS_BIN, gIMSpaceThrusterKeyframeIndicesB[kind] * 0x28,
                        0x28);
        }
    }

    obj->anim.alpha = 0;
}

void imSpaceThruster_release(void) {
}

void imSpaceThruster_initialise(void) {
}

ObjectDescriptor gIMSpaceThrusterObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imSpaceThruster_initialise,
    (ObjectDescriptorCallback)imSpaceThruster_release,
    0,
    (ObjectDescriptorCallback)imSpaceThruster_init,
    (ObjectDescriptorCallback)imSpaceThruster_update,
    (ObjectDescriptorCallback)imSpaceThruster_hitDetect,
    (ObjectDescriptorCallback)imSpaceThruster_render,
    (ObjectDescriptorCallback)imSpaceThruster_free,
    (ObjectDescriptorCallback)imSpaceThruster_getObjectTypeId,
    imSpaceThruster_getExtraSize,
};
