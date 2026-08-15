/*
 * KT_Torch object family (DLL slot 296 / 0x128).
 *
 * Shared by torches and other stationary animated props. Placement selects
 * the model, animation, scale, yaw, playback speed, and optional visibility
 * game bit.
 */
#include "dlls/objects/296_KT_Torch.h"

#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/object_render.h"

#define KT_TORCH_GAME_BIT_NONE                     -1
#define KT_TORCH_MINIMUM_SCALE                     10.0f
#define KT_TORCH_SCALE_FACTOR                      0.015625f
#define KT_TORCH_ANIMATION_SPEED_DIVISOR           10000.0f
#define KT_TORCH_INITIAL_ANIMATION_PROGRESS_FACTOR 0.00390625f
#define KT_TORCH_INITIAL_YAW_MASK                  0x3F
#define KT_TORCH_INITIAL_YAW_SHIFT                 10

int KT_Torch_getExtraSize(void) {
    return 0;
}

int KT_Torch_getObjectTypeId(void) {
    return 0;
}

void KT_Torch_free(void) {
}

void KT_Torch_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void KT_Torch_hitDetect(void) {
}

void KT_Torch_update(GameObject* obj) {
    KTTorchPlacement* placement;
    int visibilityGameBit;

    placement = (KTTorchPlacement*)obj->anim.placementData;
    ObjAnim_AdvanceCurrentMove(obj, (f32)placement->animationSpeed / KT_TORCH_ANIMATION_SPEED_DIVISOR, timeDelta,
                               (ObjAnimEventList*)0);
    visibilityGameBit = placement->visibilityGameBit;
    if (visibilityGameBit != KT_TORCH_GAME_BIT_NONE) {
        if (mainGetBit(visibilityGameBit) != 0) {
            obj->anim.alpha = 0xff;
        } else {
            obj->anim.alpha = 0;
        }
    }
}

void KT_Torch_init(GameObject* obj, KTTorchPlacement* placement) {
    ObjAnimComponent* objAnim = &obj->anim;
    f32 scale;
    f32 initialAnimationProgress;
    u8 scaleByte;

    objAnim->flags |= 2;
    scaleByte = placement->scaleMultiplier;
    scale = (f32)(int)scaleByte;
    if ((f32)(int)scaleByte < KT_TORCH_MINIMUM_SCALE) {
        scale = KT_TORCH_MINIMUM_SCALE;
    }
    scale *= KT_TORCH_SCALE_FACTOR;
    objAnim->rootMotionScale = objAnim->modelInstance->rootMotionScaleBase * scale;
    objAnim->rotX = (s16)((placement->initialYaw & KT_TORCH_INITIAL_YAW_MASK) << KT_TORCH_INITIAL_YAW_SHIFT);
    if (objAnim->modelState != NULL) {
        objAnim->modelState->shadowScale = objAnim->modelInstance->shadowScaleBase * scale;
    }
    objAnim->bankIndex = (s8)placement->modelBankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount) {
        objAnim->bankIndex = 0;
    }
    ObjAnim_SetCurrentMove(obj, placement->animationIndex,
                           (initialAnimationProgress = placement->initialAnimationProgress,
                            initialAnimationProgress *= KT_TORCH_INITIAL_ANIMATION_PROGRESS_FACTOR),
                           0);
    {
        s16 visibilityGameBit = placement->visibilityGameBit;
        if (visibilityGameBit != KT_TORCH_GAME_BIT_NONE) {
            if (mainGetBit(visibilityGameBit) != 0) {
                objAnim->alpha = 0xff;
            } else {
                objAnim->alpha = 0;
            }
        }
    }
}

void KT_Torch_release(void) {
}

void KT_Torch_initialise(void) {
}

ObjectDescriptor gKT_TorchObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)KT_Torch_initialise,
    (ObjectDescriptorCallback)KT_Torch_release,
    0,
    (ObjectDescriptorCallback)KT_Torch_init,
    (ObjectDescriptorCallback)KT_Torch_update,
    (ObjectDescriptorCallback)KT_Torch_hitDetect,
    (ObjectDescriptorCallback)KT_Torch_render,
    (ObjectDescriptorCallback)KT_Torch_free,
    (ObjectDescriptorCallback)KT_Torch_getObjectTypeId,
    KT_Torch_getExtraSize,
};
