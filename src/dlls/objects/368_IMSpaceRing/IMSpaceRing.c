#include "dlls/objects/368_IMSpaceRing.h"

#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define IM_SPACE_RING_SPIN_AXIS(obj) ((obj)->userData1)

GameObject* gIMSpaceRingLeader;

int imSpaceRing_getExtraSize(void) {
    return 0;
}

int imSpaceRing_getObjectTypeId(void) {
    return 0;
}

void imSpaceRing_free(void) {
}

void imSpaceRing_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible == 0) {
        return;
    }

    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void imSpaceRing_hitDetect(void) {
}

void imSpaceRing_update(GameObject* obj) {
    const IMSpaceRingPlacement* placement = (const IMSpaceRingPlacement*)obj->anim.placementData;

    if (IM_SPACE_RING_SPIN_AXIS(obj) != 0) {
        obj->anim.rotX = (s16)(obj->anim.rotX + placement->spinSpeed * framesThisStep);
    } else {
        obj->anim.rotY = (s16)(obj->anim.rotY + placement->spinSpeed * framesThisStep);
    }
    obj->anim.rotZ = (s16)(obj->anim.rotZ + placement->tiltSpeed * framesThisStep);
    if (gIMSpaceRingLeader != NULL) {
        obj->anim.alpha = gIMSpaceRingLeader->anim.alpha;
        objMove(obj, gIMSpaceRingLeader->anim.localPosX - obj->anim.localPosX,
                gIMSpaceRingLeader->anim.localPosY - obj->anim.localPosY,
                gIMSpaceRingLeader->anim.localPosZ - obj->anim.localPosZ);
    }
}

void imSpaceRing_init(GameObject* obj, const IMSpaceRingPlacement* placement) {
    obj->anim.rotX = placement->initialRotX << 8;
    IM_SPACE_RING_SPIN_AXIS(obj) = randomGetRange(0, 1);
}

void imSpaceRing_release(void) {
}

void imSpaceRing_initialise(void) {
}

ObjectDescriptor gIMSpaceRingObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imSpaceRing_initialise,
    (ObjectDescriptorCallback)imSpaceRing_release,
    0,
    (ObjectDescriptorCallback)imSpaceRing_init,
    (ObjectDescriptorCallback)imSpaceRing_update,
    (ObjectDescriptorCallback)imSpaceRing_hitDetect,
    (ObjectDescriptorCallback)imSpaceRing_render,
    (ObjectDescriptorCallback)imSpaceRing_free,
    (ObjectDescriptorCallback)imSpaceRing_getObjectTypeId,
    imSpaceRing_getExtraSize,
};
