#include "dlls/objects/369_IMSpaceRing.h"

#include "main/frame_timing.h"
#include "main/obj_list.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define IM_SPACE_RING_GENERATOR_SEQUENCE_ID_A 0x164
#define IM_SPACE_RING_GENERATOR_SEQUENCE_ID_B 0x168

#define IM_SPACE_RING_GENERATOR_CHILD_OBJECT_ID  0x301
#define IM_SPACE_RING_GENERATOR_HAS_SPAWNED(obj) ((obj)->userData1)

int imSpaceRingGenerator_getExtraSize(void) {
    return sizeof(IMSpaceRingGeneratorState);
}

int imSpaceRingGenerator_getObjectTypeId(void) {
    return 0;
}

void imSpaceRingGenerator_free(void) {
    gIMSpaceRingLeader = NULL;
}

void imSpaceRingGenerator_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                                 s8 visible) {
    IMSpaceRingGeneratorState* state = obj->extra;

    if (visible != 0 && (state->visible != 0 || obj->anim.alpha != 0)) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void imSpaceRingGenerator_hitDetect(void) {
}

void imSpaceRingGenerator_update(GameObject* obj) {
    int ringIndex;
    IMSpaceRingPlacement* ringPlacement;
    ObjPlacement* placement;
    IMSpaceRingGeneratorState* state;
    int objectIndex;
    int objectCount;

    placement = obj->anim.placement;
    state = obj->extra;
    if (state->ringA == NULL || state->ringB == NULL) {
        GameObject** objects = ObjList_GetObjects(&objectIndex, &objectCount);

        for (objectIndex = 0; objectIndex < objectCount; objectIndex++) {
            GameObject* candidate = objects[objectIndex];

            if (candidate->anim.romDefNo == IM_SPACE_RING_GENERATOR_SEQUENCE_ID_A) {
                state->ringA = candidate;
            }
            if (candidate->anim.romDefNo == IM_SPACE_RING_GENERATOR_SEQUENCE_ID_B) {
                state->ringB = candidate;
            }
        }
    } else {
        int alpha;

        state->visible = IM_SPACE_RING_INTERFACE(state->ringB)->isVisible(state->ringB);
        if (state->visible != 0) {
            alpha = obj->anim.alpha + framesThisStep * 8;
            if (alpha > 0xFF) {
                alpha = 0xFF;
            }
        } else {
            alpha = obj->anim.alpha - framesThisStep * 8;
            if (alpha < 0) {
                alpha = 0;
            }
        }
        obj->anim.alpha = alpha;

        if (IM_SPACE_RING_GENERATOR_HAS_SPAWNED(obj) == 0 && Obj_CanSetupObject() != 0) {
            for (ringIndex = 0; ringIndex < IM_SPACE_RING_GENERATOR_CHILD_COUNT; ringIndex++) {
                ringPlacement = (IMSpaceRingPlacement*)Obj_AllocObjectSetup(sizeof(IMSpaceRingPlacement),
                                                                            IM_SPACE_RING_GENERATOR_CHILD_OBJECT_ID);
                ringPlacement->base.posX = obj->anim.localPosX;
                ringPlacement->base.posY = obj->anim.localPosY;
                ringPlacement->base.posZ = obj->anim.localPosZ;
                ringPlacement->initialRotX = randomGetRange(0, 0xFFFF);
                ringPlacement->spinSpeed = randomGetRange(200, 400);
                if ((int)randomGetRange(0, 1) == 0) {
                    ringPlacement->spinSpeed = -ringPlacement->spinSpeed;
                }
                ringPlacement->tiltSpeed = randomGetRange(200, 400);
                if ((int)randomGetRange(0, 1) == 0) {
                    ringPlacement->tiltSpeed = -ringPlacement->tiltSpeed;
                }
                ringPlacement->base.color[0] = placement->color[0];
                ringPlacement->base.color[2] = placement->color[2];
                ringPlacement->base.color[1] = 1;
                ringPlacement->base.color[3] = 0xFF;
                objSetupObject(&ringPlacement->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
            }
            IM_SPACE_RING_GENERATOR_HAS_SPAWNED(obj) = 1;
        }

        objMove(obj, state->ringA->anim.localPosX - obj->anim.localPosX,
                (9.0f + state->ringA->anim.localPosY) - obj->anim.localPosY,
                state->ringA->anim.localPosZ - obj->anim.localPosZ);
        obj->anim.rotX = obj->anim.rotX + framesThisStep * 0x100;
        obj->anim.rotY = obj->anim.rotY + framesThisStep * 0x20;
        obj->anim.rotZ = obj->anim.rotZ + framesThisStep * 0x40;
        obj->anim.parent = NULL;
    }
}

void imSpaceRingGenerator_init(GameObject* obj) {
    IM_SPACE_RING_GENERATOR_HAS_SPAWNED(obj) = 0;
    gIMSpaceRingLeader = obj;
}

void imSpaceRingGenerator_release(void) {
}

void imSpaceRingGenerator_initialise(void) {
}

ObjectDescriptor gIMSpaceRingGeneratorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imSpaceRingGenerator_initialise,
    (ObjectDescriptorCallback)imSpaceRingGenerator_release,
    0,
    (ObjectDescriptorCallback)imSpaceRingGenerator_init,
    (ObjectDescriptorCallback)imSpaceRingGenerator_update,
    (ObjectDescriptorCallback)imSpaceRingGenerator_hitDetect,
    (ObjectDescriptorCallback)imSpaceRingGenerator_render,
    (ObjectDescriptorCallback)imSpaceRingGenerator_free,
    (ObjectDescriptorCallback)imSpaceRingGenerator_getObjectTypeId,
    imSpaceRingGenerator_getExtraSize,
};
