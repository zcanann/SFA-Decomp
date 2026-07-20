/*
 * imspacering (DLL 0x170) - one of the spinning rings that orbit the
 * SpaceCraft cinematic object on the Ice Mountain map.
 *
 * Each ring picks a random spin axis at init (X or Y) and tumbles
 * continuously on that axis plus Z. While the ring generator
 * (imspaceringgen) has published a leader object in gSpaceRingLeader,
 * every ring copies the leader's alpha and chases its world position so
 * the whole swarm tracks the spacecraft.
 */
#include "main/game_object.h"
#include "main/object_render.h"
#include "main/object_api.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/dll/IM/dll_0170_imspacering.h"
#include "main/object_descriptor.h"

#define IMSPACERING_SPIN_AXIS(obj) ((obj)->userData1)

int IMSpaceRing_getExtraSize(void)
{
    return 0x0;
}
int IMSpaceRing_getObjectTypeId(void)
{
    return 0x0;
}

void IMSpaceRing_free(GameObject* obj)
{
}

void IMSpaceRing_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void IMSpaceRing_hitDetect(void)
{
}

void IMSpaceRing_update(GameObject* obj)
{
    IMSpaceRingPlacement* placement = (IMSpaceRingPlacement*)obj->anim.placementData;
    if (IMSPACERING_SPIN_AXIS(obj) != 0)
    {
        obj->anim.rotX = (s16)(obj->anim.rotX + placement->spinSpeed * framesThisStep);
    }
    else
    {
        obj->anim.rotY = (s16)(obj->anim.rotY + placement->spinSpeed * framesThisStep);
    }
    obj->anim.rotZ = (s16)(obj->anim.rotZ + placement->tiltSpeed * framesThisStep);
    if (gSpaceRingLeader != NULL)
    {
        obj->anim.alpha = gSpaceRingLeader->anim.alpha;
        objMove(obj, gSpaceRingLeader->anim.localPosX - obj->anim.localPosX,
                gSpaceRingLeader->anim.localPosY - obj->anim.localPosY,
                gSpaceRingLeader->anim.localPosZ - obj->anim.localPosZ);
    }
}

void IMSpaceRing_init(GameObject* obj, IMSpaceRingPlacement* placement)
{
    obj->anim.rotX = (s16)((s32)placement->initialRotX << 8);
    IMSPACERING_SPIN_AXIS(obj) = randomGetRange(0, 1);
}

void IMSpaceRing_release(void)
{
}

void IMSpaceRing_initialise(void)
{
}

ObjectDescriptor gIMSpaceRingObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)IMSpaceRing_initialise,
    (ObjectDescriptorCallback)IMSpaceRing_release,
    0,
    (ObjectDescriptorCallback)IMSpaceRing_init,
    (ObjectDescriptorCallback)IMSpaceRing_update,
    (ObjectDescriptorCallback)IMSpaceRing_hitDetect,
    (ObjectDescriptorCallback)IMSpaceRing_render,
    (ObjectDescriptorCallback)IMSpaceRing_free,
    (ObjectDescriptorCallback)IMSpaceRing_getObjectTypeId,
    IMSpaceRing_getExtraSize,
};
