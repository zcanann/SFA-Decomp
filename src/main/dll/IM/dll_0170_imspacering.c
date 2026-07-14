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
#include "main/object_render_legacy.h"
#include "main/object_api.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/dll/IM/dll_0170_imspacering.h"
#include "main/object_descriptor.h"

extern GameObject* lbl_803DDB48;
__declspec(section ".sdata2") f32 lbl_803E47B8 = 1.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E47BC = 0.0f;
#pragma explicit_zero_data off

int IMSpaceRing_getExtraSize(void)
{
    return 0x0;
}
int IMSpaceRing_getObjectTypeId(void)
{
    return 0x0;
}

void IMSpaceRing_free(void)
{
}

void IMSpaceRing_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E47B8);
}

void IMSpaceRing_hitDetect(void)
{
}

void IMSpaceRing_update(GameObject* obj)
{
    s16* placement = *(s16**)&obj->anim.placementData;
    if (obj->unkF4 != 0)
    {
        obj->anim.rotX = (s16)(obj->anim.rotX + placement[0xd] * framesThisStep);
    }
    else
    {
        obj->anim.rotY = (s16)(obj->anim.rotY + placement[0xd] * framesThisStep);
    }
    obj->anim.rotZ = (s16)(obj->anim.rotZ + placement[0xe] * framesThisStep);
    if (lbl_803DDB48 != NULL)
    {
        obj->anim.alpha = lbl_803DDB48->anim.alpha;
        objMove((GameObject*)obj, lbl_803DDB48->anim.localPosX - obj->anim.localPosX,
                lbl_803DDB48->anim.localPosY - obj->anim.localPosY, lbl_803DDB48->anim.localPosZ - obj->anim.localPosZ);
    }
}

void IMSpaceRing_init(GameObject* obj, s8* placement)
{
    obj->anim.rotX = (s16)((s32)placement[0x18] << 8);
    obj->unkF4 = randomGetRange(0, 1);
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
