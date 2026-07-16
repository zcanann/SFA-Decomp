/*
 * imicepillar (DLL 0x16D) - a decorative ice pillar prop on the Ice
 * Mountain map. It has no behaviour of its own: every callback is a
 * stub apart from render, which draws the model through the shared
 * object render helper. A 4-byte extra block is reserved but unused.
 */
#include "main/game_object.h"
#include "main/object_render_legacy.h"
#include "main/dll/IM/dll_016D_imicepillar.h"
#include "main/object_descriptor.h"

const f32 lbl_803E4768 = 1.0f;
const f32 lbl_803E476C = 0.0f;

int imicepillar_getExtraSize(void)
{
    return 0x4;
}
int imicepillar_getObjectTypeId(void)
{
    return 0x0;
}

void imicepillar_free(void)
{
}

void imicepillar_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void imicepillar_hitDetect(void)
{
}

void imicepillar_update(void)
{
}

void imicepillar_init(void)
{
}

void imicepillar_release(void)
{
}

void imicepillar_initialise(void)
{
}
ObjectDescriptor gIMIcePillarObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imicepillar_initialise,
    (ObjectDescriptorCallback)imicepillar_release,
    0,
    (ObjectDescriptorCallback)imicepillar_init,
    (ObjectDescriptorCallback)imicepillar_update,
    (ObjectDescriptorCallback)imicepillar_hitDetect,
    (ObjectDescriptorCallback)imicepillar_render,
    (ObjectDescriptorCallback)imicepillar_free,
    (ObjectDescriptorCallback)imicepillar_getObjectTypeId,
    imicepillar_getExtraSize,
};
