/*
 * imicepillar (DLL 0x16D) - a decorative ice pillar prop on the Ice
 * Mountain map. It has no behaviour of its own: every callback is a
 * stub apart from render, which draws the model through the shared
 * object render helper. A 4-byte extra block is reserved but unused.
 */
#include "main/game_object.h"
#include "main/dll/VF/vf_shared.h"
extern f32 lbl_803E4768;

int imicepillar_getExtraSize(void) { return 0x4; }
int imicepillar_getObjectTypeId(void) { return 0x0; }

void imicepillar_free(void)
{
}

void imicepillar_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E4768);
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
