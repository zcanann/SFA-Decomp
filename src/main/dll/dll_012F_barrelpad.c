/*
 * barrelpad (DLL 0x12F) - the barrel-launcher pad object. Spawns
 * arced-burst particle effects when the barrel's seqId indicates an
 * active launch (0x79) or a secondary launch state (0x748). init reads
 * rotation and rootMotionScale from the placement record and enables the
 * object in the engine (objectFlags |= BARRELPAD_OBJFLAG_HITDETECT_DISABLED).
 */
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/dll/VF/vf_shared.h"
#include "main/dll/dll_012F_barrelpad.h"

#define BARRELPAD_OBJFLAG_HITDETECT_DISABLED 0x2000

/* anim.seqId variants driving the launch particle burst */
#define BARRELPAD_SEQ_LAUNCH_ACTIVE    0x79  /* active launch burst */
#define BARRELPAD_SEQ_LAUNCH_SECONDARY 0x748 /* secondary launch state */

typedef struct BarrelPadPlacement
{
    u8 pad00[0x18];
    u8 rotZByte;  /* 0x18 */
    u8 rotYByte;  /* 0x19 */
    u8 rotXByte;  /* 0x1a */
    u8 scaleByte; /* 0x1b: rootMotionScale = /255 */
} BarrelPadPlacement;


int BarrelPad_getExtraSize(void)
{
    return 0x0;
}
int BarrelPad_getObjectTypeId(void)
{
    return 0x0;
}

void BarrelPad_free(void)
{
}

void BarrelPad_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void BarrelPad_hitDetect(void)
{
}

void BarrelPad_update(s16* obj)
{
    BarrelPadParticleArgs particleArgs;

    if (((GameObject*)obj)->anim.seqId == BARRELPAD_SEQ_LAUNCH_ACTIVE)
    {
        particleArgs.offset[0] = 0.0f;
        particleArgs.offset[1] = 8.0f;
        particleArgs.offset[2] = 0.0f;
        objfx_spawnArcedBurstLegacy((int)obj, 5, 0.75f, 5, 2, 0x19, 12.0f, 12.0f, 2.0f, &particleArgs, 0);
    }
    else if (((GameObject*)obj)->anim.seqId == BARRELPAD_SEQ_LAUNCH_SECONDARY)
    {
        particleArgs.offset[0] = 0.0f;
        particleArgs.offset[1] = 6.0f;
        particleArgs.offset[2] = 0.0f;
        objfx_spawnArcedBurstLegacy((int)obj, 5, 0.25f, 5, 2, 5, 7.0f, 7.0f, 2.0f, &particleArgs, 0);
    }
}

void BarrelPad_init(s16* obj, u8* def)
{
    BarrelPadPlacement* p = (BarrelPadPlacement*)def;
    ((GameObject*)obj)->anim.rotZ = (s16)((s32)p->rotZByte << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32)p->rotYByte << 8);
    ((GameObject*)obj)->anim.rotX = (s16)((s32)p->rotXByte << 8);
    if (p->scaleByte != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)p->scaleByte / 255.0f;
        if (!((GameObject*)obj)->anim.rootMotionScale)
        {
            ((GameObject*)obj)->anim.rootMotionScale = 1.0f;
        }
        ((GameObject*)obj)->anim.rootMotionScale =
            ((GameObject*)obj)->anim.rootMotionScale * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    }
    ((GameObject*)obj)->objectFlags |= BARRELPAD_OBJFLAG_HITDETECT_DISABLED;
}

void BarrelPad_release(void)
{
}

void BarrelPad_initialise(void)
{
}
