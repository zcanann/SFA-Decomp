/*
 * barrelpad (DLL 0x12F) - the barrel-launcher pad object. Spawns
 * arced-burst particle effects when the barrel's seqId indicates an
 * active launch (0x79) or a secondary launch state (0x748). init reads
 * rotation and rootMotionScale from the placement record and enables the
 * object in the engine (objectFlags |= BARRELPAD_OBJFLAG_HITDETECT_DISABLED). This TU also contains
 * the cf_doorlight object (DLL 0x131).
 */
#include "main/game_object.h"
#include "main/dll/VF/vf_shared.h"

#define BARRELPAD_OBJFLAG_HITDETECT_DISABLED 0x2000

/* anim.seqId variants driving the launch particle burst */
#define BARRELPAD_SEQ_LAUNCH_ACTIVE    0x79  /* active launch burst */
#define BARRELPAD_SEQ_LAUNCH_SECONDARY 0x748 /* secondary launch state */
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                  f32 scaleZ, void* args, int arg9);

typedef struct BarrelPadParticleArgs
{
    u8 pad00[0xc];
    f32 offset[3];
} BarrelPadParticleArgs;

extern f32 lbl_803E3F00;
extern f32 lbl_803E3F04;
extern f32 lbl_803E3F08;
extern f32 lbl_803E3F0C;
extern f32 lbl_803E3F10;
extern f32 lbl_803E3F14;
extern f32 lbl_803E3F18;
extern f32 lbl_803E3F1C;
extern f32 lbl_803E3F20;
extern f32 lbl_803E3F24;

void barrelpad_free(void)
{
}

void barrelpad_hitDetect(void)
{
}

void barrelpad_release(void)
{
}

void barrelpad_initialise(void)
{
}


int barrelpad_getExtraSize(void) { return 0x0; }
int barrelpad_getObjectTypeId(void) { return 0x0; }

void barrelpad_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E3F00); }

void barrelpad_update(s16* obj)
{
    BarrelPadParticleArgs particleArgs;

    if (((GameObject*)obj)->anim.seqId == BARRELPAD_SEQ_LAUNCH_ACTIVE)
    {
        particleArgs.offset[0] = lbl_803E3F04;
        particleArgs.offset[1] = lbl_803E3F08;
        particleArgs.offset[2] = lbl_803E3F04;
        objfx_spawnArcedBurst((int)obj, 5, lbl_803E3F0C, 5, 2, 0x19, lbl_803E3F10,
                              *(f32*)&lbl_803E3F10, lbl_803E3F14, &particleArgs, 0);
    }
    else if (((GameObject*)obj)->anim.seqId == BARRELPAD_SEQ_LAUNCH_SECONDARY)
    {
        particleArgs.offset[0] = lbl_803E3F04;
        particleArgs.offset[1] = lbl_803E3F18;
        particleArgs.offset[2] = lbl_803E3F04;
        objfx_spawnArcedBurst((int)obj, 5, lbl_803E3F1C, 5, 2, 5, lbl_803E3F20,
                              *(f32*)&lbl_803E3F20, lbl_803E3F14, &particleArgs, 0);
    }
}

void barrelpad_init(s16* obj, u8* def)
{
    ((GameObject*)obj)->anim.rotZ = (s16)((s32)def[0x18] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32)def[0x19] << 8);
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x1a] << 8);
    if (def[0x1b] != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)
        def[0x1b] / lbl_803E3F24;
        if (((GameObject*)obj)->anim.rootMotionScale == lbl_803E3F04)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3F00;
        }
        ((GameObject*)obj)->anim.rootMotionScale =
            ((GameObject*)obj)->anim.rootMotionScale * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    }
    ((GameObject*)obj)->objectFlags |= BARRELPAD_OBJFLAG_HITDETECT_DISABLED;
}
