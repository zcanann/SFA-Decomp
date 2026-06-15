#include "main/dll/mmp_asteroid_re.h"
#include "main/game_object.h"

extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                  f32 scaleZ, void* args, int arg9);

typedef struct BarrelPadParticleArgs
{
    u8 pad00[0xc];
    f32 offset[3];
} BarrelPadParticleArgs;

/*
 * Recovered: large switch on params[20] (32-bit id) that sets bits in
 * state->flags per map/area id. Six GameBit-guarded cases set bit 0x20 only
 * when any of 3 listed event bits is set; the rest set 0x68, 0x08, 0x30, or
 * 0x10 directly. Tail: if state->flags & 0x40 (which 0x68 includes), set
 * obj->_af |= 8 (redundant with the unconditional prologue store).
 */

extern void objRenderFn_8003b8f4(f32);
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

void cf_doorlight_free(void);

int barrelpad_getExtraSize(void) { return 0x0; }
int barrelpad_getObjectTypeId(void) { return 0x0; }
int cf_doorlight_getExtraSize(void);

void barrelpad_render(void) { objRenderFn_8003b8f4(lbl_803E3F00); }

void barrelpad_update(s16* obj)
{
    BarrelPadParticleArgs particleArgs;

    if (((GameObject*)obj)->anim.seqId == 0x79)
    {
        particleArgs.offset[0] = lbl_803E3F04;
        particleArgs.offset[1] = lbl_803E3F08;
        particleArgs.offset[2] = lbl_803E3F04;
        objfx_spawnArcedBurst((int)obj, 5, lbl_803E3F0C, 5, 2, 0x19, lbl_803E3F10,
                              lbl_803E3F10, lbl_803E3F14, &particleArgs, 0);
    }
    else if (((GameObject*)obj)->anim.seqId == 0x748)
    {
        particleArgs.offset[0] = lbl_803E3F04;
        particleArgs.offset[1] = lbl_803E3F18;
        particleArgs.offset[2] = lbl_803E3F04;
        objfx_spawnArcedBurst((int)obj, 5, lbl_803E3F1C, 5, 2, 5, lbl_803E3F20,
                              lbl_803E3F20, lbl_803E3F14, &particleArgs, 0);
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
    ((GameObject*)obj)->objectFlags |= 0x2000;
}
