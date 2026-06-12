#include "main/dll/mmp_asteroid_re.h"
#include "main/game_object.h"

/*
 * Recovered: large switch on params[20] (32-bit id) that sets bits in
 * state->flags per map/area id. Six GameBit-guarded cases set bit 0x20 only
 * when any of 3 listed event bits is set; the rest set 0x68, 0x08, 0x30, or
 * 0x10 directly. Tail: if state->flags & 0x40 (which 0x68 includes), set
 * obj->_af |= 8 (redundant with the unconditional prologue store).
 */

void cflightwall_free(void)
{
}

void cflightwall_hitDetect(void)
{
}

void cflightwall_update(void)
{
}

void cflightwall_release(void)
{
}

void cflightwall_initialise(void)
{
}

void barrelpad_free(void);

int cflightwall_getExtraSize(void) { return 0x0; }
int cflightwall_getObjectTypeId(void) { return 0x0; }
int barrelpad_getExtraSize(void);

extern f32 lbl_803E3EE8;
extern void objRenderFn_8003b8f4(f32);
void cflightwall_render(void) { objRenderFn_8003b8f4(lbl_803E3EE8); }
void barrelpad_render(void);

extern f32 lbl_803E3EEC;
extern f32 lbl_803E3EF0;

void cflightwall_init(s16* obj, u8* def)
{
    ((GameObject*)obj)->anim.rotZ = (s16)((s32)def[0x18] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32)def[0x19] << 8);
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x1a] << 8);
    if (def[0x1b] != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)
        def[0x1b] / lbl_803E3EEC;
        if (((GameObject*)obj)->anim.rootMotionScale == lbl_803E3EF0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3EE8;
        }
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * *(f32*)((char*)*(int**)&((
            GameObject*)obj)->anim.modelInstance + 4);
    }
    ((GameObject*)obj)->objectFlags |= 0xA000;
}

void cf_doorlight_update(int obj);
