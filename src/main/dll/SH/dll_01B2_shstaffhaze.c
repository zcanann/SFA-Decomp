/*
 * shstaffhaze (DLL 0x1B2) - the shimmering haze drawn around the staff
 * [801D9B1C-801D9BDC).
 *
 * render() draws the object model at a fixed scale and overlays the haze
 * effect through fn_80098B18; update() frees the object once its
 * animation has been hidden.
 */
#include "main/game_object.h"
#include "main/dll/VF/vf_shared.h"

extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);

extern f32 lbl_803E5518;
extern f32 lbl_803E551C;
extern f32 lbl_803E5520;

void sh_staffhaze_render(int obj, u32 p2, u32 p3, u32 p4, u32 p5)
{
    float vec[3];
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E5518);
    vec[0] = lbl_803E551C;
    vec[1] = lbl_803E5520;
    vec[2] = lbl_803E551C;
    fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 4, 0, 0, (int)&vec[0]);
}

void sh_staffhaze_update(int obj)
{
    if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
    {
        Obj_FreeObject(obj);
    }
}
