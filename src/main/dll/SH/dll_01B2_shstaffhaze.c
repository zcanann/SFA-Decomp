/*
 * shstaffhaze (DLL 0x1B2) - the shimmering haze drawn around the staff
 * [801D9B1C-801D9BDC).
 *
 * render() draws the object model at a fixed scale and overlays the haze
 * effect through fn_80098B18; update() frees the object once its
 * animation has been hidden.
 */
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/object.h"
#include "main/object_render_legacy.h"
#include "main/dll/SH/dll_01B2_shstaffhaze.h"

void SH_StaffHaze_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5)
{
    float vec[3];
    objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, 1.0f);
    vec[0] = 0.0f;
    vec[1] = 0.5f;
    vec[2] = 0.0f;
    fn_80098B18Legacy((int)obj, (obj)->anim.rootMotionScale, 4, 0, 0, (int)&vec[0]);
}

void SH_StaffHaze_update(GameObject* obj)
{
    if (((obj)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
    {
        Obj_FreeObject(obj);
    }
}
