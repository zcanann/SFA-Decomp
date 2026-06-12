/* DLL 0x01B2 — SH staff-haze / level-control objects [801D9B1C-801D9BDC) */
#include "main/game_object.h"
#include "main/dll/beaconflags_types.h"

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */

#include "main/dll/DR/DRearthwalk.h"
#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objseq.h"

#include "main/dll/DR/shstaff_state.h"

/* sh_beacon_getExtraSize == 0x18. */

STATIC_ASSERT(sizeof(ShBeaconState) == 0x18);

/* 8b "li r3, N; blr" returners. */

extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);
extern void Obj_FreeObject(int obj);
extern f32 lbl_803E5518;
extern f32 lbl_803E551C;
extern f32 lbl_803E5520;

/* 96b: render via objRenderFn + fn_80098B18 with 3-float local. */
void sh_staffhaze_render(int obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5)
{
    extern void objRenderFn_8003b8f4(int obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, double scale); /* #57 */
    float local[3];
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E5518);
    local[0] = lbl_803E551C;
    local[1] = lbl_803E5520;
    local[2] = lbl_803E551C;
    fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 4, 0, 0, (int)&local[0]);
}

/* 48b: free if 0x4000 flag set. */
void sh_staffhaze_update(int obj)
{
    if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
    {
        Obj_FreeObject(obj);
    }
}

/* 120b: tick a float timer; on wrap optionally trigger an effect. */
int sh_beacon_SeqFn(int obj);

/* 20b: reset extra->field_0x8 = lbl_803E552C, return 1. */

/* 112b: vtable cleanup then maybe Obj_FreeObject. */

/* 56b: single-call hit-effect poll. */

/* TODO stubs to align function set with v1.0 asm. Bodies are large
 * state-machine and animation logic; filling them is a follow-up task. */
