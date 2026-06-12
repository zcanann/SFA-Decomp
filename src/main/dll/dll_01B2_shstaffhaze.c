/* === moved from main/dll/IM/IMsnowbike.c [801D9B1C-801D9BDC) (TU re-split, docs/boundary_audit.md) === */
#include "main/game_object.h"





/*
 * --INFO--
 *
 * Function: sh_levelcontrol_update
 * EN v1.0 Address: 0x801D8D20
 * EN v1.0 Size: 2452b
 * EN v1.1 Address: 0x801D90F0
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


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
typedef struct ShBeaconState
{
    int childObj; /* 0x00: spawned 0x55 flame object */
    f32 seqTimer; /* 0x04 */
    f32 fadeTimer; /* 0x08 */
    f32 burstTimer; /* 0x0c */
    f32 modeTimer; /* 0x10 */
    u8 mode; /* 0x14: 0 unlit, 1 lit, 2 igniting */
    u8 flags15; /* 0x15: bit 7 = looping sfx active (BeaconFlags) */
    u8 pad16[2];
} ShBeaconState;

STATIC_ASSERT(sizeof(ShBeaconState) == 0x18);




/*
 * --INFO--
 *
 * Function: sh_staff_render
 * EN v1.0 Address: 0x801D9BDC
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x801DA010
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



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







typedef struct
{
    u8 looping : 1;
    u8 rest : 7;
} BeaconFlags;

/*
 * --INFO--
 *
 * Function: sh_beacon_update
 * EN v1.0 Address: 0x801DAA58
 * EN v1.0 Size: 1080b
 */
