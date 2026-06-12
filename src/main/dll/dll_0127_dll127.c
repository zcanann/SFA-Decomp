#include "main/game_object.h"
#include "main/screen_transition.h"




/*
 * --INFO--
 *
 * Function: deathgas_free
 * EN v1.0 Address: 0x8018BC50
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x8018BC64
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



/* Trivial 4b 0-arg blr leaves. */




void dll_127_free_nop(void)
{
}

void dll_127_hitDetect_nop(void)
{
}

/* 8b "li r3, N; blr" returners. */
int fuelcell_getExtraSize(void);
int dll_127_getExtraSize_ret_0(void) { return 0x0; }
int dll_127_getObjectTypeId(void) { return 0x13; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3D60;
extern void objRenderFn_8003b8f4(f32);

void dll_127_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3D60);
}

/* Drift-recovery: add new fns with v1.0 names. */
extern void setPendingMapLoad(int v);




















#pragma opt_loop_invariants off
#pragma opt_loop_invariants reset




#include "main/dll/CF/treasureRelated0177.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/screen_transition.h"




extern u8 framesThisStep;
extern f32 lbl_803E3D64;
extern f32 lbl_803E3D68;

/*
 * --INFO--
 *
 * Function: dll_127_update
 * EN v1.0 Address: 0x8018CDAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018CDAC
 * EN v1.1 Size: 1116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_127_update(int obj)
{
    int flags;

    if (((GameObject*)obj)->anim.hitReactState == 0)
    {
        return;
    }
    if (*(short*)(obj + 0xf8) > 0)
    {
        *(short*)(obj + 0xf8) -= framesThisStep;
    }
    flags = (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags & 8;
    if (flags == 0)
    {
        return;
    }
    if (*(short*)(obj + 0xf8) > 0)
    {
        return;
    }
    *(short*)(obj + 0xf8) = 100;
}


/*
 * --INFO--
 *
 * Function: dll_127_init
 * EN v1.0 Address: 0x8018CF80
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x8018D378
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_127_init(short* param_1, int param_2)
{
    ObjAnimComponent* objAnim;
    float fVar1;
    uint uVar2;
    u8 b;

    objAnim = (ObjAnimComponent*)param_1;
    param_1[3] = param_1[3] | 2;
    b = *(u8*)(param_2 + 0x19);
    fVar1 = (f32)(int)
    b;
    if ((f32)(int)b < lbl_803E3D64
    )
    {
        fVar1 = *(f32*)&lbl_803E3D64;
    }
    fVar1 = fVar1 * lbl_803E3D68;
    *(float*)(param_1 + 4) = *(float*)(*(int*)(param_1 + 0x28) + 4) * fVar1;
    if (*(float**)(param_1 + 0x32) != (float*)0x0)
    {
        **(float**)(param_1 + 0x32) = **(float**)(param_1 + 0x28) * fVar1;
    }
    objAnim->bankIndex = (s8) * (u8*)(param_2 + 0x18);
    uVar2 = *(byte*)(param_2 + 0x1a) & 0x3f;
    *param_1 = (short)(uVar2 << 10);
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    *(undefined4*)(param_1 + 0x7a) = 0;
    *(undefined4*)(param_1 + 0x7c) = 0;
    return;
}


/* Trivial 4b 0-arg blr leaves. */
void dll_127_release_nop(void)
{
}

void dll_127_initialise_nop(void)
{
}

extern int* gSHthorntailAnimationInterface;


/*
 * --INFO--
 *
 * Function: campfire_update
 * EN v1.0 Address: 0x8018CFA4
 * EN v1.0 Size: 556b
 */


/*
 * --INFO--
 *
 * Function: campfire_init
 * EN v1.0 Address: 0x8018D1D0
 * EN v1.0 Size: 732b
 */


/*
 * --INFO--
 *
 * Function: kt_torch_init
 * EN v1.0 Address: 0x8018D584
 * EN v1.0 Size: 348b
 */








/* 8b "li r3, N; blr" returners. */


/* render-with-objRenderFn_8003b8f4 pattern. */
