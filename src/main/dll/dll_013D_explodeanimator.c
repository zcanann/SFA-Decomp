/* === moved from main/dll/MMP/mmp_levelcontrol.c [801948C0-80195008) (TU re-split, docs/boundary_audit.md) === */
#include "main/effect_interfaces.h"
#include "main/game_object.h"







extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();

extern EffectInterface** gPartfxInterface;

/*
 * --INFO--
 *
 * Function: wallanimator_setScale
 * EN v1.0 Address: 0x8019443C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x80194688
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_80194544
 * EN v1.0 Address: 0x80194544
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801947D4
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: objFn_801948c0
 * EN v1.0 Address: 0x801948C0
 * EN v1.0 Size: 164b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: FUN_80194a70
 * EN v1.0 Address: 0x80194A70
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x80194E3C
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_80194b10
 * EN v1.0 Address: 0x80194B10
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x80194EE0
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on





#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: wallanimator_getExtraSize
 * EN v1.0 Address: 0x8019469C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: xyzanimator_getExtraSize
 * EN v1.0 Address: 0x80194B5C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* render-with-objRenderFn_8003b8f4 pattern. */






/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/map_block.h"
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/path_control_interface.h"
#include "main/game_object.h"



typedef struct ExplodeanimatorState
{
    u8 pad0[0x2 - 0x0];
    u8 unk2;
    u8 pad3[0x4 - 0x3];
} ExplodeanimatorState;






typedef struct ExplodeanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
    s16 unk28;
    s16 unk2A;
    u8 pad2C[0x2E - 0x2C];
    s16 unk2E;
    s16 unk30;
    s16 unk32;
    s16 unk34;
    u8 pad36[0x38 - 0x36];
} ExplodeanimatorPlacement;




/*
 * --INFO--
 *
 * Function: xyzanimator_update
 * EN v1.0 Address: 0x80195008
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x801950E0
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801950ac
 * EN v1.0 Address: 0x801950AC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019518C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801954f0
 * EN v1.0 Address: 0x801954F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80195584
 * EN v1.1 Size: 4624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801954f4
 * EN v1.0 Address: 0x801954F4
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x80196794
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_80195b40
 * EN v1.0 Address: 0x80195B40
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80196EA8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_80195b74
 * EN v1.0 Address: 0x80195B74
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80196ED8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void explodeanimator_render(void)
{
}

void explodeanimator_hitDetect(void)
{
}

void explodeanimator_release(void)
{
}

void explodeanimator_initialise(void)
{
}

extern f32 lbl_803E4020;

void explodeanimator_update(int* obj)
{
    u8* sub;
    u8* def;
    int i;
    f32 buf[6];
    f32 vel[2];

    sub = ((GameObject*)obj)->extra;
    if ((sub[2] & 1) != 0) return;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(((ExplodeanimatorPlacement*)def)->unk34) == 0) return;
    GameBit_Set(((ExplodeanimatorPlacement*)def)->unk32, 1);
    sub[2] = (u8)(sub[2] | 1);
    for (i = 0; i < def[0x2c]; i++)
    {
        vel[0] = (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->unk2E, ((ExplodeanimatorPlacement*)def)->unk28) * lbl_803E4020;
        vel[1] = (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->unk30, ((ExplodeanimatorPlacement*)def)->unk2A) * lbl_803E4020;
        buf[3] = (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->unk18, ((ExplodeanimatorPlacement*)def)->unk1E);
        buf[4] = (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->unk1A, ((ExplodeanimatorPlacement*)def)->unk20);
        buf[5] = (f32)(s32)
        randomGetRange(((ExplodeanimatorPlacement*)def)->unk1C, ((ExplodeanimatorPlacement*)def)->unk22);
        (*gPartfxInterface)->spawnObject(obj, ((ExplodeanimatorPlacement*)def)->unk24, buf, 2, -1, vel);
    }
}

void dimbossicesmash_hitDetect(void);












/* 8b "li r3, N; blr" returners. */
int explodeanimator_getExtraSize(void) { return 0x4; }
int explodeanimator_getObjectTypeId(void) { return 0x0; }
int dimbossicesmash_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */



/* ObjGroup_RemoveObject(x, N) wrappers. */
void explodeanimator_free(int x) { ObjGroup_RemoveObject(x, 0x1a); }

/* state encode: ((obj->_X)->_Y << shift) | const. */
u32 dimbossicesmash_getObjectTypeId(int* obj);

/* Drift-recovery: add new fns with v1.0 names. */








void explodeanimator_init(int* obj, int* def)
{
    int* state = ((GameObject*)obj)->extra;
    int v;
    if ((u32)GameBit_Get(*(s16*)((char*)def + 50)) != 0u)
    {
        v = 1;
    }
    else
    {
        v = 0;
    }
    ((ExplodeanimatorState*)state)->unk2 = (u8)v;
    ObjGroup_AddObject(obj, 26);
}


void xyzanimator_init(int obj);


/* EN v1.0 0x80196990  size: 1752b  dimbossicesmash_update: gate on the
 * trigger gamebit, integrate velocity/rotation with per-axis gravity
 * clamps, run the path-control hooks with surface bounce, fade alpha over
 * the lifetime window, and emit the two trail particles. */


/* EN v1.0 0x80196520  size: 1008b  fn_80196520: seed the icesmash launch
 * state from the setup record: spawn position/rotation, launch velocity
 * (optionally homing on the target point), rotation velocities and the
 * gravity/clamp direction flags. */

/* EN v1.0 0x80197068  size: 284b  dimbossicesmash_init. */


/* EN v1.0 0x80197474  size: 648b  fogcontrol_update: ramp the fog blend
 * toward the gamebit-selected target and feed the heavy fog params. */
