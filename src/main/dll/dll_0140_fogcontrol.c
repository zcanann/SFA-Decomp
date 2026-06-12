#include "main/effect_interfaces.h"
#include "main/game_object.h"


extern uint GameBit_Get(int eventId);


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


#include "main/map_block.h"
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/path_control_interface.h"
#include "main/game_object.h"


typedef struct FogcontrolPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 enableGameBit;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    s16 unk26;
    s16 unk28;
    s16 unk2A;
    s16 unk2C;
    s16 unk2E;
    s16 unk30;
    s16 unk32;
    s16 unk34;
    s16 unk36;
    u16 unk38;
    u16 unk3A;
    u8 unk3C;
    u8 pad3D[0x3E - 0x3D];
    s16 unk3E;
    s16 unk40;
    s16 unk42;
    s16 unk44;
    s16 unk46;
} FogcontrolPlacement;


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
extern f32 timeDelta;


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


/* Trivial 4b 0-arg blr leaves. */


void fogcontrol_hitDetect(void)
{
}


/* 8b "li r3, N; blr" returners. */
int fogcontrol_getExtraSize(void) { return 0x8; }
int fogcontrol_getObjectTypeId(void) { return 0x0; }
int lightning_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */


/* ObjGroup_RemoveObject(x, N) wrappers. */

/* state encode: ((obj->_X)->_Y << shift) | const. */

/* Drift-recovery: add new fns with v1.0 names. */
extern void disableHeavyFog(void);


void fogcontrol_free(int* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    if (((u32)state[4] >> 7) & 1u)
    {
        disableHeavyFog();
    }
}

extern f32 lbl_803E4070;
extern f32 lbl_803E4074;
extern f32 lbl_803E4078;
extern f32 lbl_803E407C;
extern void enableHeavyFog(u8 mode, f32 a, f32 b, f32 c, f32 d, f32 e);

typedef struct FogControlState
{
    f32 blend;
    u8 on : 1;
    u8 full : 1;
    u8 rest : 6;
} FogControlState;


void fogcontrol_init(u8* obj, u8* params)
{
    FogControlState* st;
    u8 cv;
    f32 t;

    st = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x4000);
    st->on = 0;
    st->full = 0;
    st->blend = lbl_803E4070;
    if ((params[0x1a] & 0x08) != 0)
    {
        if (*(s16*)(params + 0x18) == -1)
        {
            cv = 1;
        }
        else
        {
            cv = (u8)GameBit_Get(*(s16*)(params + 0x18));
        }
        if (cv != 0)
        {
            st->full = 1;
            st->on = 1;
            st->blend = lbl_803E4074;
            t = ((GameObject*)obj)->anim.localPosY +
            (st->blend * ((f32) * (s16*)(params + 0x1c) - (f32) * (s16*)(params + 0x20)) +
                (f32) * (s16*)(params + 0x20));
            enableHeavyFog(params[0x1a] & 1, t,
                           ((f32) * (s16*)(params + 0x1e) + t) - (f32) * (s16*)(params + 0x1c),
                           (f32) * (s16*)(params + 0x24),
                           (f32) * (s16*)(params + 0x22) / lbl_803E4078,
                           lbl_803E407C);
        }
    }
}

void explodeanimator_init(int* obj, int* def);


/* EN v1.0 0x80196990  size: 1752b  dimbossicesmash_update: gate on the
 * trigger gamebit, integrate velocity/rotation with per-axis gravity
 * clamps, run the path-control hooks with surface bounce, fade alpha over
 * the lifetime window, and emit the two trail particles. */


/* EN v1.0 0x80196520  size: 1008b  fn_80196520: seed the icesmash launch
 * state from the setup record: spawn position/rotation, launch velocity
 * (optionally homing on the target point), rotation velocities and the
 * gravity/clamp direction flags. */

/* EN v1.0 0x80197068  size: 284b  dimbossicesmash_init. */

extern f32 lbl_803E4068;
extern f32 lbl_803E406C;

/* EN v1.0 0x80197474  size: 648b  fogcontrol_update: ramp the fog blend
 * toward the gamebit-selected target and feed the heavy fog params. */
void fogcontrol_update(int obj)
{
    u8* setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    FogControlState* st = ((GameObject*)obj)->extra;
    u8 cv;
    u8 run;
    f32 t;

    if (((FogcontrolPlacement*)setup)->enableGameBit == -1)
    {
        cv = 1;
    }
    else
    {
        cv = (u8)GameBit_Get(((FogcontrolPlacement*)setup)->enableGameBit);
    }
    if ((cv != 0 && st->full == 0) || (cv == 0 && st->on != 0))
    {
        run = 1;
    }
    else
    {
        run = 0;
    }
    if (run != 0)
    {
        if (cv != 0)
        {
            if ((*(u8*)(setup + 0x1a) & 2) != 0)
            {
                st->blend = lbl_803E4068 * timeDelta + st->blend;
            }
            else
            {
                st->blend = lbl_803E406C * timeDelta + st->blend;
            }
            st->on = 1;
        }
        else
        {
            if ((*(u8*)(setup + 0x1a) & 4) != 0)
            {
                st->blend = -(lbl_803E4068 * timeDelta - st->blend);
            }
            else
            {
                st->blend = -(lbl_803E406C * timeDelta - st->blend);
            }
            st->full = 0;
        }
        if (st->blend <= lbl_803E4070)
        {
            st->blend = *(f32*)&lbl_803E4070;
            st->on = 0;
            disableHeavyFog();
        }
        else
        {
            st->on = 1;
            if (st->blend > lbl_803E4074)
            {
                st->blend = *(f32*)&lbl_803E4074;
                st->full = 1;
            }
            t = st->blend * ((f32)((FogcontrolPlacement*)setup)->unk1C - (f32)((FogcontrolPlacement*)setup)->unk20) +
                (f32)((FogcontrolPlacement*)setup)->unk20;
            t = ((GameObject*)obj)->anim.localPosY + t;
            enableHeavyFog(*(u8*)(setup + 0x1a) & 1, t,
                           ((f32)((FogcontrolPlacement*)setup)->unk1E + t) - (f32)((FogcontrolPlacement*)setup)->unk1C,
                           (f32)((FogcontrolPlacement*)setup)->unk24,
                           (f32)((FogcontrolPlacement*)setup)->unk22 / lbl_803E4078,
                           lbl_803E407C);
        }
    }
}
