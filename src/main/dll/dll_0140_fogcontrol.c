#include "main/game_object.h"

extern uint GameBit_Get(int eventId);

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

extern f32 timeDelta;

extern void disableHeavyFog(void);
extern f32 lbl_803E4070;
extern f32 lbl_803E4074;
extern f32 lbl_803E4078;
extern f32 lbl_803E407C;
extern void enableHeavyFog(f32 a, f32 b, f32 c, f32 d, f32 e, u8 mode);
extern f32 lbl_803E4068;
extern f32 lbl_803E406C;

void fogcontrol_hitDetect(void)
{
}

int fogcontrol_getExtraSize(void) { return 0x8; }
int fogcontrol_getObjectTypeId(void) { return 0x0; }
int lightning_getExtraSize(void);

void fogcontrol_free(int* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    if (((u32)state[4] >> 7) & 1u)
    {
        disableHeavyFog();
    }
}

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
            t = st->blend * ((f32) * (s16*)(params + 0x1c) - (f32) * (s16*)(params + 0x20)) +
                (f32) * (s16*)(params + 0x20);
            t = ((GameObject*)obj)->anim.localPosY + t;
            enableHeavyFog(params[0x1a] & 1, t,
                           ((f32) * (s16*)(params + 0x1e) + t) - (f32) * (s16*)(params + 0x1c),
                           (f32) * (s16*)(params + 0x24),
                           (f32) * (s16*)(params + 0x22) / lbl_803E4078,
                           lbl_803E407C);
        }
    }
}

void explodeanimator_init(int* obj, int* def);

/* EN v1.0 0x80197068  size: 284b  dimbossicesmash_init. */

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
            enableHeavyFog(t,
                           ((f32)((FogcontrolPlacement*)setup)->unk1E + t) - (f32)((FogcontrolPlacement*)setup)->unk1C,
                           (f32)((FogcontrolPlacement*)setup)->unk24,
                           (f32)((FogcontrolPlacement*)setup)->unk22 / lbl_803E4078,
                           lbl_803E407C,
                           *(u8*)(setup + 0x1a) & 1);
        }
    }
}
