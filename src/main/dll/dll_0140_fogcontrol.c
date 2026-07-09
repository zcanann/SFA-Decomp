/*
 * fogcontrol (DLL 0x140) - a placed object that drives the engine's
 * heavy-fog volume.
 *
 * The fog is gated by a placement game bit (enableGameBit, -1 = always
 * on). While the gate transitions, FogControl_update ramps a 0..1 blend
 * value toward the gated target (ramp speeds 0.005/0.02 scaled by
 * timeDelta, selected by the FOG_FLAG_FAST_* bits) and feeds the
 * resulting fog band/density to enableHeavyFog each frame; at blend
 * <= floor (0.0) the fog is turned off (disableHeavyFog).
 * FogControl_init primes the blend from the gate state and FogControl_free
 * tears the fog down if it was left active.
 *
 * The fog band is derived from the object's localPosY plus the placement
 * height fields (fogTop/fogBottom/fogBase), with fog colors at
 * fogGreen/fogRed and the enableHeavyFog mode taken from FOG_FLAG_MODE.
 */
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/dll/dll_0140_fogcontrol.h"

#define FOGCONTROL_OBJFLAG_HIDDEN 0x4000

/* FogcontrolPlacement::flags (low byte, offset 0x1A) */
#define FOG_FLAG_MODE     0x01 /* enableHeavyFog mode arg */
#define FOG_FLAG_FAST_IN  0x02 /* ramp-in uses fast speed 0.005 (else 0.02) */
#define FOG_FLAG_FAST_OUT 0x04 /* ramp-out uses fast speed 0.005 (else 0.02) */
#define FOG_FLAG_ENABLE   0x08 /* fog volume is placed/active */

extern void enableHeavyFog(f32 a, f32 b, f32 c, f32 d, f32 e, u8 mode);

int FogControl_getExtraSize(void)
{
    return sizeof(FogControlState);
}
int FogControl_getObjectTypeId(void)
{
    return 0x0;
}

void FogControl_free(struct GameObject *obj)
{
    FogControlState* st = ((GameObject*)obj)->extra;
    if (st->on)
    {
        disableHeavyFog();
    }
}

void FogControl_hitDetect(void)
{
}

/* FogControl_update: ramp the fog blend toward the gamebit-selected
 * target and feed the heavy fog params. */
void FogControl_update(struct GameObject *obj)
{
    u8* setup = (u8*)((GameObject*)obj)->anim.placement;
    FogControlState* st = ((GameObject*)obj)->extra;
    u8 cv;
    u8 run;
    f32 fogY;

    if (((FogcontrolPlacement*)setup)->enableGameBit == -1)
    {
        cv = 1;
    }
    else
    {
        cv = mainGetBit(((FogcontrolPlacement*)setup)->enableGameBit);
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
            if ((*(u8*)&((FogcontrolPlacement*)setup)->flags & FOG_FLAG_FAST_IN) != 0)
            {
                st->blend = 0.005f * timeDelta + st->blend;
            }
            else
            {
                st->blend = 0.02f * timeDelta + st->blend;
            }
            st->on = 1;
        }
        else
        {
            if ((*(u8*)&((FogcontrolPlacement*)setup)->flags & FOG_FLAG_FAST_OUT) != 0)
            {
                st->blend = -(0.005f * timeDelta - st->blend);
            }
            else
            {
                st->blend = -(0.02f * timeDelta - st->blend);
            }
            st->full = 0;
        }
        if (st->blend <= 0.0f)
        {
            st->blend = 0.0f;
            st->on = 0;
            disableHeavyFog();
        }
        else
        {
            st->on = 1;
            if (st->blend > 1.0f)
            {
                st->blend = 1.0f;
                st->full = 1;
            }
            fogY =
                st->blend * ((f32)((FogcontrolPlacement*)setup)->fogTop - (f32)((FogcontrolPlacement*)setup)->fogBase) +
                (f32)((FogcontrolPlacement*)setup)->fogBase;
            fogY = ((GameObject*)obj)->anim.localPosY + fogY;
            enableHeavyFog(
                fogY,
                ((f32)((FogcontrolPlacement*)setup)->fogBottom + fogY) - (f32)((FogcontrolPlacement*)setup)->fogTop,
                (f32)((FogcontrolPlacement*)setup)->fogRed, (f32)((FogcontrolPlacement*)setup)->fogGreen / 65535.0f,
                0.0001f, *(u8*)&((FogcontrolPlacement*)setup)->flags & FOG_FLAG_MODE);
        }
    }
}

void FogControl_init(struct GameObject *obj, FogcontrolPlacement* placement)
{
    FogControlState* st;
    u8 cv;
    f32 fogY;

    st = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | FOGCONTROL_OBJFLAG_HIDDEN);
    st->on = 0;
    st->full = 0;
    st->blend = 0.0f;
    if ((*(u8*)&placement->flags & FOG_FLAG_ENABLE) != 0)
    {
        if (placement->enableGameBit == -1)
        {
            cv = 1;
        }
        else
        {
            cv = mainGetBit(placement->enableGameBit);
        }
        if (cv != 0)
        {
            st->full = 1;
            st->on = 1;
            st->blend = 1.0f;
            fogY = st->blend * ((f32)placement->fogTop - placement->fogBase) + placement->fogBase;
            fogY = ((GameObject*)obj)->anim.localPosY + fogY;
            enableHeavyFog(fogY, ((f32)placement->fogBottom + fogY) - placement->fogTop, placement->fogRed,
                           placement->fogGreen / 65535.0f, 0.0001f, *(u8*)&placement->flags & FOG_FLAG_MODE);
        }
    }
}
