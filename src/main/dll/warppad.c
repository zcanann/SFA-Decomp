/*
 * warppad - shared helpers for the warp-pad / transporter object
 * (driven from dll_012C_transporter). Two routines, called from the
 * transporter's per-frame update:
 *
 *  warpPadFn_8019042c      - renders the pad's idle / activation
 *                            particle fx. The pad's effect family is
 *                            chosen from state->flags (warp-type bits
 *                            0x40/0x10/0x8); the proximity burst fires
 *                            when the player is within range and a
 *                            ramping pulse fx (flag 4) cycles through
 *                            stages keyed on state->pulseTimer.
 *  warpPadPlayerStandingOn - the interaction/trigger logic: arms the
 *                            A-button prompt, runs trigger sequences
 *                            0/1/2 depending on gamebit + proximity,
 *                            and runs the post-trigger countdown /
 *                            cooldown timers.
 *
 * The per-object extra state is WarpPadState and the placement record
 * is WarpPadPlacement (both in CF/warp_pad.h).
 */
#include "main/dll/partfx_interface.h"
#include "main/object_api.h"
#include "main/dll/tricky_api.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/dll/CF/warp_pad.h"
#include "main/gamebits.h"
#include "main/objseq.h"
#include "main/obj_trigger.h"
#include "main/frame_timing.h"
#include "main/vecmath_distance_api.h"

#define WARPPAD_OBJFLAG_PARENT_SLACK 0x1000

/* one-shot latch: gates the first A-prompt trigger sequence for any warp pad */
#define GAMEBIT_WARPPAD_PROMPT_SHOWN 0x912

/* recurring shimmer emitted randomly across all warp-pulse stages */
#define WARPPAD_PARTFX_PULSE 0x7ca
/* surge burst emitted at the stage-2 transition and the stage-3 latch release */
#define WARPPAD_PARTFX_SURGE 0x7d2

extern u8 lbl_803DCDE0;
extern s16 lbl_803DCEB8;
#define WARP_PAD_PULSE_STAGE1_TIME 120.0f
#define WARP_PAD_PULSE_STAGE2_TIME 360.0f
#define WARP_PAD_PULSE_STAGE3_TIME 420.0f
#define WARP_PAD_PULSE_END_TIME 480.0f
f32 lbl_803E3E98 = 0.0f;
f32 gWarpPadProximityBurstDistSq = 409600.0f;
/* state->flags bits are defined in warp_pad.h (WARPPAD_FLAG_*) */

extern f32 gWarpPadTriggerDist;

void warpPadFn_8019042c(GameObject* obj)
{
    WarpPadState* state;
    void* player;
    u8 flags;
    u8 i;
    struct
    {
        s16 unk0;
        s16 mode;
        s16 effectId;
        s16 count;
        f32 scale;
        f32 pos[3];
    } fx;

    state = (obj)->extra;
    player = Obj_GetPlayerObject();
    fx.pos[0] = lbl_803E3E98;
    fx.pos[1] = 55.0f;
    fx.pos[2] = lbl_803E3E98;
    flags = state->flags;

    if ((flags & WARPPAD_FLAG_WARP_A) != 0)
    {
        if ((flags & WARPPAD_FLAG_WARP_B) != 0)
        {
            fx.effectId = 0xc0e;
            fx.mode = 1;
        }
        else if ((flags & WARPPAD_FLAG_WARP_C) != 0)
        {
            fx.effectId = 0xc7e;
            fx.mode = 2;
        }
        else
        {
            fx.effectId = 0xc13;
            fx.mode = 0;
        }
    }
    else if ((flags & WARPPAD_FLAG_WARP_B) != 0)
    {
        if (vec3f_distanceSquared(&(obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            gWarpPadProximityBurstDistSq)
        {
            if (((state->flags & (WARPPAD_FLAG_DISABLED | WARPPAD_FLAG_GAMEBIT_DISABLED)) != 0) &&
                (state->countdownActive == 0))
            {
                objfx_spawnArcedBurstLegacy((int)obj, 1, 0.75f, 2, 7, 100, 30.0f,
                                            30.0f,
                                      110.0f, &fx, 0);
            }
            else
            {
                objfx_spawnArcedBurstLegacy((int)obj, 1, 0.5f, 1, 6, 100, 30.0f,
                                            30.0f,
                                      110.0f, &fx, 0);
            }
        }
        fx.effectId = 0xc0e;
        fx.mode = 1;
    }
    else if ((flags & WARPPAD_FLAG_WARP_C) != 0)
    {
        if (vec3f_distanceSquared(&(obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            gWarpPadProximityBurstDistSq)
        {
            if (((state->flags & (WARPPAD_FLAG_DISABLED | WARPPAD_FLAG_GAMEBIT_DISABLED)) != 0) &&
                (state->countdownActive == 0))
            {
                objfx_spawnArcedBurstLegacy((int)obj, 1, 0.75f, 2, 7, 100, 30.0f,
                                            30.0f,
                                      110.0f, &fx, 0);
            }
            else
            {
                objfx_spawnArcedBurstLegacy((int)obj, 1, 0.5f, 5, 6, 100, 30.0f,
                                            30.0f,
                                      110.0f, &fx, 0);
            }
        }
        fx.effectId = 0xc7e;
        fx.mode = 2;
    }
    else
    {
        if (vec3f_distanceSquared(&(obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            gWarpPadProximityBurstDistSq)
        {
            if (((state->flags & (WARPPAD_FLAG_DISABLED | WARPPAD_FLAG_GAMEBIT_DISABLED)) != 0) &&
                (state->countdownActive == 0))
            {
                objfx_spawnArcedBurstLegacy((int)obj, 1, 0.75f, 2, 7, 100, 30.0f,
                                            30.0f,
                                      110.0f, &fx, 0);
            }
            else
            {
                objfx_spawnArcedBurstLegacy((int)obj, 1, 0.5f, 3, 6, 100, 30.0f,
                                            30.0f,
                                      110.0f, &fx, 0);
            }
        }
        fx.effectId = 0xc13;
        fx.mode = 0;
    }

    if ((state->flags & WARPPAD_FLAG_PULSE_FX) != 0)
    {
        if (state->pulseTimer < WARP_PAD_PULSE_STAGE1_TIME)
        {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < state->pulseTimer * 0.5f)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, WARPPAD_PARTFX_PULSE, &fx, 2, -1, NULL);
            }
        }
        else if (state->pulseTimer < WARP_PAD_PULSE_STAGE2_TIME)
        {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < state->pulseTimer / 3.0f)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, WARPPAD_PARTFX_PULSE, &fx, 2, -1, NULL);
            }
            fx.count = 0x28;
            fx.unk0 = 0;
            fx.scale = 0.0009f * ((state->pulseTimer - WARP_PAD_PULSE_STAGE1_TIME) / 240.0f);
            (*gPartfxInterface)->spawnObject((void*)obj, WARPPAD_PARTFX_SURGE, &fx, 2, -1, NULL);
            state->flags = state->flags | WARPPAD_FLAG_LATCH;
        }
        else if (state->pulseTimer < WARP_PAD_PULSE_STAGE3_TIME)
        {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < state->pulseTimer * 0.5f)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, WARPPAD_PARTFX_PULSE, &fx, 2, -1, NULL);
            }
            if ((state->flags & WARPPAD_FLAG_LATCH) != 0)
            {
                state->flags = state->flags & ~WARPPAD_FLAG_LATCH;
                fx.count = 0x46;
                fx.scale = 0.00036f;
                for (i = 0xf; i != 0; i--)
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, WARPPAD_PARTFX_SURGE, &fx, 2, -1, NULL);
                }
            }
        }
        else if (!(state->pulseTimer < WARP_PAD_PULSE_END_TIME))
        {
            state->pulseTimer = lbl_803E3E98;
            state->flags = state->flags & ~WARPPAD_FLAG_PULSE_FX;
        }
        state->pulseTimer = state->pulseTimer + timeDelta;
    }
}

void warpPadPlayerStandingOn(GameObject* obj)
{
    WarpPadPlacement* placement;
    WarpPadState* state;
    void* player;
    s16 gameBit;

    placement = (WarpPadPlacement*)(obj)->anim.placement;
    state = (obj)->extra;
    gameBit = placement->enableGameBit;
    if (gameBit != -1)
    {
        if (mainGetBit(gameBit) != 0)
        {
            state->flags = state->flags & ~WARPPAD_FLAG_GAMEBIT_DISABLED;
        }
        else
        {
            state->flags = state->flags | WARPPAD_FLAG_GAMEBIT_DISABLED;
        }
    }

    if (((obj)->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
    {
        setAButtonIcon(0x1b);
        if (mainGetBit(GAMEBIT_WARPPAD_PROMPT_SHOWN) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
            mainSetBits(GAMEBIT_WARPPAD_PROMPT_SHOWN, 1);
            return;
        }
    }

    player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }

    if ((state->triggerMode == 0) && (state->countdownActive == 0) &&
        (((obj)->objectFlags & WARPPAD_OBJFLAG_PARENT_SLACK) == 0))
    {
        if ((lbl_803DCEB8 > -1) &&
            (Vec_xzDistance(&(obj)->anim.worldPosX, &((GameObject*)Obj_GetPlayerObject())->anim.worldPosX) <
             gWarpPadTriggerDist))
        {
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
            (obj)->userData1 = state->activateDelay;
            state->triggerMode = 0;
            state->countdownActive = 1;
            lbl_803DCDE0 = 2;
        }
        else
        {
            gameBit = placement->enableGameBit;
            if (((gameBit == -1) ||
                 ((mainGetBit(gameBit) != 0) && (((obj)->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0))) &&
                (ObjTrigger_IsSet((int)obj) != 0))
            {
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                (obj)->userData1 = state->activateDelay;
                state->triggerMode = 1;
                state->countdownActive = 1;
            }
        }
    }

    if (state->countdownActive != 0)
    {
        if ((obj)->userData1 > 0)
        {
            (obj)->userData1 = (obj)->userData1 - framesThisStep;
        }
        else
        {
            (obj)->userData1 = 0;
            state->countdownActive = 0;
        }
    }
    state->cooldownTimer = state->cooldownTimer - timeDelta;
    if (state->cooldownTimer <= lbl_803E3E98)
    {
        state->cooldownTimer = lbl_803E3E98;
        state->unk0A = -1;
    }
}

f32 gWarpPadTriggerDist = 40.0f;
