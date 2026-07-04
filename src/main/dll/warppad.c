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
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/CF/warp_pad.h"
#include "main/gamebits.h"
#include "main/objseq.h"
#include "main/gameplay_runtime.h"

#define WARPPAD_OBJFLAG_PARENT_SLACK 0x1000
extern int ObjTrigger_IsSet(int obj);
extern f32 Vec_xzDistance(f32* a, f32* b);
extern f32 vec3f_distanceSquared(f32* a, f32* b);
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                  f32 scaleZ, void* args, int arg9);

extern u8 lbl_803DCDE0;
extern s16 lbl_803DCEB8;
extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E3E98;
extern f32 lbl_803E3E9C;
extern f32 gWarpPadProximityBurstDistSq;
extern f32 lbl_803E3EA4;
extern f32 lbl_803E3EA8;
extern f32 lbl_803E3EAC;
extern f32 lbl_803E3EB0;
extern f32 gWarpPadPulseStage1Time;
extern f32 gWarpPadPulseStage2Time;
extern f32 lbl_803E3EBC;
extern f32 lbl_803E3EC0;
extern f32 lbl_803E3EC4;
extern f32 gWarpPadPulseStage3Time;
extern f32 lbl_803E3ECC;
extern f32 gWarpPadPulseEndTime;
extern f32 gWarpPadTriggerDist;
extern void setAButtonIcon(int x);

/* one-shot latch: gates the first A-prompt trigger sequence for any warp pad */
#define GAMEBIT_WARPPAD_PROMPT_SHOWN 0x912

/* state->flags bits are defined in warp_pad.h (WARPPAD_FLAG_*) */

void warpPadFn_8019042c(int obj)
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

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    fx.pos[0] = lbl_803E3E98;
    fx.pos[1] = lbl_803E3E9C;
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
        if (vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) < gWarpPadProximityBurstDistSq)
        {
            if (((state->flags & (WARPPAD_FLAG_DISABLED | WARPPAD_FLAG_GAMEBIT_DISABLED)) != 0) && (state->countdownActive == 0))
            {
                objfx_spawnArcedBurst(obj, 1, lbl_803E3EA4, 2, 7, 100,
                                      lbl_803E3EA8, *(f32*)&lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
            else
            {
                objfx_spawnArcedBurst(obj, 1, lbl_803E3EB0, 1, 6, 100,
                                      lbl_803E3EA8, *(f32*)&lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
        }
        fx.effectId = 0xc0e;
        fx.mode = 1;
    }
    else if ((flags & WARPPAD_FLAG_WARP_C) != 0)
    {
        if (vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) < gWarpPadProximityBurstDistSq)
        {
            if (((state->flags & (WARPPAD_FLAG_DISABLED | WARPPAD_FLAG_GAMEBIT_DISABLED)) != 0) && (state->countdownActive == 0))
            {
                objfx_spawnArcedBurst(obj, 1, lbl_803E3EA4, 2, 7, 100,
                                      lbl_803E3EA8, *(f32*)&lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
            else
            {
                objfx_spawnArcedBurst(obj, 1, lbl_803E3EB0, 5, 6, 100,
                                      lbl_803E3EA8, *(f32*)&lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
        }
        fx.effectId = 0xc7e;
        fx.mode = 2;
    }
    else
    {
        if (vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) < gWarpPadProximityBurstDistSq)
        {
            if (((state->flags & (WARPPAD_FLAG_DISABLED | WARPPAD_FLAG_GAMEBIT_DISABLED)) != 0) && (state->countdownActive == 0))
            {
                objfx_spawnArcedBurst(obj, 1, lbl_803E3EA4, 2, 7, 100,
                                      lbl_803E3EA8, *(f32*)&lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
            else
            {
                objfx_spawnArcedBurst(obj, 1, lbl_803E3EB0, 3, 6, 100,
                                      lbl_803E3EA8, *(f32*)&lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
        }
        fx.effectId = 0xc13;
        fx.mode = 0;
    }

    if ((state->flags & WARPPAD_FLAG_PULSE_FX) != 0)
    {
        if (state->pulseTimer < gWarpPadPulseStage1Time)
        {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < state->pulseTimer * lbl_803E3EB0
            )
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7ca, &fx, 2, -1, NULL);
            }
        }
        else if (state->pulseTimer < gWarpPadPulseStage2Time)
        {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < state->pulseTimer / lbl_803E3EBC
            )
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7ca, &fx, 2, -1, NULL);
            }
            fx.count = 0x28;
            fx.unk0 = 0;
            fx.scale = lbl_803E3EC0 * ((state->pulseTimer - gWarpPadPulseStage1Time) / lbl_803E3EC4);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7d2, &fx, 2, -1, NULL);
            state->flags = state->flags | WARPPAD_FLAG_LATCH;
        }
        else if (state->pulseTimer < gWarpPadPulseStage3Time)
        {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < state->pulseTimer * lbl_803E3EB0
            )
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7ca, &fx, 2, -1, NULL);
            }
            if ((state->flags & WARPPAD_FLAG_LATCH) != 0)
            {
                state->flags = state->flags & ~WARPPAD_FLAG_LATCH;
                fx.count = 0x46;
                fx.scale = lbl_803E3ECC;
                for (i = 0xf; i != 0; i--)
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7d2, &fx, 2, -1, NULL);
                }
            }
        }
        else if (!(state->pulseTimer < gWarpPadPulseEndTime))
        {
            state->pulseTimer = lbl_803E3E98;
            state->flags = state->flags & ~WARPPAD_FLAG_PULSE_FX;
        }
        state->pulseTimer = state->pulseTimer + timeDelta;
    }
}

void warpPadPlayerStandingOn(int obj)
{
    WarpPadPlacement* placement;
    WarpPadState* state;
    void* player;
    s16 gameBit;

    placement = (WarpPadPlacement*)((GameObject*)obj)->anim.placement;
    state = ((GameObject*)obj)->extra;
    gameBit = placement->enableGameBit;
    if (gameBit != -1)
    {
        if (GameBit_Get(gameBit) != 0)
        {
            state->flags = state->flags & ~WARPPAD_FLAG_GAMEBIT_DISABLED;
        }
        else
        {
            state->flags = state->flags | WARPPAD_FLAG_GAMEBIT_DISABLED;
        }
    }

    if ((((GameObject*)obj)->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
    {
        setAButtonIcon(0x1b);
        if (GameBit_Get(GAMEBIT_WARPPAD_PROMPT_SHOWN) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
            GameBit_Set(GAMEBIT_WARPPAD_PROMPT_SHOWN, 1);
            return;
        }
    }

    player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }

    if ((state->triggerMode == 0) && (state->countdownActive == 0) &&
        ((((GameObject*)obj)->objectFlags & WARPPAD_OBJFLAG_PARENT_SLACK) == 0))
    {
        if (lbl_803DCEB8 > -1)
        {
            player = Obj_GetPlayerObject();
            if (Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) < gWarpPadTriggerDist)
            {
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                ((GameObject*)obj)->unkF4 = state->activateDelay;
                state->triggerMode = 0;
                state->countdownActive = 1;
                lbl_803DCDE0 = 2;
                goto updateTimer;
            }
        }
        gameBit = placement->enableGameBit;
        if (((gameBit == -1) ||
                ((GameBit_Get(gameBit) != 0) && ((((GameObject*)obj)->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0))) &&
            (ObjTrigger_IsSet(obj) != 0))
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            ((GameObject*)obj)->unkF4 = state->activateDelay;
            state->triggerMode = 1;
            state->countdownActive = 1;
        }
    }

updateTimer:
    if (state->countdownActive != 0)
    {
        if (((GameObject*)obj)->unkF4 > 0)
        {
            ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - framesThisStep;
        }
        else
        {
            ((GameObject*)obj)->unkF4 = 0;
            state->countdownActive = 0;
        }
    }
    state->cooldownTimer = state->cooldownTimer - timeDelta;
    if (state->cooldownTimer <= *(f32*)&lbl_803E3E98)
    {
        state->cooldownTimer = lbl_803E3E98;
        state->unk0A = -1;
    }
}
