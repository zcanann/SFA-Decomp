/*
 * timer (DLL 0x2B5) - a countdown-timer object with two modes.
 *
 * mode TIMER_MODE_GLOBAL drives the on-screen game timer (gameTimerInit /
 * timerSetToCountUp / gameTimerStop) for a placement-set duration in minutes;
 * mode TIMER_MODE_EFFECT instead runs a pulsing point-light/glow whose
 * texture animates as the countdown progresses.
 *
 * The countdown is armed by the placement's startGameBit (or by
 * timer_forceStart setting the manual flag), and on expiry sets
 * expiredGameBit and raises state->flags.expired. timer_addDuration extends a
 * running timer.
 */
#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/game_timer.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/model_light.h"
#include "main/objlib.h"
#include "main/objtexture.h"
#include "main/maketex_timer_api.h"
#include "main/dll/dll_02B5_timer.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

#define TIMER_OBJGROUP 0x4c

#define TIMER_MODE_GLOBAL 1
#define TIMER_MODE_EFFECT 2

/* placement mapId excluded from the count-not-started footstep cue */
#define TIMER_MAP_NO_FOOTSTEP 0x466ED

/* gameTimerInit timer id used by the global-mode timer */
#define GAME_TIMER_ID 29

/* point-light struct fields gating the glow render (untyped here) */
#define LIGHT_FIELD_2F8_OFFSET 0x2f8
#define LIGHT_FIELD_4C_OFFSET  0x4c

int timer_getExtraSize(void)
{
    return sizeof(TimerState);
}

void timer_free(GameObject* obj)
{
    TimerState* state = (obj)->extra;
    ObjGroup_RemoveObject((int)obj, TIMER_OBJGROUP);
    if (state->lightSlot != NULL)
    {
        modelLightStruct_freeSlot(&state->lightSlot);
    }
    gameTimerStop();
}

int timer_hasExpired(GameObject* obj)
{
    TimerState* state = (obj)->extra;
    return state->flags.expired;
}

int timer_isEffectMode(GameObject* obj)
{
    TimerState* state = (obj)->extra;
    return state->mode == TIMER_MODE_EFFECT;
}

void timer_clearManualFlags(GameObject* obj)
{
    TimerState* state = (obj)->extra;
    state->flags.manual = 0;
    state->flags.expired = 0;
}

void timer_forceStart(GameObject* obj)
{
    TimerState* state = (obj)->extra;
    state->flags.manual = 1;
}

void timer_addDuration(GameObject* obj, int duration)
{
    TimerState* state = obj->extra;
    if (((int (*)(int))fn_80080150)((int)state) != 0)
    {
        state->countdownTimer = state->countdownTimer + duration;
        if (state->mode == TIMER_MODE_GLOBAL)
        {
            gameTimerInit(GAME_TIMER_ID, (int)(state->countdownTimer / lbl_803E7408));
            timerSetToCountUp();
        }
    }
}

void timer_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale)
{
    TimerState* state = (obj)->extra;
    ModelLight* light = state->lightSlot;
    if (light != NULL && *(u8*)((char*)light + LIGHT_FIELD_2F8_OFFSET) != 0 &&
        *(u8*)((char*)light + LIGHT_FIELD_4C_OFFSET) != 0)
    {
        queueGlowRender(light);
    }
    if ((obj)->ownerObj == NULL)
    {
        objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E7418);
    }
}

void timer_init(GameObject* obj, TimerSetup* setup)
{
    TimerState* state = (obj)->extra;
    TimerSetup* setupData = setup;

    storeZeroToFloatParam(&state->countdownTimer);
    state->mode = setupData->mode;
    state->lightScale = lbl_803E7424;
    state->flags.expired = 0;
    state->flags.manual = 0;
    state->lightSlot = NULL;
    ObjGroup_AddObject((int)obj, TIMER_OBJGROUP);
    state->flags.flag20 = 0;
}

void timer_update(GameObject* obj)
{
    int textureId[1];
    int expiredThisFrame;
    TimerFlags* flags;
    TimerSetup* setup;
    TimerState* state;
    state = (obj)->extra;
    setup = (TimerSetup*)(obj)->anim.placementData;
    flags = &state->flags;

    if (((int (*)(int))fn_80080150)((int)state) != 0)
    {
        expiredThisFrame = 0;
        if (flags->manual == 0 && (void*)mainGetBit(setup->startGameBit) == NULL)
        {
            storeZeroToFloatParam(&state->countdownTimer);
            if (state->mode == TIMER_MODE_GLOBAL)
            {
                switch (((TimerSetup*)(obj)->anim.placementData)->base.mapId)
                {
                case TIMER_MAP_NO_FOOTSTEP:
                    break;
                default:
                    Sfx_PlayFromObject((int)obj, SFXTRIG_mpick1_b);
                    break;
                }
            }
            expiredThisFrame = 1;
        }
        if (timerCountDown(&state->countdownTimer) != 0)
        {
            mainSetBits(setup->expiredGameBit, 1);
            mainSetBits(setup->startGameBit, 0);
            expiredThisFrame = 1;
        }
        if (expiredThisFrame == 0)
        {
            goto tail;
        }
        {
            flags->expired = 1;
            switch (state->mode)
            {
            case TIMER_MODE_GLOBAL:
                if (state->mode == 0)
                {
                    break;
                }
                gameTimerStop();
                break;
            case TIMER_MODE_EFFECT:
                modelLightStruct_freeSlot(&state->lightSlot);
                break;
            }
            flags->manual = 0;
        }
    }
    else
    {
        if ((void*)mainGetBit(setup->startGameBit) != NULL || flags->manual != 0)
        {
            storeZeroToFloatParam(&state->countdownTimer);
            if (setup->durationMinutes != 0)
            {
                s16toFloat(&state->countdownTimer, (s16)(setup->durationMinutes * 60));
            }
            switch (state->mode)
            {
            case TIMER_MODE_GLOBAL:
                gameTimerInit(GAME_TIMER_ID, setup->durationMinutes);
                timerSetToCountUp();
                break;
            case TIMER_MODE_EFFECT:
                state->lightSlot = modelLightStruct_createPointLight(obj, 255, 0, 0, 0);
                if (state->lightSlot != NULL)
                {
                    modelLightStruct_setupGlow(state->lightSlot, 0, 255, 0, 0, 100, lbl_803DC418);
                    modelLightStruct_setPosition(state->lightSlot, lbl_803E741C, lbl_803E7420, *(f32*)&lbl_803E741C);
                }
                break;
            }
        }
    tail:
        if (state->mode == TIMER_MODE_EFFECT && ((int (*)(int))fn_80080150)((int)state) != 0)
        {
            ModelLight* light = state->lightSlot;
            f32 glowAlpha; /* embedded-assign pins lbl_803DC41C to glowAlpha's reg */
            int scroll = (int)((f32)(setup->durationMinutes * 60) / state->countdownTimer * (glowAlpha = lbl_803DC41C));
            ObjTextureRuntimeSlot* texPtr = objFindTexture(obj, 0, 0);
            if (texPtr != 0)
            {
                textureId[0] = texPtr->textureId + scroll * framesThisStep;
                if (textureId[0] > 512)
                {
                    textureId[0] -= 512;
                }
                texPtr->textureId = textureId[0];
            }
            if (light != NULL)
            {
                scroll = textureId[0] >> 8;
            }
            else
            {
                scroll = 0;
            }
            if (state->lightSlot != NULL)
            {
                if (scroll == 1 && scroll != flags->flag20)
                {
                    Sfx_PlayFromObject((int)obj, SFXTRIG_barrel_timerbeep);
                }
                modelLightStruct_setEnabled(state->lightSlot, (u8)scroll, lbl_803E741C);
            }
            flags->flag20 = scroll;
        }
        if (state->lightSlot != NULL)
        {
            modelLightStruct_updateGlowAlpha(state->lightSlot);
        }
    }
}
