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
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"

#define TIMER_MODE_GLOBAL 1
#define TIMER_MODE_EFFECT 2

/* placement mapId excluded from the count-not-started footstep cue */
#define TIMER_MAP_NO_FOOTSTEP 0x466ED

/* gameTimerInit timer id used by the global-mode timer */
#define GAME_TIMER_ID 29

/* point-light struct fields gating the glow render (untyped here) */
#define LIGHT_FIELD_2F8_OFFSET 0x2f8
#define LIGHT_FIELD_4C_OFFSET 0x4c

typedef struct TimerSetup
{
    ObjPlacement base;
    u8 pad18;            /* 0x18 */
    u8 mode;             /* 0x19: TIMER_MODE_* */
    s16 durationMinutes; /* 0x1A */
    s16 pad1C;           /* 0x1C */
    s16 expiredGameBit;  /* 0x1E: set when the countdown reaches zero */
    s16 startGameBit;    /* 0x20: arms / disarms the countdown */
} TimerSetup;

typedef struct TimerState
{
    f32 countdownTimer;  /* 0x00 */
    void* lightSlot;     /* 0x04: effect-mode point-light slot pointer */
    f32 lightScale;      /* 0x08 */
    u8 mode;             /* 0x0C: TIMER_MODE_* */
    TimerFlags flags;    /* 0x0D */
    u8 pad0E[0x20 - 0xE]; /* 0x0E */
} TimerState;

STATIC_ASSERT(offsetof(TimerSetup, mode) == 0x19);
STATIC_ASSERT(offsetof(TimerSetup, durationMinutes) == 0x1A);
STATIC_ASSERT(offsetof(TimerSetup, expiredGameBit) == 0x1E);
STATIC_ASSERT(offsetof(TimerSetup, startGameBit) == 0x20);
STATIC_ASSERT(sizeof(TimerSetup) == 0x24);
STATIC_ASSERT(offsetof(TimerState, lightSlot) == 0x04);
STATIC_ASSERT(offsetof(TimerState, lightScale) == 0x08);
STATIC_ASSERT(offsetof(TimerState, mode) == 0x0C);
STATIC_ASSERT(offsetof(TimerState, flags) == 0x0D);
STATIC_ASSERT(sizeof(TimerState) == 0x20);

int timer_getExtraSize(void) { return sizeof(TimerState); }

void timer_free(int obj)
{
    TimerState* state = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 0x4c);
    if (state->lightSlot != NULL)
    {
        modelLightStruct_freeSlot((int)&state->lightSlot);
    }
    gameTimerStop();
}

int timer_hasExpired(int obj)
{
    TimerState* state = ((GameObject*)obj)->extra;
    return state->flags.expired;
}

int timer_isEffectMode(int obj)
{
    TimerState* state = ((GameObject*)obj)->extra;
    return state->mode == TIMER_MODE_EFFECT;
}

void timer_clearManualFlags(int obj)
{
    TimerState* state = ((GameObject*)obj)->extra;
    state->flags.manual = 0;
    state->flags.expired = 0;
}

void timer_forceStart(int obj)
{
    TimerState* state = ((GameObject*)obj)->extra;
    state->flags.manual = 1;
}

void timer_addDuration(int obj, int duration)
{
    TimerState* state = ((GameObject*)obj)->extra;
    if (fn_80080150((int)state) != 0)
    {
        state->countdownTimer = state->countdownTimer + duration;
        if (state->mode == TIMER_MODE_GLOBAL)
        {
            gameTimerInit(GAME_TIMER_ID, (int)(state->countdownTimer / lbl_803E7408));
            timerSetToCountUp();
        }
    }
}

void timer_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    TimerState* state = ((GameObject*)obj)->extra;
    void* light = state->lightSlot;
    if (light != NULL && *(u8*)((char*)light + LIGHT_FIELD_2F8_OFFSET) != 0 &&
        *(u8*)((char*)light + LIGHT_FIELD_4C_OFFSET) != 0)
    {
        queueGlowRender(light);
    }
    if (((GameObject*)obj)->ownerObj == NULL)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7418);
    }
}

void timer_init(int obj, int setup)
{
    TimerState* state = ((GameObject*)obj)->extra;
    TimerSetup* setupData = (TimerSetup*)setup;

    storeZeroToFloatParam((void*)state);
    state->mode = setupData->mode;
    state->lightScale = lbl_803E7424;
    state->flags.expired = 0;
    state->flags.manual = 0;
    state->lightSlot = NULL;
    ObjGroup_AddObject(obj, 0x4c);
    state->flags.flag20 = 0;
}

void timer_update(int obj)
{
    int textureId;
    int expiredThisFrame;
    TimerFlags* flags;
    TimerSetup* setup;
    TimerState* state;
    state = ((GameObject*)obj)->extra;
    setup = (TimerSetup*)((GameObject*)obj)->anim.placementData;
    flags = &state->flags;

    if (fn_80080150((int)state) != 0)
    {
        expiredThisFrame = 0;
        if (flags->manual == 0 && (void*)GameBit_Get(setup->startGameBit) == NULL)
        {
            storeZeroToFloatParam((void*)state);
            if (state->mode == TIMER_MODE_GLOBAL)
            {
                switch (((TimerSetup*)((GameObject*)obj)->anim.placementData)->base.mapId)
                {
                case TIMER_MAP_NO_FOOTSTEP:
                    break;
                default:
                    Sfx_PlayFromObject(obj, SFXmn_sml_trex_fstep);
                    break;
                }
            }
            expiredThisFrame = 1;
        }
        if (timerCountDown((void*)state) != 0)
        {
            GameBit_Set(setup->expiredGameBit, 1);
            GameBit_Set(setup->startGameBit, 0);
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
                modelLightStruct_freeSlot((int)&state->lightSlot);
                break;
            }
            flags->manual = 0;
        }
    }
    else
    {
        if ((void*)GameBit_Get(setup->startGameBit) != NULL || flags->manual != 0)
        {
            storeZeroToFloatParam((void*)state);
            if (setup->durationMinutes != 0)
            {
                s16toFloat((void*)state, (s16)(setup->durationMinutes * 60));
            }
            switch (state->mode)
            {
            case TIMER_MODE_GLOBAL:
                gameTimerInit(GAME_TIMER_ID, setup->durationMinutes);
                timerSetToCountUp();
                break;
            case TIMER_MODE_EFFECT:
                state->lightSlot = (void*)modelLightStruct_createPointLight(obj, 255, 0, 0, 0);
                if (state->lightSlot != NULL)
                {
                    modelLightStruct_setupGlow(state->lightSlot, 0, 255, 0, 0, 100, lbl_803DC418);
                    modelLightStruct_setPosition(state->lightSlot, lbl_803E741C, lbl_803E7420,
                                                 *(f32*)&lbl_803E741C);
                }
                break;
            }
        }
tail:
        if (state->mode == TIMER_MODE_EFFECT && fn_80080150((int)state) != 0)
        {
            void* light = state->lightSlot;
            f32 glowAlpha; /* embedded-assign pins lbl_803DC41C to glowAlpha's reg */
            int scroll = (int)((f32)(setup->durationMinutes * 60) / state->countdownTimer *
                (glowAlpha = lbl_803DC41C));
            ObjTextureRuntimeSlot* texPtr = objFindTexture((void*)obj, 0, 0);
            if (texPtr != 0)
            {
                textureId = texPtr->textureId + scroll * framesThisStep;
                if (textureId > 512)
                {
                    textureId -= 512;
                }
                texPtr->textureId = textureId;
            }
            if (light != NULL)
            {
                scroll = textureId >> 8;
            }
            else
            {
                scroll = 0;
            }
            if (state->lightSlot != NULL)
            {
                if (scroll == 1 && scroll != flags->flag20)
                {
                    Sfx_PlayFromObject(obj, 986);
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
