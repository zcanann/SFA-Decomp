/*
 * Timer (DLL 693) counts nominal frames from a placement duration in seconds.
 * Mode 1 controls the shared HUD countdown; mode 2 animates a point-light glow.
 * Clearing the start bit cancels an unforced run. Both cancellation and natural
 * expiry latch ended, but only natural expiry writes the completion game bit.
 * Starting again does not clear that latch. Free always stops the global timer.
 */
#include "dlls/objects/693_Timer.h"
#include "game/objects/object.h"
#include "main/frame_timing.h"
#include "main/model_light.h"
#include "main/objtexture.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_render.h"
#include "main/audio/sfx_play_api.h"
#include "main/game_timer_control_api.h"
#include "main/gamebits_api.h"
#include "main/maketex_timer_api.h"
#include "main/objtype.h"

f32 gTimerGlowScale = 7.0f;
f32 gTimerTextureScrollScale = 5.0f;


#define TIMER_MODE_GLOBAL 1
#define TIMER_MODE_EFFECT 2

/* Placement identity excluded from the global-mode cancellation sound. */
#define TIMER_SILENT_CANCEL_IDENT 0x466ED



void timer_addDuration(GameObject* obj, int durationFrames)
{
    TimerState* state = obj->extra;
    if (timerIsActive(&state->remainingFrames) != 0)
    {
        state->remainingFrames += durationFrames;
        if (state->mode == TIMER_MODE_GLOBAL)
        {
            gameTimerInit(GAME_TIMER_COUNT_DOWN | GAME_TIMER_LOOP_SOUND | GAME_TIMER_END_SOUND | GAME_TIMER_DISPLAY, (int)(state->remainingFrames / 60.0f));
            gameTimerResume();
        }
    }
}

void timer_clearStartAndEndFlags(GameObject* obj)
{
    TimerState* state = obj->extra;
    state->flags.startOverride = 0;
    state->flags.ended = 0;
}

void timer_forceStart(GameObject* obj)
{
    TimerState* state = obj->extra;
    state->flags.startOverride = 1;
}

int timer_isEffectMode(GameObject* obj)
{
    TimerState* state = obj->extra;
    return state->mode == TIMER_MODE_EFFECT;
}

int timer_hasEnded(GameObject* obj)
{
    TimerState* state = obj->extra;
    return state->flags.ended;
}

int timer_getExtraSize(void)
{
    return sizeof(TimerState);
}

void timer_free(GameObject* obj)
{
    TimerState* state = obj->extra;
    objFreeObjectType(obj, TIMER_OBJECT_GROUP);
    if (state->lightSlot != NULL)
    {
        modelLightStruct_freeSlot(&state->lightSlot);
    }
    gameTimerStop();
}

void timer_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale)
{
    TimerState* state = obj->extra;
    ModelLight* light = state->lightSlot;
    if (light != NULL && light->glowType != 0 &&
        light->enabled != 0)
    {
        queueGlowRender(light);
    }
    if (obj->ownerObj == NULL) {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void timer_update(GameObject* obj)
{
    int textureId[1];
    int endedThisFrame;
    TimerFlags* flags;
    TimerState* state;
    TimerPlacementPrefix* setup;
    state = obj->extra;
    setup = (TimerPlacementPrefix*)obj->anim.placementData;
    flags = &state->flags;

    if (timerIsActive(&state->remainingFrames) != 0)
    {
        endedThisFrame = 0;
        if (flags->startOverride == 0 && (void*)mainGetBit(setup->startGameBit) == NULL)
        {
            storeZeroToFloatParam(&state->remainingFrames);
            if (state->mode == TIMER_MODE_GLOBAL)
            {
                switch (((TimerPlacementPrefix*)obj->anim.placementData)->base.ident) {
                case TIMER_SILENT_CANCEL_IDENT:
                    break;
                default:
                    Sfx_PlayFromObject(obj, SFXTRIG_mpick1_b);
                    break;
                }
            }
            endedThisFrame = 1;
        }
        if (timerCountDown(&state->remainingFrames) != 0)
        {
            mainSetBits(setup->expiredGameBit, 1);
            mainSetBits(setup->startGameBit, 0);
            endedThisFrame = 1;
        }
#if defined(VERSION_GSAE01_rev1) || defined(VERSION_GSAP01_rev1)
        /* These revisions compare the disabled mask (0 or 2) with 1. */
        if (state->mode == TIMER_MODE_GLOBAL && isGameTimerDisabled() == 1) {
            mainSetBits(setup->expiredGameBit, 1);
            mainSetBits(setup->startGameBit, 0);
            endedThisFrame = 1;
        }
#endif
        if (endedThisFrame != 0)
        {
            flags->ended = 1;
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
            flags->startOverride = 0;
            return;
        }
    }
    else
    {
        if ((void*)mainGetBit(setup->startGameBit) != NULL || flags->startOverride != 0)
        {
            storeZeroToFloatParam(&state->remainingFrames);
            if (setup->durationSeconds != 0)
            {
                s16toFloat(&state->remainingFrames, (s16)(setup->durationSeconds * 60));
            }
            switch (state->mode)
            {
            case TIMER_MODE_GLOBAL:
                gameTimerInit(GAME_TIMER_COUNT_DOWN | GAME_TIMER_LOOP_SOUND | GAME_TIMER_END_SOUND | GAME_TIMER_DISPLAY, setup->durationSeconds);
                gameTimerResume();
                break;
            case TIMER_MODE_EFFECT:
                state->lightSlot = modelLightStruct_createPointLight(obj, 255, 0, 0, 0);
                if (state->lightSlot != NULL)
                {
                    modelLightStruct_setupGlow(state->lightSlot, 0, 255, 0, 0, 100, gTimerGlowScale);
                    modelLightStruct_setPosition(state->lightSlot, 0.0f, 3.0f, 0.0f);
                }
                break;
            }
        }
    }
    if (state->mode == TIMER_MODE_EFFECT && timerIsActive(&state->remainingFrames) != 0)
    {
        ModelLight* light = state->lightSlot;
        f32 durationRatio = (f32)(setup->durationSeconds * 60) / state->remainingFrames;
        int scroll = (int)(durationRatio * gTimerTextureScrollScale);
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
            /* Retail reads the uninitialized local if the texture lookup failed. */
            scroll = textureId[0] >> 8;
        }
        else
        {
            scroll = 0;
        }
        if (state->lightSlot != NULL)
        {
            if (scroll == 1 && scroll != flags->previousGlowPhaseBit)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_barrel_timerbeep);
            }
            modelLightStruct_setEnabled(state->lightSlot, (u8)scroll, 0.0f);
        }
        flags->previousGlowPhaseBit = scroll;
    }
    if (state->lightSlot != NULL)
    {
        modelLightStruct_updateGlowAlpha(state->lightSlot);
    }
}

void timer_init(GameObject* obj, TimerPlacementPrefix* setup)
{
    TimerState* state = obj->extra;
    TimerPlacementPrefix* setupData = setup;

    storeZeroToFloatParam(&state->remainingFrames);
    state->mode = setupData->mode;
    state->initialized08 = 0.04f;
    state->flags.ended = 0;
    state->flags.startOverride = 0;
    state->lightSlot = NULL;
    objAddObjectType(obj, TIMER_OBJECT_GROUP);
    state->flags.previousGlowPhaseBit = 0;
}

ObjectDescriptor gTimerObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)timer_init,
    (ObjectDescriptorCallback)timer_update,
    0,
    (ObjectDescriptorCallback)timer_render,
    (ObjectDescriptorCallback)timer_free,
    0,
    timer_getExtraSize,
};
