#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"

#define TIMER_MODE_GLOBAL 1
#define TIMER_MODE_EFFECT 2

typedef struct TimerSetup {
    ObjPlacement base;
    u8 pad18;
    u8 mode;
    s16 durationMinutes;
    s16 pad1C;
    s16 expiredGameBit;
    s16 startGameBit;
} TimerSetup;

typedef struct TimerState {
    f32 countdownTimer;
    int lightSlot;
    f32 lightScale;
    u8 mode;
    TimerFlags flags;
    u8 padE[0x20 - 0xE];
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


int timer_getExtraSize(void) { return 0x20; }

void timer_free(int obj)
{
    TimerState *state = ((GameObject *)obj)->extra;
    ObjGroup_RemoveObject(obj, 0x4c);
    if ((void *)state->lightSlot != NULL) {
        modelLightStruct_freeSlot((int)&state->lightSlot);
    }
    gameTimerStop();
}

int timer_hasExpired(int obj)
{
    TimerState *state = ((GameObject *)obj)->extra;
    return state->flags.expired;
}

int timer_isEffectMode(int obj)
{
    TimerState *state = ((GameObject *)obj)->extra;
    return state->mode == TIMER_MODE_EFFECT;
}

void timer_clearManualFlags(int obj)
{
    TimerState *state = ((GameObject *)obj)->extra;
    state->flags.manual = 0;
    state->flags.expired = 0;
}

void timer_forceStart(int obj)
{
    TimerState *state = ((GameObject *)obj)->extra;
    state->flags.manual = 1;
}

void timer_addDuration(int obj, int duration)
{
    TimerState *state = ((GameObject *)obj)->extra;
    if (fn_80080150((int)state) != 0) {
        state->countdownTimer = state->countdownTimer + (f32)duration;
        if (state->mode == TIMER_MODE_GLOBAL) {
            gameTimerInit(0x1d, (int)(state->countdownTimer / lbl_803E7408));
            timerSetToCountUp();
        }
    }
}

void timer_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    TimerState *state = ((GameObject *)obj)->extra;
    void *light = (void *)state->lightSlot;
    if (light != NULL && *(u8 *)((char *)light + 0x2f8) != 0 &&
        *(u8 *)((char *)light + 0x4c) != 0) {
        queueGlowRender(light);
    }
    if (((GameObject *)obj)->unkC4 == NULL) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7418);
    }
}

void timer_init(int obj, int setup)
{
    TimerState *state = ((GameObject *)obj)->extra;
    TimerSetup *setupData = (TimerSetup *)setup;

    storeZeroToFloatParam((void *)state);
    state->mode = setupData->mode;
    state->lightScale = lbl_803E7424;
    state->flags.expired = 0;
    state->flags.manual = 0;
    state->lightSlot = 0;
    ObjGroup_AddObject(obj, 0x4c);
    state->flags.flag20 = 0;
}

void timer_update(int obj)
{
    int v;
    TimerState *state = ((GameObject *)obj)->extra;
    TimerSetup *setup = (TimerSetup *)((GameObject *)obj)->anim.placementData;
    TimerFlags *f = &state->flags;
    int flag;

    if (fn_80080150((int)state) != 0) {
        flag = 0;
        if (f->manual == 0 && (u32)GameBit_Get(setup->startGameBit) == 0) {
            storeZeroToFloatParam((void *)state);
            if (state->mode == TIMER_MODE_GLOBAL) {
                switch (setup->base.mapId) {
                case 0x466ED:
                    break;
                default:
                    Sfx_PlayFromObject(obj, SFXmn_sml_trex_fstep);
                    break;
                }
            }
            flag = 1;
        }
        if (timerCountDown((void *)state) != 0) {
            GameBit_Set(setup->expiredGameBit, 1);
            GameBit_Set(setup->startGameBit, 0);
            flag = 1;
        }
        if (flag != 0) {
            f->expired = 1;
            switch (state->mode) {
            case TIMER_MODE_GLOBAL:
                if (state->mode == 0) {
                    break;
                }
                gameTimerStop();
                break;
            case TIMER_MODE_EFFECT:
                modelLightStruct_freeSlot((int)&state->lightSlot);
                break;
            }
            f->manual = 0;
        }
    } else {
        if ((u32)GameBit_Get(setup->startGameBit) != 0 || f->manual != 0) {
            storeZeroToFloatParam((void *)state);
            if (setup->durationMinutes != 0) {
                s16toFloat((void *)state, (s16)(setup->durationMinutes * 60));
            }
            switch (state->mode) {
            case TIMER_MODE_GLOBAL:
                gameTimerInit(29, setup->durationMinutes);
                timerSetToCountUp();
                break;
            case TIMER_MODE_EFFECT:
                state->lightSlot = modelLightStruct_createPointLight(obj, 255, 0, 0, 0);
                if (state->lightSlot != 0) {
                    modelLightStruct_setupGlow((void *)state->lightSlot, 0, 255, 0, 0, 100, lbl_803DC418);
                    modelLightStruct_setPosition((void *)state->lightSlot, lbl_803E741C, lbl_803E7420,
                                        *(f32 *)&lbl_803E741C);
                }
                break;
            }
        }
        if (state->mode == TIMER_MODE_EFFECT && fn_80080150((int)state) != 0) {
            void *hold = (void *)state->lightSlot;
            f32 fm;
            int tv = (int)((f32)(setup->durationMinutes * 60) / state->countdownTimer *
                           (fm = lbl_803DC41C));
            int *texPtr = objFindTexture(obj, 0, 0);
            if (texPtr != 0) {
                v = *texPtr + tv * framesThisStep;
                if (v > 512) {
                    v -= 512;
                }
                *texPtr = v;
            }
            if (hold != NULL) {
                tv = v >> 8;
            } else {
                tv = 0;
            }
            if (state->lightSlot != 0) {
                if (tv == 1 && tv != f->flag20) {
                    Sfx_PlayFromObject(obj, 986);
                }
                modelLightStruct_setEnabled((void *)state->lightSlot, (u8)tv, lbl_803E741C);
            }
            f->flag20 = (u8)tv;
        }
        if (state->lightSlot != 0) {
            modelLightStruct_updateGlowAlpha((void *)state->lightSlot);
        }
    }
}
