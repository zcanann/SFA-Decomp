/*
 * LevelName (DLL 0xF8) - proximity- and sequence-triggered level banners.
 *
 * A banner slides in, wobbles for a fixed interval, then slides out. An
 * optional game bit records that the placement has already been shown.
 */
#include "dlls/objects/248_LevelName.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/gametext_internal.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "main/textrender_api.h"
#include "main/objseq.h"

#define LEVELNAME_OBJECT_TYPE_ID 0

#define LEVELNAME_NO_GAME_BIT -1

#define LEVELNAME_BANNER_Y_MAX         220
#define LEVELNAME_BANNER_Y_STEP        4
#define LEVELNAME_BANNER_HOLD_DURATION 100
#define LEVELNAME_BANNER_WOBBLE_HEIGHT 30.0f
#define LEVELNAME_BANNER_WOBBLE_STEP   0x500
#define LEVELNAME_PI                   3.1415927f
#define LEVELNAME_BINARY_ANGLE_SCALE   32768.0f

#define LEVELNAME_SEQUENCE_EVENT_SHOW   1
#define LEVELNAME_SEQUENCE_RESULT_SHOWN 4

enum {
    LEVELNAME_PHASE_WAIT = 0,
    LEVELNAME_PHASE_SLIDE_IN = 1,
    LEVELNAME_PHASE_HOLD = 2,
    LEVELNAME_PHASE_SLIDE_OUT = 3,
    LEVELNAME_PHASE_IDLE = 4
};

int LevelName_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    LevelNameState* state = obj->extra;
    int eventIndex;

    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        if (animUpdate->eventIds[eventIndex] == LEVELNAME_SEQUENCE_EVENT_SHOW) {
            if (state->enableGameBit != LEVELNAME_NO_GAME_BIT) {
                mainSetBits(state->enableGameBit, 1);
            }
            state->phase = LEVELNAME_PHASE_SLIDE_IN;
            return LEVELNAME_SEQUENCE_RESULT_SHOWN;
        }
    }
    return 0;
}

int LevelName_getExtraSize(void) {
    return sizeof(LevelNameState);
}

int LevelName_getObjectTypeId(void) {
    return LEVELNAME_OBJECT_TYPE_ID;
}

void LevelName_free(void) {
}

void LevelName_render(void) {
}

void LevelName_hitDetect(void) {
}

void LevelName_update(GameObject* obj) {
    LevelNameState* state;
    GameObject* playerObj;

    state = obj->extra;
    switch (state->phase) {
    case LEVELNAME_PHASE_WAIT:
        playerObj = Obj_GetPlayerObject();
        if (Vec_distance(&obj->anim.worldPosX, &playerObj->anim.worldPosX) < (f32)(u32)state->triggerRadius) {
            if (state->enableGameBit != LEVELNAME_NO_GAME_BIT) {
                mainSetBits(state->enableGameBit, 1);
            }
            state->phase = LEVELNAME_PHASE_SLIDE_IN;
        }
        break;
    case LEVELNAME_PHASE_SLIDE_IN:
        state->bannerY = state->bannerY + framesThisStep * LEVELNAME_BANNER_Y_STEP;
        if (state->bannerY > LEVELNAME_BANNER_Y_MAX) {
            state->bannerY = LEVELNAME_BANNER_Y_MAX;
            state->phase = LEVELNAME_PHASE_HOLD;
        }
        break;
    case LEVELNAME_PHASE_HOLD: {
        state->elapsedFrames += framesThisStep;
        if ((u32)state->elapsedFrames > (u32)state->holdDuration) {
            state->phase = LEVELNAME_PHASE_SLIDE_OUT;
        }
        state->bannerY =
            (s16)((s32)(LEVELNAME_BANNER_WOBBLE_HEIGHT *
                        mathSinf((LEVELNAME_PI * (f32)((s32)state->elapsedFrames * LEVELNAME_BANNER_WOBBLE_STEP)) /
                                 LEVELNAME_BINARY_ANGLE_SCALE)) +
                  LEVELNAME_BANNER_Y_MAX);
        break;
    }
    case LEVELNAME_PHASE_SLIDE_OUT:
        state->bannerY = state->bannerY - framesThisStep * LEVELNAME_BANNER_Y_STEP;
        if (state->bannerY < 0) {
            state->bannerY = 0;
            state->phase = LEVELNAME_PHASE_IDLE;
        }
        break;
    case LEVELNAME_PHASE_IDLE:
        break;
    }
}

void LevelName_init(GameObject* obj, LevelNamePlacement* placement) {
    LevelNameState* state;
    GameTextDef* textDef;

    state = obj->extra;
    obj->animEventCallback = LevelName_SeqFn;
    textDef = gameTextGet(placement->textId);
    state->text = *textDef->strings;
    state->holdDuration = LEVELNAME_BANNER_HOLD_DURATION;
    state->textDef = textDef;
    state->triggerRadius = placement->triggerRadius;
    state->enableGameBit = placement->enableGameBit;
    state->phase = LEVELNAME_PHASE_WAIT;
    state->bannerY = 0;
    state->elapsedFrames = 0;
    if (state->enableGameBit != LEVELNAME_NO_GAME_BIT) {
        if (mainGetBit(state->enableGameBit) != 0) {
            state->phase = LEVELNAME_PHASE_IDLE;
        }
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void LevelName_release(void) {
}

void LevelName_initialise(void) {
}

ObjectDescriptor gLevelNameObjDescriptor = {
    0,                                                   /* reserved0 */
    0,                                                   /* reserved1 */
    0,                                                   /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,                    /* slotCountAndFlags */
    (ObjectDescriptorCallback)LevelName_initialise,      /* initialise */
    (ObjectDescriptorCallback)LevelName_release,         /* release */
    0,                                                   /* slot02 */
    (ObjectDescriptorCallback)LevelName_init,            /* init */
    (ObjectDescriptorCallback)LevelName_update,          /* update */
    (ObjectDescriptorCallback)LevelName_hitDetect,       /* hitDetect */
    (ObjectDescriptorCallback)LevelName_render,          /* render */
    (ObjectDescriptorCallback)LevelName_free,            /* free */
    (ObjectDescriptorCallback)LevelName_getObjectTypeId, /* getObjectTypeId */
    LevelName_getExtraSize,                              /* getExtraSize */
};
