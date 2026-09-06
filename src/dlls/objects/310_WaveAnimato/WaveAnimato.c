/*
 * Procedural water-surface animator. All instances share the generated
 * height, color, and phase tables.
 */
#include "dlls/objects/310_WaveAnimato.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/object_render.h"
#include "main/objtype.h"

typedef struct WaveAnimatorColor {
    u8 red;
    u8 green;
    u8 blue;
} WaveAnimatorColor;

STATIC_ASSERT(sizeof(WaveAnimatorColor) == 3);

#define WAVE_ANIMATOR_OBJECT_GROUP 27
#define WAVE_ANIMATOR_RENDER_SCALE 1.0f

u8 gWaveAnimatorPhaseUpdateLatch;
f32* gWaveAnimatorHeightTable;
s16* gWaveAnimatorPhaseTable;
WaveAnimatorColor* gWaveAnimatorColorTable;
u8 gWaveAnimatorInstanceCount;

void WaveAnimator_modelMtxFn(GameObject* obj, int modelMtxArg0, int modelMtxArg1, int modelMtxArg2) {
    WaveAnimatorState* state = obj->extra;
    u32 newFlags;

    newFlags = (u32)state->flags | WAVE_ANIMATOR_STATE_MODEL_MTX_PENDING;
    state->flags = newFlags;
    state->modelMtxArg0 = modelMtxArg0;
    state->modelMtxArg1 = modelMtxArg1;
    state->modelMtxArg2 = modelMtxArg2;
}

void WaveAnimator_func0B(GameObject* obj) {
    WaveAnimatorState* state = obj->extra;

    state->flags |= WAVE_ANIMATOR_STATE_FUNC_0B_LATCH;
}

void WaveAnimator_setScale(GameObject* obj, f32 scale) {
    WaveAnimatorState* state = obj->extra;

    state->flags |= WAVE_ANIMATOR_STATE_SCALE_PENDING;
    state->scaleB = scale;
}

static void WaveAnimator_buildSharedTables(WaveAnimatorState* config) {
    int heightIndex;
    int rowIndex;
    int columnIndex;
    int phaseX;
    int phaseStepX;
    int phaseY;
    int phaseIndex;
    int phaseStepY;
    f32 zeroHeight;

    gWaveAnimatorHeightTable = mmAlloc(sizeof(f32) * config->period * config->period, 0xFFFFFF, 0);
    gWaveAnimatorColorTable = mmAlloc(sizeof(WaveAnimatorColor) * config->period * config->period, 0xFFFFFF, 0);

    phaseX = config->originX;
    phaseStepX = (s32)((65536.0f * config->spanX) / config->period);
    phaseY = config->originY;
    phaseStepY = (s32)((65536.0f * config->spanY) / config->period);

    zeroHeight = 0.0f;
    config->maxHeight = zeroHeight;
    config->minHeight = zeroHeight;

    heightIndex = 0;
    for (rowIndex = 0; rowIndex < config->period; rowIndex++) {
        for (columnIndex = 0; columnIndex < config->period; columnIndex++) {
            gWaveAnimatorHeightTable[heightIndex] = config->ampX * mathSinf((3.1415927f * phaseX) / 32768.0f) +
                                                    config->ampY * mathSinf((3.1415927f * phaseY) / 32768.0f);
            if (gWaveAnimatorHeightTable[heightIndex] < config->minHeight) {
                config->minHeight = gWaveAnimatorHeightTable[heightIndex];
            }
            if (gWaveAnimatorHeightTable[heightIndex] > config->maxHeight) {
                config->maxHeight = gWaveAnimatorHeightTable[heightIndex];
            }
            phaseY += phaseStepY;
            heightIndex++;
        }
        phaseX += phaseStepX;
    }

    {
        f32 colorSplitZero;
        f32 t;
        f32 negMin = -config->minHeight;
        heightIndex = 0;
        colorSplitZero = 0.0f;
        for (rowIndex = 0; rowIndex < config->period; rowIndex++) {
            for (columnIndex = 0; columnIndex < config->period; heightIndex++, columnIndex++) {
                f32 v = gWaveAnimatorHeightTable[heightIndex];
                if (v < colorSplitZero) {
                    t = (v - config->minHeight) / negMin;
                    gWaveAnimatorColorTable[heightIndex].red = 65.0f * t + 190.0f;
                    gWaveAnimatorColorTable[heightIndex].green = 165.0f * t + 90.0f;
                    gWaveAnimatorColorTable[heightIndex].blue = 235.0f * t + 20.0f;
                } else {
                    gWaveAnimatorColorTable[heightIndex].red = 255;
                    gWaveAnimatorColorTable[heightIndex].green = 255;
                    gWaveAnimatorColorTable[heightIndex].blue = 255;
                }
            }
        }
    }

    gWaveAnimatorPhaseTable = mmAlloc(2 * sizeof(s16) * config->gridN * config->gridN, 0xFFFFFF, 0);
    phaseIndex = 0;
    for (rowIndex = 0; rowIndex < config->gridN; rowIndex++) {
        for (columnIndex = 0; columnIndex < config->gridN; columnIndex++) {
            gWaveAnimatorPhaseTable[phaseIndex] = (s16)(rowIndex * 10);
            gWaveAnimatorPhaseTable[phaseIndex + 1] = (s16)(columnIndex * 10);
            phaseIndex += 2;
        }
    }
}

int WaveAnimator_getExtraSize(void) {
    return sizeof(WaveAnimatorState);
}

int WaveAnimator_getObjectTypeId(void) {
    return 0;
}

void WaveAnimator_free(GameObject* obj) {
    if (--gWaveAnimatorInstanceCount == 0) {
        if (gWaveAnimatorHeightTable != NULL) {
            mm_free(gWaveAnimatorHeightTable);
        }
        if (gWaveAnimatorPhaseTable != NULL) {
            mm_free(gWaveAnimatorPhaseTable);
        }
        if (gWaveAnimatorColorTable != NULL) {
            mm_free(gWaveAnimatorColorTable);
        }
    }
    objFreeObjectType(obj, WAVE_ANIMATOR_OBJECT_GROUP);
}

void WaveAnimator_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 visibility = visible;
    if (visibility != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, WAVE_ANIMATOR_RENDER_SCALE);
    }
}

void WaveAnimator_hitDetect(GameObject* obj) {
    int rowIndex;
    int columnIndex;
    int phaseOffset;
    WaveAnimatorState* state;

    if (gWaveAnimatorPhaseUpdateLatch != 0) {
        return;
    }
    state = obj->extra;
    phaseOffset = 0;
    for (rowIndex = 0; rowIndex < state->gridN; rowIndex++) {
        for (columnIndex = 0; columnIndex < state->gridN; columnIndex++) {
            gWaveAnimatorPhaseTable[phaseOffset] += framesThisStep >> 1;
            while (gWaveAnimatorPhaseTable[phaseOffset] >= state->period) {
                gWaveAnimatorPhaseTable[phaseOffset] -= state->period;
            }
            gWaveAnimatorPhaseTable[phaseOffset + 1] += framesThisStep >> 1;
            while (gWaveAnimatorPhaseTable[phaseOffset + 1] >= state->period) {
                gWaveAnimatorPhaseTable[phaseOffset + 1] -= state->period;
            }
            phaseOffset += 2;
        }
    }
    gWaveAnimatorPhaseUpdateLatch = 1;
}

void WaveAnimator_update(void) {
}

void WaveAnimator_init(GameObject* obj, WaveAnimatorPlacement* placement) {
    WaveAnimatorState* state = obj->extra;
    f32 initialScale;

    state->sinkDepthScale = placement->sinkDepthScale;
    state->originX = placement->originX;
    state->originY = placement->originY;
    state->spanX = placement->spanX;
    state->spanY = placement->spanY;
    state->ampX = placement->ampX;
    state->ampY = placement->ampY;
    state->period = placement->period;
    state->gridN = placement->gridN;
    initialScale = (1.0f);
    state->scaleA = initialScale;
    state->scaleB = initialScale;
    if (gWaveAnimatorInstanceCount == 0) {
        WaveAnimator_buildSharedTables(state);
    }
    objAddObjectType(obj, WAVE_ANIMATOR_OBJECT_GROUP);
    gWaveAnimatorInstanceCount++;
}

void WaveAnimator_release(void) {
}

void WaveAnimator_initialise(void) {
}

ObjectDescriptor14 gWaveAnimatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    (ObjectDescriptorCallback)WaveAnimator_initialise,
    (ObjectDescriptorCallback)WaveAnimator_release,
    0,
    (ObjectDescriptorCallback)WaveAnimator_init,
    (ObjectDescriptorCallback)WaveAnimator_update,
    (ObjectDescriptorCallback)WaveAnimator_hitDetect,
    (ObjectDescriptorCallback)WaveAnimator_render,
    (ObjectDescriptorCallback)WaveAnimator_free,
    (ObjectDescriptorCallback)WaveAnimator_getObjectTypeId,
    WaveAnimator_getExtraSize,
    (ObjectDescriptorCallback)WaveAnimator_setScale,
    (ObjectDescriptorCallback)WaveAnimator_func0B,
    (ObjectDescriptorCallback)WaveAnimator_modelMtxFn,
    0,
};
