#include "dlls/objects/571_DFP_Lightni.h"

#include "main/audio/sfx_limited_object_api.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/mm.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/newclouds.h"
#include "main/frame_timing.h"

#define DFPLIGHTNI_SFX_ID                  0x4c3
#define DFPLIGHTNI_SFX_MAX_COUNT           2

#define DFPLIGHTNI_RANDOM_TIMER_MIN 0
#define DFPLIGHTNI_RANDOM_TIMER_MAX 100
#define DFPLIGHTNI_RANDOM_XZ_MIN    -200
#define DFPLIGHTNI_RANDOM_XZ_MAX    200
#define DFPLIGHTNI_RANDOM_Y_MIN     100
#define DFPLIGHTNI_RANDOM_Y_MAX     300

#define DFPLIGHTNI_PLAYER_EFFECT_FRAMES 10
#define DFPLIGHTNI_LIFETIME_FRAME_SCALE 10
#define DFPLIGHTNI_WIDTH_STEP                 0xc
#define DFPLIGHTNI_EFFECT_WIDTH_MASK          0xff

#define DFPLIGHTNI_TIMER_MAX          1000.0f
#define DFPLIGHTNI_TIMER_INACTIVE_MAX 1010.0f

#define DFPLIGHTNI_TIMER_ACTIVE_RESET  999.0f
#define DFPLIGHTNI_OFFSET_SCALE        0.1f
#define DFPLIGHTNI_DENSITY_MIN          0.001f
#define DFPLIGHTNI_DENSITY_MAX          5.0f
#define DFPLIGHTNI_TRIGGER_TIME_BASE   400.0f
#define DFPLIGHTNI_DENSITY_NORM_DIVISOR 32767.0f

static inline DfpLightniState* dfplightni_getState(GameObject* obj) {
    return obj->extra;
}

/* Unused conversion helper retained as a literal-pool anchor. */
static inline f64 dfplightni_u32AsBiasedDouble(u32 value) {
    /* The 2^52 bias reproduces the integer-conversion bit pattern. */
    return (f64)value + 4503599627370496.0;
}

int DFP_Lightni_getExtraSize(void) {
    return sizeof(DfpLightniState);
}

void DFP_Lightni_free(GameObject* obj) {
    DfpLightniState* state;

    if (obj != 0) {
        state = dfplightni_getState(obj);
        if (state->effectHandle != 0) {
            mm_free(state->effectHandle);
            state->effectHandle = 0;
        }
    }
    return;
}

void DFP_Lightni_render(GameObject* obj) {
    DfpLightniState* state;
    int playerZapped;

    if (obj != 0) {
        state = dfplightni_getState(obj);
        if (state->timer >= DFPLIGHTNI_TIMER_MAX) {
            playerZapped = mainGetBit(GAMEBIT_OFP_ZappedByFloorTiles);
            if (state->effectHandle != 0) {
                lightningRender(state->effectHandle);
            }
            if (playerZapped != 0) {
                if (state->timer >= DFPLIGHTNI_TIMER_MAX + (f32)(s32)state->effectLifetimeFrames) {
                    state->timer = 0.0f;
                }
            } else if (state->timer >= DFPLIGHTNI_TIMER_INACTIVE_MAX) {
                state->timer = 0.0f;
            }
        }
    }
    return;
}

void DFP_Lightni_update(GameObject* obj) {
    GameObject* playerObj;
    int targetPlayer;
    u32 puzzleComplete;
    DfpLightniState* state;
    f32 boltSegmentDensity;
    f32 strandSegmentDensity;
    const Vec3f* effectStart;
    const Vec3f* effectEnd;
    Vec3f start;
    Vec3f end;

    if (obj != 0) {
        state = dfplightni_getState(obj);
        playerObj = Obj_GetPlayerObject();
        if (playerObj != 0) {
            state->timer += timeDelta;
            targetPlayer = mainGetBit(state->targetPlayerGameBit);
            if ((targetPlayer != 0) && (state->timer < DFPLIGHTNI_TIMER_MAX)) {
                state->timer = DFPLIGHTNI_TIMER_ACTIVE_RESET;
            }
            if ((state->timer > state->triggerTime) && (state->timer < DFPLIGHTNI_TIMER_MAX)) {
                start.x = obj->anim.localPosX;
                start.y = obj->anim.localPosY;
                start.z = obj->anim.localPosZ;
                if (targetPlayer != 0) {
                    end.x =
                        DFPLIGHTNI_OFFSET_SCALE * randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN, DFPLIGHTNI_RANDOM_XZ_MAX) +
                        playerObj->anim.localPosX;
                    end.y = DFPLIGHTNI_OFFSET_SCALE * randomGetRange(DFPLIGHTNI_RANDOM_Y_MIN, DFPLIGHTNI_RANDOM_Y_MAX) +
                            playerObj->anim.localPosY;
                    end.z =
                        DFPLIGHTNI_OFFSET_SCALE * randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN, DFPLIGHTNI_RANDOM_XZ_MAX) +
                        playerObj->anim.localPosZ;
                } else {
                    end.x =
                        DFPLIGHTNI_OFFSET_SCALE * randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN, DFPLIGHTNI_RANDOM_XZ_MAX) +
                        start.x;
                    end.y = DFPLIGHTNI_OFFSET_SCALE * randomGetRange(DFPLIGHTNI_RANDOM_Y_MIN, DFPLIGHTNI_RANDOM_Y_MAX) +
                            obj->anim.localPosY;
                    end.z =
                        DFPLIGHTNI_OFFSET_SCALE * randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN, DFPLIGHTNI_RANDOM_XZ_MAX) +
                        start.z;
                }
                if (state->effectHandle != 0) {
                    mm_free(state->effectHandle);
                    state->effectHandle = 0;
                }
                boltSegmentDensity = state->boltSegmentDensity;
                strandSegmentDensity = state->strandSegmentDensity;
                puzzleComplete = mainGetBit(GAMEBIT_OFP_ElectricFloorPuzzleAct1Complete);
                if (puzzleComplete == 0) {
                    f32 clampedBoltDensity;
                    f32 clampedStrandDensity;
                    Sfx_PlayFromObjectLimited(obj, DFPLIGHTNI_SFX_ID, DFPLIGHTNI_SFX_MAX_COUNT);
                    if (targetPlayer != 0) {
                        clampedStrandDensity = (strandSegmentDensity < DFPLIGHTNI_DENSITY_MIN)   ? DFPLIGHTNI_DENSITY_MIN
                                 : (strandSegmentDensity > DFPLIGHTNI_DENSITY_MAX) ? DFPLIGHTNI_DENSITY_MAX
                                                                     : strandSegmentDensity;
                        effectStart = &start;
                        effectEnd = &end;
                        clampedBoltDensity = (boltSegmentDensity < DFPLIGHTNI_DENSITY_MIN)   ? DFPLIGHTNI_DENSITY_MIN
                                 : (boltSegmentDensity > DFPLIGHTNI_DENSITY_MAX) ? DFPLIGHTNI_DENSITY_MAX
                                                                     : boltSegmentDensity;
                        state->effectHandle = lightningCreate(
                            effectStart, effectEnd, clampedBoltDensity, clampedStrandDensity, DFPLIGHTNI_PLAYER_EFFECT_FRAMES,
                            state->widthSteps * DFPLIGHTNI_WIDTH_STEP & DFPLIGHTNI_EFFECT_WIDTH_MASK, 0);
                    } else {
                        clampedStrandDensity = (strandSegmentDensity < DFPLIGHTNI_DENSITY_MIN)   ? DFPLIGHTNI_DENSITY_MIN
                                 : (strandSegmentDensity > DFPLIGHTNI_DENSITY_MAX) ? DFPLIGHTNI_DENSITY_MAX
                                                                     : strandSegmentDensity;
                        effectStart = &start;
                        effectEnd = &end;
                        clampedBoltDensity = (boltSegmentDensity < DFPLIGHTNI_DENSITY_MIN)   ? DFPLIGHTNI_DENSITY_MIN
                                 : (boltSegmentDensity > DFPLIGHTNI_DENSITY_MAX) ? DFPLIGHTNI_DENSITY_MAX
                                                                     : boltSegmentDensity;
                        state->effectHandle = lightningCreate(
                            effectStart, effectEnd, clampedBoltDensity, clampedStrandDensity, state->effectLifetimeFrames,
                            state->widthSteps * DFPLIGHTNI_WIDTH_STEP & DFPLIGHTNI_EFFECT_WIDTH_MASK, 0);
                    }
                }
                state->timer = DFPLIGHTNI_TIMER_MAX;
            }
        }
    }
    return;
}

void DFP_Lightni_init(GameObject* obj, DfpLightniPlacementPrefix* mapData) {
    DfpLightniState* state;
    int randomValue;

    if (obj != 0) {
        state = dfplightni_getState(obj);
        randomValue = randomGetRange(DFPLIGHTNI_RANDOM_TIMER_MIN, DFPLIGHTNI_RANDOM_TIMER_MAX);
        state->timer = randomValue;
        state->effectHandle = 0;
        if (mapData->boltSegmentDensityParam <= 0) {
            mapData->boltSegmentDensityParam = 1;
        }
        if (mapData->strandSegmentDensityParam <= 0) {
            mapData->strandSegmentDensityParam = 1;
        }
        randomValue = randomGetRange(DFPLIGHTNI_RANDOM_TIMER_MIN, DFPLIGHTNI_RANDOM_TIMER_MAX);
        {
            f32 triggerTime = randomValue;
            triggerTime = DFPLIGHTNI_TRIGGER_TIME_BASE + triggerTime;
            state->triggerTime = triggerTime;
        }
        state->boltSegmentDensity = ((f32)(s32)mapData->boltSegmentDensityParam / DFPLIGHTNI_DENSITY_NORM_DIVISOR) * DFPLIGHTNI_DENSITY_MAX;
        state->strandSegmentDensity = ((f32)(s32)mapData->strandSegmentDensityParam / DFPLIGHTNI_DENSITY_NORM_DIVISOR) * DFPLIGHTNI_DENSITY_MAX;
        state->widthSteps = mapData->widthSteps;
        state->effectLifetimeFrames = mapData->lifetimeTensOfFrames * DFPLIGHTNI_LIFETIME_FRAME_SCALE;
        state->targetPlayerGameBit = mapData->targetPlayerGameBit;
    }
    return;
}

ObjectDescriptor gDfplightniObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)DFP_Lightni_init,
    (ObjectDescriptorCallback)DFP_Lightni_update,
    0,
    (ObjectDescriptorCallback)DFP_Lightni_render,
    (ObjectDescriptorCallback)DFP_Lightni_free,
    0,
    DFP_Lightni_getExtraSize,
};
