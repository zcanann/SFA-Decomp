/*
 * Map-block alpha animator. Its four modes provide one-shot, ping-pong,
 * game-bit-gated, and timed fades.
 */
#include "dlls/objects/311_AlphaAnimat.h"

#include "main/audio/sfx_play_api.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/lightmap_api.h"
#include "main/mm.h"
#include "main/object_render.h"

#define ALPHA_ANIMATOR_MODE_MASK        0x03
#define ALPHA_ANIMATOR_SFX_ENABLE_SHIFT 2
#define ALPHA_ANIMATOR_RENDER_SCALE     1.0f

int AlphaAnimator_getExtraSize(void) {
    return sizeof(AlphaAnimatorState);
}

int AlphaAnimator_getObjectTypeId(void) {
    return 0;
}

void AlphaAnimator_free(GameObject* obj) {
    AlphaAnimatorState* state = obj->extra;
    void* vertexAlphaBuffer = state->vertexAlphaBuffer;

    if (vertexAlphaBuffer != NULL) {
        mm_free(vertexAlphaBuffer);
    }
}

void AlphaAnimator_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, ALPHA_ANIMATOR_RENDER_SCALE);
    }
}

void AlphaAnimator_hitDetect(void) {
}

void AlphaAnimator_update(GameObject* obj) {
    AlphaAnimatorPlacement* placement;
    AlphaAnimatorState* state;
    int mode;
    MapBlockData* block;
    f32 absRate;
    int alphaLevel;

    placement = (AlphaAnimatorPlacement*)obj->anim.placementData;
    state = obj->extra;
    mode = placement->modeFlags & ALPHA_ANIMATOR_MODE_MASK;
    block = mapGetBlock(
        objPosToMapBlockIdx((double)obj->anim.localPosX, (double)obj->anim.localPosY, (double)obj->anim.localPosZ));
    if (block == NULL) {
        state->completedCycles = 0;
        return;
    }
    if ((block->flags4 & MAP_BLOCK_FLAG_LOADED) == 0) {
        return;
    }
    if (state->vertexCount == 0) {
        state->active = placement->active;
        if (state->vertexCount == 0) {
            state->active = 0;
        }
        if ((s8)state->active == 0) {
            return;
        }
        state->fadeOffset = state->fadeProgress = 0.0f;
        state->fadeLimit = (f32)(u32)placement->fadeLimit;
        if (placement->triggerGameBit == -1) {
            state->gameBitValue = 1;
        } else {
            state->gameBitValue = mainGetBit(placement->triggerGameBit);
        }
        state->alphaLevel = placement->startAlpha;
        if (placement->completionGameBit != -1 && mainGetBit(placement->completionGameBit) != 0) {
            state->alphaLevel = placement->targetAlpha;
            state->fadeProgress = 1.0f + state->fadeLimit;
            state->gameBitValue = 1;
        }
        if (mode == ALPHA_ANIMATOR_MODE_TIMED) {
            state->vertexAlphaBuffer = mmAlloc(state->vertexCount << 2, 5, 0);
        }
        /* double-toggle of bit 0 - a real no-op present in retail */
        block->flags4 ^= 1;
        block->flags4 ^= 1;
    }
    if ((s8)state->active == 0) {
        return;
    }
    if (mode == ALPHA_ANIMATOR_MODE_GATED) {
        state->gameBitValue = mainGetBit(placement->triggerGameBit);
        if (state->completedCycles > 2 && state->gameBitValue != state->previousGameBitValue) {
            if ((placement->modeFlags >> ALPHA_ANIMATOR_SFX_ENABLE_SHIFT) != 0) {
                Sfx_PlayFromObject(obj, placement->sfxId);
            }
            state->completedCycles = 0;
            state->previousGameBitValue = state->gameBitValue;
        }
        if (state->completedCycles > 2) {
            return;
        }
    } else {
        if (state->completedCycles > 2) {
            return;
        }
        if (state->gameBitValue == 0) {
            state->gameBitValue = mainGetBit(placement->triggerGameBit);
            if (state->gameBitValue == 0) {
                return;
            }
            if ((placement->modeFlags >> ALPHA_ANIMATOR_SFX_ENABLE_SHIFT) != 0) {
                Sfx_PlayFromObject(obj, placement->sfxId);
            }
        }
    }
    switch (mode) {
    case ALPHA_ANIMATOR_MODE_ONESHOT:
        if (placement->startAlpha > placement->targetAlpha) {
            state->alphaLevel = state->alphaLevel - placement->rate * framesThisStep;
            if (state->alphaLevel <= placement->targetAlpha) {
                state->alphaLevel = placement->targetAlpha;
                if (placement->completionGameBit != -1) {
                    mainSetBits(placement->completionGameBit, 1);
                }
                state->completedCycles += 1;
            }
        } else {
            state->alphaLevel = state->alphaLevel + placement->rate * framesThisStep;
            if (state->alphaLevel >= placement->targetAlpha) {
                state->alphaLevel = placement->targetAlpha;
                if (placement->completionGameBit != -1) {
                    mainSetBits(placement->completionGameBit, 1);
                }
                state->completedCycles += 1;
            }
        }
        break;
    case ALPHA_ANIMATOR_MODE_PINGPONG:
        if (placement->startAlpha > placement->targetAlpha) {
            state->alphaLevel = state->alphaLevel - placement->rate * framesThisStep;
            if (state->alphaLevel < placement->targetAlpha) {
                state->alphaLevel = placement->startAlpha - (int)(placement->targetAlpha - state->alphaLevel);
            }
        } else {
            state->alphaLevel = state->alphaLevel + placement->rate * framesThisStep;
            alphaLevel = state->alphaLevel;
            if (alphaLevel > placement->startAlpha) {
                alphaLevel -= placement->targetAlpha;
                state->alphaLevel = (s16)(placement->targetAlpha + alphaLevel);
            }
        }
        break;
    case ALPHA_ANIMATOR_MODE_GATED:
        if (state->gameBitValue != 0) {
            if (placement->startAlpha > placement->targetAlpha) {
                state->alphaLevel = state->alphaLevel - placement->rate * framesThisStep;
                if (state->alphaLevel > placement->targetAlpha) {
                    return;
                }
                state->alphaLevel = placement->targetAlpha;
                if (placement->completionGameBit != -1) {
                    mainSetBits(placement->completionGameBit, 1);
                }
                state->completedCycles += 1;
            } else {
                state->alphaLevel = state->alphaLevel + placement->rate * framesThisStep;
                if (state->alphaLevel < placement->targetAlpha) {
                    return;
                }
                state->alphaLevel = placement->targetAlpha;
                if (placement->completionGameBit != -1) {
                    mainSetBits(placement->completionGameBit, 1);
                }
                state->completedCycles += 1;
            }
        } else {
            if (placement->startAlpha > placement->targetAlpha) {
                state->alphaLevel = state->alphaLevel + placement->rate * framesThisStep;
                if (state->alphaLevel < placement->startAlpha) {
                    return;
                }
                state->alphaLevel = placement->startAlpha;
                if (placement->completionGameBit != -1) {
                    mainSetBits(placement->completionGameBit, 0);
                }
                state->completedCycles += 1;
            } else {
                state->alphaLevel = state->alphaLevel - placement->rate * framesThisStep;
                if (state->alphaLevel > placement->startAlpha) {
                    return;
                }
                state->alphaLevel = placement->startAlpha;
                if (placement->completionGameBit != -1) {
                    mainSetBits(placement->completionGameBit, 0);
                }
                state->completedCycles += 1;
            }
        }
        break;
    case ALPHA_ANIMATOR_MODE_TIMED: {
        int rate = placement->rate;
        if (rate < 0) {
            rate = -rate;
        }
        absRate = (f32)rate / 10.0f;
        state->fadeProgress = absRate * timeDelta + state->fadeProgress;
        if (state->fadeProgress > state->fadeLimit) {
            state->fadeProgress = state->fadeLimit;
            mainSetBits(placement->completionGameBit, 1);
            state->completedCycles += 1;
        }
        state->fadeOffset = state->fadeProgress - 50.0f;
        break;
    }
    }
}

void AlphaAnimator_init(GameObject* obj) {
    ((AlphaAnimatorState*)obj->extra)->previousGameBitValue = -1;
}

void AlphaAnimator_release(void) {
}

void AlphaAnimator_initialise(void) {
}

ObjectDescriptor gAlphaAnimatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)AlphaAnimator_initialise,
    (ObjectDescriptorCallback)AlphaAnimator_release,
    0,
    (ObjectDescriptorCallback)AlphaAnimator_init,
    (ObjectDescriptorCallback)AlphaAnimator_update,
    (ObjectDescriptorCallback)AlphaAnimator_hitDetect,
    (ObjectDescriptorCallback)AlphaAnimator_render,
    (ObjectDescriptorCallback)AlphaAnimator_free,
    (ObjectDescriptorCallback)AlphaAnimator_getObjectTypeId,
    AlphaAnimator_getExtraSize,
};
