/*
 * Game-bit-driven map-block reaction animator. It toggles matching
 * polygon groups, shaders, and collision lines.
 */
#include "dlls/objects/313_HitAnimator.h"

#include "main/gamebits.h"
#include "main/lightmap_api.h"
#include "main/pi_dolphin_api.h"
#include "main/track_dolphin_api.h"

void HitAnimator_applyBlockState(MapBlockData* block, GameObject* obj, HitAnimatorState* state,
                                 HitAnimatorPlacement* placement) {
    int index;
    MapTriGroup* polygonGroup;

    if ((placement->setupFlags & HIT_ANIMATOR_SETUP_SKIP_POLYGONS) == 0) {
        for (index = 0; index < block->polyGroupCount; index++) {
            polygonGroup = mapBlockGetPolygonGroup(block, index);
            if (placement->blockEffectId == mapBlockGetPolygonGroupType(polygonGroup)) {
                if (state->active != 0) {
                    polygonGroup->flags &= ~2;
                    if ((placement->setupFlags & HIT_ANIMATOR_SETUP_AFFECT_SHADERS) != 0) {
                        polygonGroup->flags &= ~1;
                    }
                } else {
                    polygonGroup->flags |= 2;
                    if ((placement->setupFlags & HIT_ANIMATOR_SETUP_AFFECT_SHADERS) != 0) {
                        polygonGroup->flags |= 1;
                    }
                }
            }
        }
    }
    if ((placement->setupFlags & HIT_ANIMATOR_SETUP_AFFECT_SHADERS) != 0) {
        for (index = 0; index < block->shaderCount; index++) {
            Shader* shader = mapBlockGetShader(block, index);
            ShaderLayer* layer = Shader_getLayer(shader, 0);
            if (placement->blockEffectId == layer->materialId) {
                if (state->active != 0) {
                    shader->flags &= ~2;
                } else {
                    shader->flags |= 2;
                }
            }
        }
    }
}

int HitAnimator_getExtraSize(void) {
    return sizeof(HitAnimatorState);
}

void HitAnimator_update(GameObject* obj) {
    HitAnimatorPlacement* placement = (HitAnimatorPlacement*)obj->anim.placementData;
    HitAnimatorState* state = obj->extra;
    MapBlockData* block;

    block = mapGetBlock(objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ));
    if (block == NULL) {
        state->flags &= ~HIT_ANIMATOR_STATE_TOGGLE_PENDING;
        state->flags |= HIT_ANIMATOR_STATE_BLOCK_UPDATE_PENDING;
        return;
    }
    state->gameBitValue = mainGetBit(placement->gameBit);
    if (state->previousGameBitValue != state->gameBitValue) {
        state->active ^= 1;
        if (placement->toggleMode == 1) {
            state->flags |= HIT_ANIMATOR_STATE_TOGGLE_PENDING;
        }
        if ((placement->setupFlags & HIT_ANIMATOR_SETUP_HIT_LINES) != 0) {
            state->flags |= HIT_ANIMATOR_STATE_HIT_LINES_PENDING;
        }
        if ((placement->setupFlags & HIT_ANIMATOR_SETUP_BLOCK_UPDATE) != 0) {
            state->flags |= HIT_ANIMATOR_STATE_BLOCK_UPDATE_PENDING;
        }
    }
    state->previousGameBitValue = state->gameBitValue;
    if ((placement->setupFlags & HIT_ANIMATOR_SETUP_HIT_LINES) != 0) {
        if (trackIntersectRebuildPending() != 0) {
            state->flags |= HIT_ANIMATOR_STATE_HIT_LINES_PENDING;
        }
        if ((state->flags & HIT_ANIMATOR_STATE_HIT_LINES_PENDING) != 0) {
            if (trackIntersectRebuildPending() == 0) {
                trackSetLinesEnabledByParam(placement->hitLineParam, obj->anim.parent, state->active);
                state->flags &= ~HIT_ANIMATOR_STATE_HIT_LINES_PENDING;
            }
        }
    }
    if ((placement->setupFlags & HIT_ANIMATOR_SETUP_BLOCK_UPDATE) != 0) {
        if (placement->blockEffectId != 0) {
            if ((state->flags & HIT_ANIMATOR_STATE_BLOCK_UPDATE_PENDING) != 0) {
                HitAnimator_applyBlockState(block, obj, state, placement);
                state->flags &= ~HIT_ANIMATOR_STATE_BLOCK_UPDATE_PENDING;
            }
        }
    }
}

void HitAnimator_init(GameObject* obj, HitAnimatorPlacement* placement) {
    HitAnimatorState* state = obj->extra;
    MapBlockData* block;
    u8 gameBitValue;

    state->active = placement->setupFlags & HIT_ANIMATOR_SETUP_INITIAL_INVERT;
    state->flags = 0;
    if (mainGetBit(placement->gameBit) != 0) {
        state->active ^= 1;
        if (placement->toggleMode == 1) {
            state->flags |= HIT_ANIMATOR_STATE_TOGGLE_PENDING;
        }
    }
    block = mapGetBlock(objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ));
    if (block != NULL) {
        if ((placement->setupFlags & HIT_ANIMATOR_SETUP_BLOCK_UPDATE) != 0 && placement->blockEffectId != 0) {
            HitAnimator_applyBlockState(block, obj, state, placement);
        }
    }
    state->flags |= HIT_ANIMATOR_STATE_HIT_LINES_PENDING;
    if ((placement->setupFlags & HIT_ANIMATOR_SETUP_BLOCK_UPDATE) != 0) {
        state->flags |= HIT_ANIMATOR_STATE_BLOCK_UPDATE_PENDING;
    }
    gameBitValue = mainGetBit(placement->gameBit);
    state->gameBitValue = gameBitValue;
    state->previousGameBitValue = gameBitValue;
    obj->objectFlags |= (OBJECT_OBJFLAG_HITDETECT_DISABLED | OBJECT_OBJFLAG_HIDDEN);
}

ObjectDescriptor gHitAnimatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)HitAnimator_init,
    (ObjectDescriptorCallback)HitAnimator_update,
    0,
    0,
    0,
    0,
    HitAnimator_getExtraSize,
};
