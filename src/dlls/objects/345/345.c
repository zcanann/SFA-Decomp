/* Blasted-rock, -wall, and -tunnel targets. */

#include "dlls/objects/345.h"

#include "main/gamebits.h"
#include "main/lightmap_api.h"
#include "main/model.h"
#include "main/object_render.h"
#include "main/track_dolphin_map_api.h"
#include "sys/objects.h"

#define BLASTED_GAMEBIT_DAMAGE_BASE         0x2DE
#define BLASTED_DAMAGE_HIT_PRIORITY         5
#define BLASTED_DAMAGE_TIMER_FRAMES         300
#define BLASTED_MODEL_SLOT                  0x51
#define BLASTED_DESTROYED_MODEL_INDEX       2
#define BLASTED_POLYGON_GROUP_DISABLE_FLAGS 0x03
#define BLASTED_SHADER_DISABLE_FLAG         0x02

int gBlastedDamageTimer;

int blasted_activateMapLayer(GameObject* obj, int mapLayerId) {
    MapBlockData* block;

    block = mapGetBlock(objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ));
    if (block == NULL || (block->flags4 & MAP_BLOCK_FLAG_LOADED) == 0) {
        return 0;
    }
    {
        int shaderIndex;
        int polygonGroupIndex;
        for (polygonGroupIndex = 0; polygonGroupIndex < block->polyGroupCount; polygonGroupIndex++) {
            CollisionPolygonGroup* polygonGroup = mapBlockGetPolygonGroup(block, polygonGroupIndex);
            if (mapLayerId == mapBlockGetPolygonGroupType(polygonGroup)) {
                polygonGroup->flags |= BLASTED_POLYGON_GROUP_DISABLE_FLAGS;
            }
        }
        for (shaderIndex = 0; shaderIndex < block->shaderCount; shaderIndex++) {
            Shader* shader = mapBlockGetShader(block, shaderIndex);
            int layerIndex;
            for (layerIndex = 0; layerIndex < shader->layerCount; layerIndex++) {
                if (shader->layers[layerIndex].materialId == mapLayerId) {
                    shader->flags |= BLASTED_SHADER_DISABLE_FLAG;
                }
            }
        }
    }
    return 1;
}

int blasted_getExtraSize(void) {
    return sizeof(BlastedTargetState);
}

int blasted_getObjectTypeId(void) {
    return 0;
}

void blasted_free(void) {
}

void blasted_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    BlastedTargetState* state = obj->extra;
    if (visible != 0 && state->mapLayerActivated == 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void blasted_hitDetect(void) {
}

/* Track unique destroyed hit volumes and advance the staged damage model. */
void blasted_update(GameObject* obj) {
    int hitIndex;
    BlastedTargetPlacement* placement = (BlastedTargetPlacement*)obj->anim.placement;
    BlastedTargetState* state = obj->extra;
    s16 pieceCount = placement->pieceCount;

    if (state->mapLayerActivated != 0) {
        return;
    }
    if (mainGetBit(placement->completedGameBit) != 0) {
        state->mapLayerActivated = blasted_activateMapLayer(obj, placement->mapLayerId);
        return;
    }
    {
        for (hitIndex = 0; hitIndex < ((ObjHitsPriorityState*)obj->anim.hitReactState)->priorityHitCount; hitIndex++) {
            int destroyedCount;
            u32 hitObject;
            int hitPriority;
            int alreadyRecorded;
            hitPriority = *(s8*)((u8*)obj->anim.hitReactState + hitIndex + offsetof(ObjHitsPriorityState, priorities));
            hitObject = ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitObjects[hitIndex];
            alreadyRecorded = 0;
            if (hitPriority != BLASTED_DAMAGE_HIT_PRIORITY) {
                continue;
            }
            if (pieceCount == 0) {
                mainSetBits(placement->completedGameBit, TRUE);
                return;
            }
            if (hitPriority == BLASTED_DAMAGE_HIT_PRIORITY) {
                int destroyedIndex = 0;
                destroyedCount = state->damageStage;
                while (destroyedIndex != destroyedCount) {
                    if (hitObject == state->destroyedHitObjects[destroyedIndex++]) {
                        destroyedIndex = destroyedCount;
                        alreadyRecorded = 1;
                    }
                }
            }
            if (alreadyRecorded == 0) {
                state->destroyedHitObjects[state->damageStage] = hitObject;
                mainSetBits(state->damageStage + BLASTED_GAMEBIT_DAMAGE_BASE, FALSE);
                mainSetBits(state->damageStage + (BLASTED_GAMEBIT_DAMAGE_BASE + 1), TRUE);
                if (placement->progressGameBit != -1) {
                    mainSetBits(placement->progressGameBit, state->damageStage + 1);
                }
                gBlastedDamageTimer = BLASTED_DAMAGE_TIMER_FRAMES;
                if (state->damageStage + 1 > pieceCount) {
                    int damageBitIndex;
                    for (damageBitIndex = 0; damageBitIndex < pieceCount + 1; damageBitIndex++) {
                        mainSetBits(damageBitIndex + BLASTED_GAMEBIT_DAMAGE_BASE, FALSE);
                    }
                    mainSetBits(placement->completedGameBit, TRUE);
                    blasted_activateMapLayer(obj, placement->mapLayerId);
                    Obj_SetActiveModelIndex(obj, BLASTED_DESTROYED_MODEL_INDEX);
                    state->mapLayerActivated = 1;
                } else {
                    state->damageStage++;
                    Obj_SetActiveModelIndex(obj, state->damageStage);
                }
            }
        }
    }
}

void blasted_init(GameObject* obj, BlastedTargetPlacement* placement) {
    BlastedTargetState* state = obj->extra;
    ObjHitsPriorityState* hitState;
    s16 progressGameBit;
    u8 progress;

    state->mapLayerActivated = 0;
    objSetSlot(obj, BLASTED_MODEL_SLOT);
    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    hitState->flags = (s16)(hitState->flags | OBJHITS_PRIORITY_STATE_ENABLED);
    state->pieceCount = (u8)placement->pieceCount;
    progressGameBit = placement->progressGameBit;
    if (progressGameBit != -1) {
        progress = mainGetBit(progressGameBit);
        state->damageStage = progress;
        if (progress != 0) {
            Obj_SetActiveModelIndex(obj, state->damageStage);
        }
    }
    mainSetBits(BLASTED_GAMEBIT_DAMAGE_BASE, TRUE);
    obj->anim.rotX = (s16)((s32)placement->rotXByte << 8);
    if (mainGetBit(placement->completedGameBit) != 0) {
        state->mapLayerActivated = blasted_activateMapLayer(obj, placement->mapLayerId);
    }
}

void blasted_release(void) {
}

void blasted_initialise(void) {
}

ObjectDescriptor gBlastedObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)blasted_initialise,
    (ObjectDescriptorCallback)blasted_release,
    0,
    (ObjectDescriptorCallback)blasted_init,
    (ObjectDescriptorCallback)blasted_update,
    (ObjectDescriptorCallback)blasted_hitDetect,
    (ObjectDescriptorCallback)blasted_render,
    (ObjectDescriptorCallback)blasted_free,
    (ObjectDescriptorCallback)blasted_getObjectTypeId,
    blasted_getExtraSize,
};
