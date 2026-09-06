/*
 * DIMLavaSmas (DLL 0x1C7) - DIM lava-smash hazard; a surface object that
 * rises and smashes when struck by a certain hit type, sets surface-passable
 * flags on the underlying map block, and triggers a game-bit sequence event
 * on completion.
 */

#include "dlls/objects/455_DIMLavaSmas.h"

#include "dlls/objects/446.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebits_api.h"
#include "main/lightmap_api.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/pi_dolphin_api.h"
#include "main/track_dolphin_map_api.h"
#include "main/model.h"

enum DimLavaSmashPhase {
    DIM_LAVA_SMASH_PHASE_WAITING = 0,
    DIM_LAVA_SMASH_PHASE_COMPLETE = 1,
    DIM_LAVA_SMASH_PHASE_SMASHING = 2,
};

#define DIM_LAVA_SMASH_ANIM_COMMAND_COMPLETE 1

void dimlavasmash_setBlockSurfaceFlags(MapBlockData* map, int disable, int surfaceType) {
    int i;
    int j;

    for (j = 0; j < (int)map->polyGroupCount; j++) {
        MapTriGroup* polygonGroup = mapBlockGetPolygonGroup(map, j);
        if (surfaceType == mapBlockGetPolygonGroupType(polygonGroup)) {
            if (disable != 0) {
                polygonGroup->flags &= ~2;
                polygonGroup->flags &= ~1;
            } else {
                polygonGroup->flags |= 2;
                polygonGroup->flags |= 1;
            }
        }
    }
    for (i = 0; i < (int)map->shaderCount; i++) {
        Shader* shader = mapBlockGetShader(map, i);
        if (surfaceType == ((ShaderLayer*)Shader_getLayer(shader, 0))->materialId) {
            if (disable != 0) {
                shader->flags &= ~2;
            } else {
                shader->flags |= 2;
            }
        }
    }
}

int dimlavasmash_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    DimLavaSmashPlacement* def;
    GameObject* hit;
    MapBlockData* block;
    DimLavaSmashState* state;
    ObjHitsPriorityState* hitState;

    (void)unused;

    state = (obj)->extra;
    def = (DimLavaSmashPlacement*)(obj)->anim.placementData;
    if (state->phase == DIM_LAVA_SMASH_PHASE_WAITING) {
        if (mainGetBit(def->gateGameBit) != 0) {
            hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
            hitState->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
            if (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0) {
                if (hit->anim.romDefNo == DIM_LAVA_PROJECTILE_SEQUENCE_ID) {
                    state->phase = DIM_LAVA_SMASH_PHASE_SMASHING;
                    Sfx_PlayFromObject(obj, SFXTRIG_en_mushsporedisp22);
                    block =
                        mapGetBlock(objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ));
                    if (block != NULL) {
                        dimlavasmash_setBlockSurfaceFlags(block, 1, state->surfaceLayerId);
                        dimlavasmash_setBlockSurfaceFlags(block, 0, state->surfaceLayerId + 1);
                    }
                }
            }
        }
    } else {
        if (animUpdate->curEventId == DIM_LAVA_SMASH_ANIM_COMMAND_COMPLETE) {
            mainSetBits(def->triggerGameBit, 1);
            state->phase = DIM_LAVA_SMASH_PHASE_COMPLETE;
        }
    }
    return state->phase == DIM_LAVA_SMASH_PHASE_WAITING;
}

int dimlavasmash_getExtraSize(void) {
    return sizeof(DimLavaSmashState);
}

int dimlavasmash_getObjectTypeId(void) {
    return 0x0;
}

void dimlavasmash_free(void) {
}

void dimlavasmash_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    DimLavaSmashState* state = obj->extra;

    if (state->phase == DIM_LAVA_SMASH_PHASE_SMASHING && visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void dimlavasmash_hitDetect(void) {
}

void dimlavasmash_update(GameObject* obj) {
    DimLavaSmashState* state;
    ObjHitsPriorityState* hitState;

    state = obj->extra;
    if (state->phase == DIM_LAVA_SMASH_PHASE_COMPLETE) {
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
    } else if (obj->userData1 == 0) {
        if (state->sequenceSlot != -1) {
            (*gObjectTriggerInterface)->runSequence(state->sequenceSlot, obj, -1);
        }
        obj->userData1 = 1;
    }
}

void dimlavasmash_init(GameObject* obj, DimLavaSmashPlacement* placement) {
    ObjAnimComponent* objAnim;
    MapBlockData* block;
    DimLavaSmashState* state;
    ObjHitsPriorityState* hitState;

    objAnim = (ObjAnimComponent*)obj;
    obj->anim.rotX = (s16)((s32)placement->rotationXByte << 8);
    obj->animEventCallback = dimlavasmash_SeqFn;
    state = obj->extra;
    state->surfaceLayerId = (u8)placement->surfaceLayerId;
    state->sequenceSlot = (s8)placement->sequenceSlot;
    state->phase = mainGetBit(placement->triggerGameBit);
    if (state->phase == DIM_LAVA_SMASH_PHASE_COMPLETE) {
        block = mapGetBlock(objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ));
        if (block != NULL) {
            dimlavasmash_setBlockSurfaceFlags(block, 1, state->surfaceLayerId);
            dimlavasmash_setBlockSurfaceFlags(block, 0, state->surfaceLayerId + 1);
        }
    }
    objAnim->bankIndex = placement->modelBankIndex;
    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

void dimlavasmash_release(void) {
}

void dimlavasmash_initialise(void) {
}

ObjectDescriptor gDIMLavaSmashObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dimlavasmash_initialise,
    (ObjectDescriptorCallback)dimlavasmash_release,
    0,
    (ObjectDescriptorCallback)dimlavasmash_init,
    (ObjectDescriptorCallback)dimlavasmash_update,
    (ObjectDescriptorCallback)dimlavasmash_hitDetect,
    (ObjectDescriptorCallback)dimlavasmash_render,
    (ObjectDescriptorCallback)dimlavasmash_free,
    (ObjectDescriptorCallback)dimlavasmash_getObjectTypeId,
    dimlavasmash_getExtraSize,
};
