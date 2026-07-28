/*
 * DIMMagicBri (DLL 0x1CC) - the flame bridge across a lava gap.
 *
 * The bridge mesh is a strip of segments whose vertices are displaced by a
 * travelling sine wave (dimmagicbridge_updateVertexWave) while two material
 * channels scroll (dimmagicbridge_scrollTextureChannels). When ignited
 * (gamebit 0x1E9, or once the player's emission controller lingers over
 * gamebit 0x1EF) it fires the death VFX (trackSetLinesEnabledByParam) and
 * latches gamebit 0x1E8; the flame sequence (dimmagicbridge_SeqFn) lights
 * successive segments and ramps their glow toward full.
 *
 * The per-object extra block is DimMagicBridgeState (getExtraSize == 0x68).
 */
#include "dlls/objects/460_DIMMagicBri.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "dolphin/os/OSCache.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/model.h"
#include "main/objanim_update.h"
#include "main/object_render.h"
#include "main/objtexture.h"
#include "sys/objects.h"

#define DIM_MAGIC_BRIDGE_GAMEBIT_IGNITED 0x1e9
#define DIM_MAGIC_BRIDGE_GAMEBIT_TRIGGER 0x1ef
#define DIM_MAGIC_BRIDGE_GAMEBIT_LATCH   0x1e8

void dimmagicbridge_updateVertexWave(GameObject* obj, u8* stateBytes) {
    int vertexIndex;
    int vertexCount;
    ModelFileHeader* modelFile;
    ObjModel* model;
    f32 phaseScale;
    DimMagicBridgeState* state = (DimMagicBridgeState*)stateBytes;
    model = Obj_GetActiveModel(obj);
    modelFile = model->file;
    vertexIndex = 0;
    phaseScale = 65535.0f;
    for (; vertexCount = modelFile->vertexCount, vertexIndex < vertexCount; vertexIndex++) {
        s16* currentVertex = ObjModel_GetCurrentVertexCoords(model, vertexIndex);
        s16* baseVertex = ObjModel_GetBaseVertexCoords(modelFile, vertexIndex);
        int wavePosition = (u16)(int)(phaseScale * ((f32)(int)currentVertex[2] / state->minVertexY));
        wavePosition = wavePosition + state->wavePhase;
        if (*baseVertex > 0) {
            *currentVertex =
                256.0f * mathSinf((3.1415927f * (f32)(int)wavePosition) / 32768.0f) + (f32)(int)*baseVertex;
        } else {
            *currentVertex =
                -(256.0f * mathSinf((3.1415927f * (f32)(int)wavePosition) / 32768.0f) - (f32)(int)*baseVertex);
        }
    }
    DCStoreRange((void*)ObjModel_GetCurrentVertexCoords(model, 0), vertexCount * 6);
    (obj)->anim.alpha = state->segmentGlow[1];
}

void dimmagicbridge_scrollTextureChannels(int obj, u8* stateBytes) {
    DimMagicBridgeState* state = (DimMagicBridgeState*)stateBytes;
    ObjTextureRuntimeSlot* texture;
    s32 phase;

    texture = objFindTexture((GameObject*)obj, 0, 0);
    texture->offsetT += 0x14;
    if (texture->offsetT > 10000) {
        texture->offsetT -= 10000;
    }
    texture->offsetS += 10;
    if (texture->offsetS > 10000) {
        texture->offsetS -= 10000;
    }
    texture = objFindTexture((GameObject*)obj, 1, 0);
    texture->offsetT += 0x1e;
    if (texture->offsetT > 10000) {
        texture->offsetT -= 10000;
    }
    phase = (s32)state->wavePhase + framesThisStep * 0x100;
    if (phase > 0xffff) {
        phase = phase - 0xffff;
    }
    state->wavePhase = phase;
    phase = (s32)state->wavePhaseB + framesThisStep * 0x80;
    if (phase > 0xffff) {
        phase = phase - 0xffff;
    }
    state->wavePhaseB = phase;
}

int dimmagicbridge_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate) {
    int segmentIndex;
    int glowIndex;
    u8* stateBytes = (obj)->extra;
    DimMagicBridgeState* state = (DimMagicBridgeState*)stateBytes;
    animUpdate->sequenceEventActive = 0;
    animUpdate->hitVolumePair &= ~0x40;
    dimmagicbridge_scrollTextureChannels((int)obj, stateBytes);
    if (animUpdate->triggerCommand == 1) {
        animUpdate->triggerCommand = 0;
        state->ignited = 1;
    }
    if (state->ignited != 0) {
        state->igniteTimer -= framesThisStep;
        if (state->igniteTimer <= 0) {
            state->igniteTimer = 0x10;
            for (segmentIndex = 1; state->segmentLit[segmentIndex] != 0 && segmentIndex < state->segmentCount;
                 segmentIndex++) {
            }
            state->segmentLit[segmentIndex] = 1;
        }
        for (glowIndex = 1; glowIndex < state->segmentCount; glowIndex++) {
            if (state->segmentLit[glowIndex] != 0) {
                int currentGlow = state->segmentGlow[glowIndex];
                int nextGlow = currentGlow + framesThisStep;
                if (nextGlow > 0xff) {
                    nextGlow = 0xff;
                }
                state->segmentGlow[glowIndex] = nextGlow;
            }
        }
    }
    dimmagicbridge_updateVertexWave(obj, stateBytes);
    return 0;
}

PPCWGPipe GXWGFifo : (0xCC008000);

int dimmagicbridge_getExtraSize(void) {
    return sizeof(DimMagicBridgeState);
}

int dimmagicbridge_getObjectTypeId(void) {
    return 0x0;
}

void dimmagicbridge_free(void) {
}

void dimmagicbridge_render(int obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;
    if (isVisible != 0) {
        objRenderModelAndHitVolumes((GameObject*)obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void dimmagicbridge_hitDetect(void) {
}

void dimmagicbridge_update(GameObject* obj) {
    DimMagicBridgeState* state;
    void* player;
    player = Obj_GetPlayerObject();
    state = (obj)->extra;
    dimmagicbridge_scrollTextureChannels((int)obj, (u8*)state);
    dimmagicbridge_updateVertexWave(obj, (u8*)state);
    if (state->ignited == 0) {
        if (mainGetBit(DIM_MAGIC_BRIDGE_GAMEBIT_TRIGGER) != 0) {
            if (EmissionController_IsLingering((GameObject*)(player)) != 0) {
                mainSetBits(DIM_MAGIC_BRIDGE_GAMEBIT_LATCH, 1);
            }
        }
    } else {
        trackSetLinesEnabledByParam(0x11, (GameObject*)(0), 0);
    }
}

void dimmagicbridge_init(GameObject* obj, const DimMagicBridgePlacement* placement) {
    DimMagicBridgeState* state;
    int index;
    s32 minVertexY;
    ObjModel* model;
    ModelFileHeader* modelFile;
    f32* sortPair;
    int sortIndex;
    int sorted;
    f32 first, second;
    s16* vertex;
    s16 vertexY;

    obj->anim.rotX = (s16)(((s16)placement->rotationXByte) << 8);
    obj->animEventCallback = dimmagicbridge_SeqFn;
    state = obj->extra;
    minVertexY = 0;
    model = Obj_GetActiveModel(obj);
    modelFile = model->file;

    index = 0;
    while (index < modelFile->vertexCount) {
        vertex = ObjModel_GetCurrentVertexCoords(model, index);
        vertexY = vertex[2];
        if (vertexY < minVertexY) {
            minVertexY = vertexY;
        }
        index++;
    }

    sorted = 0;
    while (sorted == 0) {
        sorted = 1;
        sortIndex = 0;
        sortPair = (f32*)state;
        while (sortIndex < state->segmentCount - 1) {
            first = sortPair[1];
            second = sortPair[2];
            if (first < second) {
                sortPair[1] = second;
                sortPair[2] = (f32)(s32)first;
                sorted = 0;
            }
            sortPair++;
            sortIndex++;
        }
    }

    state->segmentCount = 0xa;
    state->minVertexY = minVertexY;

    if (mainGetBit(DIM_MAGIC_BRIDGE_GAMEBIT_IGNITED) != 0) {
        state->ignited = 1;
    }
    if (state->ignited != 0) {
        for (index = 0; index < state->segmentCount; index++) {
            state->segmentGlow[index] = 0xff;
            state->segmentLit[index] = 1;
            trackSetLinesEnabledByParam(0x11, (GameObject*)(0), 0);
        }
    }
}

void dimmagicbridge_release(void) {
}

void dimmagicbridge_initialise(void) {
}

ObjectDescriptor gDIMMagicBridgeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dimmagicbridge_initialise,
    (ObjectDescriptorCallback)dimmagicbridge_release,
    0,
    (ObjectDescriptorCallback)dimmagicbridge_init,
    (ObjectDescriptorCallback)dimmagicbridge_update,
    (ObjectDescriptorCallback)dimmagicbridge_hitDetect,
    (ObjectDescriptorCallback)dimmagicbridge_render,
    (ObjectDescriptorCallback)dimmagicbridge_free,
    (ObjectDescriptorCallback)dimmagicbridge_getObjectTypeId,
    dimmagicbridge_getExtraSize,
};
