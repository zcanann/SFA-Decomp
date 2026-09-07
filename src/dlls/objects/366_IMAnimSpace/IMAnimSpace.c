#include "dlls/objects/366_IMAnimSpace.h"

#include "main/dll/expgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objtexture.h"

#define IM_ANIM_SPACE_PARTFX_ID     0x133
#define IM_ANIM_SPACE_FLAG_BLINK_ON 0x2
#define IM_ANIM_SPACE_FLAG_TOGGLE_8 0x8
#define IM_ANIM_SPACE_FLAG_TOGGLE_4 0x4
#define IM_ANIM_SPACE_MASK_GROUP    0x70

PartFxSpawnParams gIMAnimSpacePartFxParams;

void imAnimSpace_modelMtxCallback(void) {
}

u32 imAnimSpace_getEventFlag(GameObject* obj) {
    IMAnimSpaceState* state = obj->extra;

    return state->eventFlags & IM_ANIM_SPACE_FLAG_TOGGLE_4;
}

int imAnimSpace_isSubmodelEnabled(GameObject* obj, int bitIndex) {
    IMAnimSpaceState* state = obj->extra;

    switch (state->submodelMask & (1 << bitIndex)) {
    default:
        return TRUE;
    case 0:
        return FALSE;
    }
}

ObjectDescriptor13 gIMAnimSpaceObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    (ObjectDescriptorCallback)imAnimSpace_initialise,
    (ObjectDescriptorCallback)imAnimSpace_release,
    0,
    (ObjectDescriptorCallback)imAnimSpace_init,
    (ObjectDescriptorCallback)imAnimSpace_update,
    (ObjectDescriptorCallback)imAnimSpace_hitDetect,
    (ObjectDescriptorCallback)imAnimSpace_render,
    (ObjectDescriptorCallback)imAnimSpace_free,
    (ObjectDescriptorCallback)imAnimSpace_getObjectTypeId,
    imAnimSpace_getExtraSize,
    (ObjectDescriptorCallback)imAnimSpace_isSubmodelEnabled,
    (ObjectDescriptorCallback)imAnimSpace_getEventFlag,
    (ObjectDescriptorCallback)imAnimSpace_modelMtxCallback,
};

int imAnimSpace_sequenceCallback(GameObject* obj, int unusedArg2, ObjSeqState* animUpdate) {
    IMAnimSpaceState* state;
    int eventIndex;
    ObjTextureRuntimeSlot* texture;

    state = obj->extra;
    texture = objFindTexture(obj, 1, 0);
    texture->textureId = ((state->eventFlags >> 1 & 1) ^ 1) << 8;
    if (!(state->eventFlags & IM_ANIM_SPACE_FLAG_BLINK_ON)) {
        if ((state->blinkTimer -= framesThisStep) < 0) {
            state->eventFlags |= IM_ANIM_SPACE_FLAG_BLINK_ON;
            state->blinkTimer = 0x78;
        }
    } else {
        state->eventFlags &= ~IM_ANIM_SPACE_FLAG_BLINK_ON;
    }
    if (state->eventFlags & IM_ANIM_SPACE_FLAG_BLINK_ON) {
        gIMAnimSpacePartFxParams.posX = 143.0f;
        gIMAnimSpacePartFxParams.posY = 16.0f;
        gIMAnimSpacePartFxParams.posZ = -79.0f;
        (*gPartfxInterface)->spawnObject(obj, IM_ANIM_SPACE_PARTFX_ID, &gIMAnimSpacePartFxParams, 4, -1, NULL);
        gIMAnimSpacePartFxParams.posX = -143.0f;
        gIMAnimSpacePartFxParams.posY = 16.0f;
        gIMAnimSpacePartFxParams.posZ = -79.0f;
        (*gPartfxInterface)->spawnObject(obj, IM_ANIM_SPACE_PARTFX_ID, &gIMAnimSpacePartFxParams, 4, -1, NULL);
    }
    texture = objFindTexture(obj, 0, 0);
    texture->textureId = 0x100;
    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        u32 eventId = animUpdate->eventIds[eventIndex];

        switch (eventId) {
        case 1:
            state->submodelMask = state->submodelMask ^ (1 << (eventId - 1));
            break;
        case 2:
            state->submodelMask = state->submodelMask ^ (1 << (eventId - 1));
            break;
        case 3:
            state->submodelMask = state->submodelMask ^ (1 << (eventId - 1));
            break;
        case 4:
            state->submodelMask = state->submodelMask ^ (1 << (eventId - 1));
            break;
        case 5:
            state->submodelMask ^= IM_ANIM_SPACE_MASK_GROUP;
            break;
        case 6:
            state->eventFlags = (u8)(state->eventFlags ^ IM_ANIM_SPACE_FLAG_TOGGLE_8);
            break;
        case 7:
            state->eventFlags = (u8)(state->eventFlags ^ IM_ANIM_SPACE_FLAG_TOGGLE_4);
            break;
        }
    }
    return 0;
}

int imAnimSpace_getExtraSize(void) {
    return sizeof(IMAnimSpaceState);
}

int imAnimSpace_getObjectTypeId(void) {
    return 0;
}

void imAnimSpace_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void imAnimSpace_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void imAnimSpace_hitDetect(void) {
}

void imAnimSpace_update(GameObject* obj) {
    if (obj->userData1 != 0) {
        return;
    }

    obj->userData1 = 1;
}

void imAnimSpace_init(GameObject* obj) {
    f32 position;

    obj->animEventCallback = imAnimSpace_sequenceCallback;
    position = 0.0f;
    gIMAnimSpacePartFxParams.posX = position;
    gIMAnimSpacePartFxParams.posY = position;
    gIMAnimSpacePartFxParams.posZ = position;
    mainSetBits(GAMEBIT_IM_Unk0BEB, 1);
    mainSetBits(GAMEBIT_IM_Unk0BEC, 1);
    mainSetBits(GAMEBIT_IM_Unk0BED, 1);
    mainSetBits(GAMEBIT_IM_Unk0BEE, 1);
    mainSetBits(GAMEBIT_IM_Unk0BEF, 1);
}

void imAnimSpace_release(void) {
}

void imAnimSpace_initialise(void) {
}
