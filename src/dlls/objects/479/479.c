/*
 * DLL 0x1DF (slot 479) - unidentified particle-emitting object.
 * The object applies placement rotation and scale, suppresses its texture
 * color, and periodically emits an effect while the player is nearby.
 */
#include "dlls/objects/479.h"

#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/objtexture.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"

#define DLL_1DF_PARTFX_ID            0x20D
#define DLL_1DF_PLAYER_RANGE_SQUARED 90000.0f
#define DLL_1DF_PARTFX_INTERVAL      12.0f
#define DLL_1DF_SCALE_DIVISOR        255.0f
#define DLL_1DF_INITIAL_STATE_VALUE  0.01f

int dll_1DF_getExtraSize(void) {
    return sizeof(Dll1DFState);
}

int dll_1DF_getObjectTypeId(void) {
    return 0;
}

void dll_1DF_free(void) {
}

void dll_1DF_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible == 0) {
        return;
    }

    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void dll_1DF_hitDetect(void) {
}

void dll_1DF_update(GameObject* obj) {
    Dll1DFState* state = obj->extra;
    ObjTextureRuntimeSlot* texture;
    GameObject* player;
    f32 distanceSquared;
    f32 timer;

    texture = objFindTexture(obj, 0, 0);
    if (texture != NULL) {
        if (obj->anim.romDefNo == 0xD1) {
            f32 color = 0.0f;

            texture->colorR = color;
            texture->colorG = color;
            texture->colorB = color;
        } else {
            f32 color = 0.0f;

            texture->colorR = color;
            texture->colorG = color;
            texture->colorB = color;
        }
    }
    player = Obj_GetPlayerObject();
    distanceSquared = vec3f_distanceSquared(&player->anim.worldPosX, &obj->anim.worldPosX);
    if (distanceSquared < DLL_1DF_PLAYER_RANGE_SQUARED) {
        timer = state->spawnTimer - timeDelta;
        state->spawnTimer = timer;
        if (timer < 0.0f) {
            (*gPartfxInterface)->spawnObject(obj, DLL_1DF_PARTFX_ID, NULL, 2, -1, NULL);
            state->spawnTimer = DLL_1DF_PARTFX_INTERVAL;
        }
    }
}

void dll_1DF_init(GameObject* obj, const Dll1DFPlacementView* placement) {
    u32 scaleParam;

    obj->anim.rotZ = (s16)((u32)placement->rotationZByte << 8);
    obj->anim.rotY = (s16)((u32)placement->rotationYByte << 8);
    obj->anim.rotX = (s16)((u32)placement->rotationXByte << 8);
    scaleParam = placement->scaleByte;
    if (scaleParam != 0) {
        obj->anim.rootMotionScale =
            obj->anim.modelInstance->rootMotionScaleBase * ((f32)scaleParam / DLL_1DF_SCALE_DIVISOR);
    }
    ((Dll1DFState*)obj->extra)->unknown10 = DLL_1DF_INITIAL_STATE_VALUE;
    if (obj->anim.modelState != NULL) {
        obj->anim.modelState->flags |= 0x810;
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void dll_1DF_release(void) {
}

void dll_1DF_initialise(void) {
}

ObjectDescriptor gDll1DFObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    dll_1DF_initialise,
    dll_1DF_release,
    0,
    (ObjectDescriptorCallback)dll_1DF_init,
    (ObjectDescriptorCallback)dll_1DF_update,
    dll_1DF_hitDetect,
    (ObjectDescriptorCallback)dll_1DF_render,
    dll_1DF_free,
    (ObjectDescriptorCallback)dll_1DF_getObjectTypeId,
    dll_1DF_getExtraSize,
};
