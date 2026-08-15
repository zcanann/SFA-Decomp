/*
 * SB_ShipMast (DLL 0x1EB) - the mast/rigging attachment of the SB Galleon
 * boss ship. It rides its parent galleon object, pinning its local position
 * to the origin every frame, and picks one of three animation play speeds
 * depending on the World Map galleon's object ID and its
 * userData1 phase counter. The remaining handlers (free/hitDetect/init/release/
 * initialise) are stubs - the mast is purely cosmetic.
 */
#include "dlls/objects/491_SB_ShipMast.h"

#include "dlls/objects/504_WM_Galleon.h"
#include "game/objects/object.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/objanim.h"

int SB_ShipMast_getExtraSize(void) {
    return 0;
}

int SB_ShipMast_getObjectTypeId(void) {
    return 0;
}

void SB_ShipMast_free(void) {
}

void SB_ShipMast_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void SB_ShipMast_hitDetect(void) {
}

void SB_ShipMast_update(GameObject* obj) {
    GameObject* parent;
    int phase;
    f32 speed;

    parent = obj->anim.parent;
    if (parent == NULL) {
        return;
    }
    phase = parent->userData1;
    obj->anim.localPosX = 0.0f;
    obj->anim.localPosY = 0.0f;
    obj->anim.localPosZ = 0.0f;
    if (((GameObject*)obj->anim.parent)->anim.romDefNo == WM_GALLEON_OBJECT_ID) {
        if (phase >= 0xa && phase < 0xd) {
            if (obj->anim.currentMove != 0) {
                ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
            }
            if (phase >= 0xc) {
                speed = -0.003f;
            } else {
                speed = 0.003f;
            }
        } else {
            if (obj->anim.currentMove != 1) {
                ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
            }
            speed = 0.03f;
        }
    } else {
        if (obj->anim.currentMove != 1) {
            ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
        }
        speed = 0.03f;
    }
    ObjAnim_AdvanceCurrentMove(obj, speed, (f32)(u32)framesThisStep, NULL);
}

void SB_ShipMast_init(void) {
}

void SB_ShipMast_release(void) {
}

void SB_ShipMast_initialise(void) {
}

ObjectDescriptor gSB_ShipMastObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    SB_ShipMast_initialise,
    SB_ShipMast_release,
    0,
    SB_ShipMast_init,
    (ObjectDescriptorCallback)SB_ShipMast_update,
    SB_ShipMast_hitDetect,
    (ObjectDescriptorCallback)SB_ShipMast_render,
    SB_ShipMast_free,
    (ObjectDescriptorCallback)SB_ShipMast_getObjectTypeId,
    SB_ShipMast_getExtraSize,
};
