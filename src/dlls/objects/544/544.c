/* DLL 0x0220 */
#include "dlls/objects/544.h"
#include "dolphin/mtx/vec.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/dll/expgfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/objanim_internal.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/audio/sfx_play_api.h"
#include "sys/objects.h"
#include "main/light_internal.h"

#define VFP_DOORSWITCH_LIFTIND_OBJ 0x3e7

void vfpdoorswitch_updateExplodingVariant(GameObject* obj) {
    VfpDoorSwitchState* state = obj->extra;
    Camera* camView = Camera_GetCurrent();

    if (state->activated == 0) {
        if (mainGetBit(state->gameBitId) != 0) {
            Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_10d);
            Sfx_PlayFromObject(obj, SFXTRIG_gate_stops);
            state->activated = 1;
        }
    }
    if (state->activated != 0) {
        ObjAnim_AdvanceCurrentMove(obj, 0.025f, timeDelta, NULL);
        if (state->exploded == 0) {
            if (obj->anim.currentMoveProgress >= 1.0f) {
                Vec vec;
                PSVECSubtract(&camView->position, &obj->anim.localPos, &vec);
                PSVECNormalize(&vec, &vec);
                PSVECScale(&vec, &vec, 100.0f);
                PSVECAdd(&obj->anim.localPos, &vec, &obj->anim.localPos);
                obj->anim.worldPosX = obj->anim.localPosX;
                obj->anim.worldPosY = obj->anim.localPosY;
                obj->anim.worldPosZ = obj->anim.localPosZ;
                spawnExplosion(obj, 80.0f, 1, 1, 0, 0, 0, 0, 0);
                state->exploded = 1;
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }
}

int VFP_DoorSwitch_getExtraSize(void) {
    return 0x4;
}

int VFP_DoorSwitch_getObjectTypeId(void) {
    return 0x0;
}

void VFP_DoorSwitch_free(int obj) {
    (*gExpgfxInterface)->freeSource2(obj);
}

void VFP_DoorSwitch_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) {
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void VFP_DoorSwitch_hitDetect(void) {
}

void VFP_DoorSwitch_update(GameObject* obj) {
    VfpDoorSwitchState* state;
    if ((obj)->anim.romDefNo != VFP_DOORSWITCH_LIFTIND_OBJ) {
        vfpdoorswitch_updateExplodingVariant(obj);
        return;
    }
    state = (obj)->extra;
    if (state->activated != 0) {
        return;
    }
    if (mainGetBit(state->gameBitId) == 0) {
        return;
    }
    Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
    Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_10d);
    Sfx_PlayFromObject(obj, SFXTRIG_gate_stops);
    Obj_SetActiveModelIndex(obj, 1);
    state->activated = 1;
}

void VFP_DoorSwitch_init(GameObject* obj, VfpDoorSwitchPlacement* data) {
    VfpDoorSwitchPlacement* def = data;
    VfpDoorSwitchState* state = obj->extra;
    obj->anim.rotX = (((s32)def->rotXByte) << 8);
    obj->anim.rotZ = (((s32)def->rotZByte) << 8);
    obj->anim.rotY = def->rotY;
    state->gameBitId = def->gameBitId;
    if (mainGetBit(state->gameBitId) != 0) {
        ObjAnim_SetMoveProgress((ObjAnimComponent*)obj, 1.0f);
        state->activated = 1;
        state->exploded = 1;
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    if (obj->anim.romDefNo == VFP_DOORSWITCH_LIFTIND_OBJ && state->activated != 0) {
        *&obj->anim.bankIndex = 1;
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void VFP_DoorSwitch_release(void) {
}

void VFP_DoorSwitch_initialise(void) {
}

ObjectDescriptor gVFP_DoorSwitchObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFP_DoorSwitch_initialise,
    (ObjectDescriptorCallback)VFP_DoorSwitch_release,
    0,
    (ObjectDescriptorCallback)VFP_DoorSwitch_init,
    (ObjectDescriptorCallback)VFP_DoorSwitch_update,
    (ObjectDescriptorCallback)VFP_DoorSwitch_hitDetect,
    (ObjectDescriptorCallback)VFP_DoorSwitch_render,
    (ObjectDescriptorCallback)VFP_DoorSwitch_free,
    (ObjectDescriptorCallback)VFP_DoorSwitch_getObjectTypeId,
    VFP_DoorSwitch_getExtraSize,
};
