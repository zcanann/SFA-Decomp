/* VFP_corepla (DLL 0x0223) */
#include "dlls/objects/547_VFP_corepla.h"
#include "main/dll/expgfx_interface.h"
#include "main/gamebits.h"
#include "main/object_render.h"

int VFP_coreplat_sequenceCallback(void) {
    return 0x0;
}

int VFP_coreplat_getExtraSize(void) {
    return 0x4;
}

int VFP_coreplat_getObjectTypeId(void) {
    return 0x0;
}

void VFP_coreplat_free(int obj) {
    (*gExpgfxInterface)->freeSource2(obj);
}

void VFP_coreplat_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) {
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void VFP_coreplat_hitDetect(void) {
}

void VFP_coreplat_update(void) {
}

void VFP_coreplat_init(GameObject* obj, VfpCorePlatformPlacement* data) {
    VfpCorePlatformPlacement* def = data;
    VfpCorePlatformState* state = obj->extra;

    obj->anim.rotX = (((s32)def->rotXByte) << 8);
    state->gameBitId = def->gameBitId;
    obj->animEventCallback = VFP_coreplat_sequenceCallback;
    if (obj->anim.romDefNo == 0x3cb) {
        if (mainGetBit(GAMEBIT_ITEM_SpellStone1_Used) != 0) {
            obj->anim.rootMotionScale = 0.7f * obj->anim.modelInstance->rootMotionScaleBase;
        }
        if (mainGetBit(GAMEBIT_ITEM_SpellStone3_Got) != 0) {
            obj->anim.rootMotionScale = 0.45f * obj->anim.modelInstance->rootMotionScaleBase;
        }
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void VFP_coreplat_release(void) {
}

void VFP_coreplat_initialise(void) {
}

ObjectDescriptor gVFP_coreplatObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFP_coreplat_initialise,
    (ObjectDescriptorCallback)VFP_coreplat_release,
    0,
    (ObjectDescriptorCallback)VFP_coreplat_init,
    (ObjectDescriptorCallback)VFP_coreplat_update,
    (ObjectDescriptorCallback)VFP_coreplat_hitDetect,
    (ObjectDescriptorCallback)VFP_coreplat_render,
    (ObjectDescriptorCallback)VFP_coreplat_free,
    (ObjectDescriptorCallback)VFP_coreplat_getObjectTypeId,
    VFP_coreplat_getExtraSize,
};
