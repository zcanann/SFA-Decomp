#include "main/object_descriptor.h"
#include "main/game_object.h"

int VFP_Block1_getExtraSize(void);
int VFP_Block1_getObjectTypeId(void);
void VFP_Block1_free(int obj);
void VFP_Block1_render(void);
void VFP_Block1_hitDetect(void);
void VFP_Block1_update(GameObject* obj);
void VFP_Block1_init(int obj, int data);
void VFP_Block1_release(void);
void VFP_Block1_initialise(void);

ObjectDescriptor gVFP_Block1ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFP_Block1_initialise,
    (ObjectDescriptorCallback)VFP_Block1_release,
    0,
    (ObjectDescriptorCallback)VFP_Block1_init,
    (ObjectDescriptorCallback)VFP_Block1_update,
    (ObjectDescriptorCallback)VFP_Block1_hitDetect,
    (ObjectDescriptorCallback)VFP_Block1_render,
    (ObjectDescriptorCallback)VFP_Block1_free,
    (ObjectDescriptorCallback)VFP_Block1_getObjectTypeId,
    VFP_Block1_getExtraSize,
};
