#include "main/object_descriptor.h"
#include "main/dll/VF/dll_021E_vfpblock1.h"

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
