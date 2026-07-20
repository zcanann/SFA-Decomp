/*
 * EndObject (DLL 0x108) - terminal marker object whose callbacks are stubs.
 */
#include "main/dll/dll_0108_endobject.h"

int EndObject_getExtraSize(void)
{
    return 0x0;
}
int EndObject_getObjectTypeId(void)
{
    return 0x0;
}

void EndObject_free(void)
{
}

void EndObject_render(void)
{
}

void EndObject_hitDetect(void)
{
}

void EndObject_update(void)
{
}

void EndObject_init(void)
{
}

void EndObject_release(void)
{
}

void EndObject_initialise(void)
{
}

ObjectDescriptor gEndObjectObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)EndObject_initialise,
    (ObjectDescriptorCallback)EndObject_release,
    0,
    (ObjectDescriptorCallback)EndObject_init,
    (ObjectDescriptorCallback)EndObject_update,
    (ObjectDescriptorCallback)EndObject_hitDetect,
    (ObjectDescriptorCallback)EndObject_render,
    (ObjectDescriptorCallback)EndObject_free,
    (ObjectDescriptorCallback)EndObject_getObjectTypeId,
    EndObject_getExtraSize,
};
