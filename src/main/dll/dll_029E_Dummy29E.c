/*
 * Dummy29E (DLL 0x29E) - an empty object-class slot. Every entry point
 * (extra-size, type-id, init/update/render/hitDetect/free, and the
 * (de)initialise pair) is a stub: no per-object state is allocated and no
 * behaviour runs. The DLL exists only to fill the 0x29E id in the object
 * table.
 */
#include "main/dll/dll_029E_dummy.h"
#include "main/object_descriptor.h"

ObjectDescriptor lbl_8032B6B0 = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)Dummy29E_initialise,
    (ObjectDescriptorCallback)Dummy29E_release,
    NULL,
    (ObjectDescriptorCallback)Dummy29E_init,
    (ObjectDescriptorCallback)Dummy29E_update,
    (ObjectDescriptorCallback)Dummy29E_hitDetect,
    (ObjectDescriptorCallback)Dummy29E_render,
    (ObjectDescriptorCallback)Dummy29E_free,
    (ObjectDescriptorCallback)Dummy29E_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)Dummy29E_getExtraSize,
};

int Dummy29E_getExtraSize(void)
{
    return 0x0;
}

int Dummy29E_getObjectTypeId(void)
{
    return 0x0;
}

void Dummy29E_free(void)
{
}

void Dummy29E_render(void)
{
}

void Dummy29E_hitDetect(void)
{
}

void Dummy29E_update(void)
{
}

void Dummy29E_init(void)
{
}

void Dummy29E_release(void)
{
}

void Dummy29E_initialise(void)
{
}
