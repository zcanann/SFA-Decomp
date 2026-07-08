/*
 * EndObject (DLL 0x108) - dummy descriptor whose every callback is a stub.
 * TU = 0x8018646C..0x80186498 plus the gDummy108ObjDescriptor .data object
 * at 0x803217C0.
 */
#include "main/dll_000A_expgfx.h"

int Dummy108_getExtraSize(void)
{
    return 0x0;
}
int Dummy108_getObjectTypeId(void)
{
    return 0x0;
}

void Dummy108_free(void)
{
}

void Dummy108_render(void)
{
}

void Dummy108_hitDetect(void)
{
}

void Dummy108_update(void)
{
}

void Dummy108_init(void)
{
}

void Dummy108_release(void)
{
}

void Dummy108_initialise(void)
{
}

ObjectDescriptor gDummy108ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)Dummy108_initialise,
    (ObjectDescriptorCallback)Dummy108_release,
    0,
    (ObjectDescriptorCallback)Dummy108_init,
    (ObjectDescriptorCallback)Dummy108_update,
    (ObjectDescriptorCallback)Dummy108_hitDetect,
    (ObjectDescriptorCallback)Dummy108_render,
    (ObjectDescriptorCallback)Dummy108_free,
    (ObjectDescriptorCallback)Dummy108_getObjectTypeId,
    Dummy108_getExtraSize,
};
