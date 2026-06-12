/*
 * EndObject (DLL 0x108) - dummy descriptor whose every callback is a stub.
 * Re-split (descriptor forensics, docs/boundary_audit.md): TU =
 * 0x8018646C..0x80186498 plus the gDummy108ObjDescriptor .data object at
 * 0x803217C0 (both formerly inside windlift.c).
 */
#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"
#include "main/objhits_types.h"
#include "main/dll/CF/windlift.h"
#include "main/dll/CF/lanternfirefly_state.h"
#include "main/resource.h"
#include "global.h"

/* Trivial 4b 0-arg blr leaves. */
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

/* 8b "li r3, N; blr" returners. */
int Dummy108_getExtraSize(void) { return 0x0; }
int Dummy108_getObjectTypeId(void) { return 0x0; }

ObjectDescriptor gDummy108ObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
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
