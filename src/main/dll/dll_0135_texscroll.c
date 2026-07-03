/*
 * texscroll (DLL 0x135) - minimal per-placement texture-scroll object.
 * A pared-down sibling of texscroll2 (DLL 0x134): texscroll_init copies
 * the placement's scroll step rates and game bit into its extra state
 * (TexScrollState, 0x1C bytes) and zeroes the running UV offsets on a
 * cold load (loadFlags == 0). update/hitDetect are stubs here; render
 * just forwards a fixed scale to objRenderFn_8003b8f4 when visible.
 * init guards on state == NULL before writing (absent in texscroll2).
 *
 * gTexscrollObjDescriptor is declared extern in mmp_moonrock.h but is
 * not defined in this TU (deferred to the parent multi-TU descriptor file).
 */
#include "main/dll/mmp_moonrock.h"
#include "main/dll/VF/vf_shared.h"

extern f32 lbl_803E3F38;

void texscroll_free(void)
{
}

void texscroll_hitDetect(void)
{
}

void texscroll_update(void)
{
}

void texscroll_release(void)
{
}

void texscroll_initialise(void)
{
}

int texscroll_getExtraSize(void) { return TEXSCROLL_EXTRA_STATE_BYTES; }
int texscroll_getObjectTypeId(void) { return 0x0; }

void texscroll_init(TexScrollObject* obj, TexScrollPlacement* placement, int loadFlags)
{
    TexScrollState* state = obj->state;
    if (state == NULL) return;
    state->initLock = 1;
    state->stepX = (s16)(s32)placement->stepX;
    state->stepY = (s16)(s32)placement->stepY;
    state->scrollSlot = 0;
    state->flags = 0;
    state->gameBit = placement->gameBit;
    if (loadFlags == 0)
    {
        state->offsetX = 0;
        state->offsetY = 0;
    }
    state->initLock = 0;
}

void texscroll_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3F38);
}

ObjectDescriptor gTexscrollObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)texscroll_initialise,
    (ObjectDescriptorCallback)texscroll_release,
    0,
    (ObjectDescriptorCallback)texscroll_init,
    (ObjectDescriptorCallback)texscroll_update,
    (ObjectDescriptorCallback)texscroll_hitDetect,
    (ObjectDescriptorCallback)texscroll_render,
    (ObjectDescriptorCallback)texscroll_free,
    (ObjectDescriptorCallback)texscroll_getObjectTypeId,
    texscroll_getExtraSize,
};
