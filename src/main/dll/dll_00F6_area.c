#include "main/dll/tFrameAnimator.h"
#include "main/game_object.h"
#include "main/dll/tframeanimator_state.h"






/*
 * --INFO--
 *
 * Function: sidekickball_init
 * EN v1.0 Address: 0x80179EB0
 * EN v1.0 Size: 1220b
 * EN v1.1 Address: 0x80179F40
 * EN v1.1 Size: 1204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


int area_getExtraSize(void) { return 0x0; }
int area_getObjectTypeId(void) { return 0x0; }

void area_free(void)
{
}

void area_render(void)
{
}

void area_hitDetect(void)
{
}

void area_update(void)
{
}

/* obj->u16_X |= MASK */
void area_init(u16* obj)
{
    u32 v;
    v = ((GameObject*)obj)->objectFlags;
    v |= 0xa000;
    ((GameObject*)obj)->objectFlags = (u16)v;
}

void area_release(void)
{
}

void area_initialise(void)
{
}

/* Trivial 4b 0-arg blr leaves. */
void levelname_free(void);









/* 8b "li r3, N; blr" returners. */



ObjectDescriptor gAreaObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)area_initialise,
    (ObjectDescriptorCallback)area_release,
    0,
    (ObjectDescriptorCallback)area_init,
    (ObjectDescriptorCallback)area_update,
    (ObjectDescriptorCallback)area_hitDetect,
    (ObjectDescriptorCallback)area_render,
    (ObjectDescriptorCallback)area_free,
    (ObjectDescriptorCallback)area_getObjectTypeId,
    area_getExtraSize,
};
