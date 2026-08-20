/*
 * SPitembeam (DLL 649) - the glowing "for sale" beam that marks a
 * purchasable item on a SnowHorn shop stall.
 *
 * Each beam latches onto the nearest shop object (object group 9, the
 * same group the shopkeeper and scarab coins look up) and tracks one
 * item slot (placement->itemIndex). While that item is still for sale
 * the beam scrolls its texture; once the shop reports the item is no
 * longer available, or has already been bought, the beam hides and
 * despawns itself.
 */
#include "main/objtexture.h"
#include "main/objtype.h"
#include "main/dll/SP/dll_0285_spshop.h"
#include "main/dll/SP/dll_0289_spitembeam.h"
#include "dlls/object_descriptor.h"

/* texture-scroll wrap (1/4 of the 0x1000 fixed-point texcoord range) */
#define SPITEMBEAM_SCROLL_STEP 8
#define SPITEMBEAM_SCROLL_WRAP 0x400

#define SPITEMBEAM_TARGET_OBJGROUP 9

int spitembeam_getExtraSize(void)
{
    return 0x0;
}
int spitembeam_getObjectTypeId(void)
{
    return 0x0;
}

void spitembeam_free(void)
{
}

void spitembeam_render(void)
{
}

void spitembeam_hitDetect(void)
{
}

void spitembeam_update(GameObject* obj)
{
    int* shop;
    SpitembeamPlacement* def;
    ObjTextureRuntimeSlot* tex;
    f32 searchRadius;

    shop = (int*)obj->userData1;
    def = (SpitembeamPlacement*)obj->anim.placementData;
    searchRadius = 10000.0f;
    if (shop == NULL)
    {
        obj->userData1 = (int)(int*)objGetNearestTypeTo(SPITEMBEAM_TARGET_OBJGROUP, obj, &searchRadius);
    }
    else
    {
        if (SHOP_INTERFACE(shop)->isItemAvailable((GameObject*)shop,
                                                  def->itemIndex) == 0 ||
            SHOP_INTERFACE(shop)->isItemBought((GameObject*)shop,
                                               def->itemIndex) != 0)
        {
            obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
            obj->objectFlags =
                (u16)(obj->objectFlags | OBJECT_OBJFLAG_UPDATE_DISABLED);
        }
        tex = objFindTexture(obj, 0, 0);
        if (tex != NULL)
        {
            tex->offsetS += SPITEMBEAM_SCROLL_STEP;
            if (tex->offsetS > SPITEMBEAM_SCROLL_WRAP)
            {
                tex->offsetS -= SPITEMBEAM_SCROLL_WRAP;
            }
        }
    }
}

void spitembeam_init(GameObject* obj) {
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void spitembeam_release(void)
{
}

void spitembeam_initialise(void)
{
}

ObjectDescriptor gSPitembeamObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)spitembeam_initialise,
    (ObjectDescriptorCallback)spitembeam_release,
    0,
    (ObjectDescriptorCallback)spitembeam_init,
    (ObjectDescriptorCallback)spitembeam_update,
    (ObjectDescriptorCallback)spitembeam_hitDetect,
    (ObjectDescriptorCallback)spitembeam_render,
    (ObjectDescriptorCallback)spitembeam_free,
    (ObjectDescriptorCallback)spitembeam_getObjectTypeId,
    spitembeam_getExtraSize,
};

