/*
 * spitembeam (DLL 0x289) - the glowing "for sale" beam that marks a
 * purchasable item on a SnowHorn shop stall.
 *
 * Each beam latches onto the nearest shop object (object group 9, the
 * same group the shopkeeper and scarab coins look up) and tracks one
 * item slot (placement->itemIndex). While that item is still for sale
 * the beam scrolls its texture; once the shop reports the item is no
 * longer available, or has already been bought, the beam hides and
 * despawns itself.
 */
#include "main/dll/DR/dll_0287_spscarab.h"
#include "main/objtexture.h"
#include "main/game_object.h"

/* slots on the shop object's interface vtable (obj+0x68) queried per item */
enum
{
    SHOP_IFACE_IS_AVAILABLE = 10,
    SHOP_IFACE_IS_BOUGHT = 11
};

/* texture-scroll wrap (1/4 of the 0x1000 fixed-point texcoord range) */
#define SPITEMBEAM_SCROLL_STEP 8
#define SPITEMBEAM_SCROLL_WRAP 0x400

#define SPITEMBEAM_OBJFLAG_HIDDEN 0x4000
#define SPITEMBEAM_OBJFLAG_HITDETECT_DISABLED 0x2000
#define SPITEMBEAM_OBJFLAG_UPDATE_DISABLED 0x8000

extern f32 lbl_803E5AD8;
extern int* ObjGroup_FindNearestObject(int group, int* obj, f32* dist);

typedef struct SpitembeamPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 itemIndex; /* 0x1A: shop item slot this beam marks */
    u8 pad1C[0x20 - 0x1C];
} SpitembeamPlacement;

STATIC_ASSERT(sizeof(SpitembeamPlacement) == 0x20);

void spitembeam_init(int obj)
{
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | (SPITEMBEAM_OBJFLAG_HIDDEN | SPITEMBEAM_OBJFLAG_HITDETECT_DISABLED));
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

void spitembeam_release(void)
{
}

void spitembeam_initialise(void)
{
}

void spitembeam_update(int* obj)
{
    int* shop;
    u8* def;
    ObjTextureRuntimeSlot* tex;
    f32 searchRadius;

    shop = *(int**)&((GameObject*)obj)->unkF4;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    searchRadius = lbl_803E5AD8;
    if (shop == NULL)
    {
        *(int**)&((GameObject*)obj)->unkF4 = ObjGroup_FindNearestObject(9, obj, &searchRadius);
    }
    else
    {
        if (((int(*)(int*, s16))(**(int***)((char*)shop + 0x68))[SHOP_IFACE_IS_AVAILABLE])(
                shop, ((SpitembeamPlacement*)def)->itemIndex) == 0 ||
            ((int(*)(int*, s16))(**(int***)((char*)shop + 0x68))[SHOP_IFACE_IS_BOUGHT])(
                shop, ((SpitembeamPlacement*)def)->itemIndex) != 0)
        {
            ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
            ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | SPITEMBEAM_OBJFLAG_UPDATE_DISABLED);
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

int spitembeam_getExtraSize(void) { return 0x0; }
int spitembeam_getObjectTypeId(void) { return 0x0; }

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

/* used by dll_0255 (snowbike) as a base+offset table; placed in this unit by link order */
f32 lbl_803284E0[19] = {
    -6.5f, 0.0f, -13.0f,
    6.5f, 0.0f, -13.0f,
    6.5f, 0.0f, 13.0f,
    -6.5f, 0.0f, 13.0f,
    1.0f, 1.0f, 1.0f, 1.0f,
    0.0f, 0.0f, 0.0f,
};
