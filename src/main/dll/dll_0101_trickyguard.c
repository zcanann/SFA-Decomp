#include "main/obj_placement.h"
#include "main/dll/dusterstate_types.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/cfprisonuncle.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objfx.h"

typedef struct TrickyguardPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
} TrickyguardPlacement;


extern u32 GameBit_Get(int eventId);
extern void* getTrickyObject(void);
extern void objRenderFn_80041018(int* obj);


/*
 * --INFO--
 *
 * Function: fn_8017F4F4
 * EN v1.0 Address: 0x8017F4F4
 * EN v1.0 Size: 760b
 * EN v1.1 Address: 0x8017F548
 * EN v1.1 Size: 836b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_8017f7ec
 * EN v1.0 Address: 0x8017F7EC
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x8017F88C
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: MagicPlant_update
 * EN v1.0 Address: 0x8017FA10
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017FA4C
 * EN v1.1 Size: 708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void MagicPlant_update(int obj);

/*
 * --INFO--
 *
 * Function: FUN_8017fa14
 * EN v1.0 Address: 0x8017FA14
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x8017FD10
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801804a0
 * EN v1.0 Address: 0x801804A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801802DC
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801804a4
 * EN v1.0 Address: 0x801804A4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80180464
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801804d8
 * EN v1.0 Address: 0x801804D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801804A0
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801804dc
 * EN v1.0 Address: 0x801804DC
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x80180528
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801811c8
 * EN v1.0 Address: 0x801811C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80181204
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801811cc
 * EN v1.0 Address: 0x801811CC
 * EN v1.0 Size: 2244b
 * EN v1.1 Address: 0x80181328
 * EN v1.1 Size: 1672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* 8b "li r3, N; blr" returners. */
int MagicPlant_getExtraSize(void);
int trickywarp_getExtraSize(void);
int duster_getExtraSize(void);
int curvefish_getExtraSize(void);


STATIC_ASSERT(sizeof(DusterStateFlags) == 1);
STATIC_ASSERT(sizeof(DusterState) == 0x20);
STATIC_ASSERT(offsetof(DusterState, moveStepScale) == 0x00);
STATIC_ASSERT(offsetof(DusterState, floorY) == 0x04);
STATIC_ASSERT(offsetof(DusterState, settleTimer) == 0x08);
STATIC_ASSERT(offsetof(DusterState, hitReactTimer) == 0x0a);
STATIC_ASSERT(offsetof(DusterState, completeGameBit) == 0x0c);
STATIC_ASSERT(offsetof(DusterState, activeGameBit) == 0x0e);
STATIC_ASSERT(offsetof(DusterState, heldObjectId) == 0x10);
STATIC_ASSERT(offsetof(DusterState, driftDir) == 0x18);
STATIC_ASSERT(offsetof(DusterState, hitReactActive) == 0x19);
STATIC_ASSERT(offsetof(DusterState, priorityHit) == 0x1a);
STATIC_ASSERT(offsetof(DusterState, active) == 0x1b);
STATIC_ASSERT(offsetof(DusterState, complete) == 0x1c);
STATIC_ASSERT(offsetof(DusterState, useLaunchVelocity) == 0x1d);
STATIC_ASSERT(offsetof(DusterState, flags) == 0x1e);


/* gCameraInterface: vtable pointer used for state-machine dispatches. */

/* MagicPlant_SeqFn: vtable[0x13]() with obj passed through implicitly, return 0. */

u32 MagicPlant_getObjectTypeId(MagicPlantObject* obj);

/* obj->u16_X |= MASK */
void StayPoint_init(u16* obj);


void MagicPlant_free(int obj, int param_2);

void MagicPlant_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

void trickywarp_free(int obj);


void trickywarp_init(s16* obj, u8* param_2);

void trickyguard_init(s16* obj, u8* param_2)
{
    u32 v;
    *obj = (s16)((u32)param_2[0x18] << 8);
    v = ((GameObject*)obj)->objectFlags;
    v |= 0x4000;
    ((GameObject*)obj)->objectFlags = (u16)v;
}

void duster_render(int obj, int p2, int p3, int p4, int p5, s8 visible);


void duster_hitDetect(int param_1);


void duster_init(int obj, u8* params);

void duster_update(int obj);


void MagicPlant_init(int obj, MagicPlantSetup* setup);


void trickywarp_update(int param_1);

void curvefish_update(int obj);

void curvefish_init(int obj, u8* param_2);


void trickyguard_update(int* obj)
{
    int* tricky;
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
    if (((TrickyguardPlacement*)def)->unk1A != -1)
    {
        if ((u32)GameBit_Get(((TrickyguardPlacement*)def)->unk1A) == 0) return;
    }
    tricky = (int*)getTrickyObject();
    if (tricky == NULL) return;
    if ((u8)((int (*)(int*))(**(int***)((char*)tricky + 0x68))[0x11])(tricky) != 0) return;
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x04) != 0)
    {
        ((void (*)(int*, int*, int, int))(**(int***)((char*)tricky + 0x68))[0xa])(tricky, obj, 1, 3);
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x08);
    objRenderFn_80041018(obj);
}


void StayPoint_update(int obj);

ObjectDescriptor gMagicPlantObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)MagicPlant_init,
    (ObjectDescriptorCallback)MagicPlant_update,
    0,
    (ObjectDescriptorCallback)MagicPlant_render,
    (ObjectDescriptorCallback)MagicPlant_free,
    (ObjectDescriptorCallback)MagicPlant_getObjectTypeId,
    MagicPlant_getExtraSize,
};

ObjectDescriptor gTrickyWarpObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)trickywarp_init,
    (ObjectDescriptorCallback)trickywarp_update,
    0,
    0,
    (ObjectDescriptorCallback)trickywarp_free,
    0,
    trickywarp_getExtraSize,
};

ObjectDescriptor gTrickyGuardObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)trickyguard_init,
    (ObjectDescriptorCallback)trickyguard_update,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gStayPointObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)StayPoint_init,
    (ObjectDescriptorCallback)StayPoint_update,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gDusterObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)duster_init,
    (ObjectDescriptorCallback)duster_update,
    (ObjectDescriptorCallback)duster_hitDetect,
    (ObjectDescriptorCallback)duster_render,
    0,
    0,
    duster_getExtraSize,
};

ObjectDescriptor gCurveFishObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)curvefish_init,
    (ObjectDescriptorCallback)curvefish_update,
    0,
    0,
    0,
    0,
    curvefish_getExtraSize,
};
