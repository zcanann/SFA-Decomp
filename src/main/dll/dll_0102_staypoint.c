#include "main/dll/dusterstate_types.h"
#include "main/game_object.h"
#include "main/dll/cfprisonuncle.h"

extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void* getTrickyObject(void);
extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
extern int cMenuGetSelectedItem(void);
extern int fn_80138F84(int tricky);
extern void objRenderFn_80041018(int* obj);

extern f32 lbl_803E38A8;

void MagicPlant_update(int obj);

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

u32 MagicPlant_getObjectTypeId(MagicPlantObject* obj);

void StayPoint_init(u16* obj)
{
    u32 v;
    v = ((GameObject*)obj)->objectFlags;
    v |= 0x4000;
    ((GameObject*)obj)->objectFlags = (u16)v;
}

void MagicPlant_free(int obj, int param_2);

void MagicPlant_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

void trickywarp_free(int obj);

void trickywarp_init(s16* obj, u8* param_2);

void trickyguard_init(s16* obj, u8* param_2);

void duster_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

void duster_hitDetect(int param_1);

void duster_init(int obj, u8* params);

void duster_update(int obj);

void MagicPlant_init(int obj, MagicPlantSetup* setup);

void trickywarp_update(int param_1);

void curvefish_update(int obj);

void curvefish_init(int obj, u8* param_2);

void trickyguard_update(int* obj);

typedef struct StayPointSetup
{
    u8 pad00[0x1e];
    s16 activeGameBit;
    s16 requiredGameBit;
} StayPointSetup;

void StayPoint_update(int obj)
{
    StayPointSetup* setup;
    void* tricky;
    int isCurrentStayPoint;

    setup = *(StayPointSetup**)&((GameObject*)obj)->anim.placementData;
    tricky = getTrickyObject();
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
    if (tricky != NULL)
    {
        isCurrentStayPoint = (obj - fn_80138F84((int)tricky) == 0);
        if (isCurrentStayPoint == 0 && setup->activeGameBit != -1)
        {
            GameBit_Set(setup->activeGameBit, 0);
        }
        if (setup->requiredGameBit == -1 || GameBit_Get(setup->requiredGameBit) != 0)
        {
            if (isCurrentStayPoint != 0 &&
                vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, (f32*)((int)tricky + 0x18)) < lbl_803E38A8)
            {
                if (setup->activeGameBit != -1)
                {
                    GameBit_Set(setup->activeGameBit, 1);
                }
                return;
            }
            if (cMenuGetSelectedItem() == -1)
            {
                ((GameObject*)obj)->anim.modelInstance->hitVolumes[0].priority = 0;
            }
            else
            {
                ((GameObject*)obj)->anim.modelInstance->hitVolumes[0].priority = 0x10;
            }
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (
                u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~8);
            if (((((ObjAnimComponent*)obj)->modelInstance->flags & 1) != 0) &&
                ((ObjAnimComponent*)obj)->hitVolumeTransforms != NULL)
            {
                objRenderFn_80041018((int*)obj);
            }
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
            {
                ((void (*)(void*, int, int, int))(*(int*)(*(int*)(*(int*)((int)tricky + 0x68)) + 0x28)))(
                    tricky, obj, 1, 3);
            }
        }
    }
}

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
