#include "main/obj_placement.h"
#include "main/dll/dusterstate_types.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/cfprisonuncle.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objfx.h"

extern void Obj_StartModelFadeIn(int obj, int frames);
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined8 ObjHits_DisableObject();
extern int ObjHits_IsObjectEnabled();
extern undefined4 ObjHits_RecordObjectHit();
extern int ObjHits_GetPriorityHitWithPosition();
extern void* ObjGroup_GetObjects();
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern void fn_801816F8(int obj, int param_2, u8* state);
extern int Sfx_IsPlayingFromObject(int obj, u16 sfxId);
extern void Sfx_PlayFromObject(int obj, u16 sfxId);
extern void Obj_SetModelColorFadeRecursive(int obj, int frames, int red, int green, int blue, int startAtHalf);

extern int lbl_803DBDA0;
extern f32 lbl_803DBDA4;
extern f32 lbl_803DBDA8;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E3934;
extern f32 lbl_803E3938;



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
















typedef struct DusterHitEffectPos
{
    u8 pad00[0xc];
    f32 x;
    f32 y;
    f32 z;
} DusterHitEffectPos;

void fn_801814D0(int obj, int param_2, u8* state)
{
    int hitWork[4];
    DusterHitEffectPos effectPos;
    int hitType;
    int* objects;
    int i;
    int* ret;
    f32 objY;
    f32 groupObjY;
    f32 f;

    hitType = ObjHits_GetPriorityHitWithPosition(obj, &hitWork[3], &hitWork[2], &hitWork[1],
                                                 &effectPos.x, &effectPos.y, &effectPos.z);
    if (hitType != 0)
    {
        if (hitType == 0x10)
        {
            Obj_StartModelFadeIn(obj, 0x12c);
        }
        else
        {
            effectPos.x += playerMapOffsetX;
            effectPos.z += playerMapOffsetZ;
            if (state[0x20] != 0)
            {
                if (hitType != 5)
                {
                    objLightFn_8009a1dc((void*)obj, lbl_803E3934, &effectPos, 4, 0);
                    if (Sfx_IsPlayingFromObject(0, 0x37e) == 0)
                    {
                        Sfx_PlayFromObject(obj, 0x37e);
                    }
                    return;
                }
                ret = (int*)ObjGroup_GetObjects(0x10, &hitWork[0]);
                i = 0;
                objects = ret;
                for (; i < hitWork[0]; i++)
                {
                    if (ObjHits_IsObjectEnabled(*objects) != 0)
                    {
                        groupObjY = *(f32*)(*objects + 0x10);
                        objY = ((GameObject*)obj)->anim.localPosY;
                        if (groupObjY > objY && groupObjY < objY + lbl_803DBDA8)
                        {
                            if (Vec_xzDistance((f32*)(*objects + 0x18), (f32*)(obj + 0x18)) < lbl_803DBDA4)
                            {
                                ObjHits_RecordObjectHit(*objects, hitWork[3], 5, 1, 0);
                            }
                        }
                    }
                    objects++;
                }
            }
            objLightFn_8009a1dc((void*)obj, lbl_803E3934, &effectPos, 1, 0);
            Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
            if (Sfx_IsPlayingFromObject(0, (u16) * (s16*)(state + 0x10)) == 0)
            {
                Sfx_PlayFromObject(obj, (u16) * (s16*)(state + 0x10));
            }
            *(s16*)(state + 0xa) = 0x32;
            state[9] = 0;
            fn_801816F8(obj, param_2, state);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
            f = lbl_803E3938;
            ((GameObject*)obj)->anim.velocityX = lbl_803E3938;
            ((GameObject*)obj)->anim.velocityZ = f;
            ObjHits_ClearHitVolumes(obj);
            if (lbl_803DBDA0 != 0)
            {
                ObjHits_DisableObject(obj);
            }
        }
    }
}

void trickyguard_update(int* obj);


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
