/*
 * drcagewith (DLL 0x26C) - a hanging cage with a winch rope. On first
 * hit it spawns its linked rope/winch object and, while unlocked,
 * integrates a damped angular velocity (angularVel) from the object's
 * horizontal motion, driving the rope segments' rotZ and the linked
 * object. The placement supplies setup flags and the game bit
 * that marks the cage already opened (openedGameBit).
 */
#include "main/dll/DR/dll_026C_drcagewith.h"
#include "main/vecmath.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/obj_path.h"
#include "main/obj_placement.h"
#include "main/objhits.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/objprint_api.h"
#include "main/dll/objfx_api.h"
#include "main/object_descriptor.h"

#define DRCAGEWITH_CHILD_OBJ 1143

#define DRCAGEWITH_OBJGROUP 0x18

#define DRCAGEWITH_TARGET_OBJGROUP 0xa /* nearest group-10 object (seqId 1049) linked as the cage target */

#define DRCAGEWITH_OBJFLAG_FREED 0x40

#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E69F0 = 1.0f;
__declspec(section ".sdata2") f32 gDrCageWithFindObjMaxDist = 300.0f;
__declspec(section ".sdata2") f32 lbl_803E69F8 = 1.5f;
__declspec(section ".sdata2") f32 lbl_803E69FC = -1300.0f;
__declspec(section ".sdata2") f32 lbl_803E6A00 = 0.05f;
__declspec(section ".sdata2") f32 gDrCageWithAngVelRateMin = -50.0f;
__declspec(section ".sdata2") f32 gDrCageWithAngVelRateMax = 50.0f;
__declspec(section ".sdata2") f32 lbl_803E6A0C = 9.0f;
__declspec(section ".sdata2") f32 lbl_803E6A10 = -16990.0f;
__declspec(section ".sdata2") f32 lbl_803E6A14 = -16968.0f;
__declspec(section ".sdata2") f32 lbl_803E6A18 = 10.0f;
__declspec(section ".sdata2") f32 lbl_803E6A1C = 0.0f;
#pragma explicit_zero_data off

int DR_CageWith_setScale(GameObject* obj)
{
    DrcagewithState* state = obj->extra;
    return state->scaleMode;
}

int DR_CageWith_toggleRopeStateCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    DrcagewithState* state = obj->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            state->ropeFlags.b1 ^= 1;
        }
    }
    return 0;
}

int DR_CageWith_getExtraSize(void)
{
    return 0x34;
}

int DR_CageWith_getObjectTypeId(void)
{
    return 0x0;
}

void DR_CageWith_free(GameObject* obj, int arg)
{
    DrcagewithState* state = (obj)->extra;
    GameObject* linked = state->spawnedObject;
    if (linked != 0 && arg == 0 && linked->anim.modelInstance != 0)
    {
        GameObject* child = state->linkedObject;
        if (child != 0)
        {
            child->unkF4 = 0;
        }
        state->spawnedObject->unkF4 = 0;
        Obj_FreeObject(state->spawnedObject);
    }
    ObjGroup_RemoveObject((int)obj, DRCAGEWITH_OBJGROUP);
}

void DR_CageWith_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    DrcagewithState* state = (obj)->extra;
    GameObject* linkedObj;
    if (visible != 0)
    {
        objRenderModelAndHitVolumesFwdDoubleLegacy(obj, p2, p3, p4, p5, (double)lbl_803E69F0);
        if (state->spawnedObject != 0)
        {
            ObjPath_GetPointWorldPosition(obj, 0, &state->spawnedObject->anim.localPosX,
                                          &state->spawnedObject->anim.localPosY,
                                          &state->spawnedObject->anim.localPosZ, 0);
            objRenderModelAndHitVolumesFwdDoubleLegacy(state->spawnedObject, p2, p3, p4, p5,
                                                        (double)lbl_803E69F0);
            linkedObj = state->linkedObject;
            if (linkedObj != 0)
            {
                linkedObj->anim.rotY = state->spawnedObject->anim.rotY;
                linkedObj->anim.rotZ = state->spawnedObject->anim.rotZ;
                ObjPath_GetPointWorldPosition(state->spawnedObject, 0, &linkedObj->anim.localPosX,
                                              &linkedObj->anim.localPosY, &linkedObj->anim.localPosZ, 0);
                objRenderModelAndHitVolumesFwdDoubleLegacy(linkedObj, p2, p3, p4, p5, (double)lbl_803E69F0);
            }
        }
    }
}

void DR_CageWith_hitDetect(GameObject* obj)
{
    DrcagewithPlacement* placement = (DrcagewithPlacement*)obj->anim.placementData;
    DrcagewithState* state;
    BitFlags8* bf31;
    f32 maxDist;
    int i;
    ObjPlacement* spawned;
    int* nearest;
    f32 angVel;
    f32 clamped;
    f32 px;
    f32 div;

    maxDist = gDrCageWithFindObjMaxDist;
    state = (obj)->extra;
    bf31 = &state->ropeFlags;

    if (bf31->b1 != 0)
    {
        objParticleFn_80099d84(obj, lbl_803E69F8, 6, lbl_803E69F0, NULL);
    }

    if ((obj)->anim.seqId == 2154 || (obj)->anim.seqId == 2155)
    {
        if (mainGetBit(GAMEBIT_DR_RescuedCloudRunner) != 0)
        {
            (obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        }
        return;
    }
    if (state->spawnedObject == NULL)
    {
        if (Obj_IsLoadingLocked())
        {
            spawned = Obj_AllocObjectSetup(32, DRCAGEWITH_CHILD_OBJ);
            spawned->color[0] = 2;
            spawned->color[1] = 1;
            spawned->color[1] = (u8)(spawned->color[1] | (placement->flags & 0x18));
            ((GameObject*)spawned)->anim.rootMotionScale = (obj)->anim.localPosX;
            ((GameObject*)spawned)->anim.localPosX = (obj)->anim.localPosY;
            ((GameObject*)spawned)->anim.localPosY = (obj)->anim.localPosZ;
            spawned = (ObjPlacement*)Obj_SetupObject(spawned, 5, (obj)->anim.mapEventSlot, -1, (obj)->anim.parent);
            ((GameObject*)spawned)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ((GameObject*)spawned)->unkF4 = 1;
            state->spawnedObject = (GameObject*)spawned;
            return;
        }
    }
    if (bf31->b0 == 0)
    {
        if (mainGetBit(GAMEBIT_DR_RescuedCloudRunner) != 0)
        {
            ObjHits_DisableObject((int)obj);
            (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            bf31->b0 = 1;
            nearest = (int*)ObjGroup_FindNearestObject(DRCAGEWITH_TARGET_OBJGROUP, (int)obj, &maxDist);
            if (nearest != NULL && ((GameObject*)nearest)->anim.seqId == 1049)
            {
                ((GameObject*)nearest)->unkF4 = 0;
                state->linkedObject = NULL;
            }
            return;
        }
        angVel = oneOverTimeDelta * ((obj)->anim.localPosX - (obj)->anim.previousLocalPosX);
        angVel = angVel * lbl_803E69FC;
        angVel = interpolate(angVel - state->angularVel, lbl_803E6A00, timeDelta);
        clamped =
            (angVel < gDrCageWithAngVelRateMin * timeDelta)
                ? gDrCageWithAngVelRateMin * timeDelta
                : ((angVel > gDrCageWithAngVelRateMax * timeDelta) ? gDrCageWithAngVelRateMax * timeDelta : angVel);
        state->angularVel = state->angularVel + clamped;
        for (i = 0, div = lbl_803E6A0C; i < 9; i++)
        {
            s16* jointVec = objModelGetVecFn_800395d8(obj, i);
            if (jointVec != NULL)
            {
                jointVec[2] = state->angularVel / div;
            }
        }
        if (state->spawnedObject != NULL)
        {
            state->spawnedObject->anim.rotZ = (s16)state->angularVel;
            nearest = (int*)ObjGroup_FindNearestObject(DRCAGEWITH_TARGET_OBJGROUP, (int)obj, &maxDist);
            if (nearest != NULL && ((GameObject*)nearest)->anim.seqId == 1049)
            {
                ((GameObject*)nearest)->unkF4 = 1;
                state->linkedObject = (GameObject*)nearest;
                ((GameObject*)nearest)->anim.rotZ = state->spawnedObject->anim.rotZ;
                state->spawnedObject->unkF4 = 1;
            }
            if (state->linkedObject != NULL && (state->linkedObject->objectFlags & DRCAGEWITH_OBJFLAG_FREED) != 0)
            {
                state->linkedObject = NULL;
            }
        }
    }
    if (bf31->b0 == 0)
    {
        if (mainGetBit(3175) != 0)
        {
            px = (obj)->anim.localPosX;
            if (px >= lbl_803E6A10 && px <= lbl_803E6A14)
            {
                mainSetBits(placement->openedGameBit, 1);
            }
            else
            {
                mainSetBits(3748, 1);
            }
        }
        else
        {
            mainSetBits(3748, 0);
        }
    }
}

void DR_CageWith_update(void)
{
}

void DR_CageWith_init(GameObject* obj, DrcagewithPlacement* placement)
{
    DrcagewithState* state = obj->extra;
    s16 type;
    f32 fz;
    obj->animEventCallback = DR_CageWith_toggleRopeStateCallback;
    type = obj->anim.seqId;
    if (type == 0x86a || type == 0x86b)
    {
        if (mainGetBit(GAMEBIT_DR_RescuedCloudRunner) == 0)
        {
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
    }
    else
    {
        ObjHits_EnableObject(obj);
        if (mainGetBit(placement->openedGameBit) != 0)
        {
            ObjHits_DisableObject(obj);
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
            state->ropeFlags.b0 = 1;
        }
        else
        {
            mainSetBits(0x7aa, 5);
        }
        obj->anim.rotX = (s16)(placement->initRotXByte << 8);
        state->unk8 = (f32)placement->unk1C;
        state->unk10 = (f32)placement->unk1A / lbl_803E6A18;
        state->linkedObject = NULL;
        fz = lbl_803E6A1C;
        state->unk14 = fz;
        state->unk18 = fz;
        state->unk1C = fz;
        state->unk20 = fz;
        ObjGroup_AddObject((int)obj, DRCAGEWITH_OBJGROUP);
    }
}

void DR_CageWith_release(void)
{
}

void DR_CageWith_initialise(void)
{
}

ObjectDescriptor11WithPadding gDrCageWithObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)DR_CageWith_initialise,
        (ObjectDescriptorCallback)DR_CageWith_release,
        0,
        (ObjectDescriptorCallback)DR_CageWith_init,
        (ObjectDescriptorCallback)DR_CageWith_update,
        (ObjectDescriptorCallback)DR_CageWith_hitDetect,
        (ObjectDescriptorCallback)DR_CageWith_render,
        (ObjectDescriptorCallback)DR_CageWith_free,
        (ObjectDescriptorCallback)DR_CageWith_getObjectTypeId,
        (ObjectDescriptorExtraSizeCallback)DR_CageWith_getExtraSize,
        (ObjectDescriptorCallback)DR_CageWith_setScale,
    },
    0,
};
