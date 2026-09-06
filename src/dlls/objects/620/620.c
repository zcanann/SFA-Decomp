/*
 * DLL 620 - a hanging cage with a winch rope. On first
 * hit it spawns its linked rope/winch object and, while unlocked,
 * integrates a damped angular velocity (angularVel) from the object's
 * horizontal motion, driving the rope segments' rotZ and the linked
 * object. The placement supplies setup flags and the game bit
 * that marks the cage already opened (openedGameBit).
 */
#include "main/dll/DR/dll_0258_drcloudrunner.h"
#include "dlls/objects/common/vehicle.h"
#include "main/dll/DR/dll_026C_drcagewith.h"
#include "main/vecmath.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"
#include "main/object_render.h"
#include "main/objprint_api.h"
#include "main/objtype.h"
#include "main/dll/objfx_api.h"
#include "dlls/object_descriptor.h"
#include "main/obj_path.h"
#include "main/objhits.h"
#include "main/objseq.h"

#define DRCAGEWITH_CHILD_OBJ 1143
#define DRCAGEWITH_CAGE_NOROPE_OBJ 2154
#define DRCAGEWITH_CAGE_ROPE_OBJ 2155
#define DRCAGEWITH_OBJGROUP 0x18

int DR_CageWith_func0A(GameObject* obj)
{
    DrcagewithState* state = obj->extra;
    return state->unk30;
}

int DR_CageWith_toggleRopeStateCallback(GameObject* obj, int unused, ObjSeqState* animUpdate)
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
    return sizeof(DrcagewithState);
}

int DR_CageWith_getObjectTypeId(void)
{
    return 0x0;
}

void DR_CageWith_free(GameObject* obj, int arg)
{
    DrcagewithState* state = obj->extra;
    GameObject* linked = state->spawnedObject;
    if (linked != 0 && arg == 0 && linked->anim.modelInstance != 0)
    {
        GameObject* child = state->linkedObject;
        if (child != 0)
        {
            child->userData1 = 0;
        }
        state->spawnedObject->userData1 = 0;
        Obj_FreeObject(state->spawnedObject);
    }
    objFreeObjectType(obj, DRCAGEWITH_OBJGROUP);
}

void DR_CageWith_render(GameObject* obj, int p2, int p3, int p4, int p5, char visible)
{
    DrcagewithState* state = obj->extra;
    GameObject* linkedObj;
    f32 renderScale = 1.0f;
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, renderScale);
        if (state->spawnedObject != 0)
        {
            ObjPath_GetPointWorldPosition(obj, 0, &state->spawnedObject->anim.localPosX,
                                          &state->spawnedObject->anim.localPosY,
                                          &state->spawnedObject->anim.localPosZ, 0);
            objRenderModelAndHitVolumes(state->spawnedObject, p2, p3, p4, p5, renderScale);
            linkedObj = state->linkedObject;
            if (linkedObj != 0)
            {
                linkedObj->anim.rotY = state->spawnedObject->anim.rotY;
                linkedObj->anim.rotZ = state->spawnedObject->anim.rotZ;
                ObjPath_GetPointWorldPosition(state->spawnedObject, 0, &linkedObj->anim.localPosX,
                                              &linkedObj->anim.localPosY, &linkedObj->anim.localPosZ, 0);
                objRenderModelAndHitVolumes(linkedObj, p2, p3, p4, p5, renderScale);
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
    GameObject* child;
    GameObject* nearest;
    f32 angVel;
    f32 clamped;
    f32 px;
    f32 div;

    maxDist = 300.0f;
    state = obj->extra;
    bf31 = &state->ropeFlags;

    if (bf31->b1 != 0)
    {
        objDoParticleFx(obj, 1.5f, 6, 1.0f, NULL);
    }

    if (obj->anim.romDefNo == DRCAGEWITH_CAGE_NOROPE_OBJ || obj->anim.romDefNo == DRCAGEWITH_CAGE_ROPE_OBJ)
    {
        if (mainGetBit(GAMEBIT_DR_RescuedCloudRunner) != 0)
        {
            obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        }
        return;
    }
    if (state->spawnedObject == NULL)
    {
        if ((u8)Obj_CanSetupObject())
        {
            spawned = Obj_AllocObjectSetup(32, DRCAGEWITH_CHILD_OBJ);
            spawned->color[0] = 2;
            spawned->color[1] = 1;
            spawned->color[1] = (u8)(spawned->color[1] | (placement->flags & 0x18));
            spawned->posX = obj->anim.localPosX;
            spawned->posY = obj->anim.localPosY;
            spawned->posZ = obj->anim.localPosZ;
            child = objSetupObject(spawned, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
            child->anim.flags |= OBJANIM_FLAG_HIDDEN;
            child->userData1 = 1;
            state->spawnedObject = child;
            return;
        }
    }
    if (bf31->b0 == 0)
    {
        if (mainGetBit(GAMEBIT_DR_RescuedCloudRunner) != 0)
        {
            ObjHits_DisableObject(obj);
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
            bf31->b0 = 1;
            nearest = objGetNearestTypeTo(VEHICLE_OBJECT_GROUP, obj, &maxDist);
            if (nearest != NULL && nearest->anim.romDefNo == DR_CLOUDRUNNER_OBJECT_ID)
            {
                nearest->userData1 = 0;
                state->linkedObject = NULL;
            }
            return;
        }
        angVel = oneOverTimeDelta * (obj->anim.localPosX - obj->anim.previousLocalPosX);
        angVel *= -1300.0f;
        angVel = interpolate(angVel - state->angularVel, 0.05f, timeDelta);
        clamped =
            (angVel < -50.0f * timeDelta)
                ? -50.0f * timeDelta
                : ((angVel > 50.0f * timeDelta) ? 50.0f * timeDelta : angVel);
        state->angularVel = state->angularVel + clamped;
        for (i = 0, div = 9.0f; i < 9; i++)
        {
            s16* jointVec = objFindJointPoseVector(obj, i);
            if (jointVec != NULL)
            {
                jointVec[2] = state->angularVel / div;
            }
        }
        if (state->spawnedObject != NULL)
        {
            state->spawnedObject->anim.rotZ = (s16)state->angularVel;
            nearest = objGetNearestTypeTo(VEHICLE_OBJECT_GROUP, obj, &maxDist);
            if (nearest != NULL && nearest->anim.romDefNo == DR_CLOUDRUNNER_OBJECT_ID)
            {
                nearest->userData1 = 1;
                state->linkedObject = nearest;
                nearest->anim.rotZ = state->spawnedObject->anim.rotZ;
                state->spawnedObject->userData1 = 1;
            }
            if (state->linkedObject != NULL && (state->linkedObject->objectFlags & OBJECT_OBJFLAG_FREED) != 0)
            {
                state->linkedObject = NULL;
            }
        }
    }
    if (bf31->b0 == 0)
    {
        if (mainGetBit(3175) != 0)
        {
            px = obj->anim.localPosX;
            if (px >= -16990.0f && px <= -16968.0f)
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
    type = obj->anim.romDefNo;
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
        state->unk8 = placement->unk1C;
        state->unk10 = (f32)placement->unk1A / 10.0f;
        state->linkedObject = NULL;
        fz = 0.0f;
        state->unk14 = fz;
        state->unk18 = fz;
        state->unk1C = fz;
        state->unk20 = fz;
        objAddObjectType(obj, DRCAGEWITH_OBJGROUP);
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
        (ObjectDescriptorCallback)DR_CageWith_func0A,
    },
    0,
};
