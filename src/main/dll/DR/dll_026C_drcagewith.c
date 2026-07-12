/*
 * drcagewith (DLL 0x26C) - a hanging cage with a winch rope. On first
 * hit it spawns its linked rope/winch object and, while unlocked,
 * integrates a damped angular velocity (angularVel) from the object's
 * horizontal motion, driving the rope segments' rotZ and the linked
 * object. The placement supplies setup flags (unk5) and the game bit
 * that marks the cage already opened (openedGameBit).
 */
#include "main/dll/DR/dr_shared.h"
#include "main/gamebit_ids.h"
#include "main/game_object.h"
#include "main/objprint_api.h"
#include "main/dll/DR/dll_026C_drcagewith.h"

#define DRCAGEWITH_CHILD_OBJ 1143

#define DRCAGEWITH_OBJGROUP 0x18

#define DRCAGEWITH_TARGET_OBJGROUP 0xa /* nearest group-10 object (seqId 1049) linked as the cage target */

#define DRCAGEWITH_OBJFLAG_FREED 0x40

int DR_CageWith_setScale(GameObject* obj)
{
    u8* state = obj->extra;
    return state[0x30];
}

int DR_CageWith_toggleRopeStateCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    char* state = obj->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            ((BitFlags8*)(state + 0x31))->b1 ^= 1;
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
    char* state = (obj)->extra;
    GameObject* linked = ((DrcagewithState*)state)->spawnedObject;
    if (linked != 0 && arg == 0 && linked->anim.modelInstance != 0)
    {
        char* child = *(char**)&((DrcagewithState*)state)->linkedObject;
        if (child != 0)
        {
            ((GameObject*)child)->unkF4 = 0;
        }
        ((DrcagewithState*)state)->spawnedObject->unkF4 = 0;
        Obj_FreeObject(((DrcagewithState*)state)->spawnedObject);
    }
    ObjGroup_RemoveObject((int)obj, DRCAGEWITH_OBJGROUP);
}

void DR_CageWith_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    char* state = (obj)->extra;
    int* linkedObj;
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E69F0);
        if (((DrcagewithState*)state)->spawnedObject != 0)
        {
            ObjPath_GetPointWorldPosition(obj, 0, &((DrcagewithState*)state)->spawnedObject->anim.localPosX,
                                          &((DrcagewithState*)state)->spawnedObject->anim.localPosY,
                                          &((DrcagewithState*)state)->spawnedObject->anim.localPosZ, 0);
            objRenderModelAndHitVolumes(((DrcagewithState*)state)->spawnedObject, p2, p3, p4, p5, (double)lbl_803E69F0);
            linkedObj = *(int**)&((DrcagewithState*)state)->linkedObject;
            if (linkedObj != 0)
            {
                ((GameObject*)linkedObj)->anim.rotY = ((DrcagewithState*)state)->spawnedObject->anim.rotY;
                ((GameObject*)linkedObj)->anim.rotZ = ((DrcagewithState*)state)->spawnedObject->anim.rotZ;
                ObjPath_GetPointWorldPosition(
                    ((DrcagewithState*)state)->spawnedObject, 0, &((GameObject*)linkedObj)->anim.localPosX,
                    &((GameObject*)linkedObj)->anim.localPosY, &((GameObject*)linkedObj)->anim.localPosZ, 0);
                objRenderModelAndHitVolumes(linkedObj, p2, p3, p4, p5, (double)lbl_803E69F0);
            }
        }
    }
}

void DR_CageWith_hitDetect(GameObject* obj)
{
    int* placement = *(int**)&(obj)->anim.placementData;
    u8* state;
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
    bf31 = (BitFlags8*)(state + 0x31);

    if (bf31->b1 != 0)
    {
        objParticleFn_80099d84((int)obj, lbl_803E69F8, 6, lbl_803E69F0, 0);
    }

    if ((obj)->anim.seqId == 2154 || (obj)->anim.seqId == 2155)
    {
        if (mainGetBit(GAMEBIT_DR_RescuedCloudRunner) != 0)
        {
            (obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        }
        return;
    }
    if (((DrcagewithState*)state)->spawnedObject == NULL)
    {
        if (Obj_IsLoadingLocked())
        {
            spawned = Obj_AllocObjectSetup(32, DRCAGEWITH_CHILD_OBJ);
            spawned->color[0] = 2;
            spawned->color[1] = 1;
            spawned->color[1] = (u8)(spawned->color[1] | (((DrcagewithPlacement*)placement)->flags & 0x18));
            ((GameObject*)spawned)->anim.rootMotionScale = (obj)->anim.localPosX;
            ((GameObject*)spawned)->anim.localPosX = (obj)->anim.localPosY;
            ((GameObject*)spawned)->anim.localPosY = (obj)->anim.localPosZ;
            spawned = (ObjPlacement*)Obj_SetupObject(spawned, 5, (obj)->anim.mapEventSlot, -1, (obj)->anim.parent);
            ((GameObject*)spawned)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ((GameObject*)spawned)->unkF4 = 1;
            ((DrcagewithState*)state)->spawnedObject = (GameObject*)spawned;
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
                ((DrcagewithState*)state)->linkedObject = 0;
            }
            return;
        }
        angVel = oneOverTimeDelta * ((obj)->anim.localPosX - (obj)->anim.previousLocalPosX);
        angVel = angVel * lbl_803E69FC;
        angVel = interpolate(angVel - ((DrcagewithState*)state)->angularVel, lbl_803E6A00, timeDelta);
        clamped =
            (angVel < gDrCageWithAngVelRateMin * timeDelta)
                ? gDrCageWithAngVelRateMin * timeDelta
                : ((angVel > gDrCageWithAngVelRateMax * timeDelta) ? gDrCageWithAngVelRateMax * timeDelta : angVel);
        ((DrcagewithState*)state)->angularVel = ((DrcagewithState*)state)->angularVel + clamped;
        for (i = 0, div = lbl_803E6A0C; i < 9; i++)
        {
            s16* jointVec = objModelGetVecFn_800395d8(obj, i);
            if (jointVec != NULL)
            {
                jointVec[2] = ((DrcagewithState*)state)->angularVel / div;
            }
        }
        if (((DrcagewithState*)state)->spawnedObject != NULL)
        {
            ((DrcagewithState*)state)->spawnedObject->anim.rotZ = (s16)((DrcagewithState*)state)->angularVel;
            nearest = (int*)ObjGroup_FindNearestObject(DRCAGEWITH_TARGET_OBJGROUP, (int)obj, &maxDist);
            if (nearest != NULL && ((GameObject*)nearest)->anim.seqId == 1049)
            {
                ((GameObject*)nearest)->unkF4 = 1;
                ((DrcagewithState*)state)->linkedObject = (int)nearest;
                ((GameObject*)nearest)->anim.rotZ = ((DrcagewithState*)state)->spawnedObject->anim.rotZ;
                ((DrcagewithState*)state)->spawnedObject->unkF4 = 1;
            }
            if (*(void**)&((DrcagewithState*)state)->linkedObject != NULL &&
                (((GameObject*)((DrcagewithState*)state)->linkedObject)->objectFlags & DRCAGEWITH_OBJFLAG_FREED) != 0)
            {
                ((DrcagewithState*)state)->linkedObject = 0;
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
                mainSetBits(((DrcagewithPlacement*)placement)->openedGameBit, 1);
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

void DR_CageWith_init(int obj, char* arg)
{
    char* state = ((GameObject*)obj)->extra;
    s16 type;
    f32 fz;
    ((GameObject*)obj)->animEventCallback = DR_CageWith_toggleRopeStateCallback;
    type = ((GameObject*)obj)->anim.seqId;
    if (type == 0x86a || type == 0x86b)
    {
        if (mainGetBit(GAMEBIT_DR_RescuedCloudRunner) == 0)
        {
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
    }
    else
    {
        ObjHits_EnableObject(obj);
        if (mainGetBit(((DrcagewithPlacement*)arg)->openedGameBit) != 0)
        {
            ObjHits_DisableObject(obj);
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ((BitFlags8*)(state + 0x31))->b0 = 1;
        }
        else
        {
            mainSetBits(0x7aa, 5);
        }
        ((GameObject*)obj)->anim.rotX = (s16)(((DrcagewithPlacement*)arg)->initRotXByte << 8);
        ((DrcagewithState*)state)->unk8 = (f32)((DrcagewithPlacement*)arg)->unk1C;
        ((DrcagewithState*)state)->unk10 = (f32)((DrcagewithPlacement*)arg)->unk1A / lbl_803E6A18;
        ((DrcagewithState*)state)->linkedObject = 0;
        fz = lbl_803E6A1C;
        ((DrcagewithState*)state)->unk14 = fz;
        ((DrcagewithState*)state)->unk18 = fz;
        ((DrcagewithState*)state)->unk1C = fz;
        ((DrcagewithState*)state)->unk20 = fz;
        ObjGroup_AddObject(obj, DRCAGEWITH_OBJGROUP);
    }
}

void DR_CageWith_release(void)
{
}

void DR_CageWith_initialise(void)
{
}
