/*
 * drcagewith (DLL 0x26C) - a hanging cage with a winch rope. On first
 * hit it spawns its linked rope/winch object and, while unlocked,
 * integrates a damped angular velocity (angularVel) from the object's
 * horizontal motion, driving the rope segments' rotZ and the linked
 * object. The placement supplies setup flags (unk5) and the game bit
 * that marks the cage already opened (openedGameBit).
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

#define DRCAGEWITH_OBJFLAG_FREED 0x40

typedef struct DrcagewithPlacement
{
    u8 pad0[0x5 - 0x0];
    u8 flags; /* 0x5: low flag bits copied into spawned object (mask 0x18) */
    u8 pad6[0x18 - 0x6];
    s8 initRotXByte; /* 0x18: signed byte, <<8 into anim.rotX at init */
    u8 pad19[0x1A - 0x19];
    s16 unk1A; /* 0x1A: int->float setup value (unk10) */
    s16 unk1C; /* 0x1C: int->float setup value (unk8) */
    s16 openedGameBit; /* 0x1E: game bit set when this cage is opened */
} DrcagewithPlacement;


typedef struct DrcagewithState
{
    GameObject* spawnedObject; /* 0x0: spawned rope/winch object */
    s32 linkedObject; /* 0x4: linked rope object, freed via Obj_FreeObject */
    f32 unk8;
    u8 padC[0x10 - 0xC];
    f32 unk10;
    f32 unk14;
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    f32 angularVel;   /* 0x24: damped angular velocity */
    u8 pad28[0x34 - 0x28];
} DrcagewithState;

STATIC_ASSERT(offsetof(DrcagewithPlacement, flags) == 0x5);
STATIC_ASSERT(offsetof(DrcagewithPlacement, initRotXByte) == 0x18);
STATIC_ASSERT(offsetof(DrcagewithPlacement, unk1A) == 0x1A);
STATIC_ASSERT(offsetof(DrcagewithPlacement, unk1C) == 0x1C);
STATIC_ASSERT(offsetof(DrcagewithPlacement, openedGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DrcagewithState, spawnedObject) == 0x0);
STATIC_ASSERT(offsetof(DrcagewithState, linkedObject) == 0x4);
STATIC_ASSERT(offsetof(DrcagewithState, angularVel) == 0x24);
STATIC_ASSERT(sizeof(DrcagewithState) == 0x34);


int drcagewith_getExtraSize(void) { return 0x34; }

int drcagewith_getObjectTypeId(void) { return 0x0; }

void drcagewith_initialise(void)
{
}

void drcagewith_release(void)
{
}

void drcagewith_update(void)
{
}

void drcagewith_hitDetect(int obj)
{
    int* placement = *(int**)&((GameObject*)obj)->anim.placementData;
    u8* state;
    BitFlags8* bf31;
    f32 maxDist;
    int i;
    int spawned;
    int* nearest;
    f32 v;
    f32 clamped;
    f32 px;
    f32 div;

    maxDist = gDrCageWithFindObjMaxDist;
    state = ((GameObject*)obj)->extra;
    bf31 = (BitFlags8*)(state + 0x31);

    if (bf31->b1 != 0)
    {
        objParticleFn_80099d84(obj, lbl_803E69F8, 6, lbl_803E69F0, 0);
    }

    if (((GameObject*)obj)->anim.seqId == 2154 || ((GameObject*)obj)->anim.seqId == 2155)
    {
        if (GameBit_Get(1545) != 0)
        {
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        }
        return;
    }
    if (((DrcagewithState*)state)->spawnedObject == NULL)
    {
        if (Obj_IsLoadingLocked())
        {
            spawned = Obj_AllocObjectSetup(32, 1143);
            *(u8*)(spawned + 4) = 2;
            *(u8*)(spawned + 5) = 1;
            *(u8*)(spawned + 5) = (u8)(*(u8*)(spawned + 5) | (((DrcagewithPlacement*)placement)->flags & 0x18));
            ((GameObject*)spawned)->anim.rootMotionScale = ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)spawned)->anim.localPosX = ((GameObject*)obj)->anim.localPosY;
            ((GameObject*)spawned)->anim.localPosY = ((GameObject*)obj)->anim.localPosZ;
            spawned = Obj_SetupObject(spawned, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                      *(int*)&((GameObject*)obj)->anim.parent);
            ((GameObject*)spawned)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ((GameObject*)spawned)->unkF4 = 1;
            ((DrcagewithState*)state)->spawnedObject = (GameObject*)spawned;
            return;
        }
    }
    if (bf31->b0 == 0)
    {
        if (GameBit_Get(1545) != 0)
        {
            ObjHits_DisableObject(obj);
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            bf31->b0 = 1;
            nearest = (int*)ObjGroup_FindNearestObject(10, obj, &maxDist);
            if (nearest != NULL && ((GameObject*)nearest)->anim.seqId == 1049)
            {
                ((GameObject*)nearest)->unkF4 = 0;
                ((DrcagewithState*)state)->linkedObject = 0;
            }
            return;
        }
        v = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX);
        v = v * lbl_803E69FC;
        v = interpolate(v - ((DrcagewithState*)state)->angularVel, lbl_803E6A00, timeDelta);
        clamped = (v < gDrCageWithAngVelRateMin * timeDelta)
                      ? gDrCageWithAngVelRateMin * timeDelta
                      : ((v > gDrCageWithAngVelRateMax * timeDelta) ? gDrCageWithAngVelRateMax * timeDelta : v);
        ((DrcagewithState*)state)->angularVel = ((DrcagewithState*)state)->angularVel + clamped;
        for (i = 0, div = lbl_803E6A0C; i < 9; i++)
        {
            nearest = objModelGetVecFn_800395d8(obj, i);
            if (nearest != NULL)
            {
                ((GameObject*)nearest)->anim.rotZ = ((DrcagewithState*)state)->angularVel / div;
            }
        }
        if (((DrcagewithState*)state)->spawnedObject != NULL)
        {
            ((DrcagewithState*)state)->spawnedObject->anim.rotZ = (s16)((DrcagewithState*)state)->angularVel;
            nearest = (int*)ObjGroup_FindNearestObject(10, obj, &maxDist);
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
        if (GameBit_Get(3175) != 0)
        {
            px = ((GameObject*)obj)->anim.localPosX;
            if (px >= lbl_803E6A10 && px <= lbl_803E6A14)
            {
                GameBit_Set(((DrcagewithPlacement*)placement)->openedGameBit, 1);
            }
            else
            {
                GameBit_Set(3748, 1);
            }
        }
        else
        {
            GameBit_Set(3748, 0);
        }
    }
}

int drcagewith_setScale(int obj)
{
    u8* state = ((GameObject*)obj)->extra;
    return state[0x30];
}

void drcagewith_free(int obj, int arg)
{
    char* state = ((GameObject*)obj)->extra;
    GameObject* linked = ((DrcagewithState*)state)->spawnedObject;
    if (linked != 0 && arg == 0 && linked->anim.modelInstance != 0)
    {
        char* child = *(char**)&((DrcagewithState*)state)->linkedObject;
        if (child != 0)
        {
            ((GameObject*)child)->unkF4 = 0;
        }
        ((DrcagewithState*)state)->spawnedObject->unkF4 = 0;
        Obj_FreeObject((int)((DrcagewithState*)state)->spawnedObject);
    }
    ObjGroup_RemoveObject(obj, 0x18);
}

int drcagewith_toggleRopeStateCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    char* state = ((GameObject*)obj)->extra;
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

void drcagewith_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    char* state = ((GameObject*)obj)->extra;
    int* linkedObj;
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E69F0);
        if (((DrcagewithState*)state)->spawnedObject != 0)
        {
            ObjPath_GetPointWorldPosition((int)obj, 0, &((DrcagewithState*)state)->spawnedObject->anim.localPosX,
                                          &((DrcagewithState*)state)->spawnedObject->anim.localPosY,
                                          &((DrcagewithState*)state)->spawnedObject->anim.localPosZ, 0);
            objRenderFn_8003b8f4(((DrcagewithState*)state)->spawnedObject, p2, p3, p4, p5, (double)lbl_803E69F0);
            linkedObj = *(int**)&((DrcagewithState*)state)->linkedObject;
            if (linkedObj != 0)
            {
                ((GameObject*)linkedObj)->anim.rotY = ((DrcagewithState*)state)->spawnedObject->anim.rotY;
                ((GameObject*)linkedObj)->anim.rotZ = ((DrcagewithState*)state)->spawnedObject->anim.rotZ;
                ObjPath_GetPointWorldPosition((int)((DrcagewithState*)state)->spawnedObject, 0,
                                              &((GameObject*)linkedObj)->anim.localPosX,
                                              &((GameObject*)linkedObj)->anim.localPosY,
                                              &((GameObject*)linkedObj)->anim.localPosZ, 0);
                objRenderFn_8003b8f4(linkedObj, p2, p3, p4, p5, (double)lbl_803E69F0);
            }
        }
    }
}

void drcagewith_init(int obj, char* arg)
{
    char* state = ((GameObject*)obj)->extra;
    s16 type;
    f32 fz;
    ((GameObject*)obj)->animEventCallback = drcagewith_toggleRopeStateCallback;
    type = ((GameObject*)obj)->anim.seqId;
    if (type == 0x86a || type == 0x86b)
    {
        if (GameBit_Get(0x609) == 0)
        {
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
    }
    else
    {
        ObjHits_EnableObject(obj);
        if (GameBit_Get(((DrcagewithPlacement*)arg)->openedGameBit) != 0)
        {
            ObjHits_DisableObject(obj);
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ((BitFlags8*)(state + 0x31))->b0 = 1;
        }
        else
        {
            GameBit_Set(0x7aa, 5);
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
        ObjGroup_AddObject(obj, 0x18);
    }
}
