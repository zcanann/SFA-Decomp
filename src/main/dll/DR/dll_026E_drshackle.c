/*
 * drshackle (DLL 0x26E) - the swinging chain/shackle that hangs from a
 * path point. drshackle_setScale orients the chain along the segment
 * between two model joints, drshackle_update binds the per-slot path
 * objects (ObjGroup 0x17) the chain rides, and drshackle_hitDetect plays
 * a distance-scaled footstep-style rattle when active.
 *
 * The 0x1A flag byte is a BitFlags8 whose b0 = "active" (chain visible
 * and rattling); the matching attachment logic lives in the separate
 * drshackle.c build unit (DRshackle.h).
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

#include "main/dll/DR/dll_026E_drshackle.h"

#define DRSHACKLE_OBJGROUP  0x37
#define DFROPENODE_OBJGROUP 0x17 /* DLL 0x175 dfropenode (path nodes) */

static inline int* DrShackle_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

int drshackle_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    char* state = obj->extra;
    void* placement = *(void**)state;
    int i;
    if (placement != 0)
    {
        ((DrshacklePlacement*)placement)->posX = obj->anim.localPosX;
        ((DrshacklePlacement*)placement)->posY = obj->anim.localPosY;
        ((DrshacklePlacement*)placement)->posZ = obj->anim.localPosZ;
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            ((BitFlags8*)(state + 0x1a))->b0 = 0;
            break;
        case 2:
            ((BitFlags8*)(state + 0x1a))->b0 = 1;
            break;
        }
    }
    return 0;
}

int drshackle_func0B(GameObject* obj)
{
    int placement = *(int*)&obj->anim.placementData;
    return ((DrshacklePlacement*)placement)->unk19;
}

int drshackle_setScale(GameObject* obj, int a, int b, int c, int d, int e, int f)
{
    int* model;
    int* modelData;
    int joint1;
    u8* p = obj->extra;
    int* q = *(int**)&obj->anim.placementData;
    f32 jointPos[3];
    f32 parentPos[3];
    char* mdPtr;
    int i;
    BitFlags8* bf = (BitFlags8*)(p + 0x1a);
    DrshacklePlacement* placement;
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;

    if (bf->b0 == 0)
    {
        return 1;
    }
    ((DrshackleState*)p)->savedPosX = obj->anim.localPosX;
    ((DrshackleState*)p)->savedPosY = obj->anim.localPosY;
    ((DrshackleState*)p)->savedPosZ = obj->anim.localPosZ;

    {
        s8* jp = (s8*)(*(int*)(*(int*)((char*)a + 0x50) + 0x2c) + b * 24);
        jp += objAnim->bankIndex;
        joint1 = jp[0x12];
    }
    model = DrShackle_GetActiveModel((void*)a);
    modelData = *(int**)model;
    mdPtr = (char*)modelData + 0x3c;

    obj->anim.rotZ = 0;
    obj->anim.rotY = 0;
    ObjModel_CopyJointTranslation(model, joint1, jointPos);
    ObjModel_CopyJointTranslation(model, *(s8*)(*(int*)mdPtr + joint1 * 28), parentPos);
    PSVECSubtract(parentPos, jointPos, jointPos);

    if (((DrshacklePlacement*)q)->quarterTurns != 0)
    {
        obj->anim.rotZ =
            (s16)(((placement = (DrshacklePlacement*)q)->quarterTurns << 14) + getAngle(jointPos[2], jointPos[0]));
        obj->anim.rotY = (s16)getAngle(jointPos[2], jointPos[1]);
    }
    else
    {
        f32 savedY = jointPos[1];
        f32 mag;
        jointPos[1] = lbl_803E6A28;
        mag = PSVECMag(jointPos);
        obj->anim.rotZ = (s16)(lbl_803DC2F0 + getAngle(jointPos[0], jointPos[2]));
        obj->anim.rotY = (s16)(lbl_803DDD70 + getAngle(mag, savedY));
        objSetMtxFn_800412d4(ObjPath_GetPointModelMtx(a, b));
    }
    ObjPath_GetPointWorldPosition(a, b, (f32*)((char*)obj + 0xc), (f32*)((char*)obj + 0x10), (f32*)((char*)obj + 0x14),
                                  0);
    objRenderModelAndHitVolumes((void*)obj, c, d, e, f, (double)lbl_803E6A2C);

    for (i = 0, a = (int)p; i < ((DrshackleState*)p)->slotCount; i++)
    {
        char* entry = *(char**)a;
        if (entry != NULL)
        {
            ((void (*)(void*, int, f32*, f32*, f32*, int))ObjPath_GetPointWorldPosition)(
                obj, p[i + 0x1b], (f32*)(entry + 0xc), (f32*)(entry + 0x10), (f32*)(entry + 0x14), 0);
        }
        a += 4;
    }
    return 0;
}

int drshackle_getExtraSize(void)
{
    return 0x20;
}

int drshackle_getObjectTypeId(void)
{
    return 0x0;
}

void drshackle_free(int obj)
{
    ObjGroup_RemoveObject(obj, DRSHACKLE_OBJGROUP);
}

void drshackle_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    int* ptr;
    u8* state = obj->extra;
    int i;
    if (((BitFlags8*)(state + 0x1a))->b0 == 0 && visible != 0)
    {
        objRenderModelAndHitVolumes((void*)obj, p2, p3, p4, p5, (double)lbl_803E6A2C);
        for (i = 0; i < ((DrshackleState*)state)->slotCount; i++)
        {
            int* entry = ((int**)state)[i];
            if (entry != 0)
            {
                ((void (*)(void*, int, f32*, f32*, f32*, int))ObjPath_GetPointWorldPosition)(
                    obj, state[i + 0x1b], (f32*)((char*)entry + 0xc), (f32*)((char*)entry + 0x10),
                    (f32*)((char*)entry + 0x14), 0);
            }
        }
    }
}

void drshackle_hitDetect(unsigned long obj)
{
    char* state = ((GameObject*)obj)->extra;
    if (Sfx_IsPlayingFromObjectChannel(obj, 1) == 0 && ((BitFlags8*)(state + 0x1a))->b0 != 0)
    {
        f32 vec[3];
        int n;
        PSVECSubtract(&((GameObject*)obj)->anim.localPosX, &((DrshackleState*)state)->savedPosX, vec);
        n = 0xc8 - (int)(lbl_803E6A30 * PSVECMag(vec));
        if ((int)randomGetRange(0, (n < 1) ? 1 : ((n > 0xc8) ? 0xc8 : n)) == 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_1b3);
        }
    }
}

void drshackle_update(GameObject* obj)
{
    char* state = obj->extra;
    int placement = *(int*)&obj->anim.placementData;
    int count;
    int sub;
    int j;
    int* list;
    if (((DrshacklePlacement*)placement)->pathObjGroupBase != 0 && *(void**)state == 0)
    {
        list = ObjGroup_GetObjects(DFROPENODE_OBJGROUP, &count);
        while (count-- != 0)
        {
            sub = *(int*)(*list + 0x4c);
            for (j = 0; j < ((DrshackleState*)state)->slotCount; j++)
            {
                if (*(u8*)(sub + 0x18) == ((DrshacklePlacement*)placement)->pathObjGroupBase + j * 4)
                {
                    ((DrshackleState*)state)->pathSlots[j] = *list;
                    (*gObjectTriggerInterface)->runSequence(0, (void*)((DrshackleState*)state)->pathSlots[j], -1);
                }
            }
            list++;
        }
    }
    if (((BitFlags8*)(state + 0x1a))->b0 != 0)
    {
        ((BitFlags8*)(state + 0x1a))->b0 = (mainGetBit(((DrshacklePlacement*)placement)->activeGameBit) == 0);
    }
}

void drshackle_init(GameObject* obj, char* arg)
{
    char* state = (obj)->extra;
    ObjGroup_AddObject((int)obj, DRSHACKLE_OBJGROUP);
    ((BitFlags8*)(state + 0x1a))->b0 = (mainGetBit(((DrshacklePlacement*)arg)->activeGameBit) == 0);
    ((DrshackleState*)state)->pathPointA = arg[0x18] % 2;
    (obj)->animEventCallback = drshackle_SeqFn;
    if (((DrshacklePlacement*)arg)->quarterTurns == 1)
    {
        ((DrshackleState*)state)->slotCount = 2;
        ((DrshackleState*)state)->pathPointB = 1 - ((DrshackleState*)state)->pathPointA;
    }
    else
    {
        ((DrshackleState*)state)->slotCount = 1;
    }
}

void drshackle_release(void)
{
}

void drshackle_initialise(void)
{
}
