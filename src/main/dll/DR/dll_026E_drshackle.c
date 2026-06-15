#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"

typedef struct DrshacklePlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
    f32 unk10;
    f32 unk14;
    u8 pad18[0x19 - 0x18];
    s8 unk19;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
} DrshacklePlacement;


typedef struct DrshackleState
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    s32 unk14;
    u8 pad18[0x19 - 0x18];
    s8 unk19;
    u8 pad1A[0x1B - 0x1A];
    u8 unk1B;
    u8 unk1C;
    u8 pad1D[0x20 - 0x1D];
} DrshackleState;


static inline int* DrShackle_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

int drshackle_getExtraSize(void) { return 0x20; }

int drshackle_getObjectTypeId(void) { return 0x0; }

void drshackle_release(void)
{
}

void drshackle_initialise(void)
{
}

int drshackle_setScale(int obj, int a, int b, int c, int d, int e, int f)
{
    u8* p = ((GameObject*)obj)->extra;
    int* q = *(int**)&((GameObject*)obj)->anim.placementData;
    int* model;
    int* modelData;
    int joint1;
    f32 jointPos[3];
    f32 parentPos[3];
    int i;
    int* ptr;
    BitFlags8* bf = (BitFlags8*)(p + 0x1a);
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;

    if (bf->b0 == 0)
    {
        return 1;
    }
    ((DrshackleState*)p)->unk8 = ((GameObject*)obj)->anim.localPosX;
    ((DrshackleState*)p)->unkC = ((GameObject*)obj)->anim.localPosY;
    ((DrshackleState*)p)->unk10 = ((GameObject*)obj)->anim.localPosZ;

    joint1 = *(s8*)(*(int*)(*(int*)((char*)a + 0x50) + 0x2c) + b * 24 + objAnim->bankIndex + 0x12);
    model = DrShackle_GetActiveModel((void*)a);
    modelData = *(int**)model;

    ((GameObject*)obj)->anim.rotZ = 0;
    ((GameObject*)obj)->anim.rotY = 0;
    ObjModel_CopyJointTranslation(model, joint1, jointPos);
    ObjModel_CopyJointTranslation(model, *(s8*)(*(int*)((char*)modelData + 0x3c) + joint1 * 28),
                                  parentPos);
    PSVECSubtract(parentPos, jointPos, jointPos);

    if (((DrshacklePlacement*)q)->unk1C != 0)
    {
        ((GameObject*)obj)->anim.rotZ =
            (s16)((((DrshacklePlacement*)q)->unk1C << 14) + getAngle(jointPos[2], jointPos[0]));
        ((GameObject*)obj)->anim.rotY = (s16)getAngle(jointPos[2], jointPos[1]);
    }
    else
    {
        f32 savedY = jointPos[1];
        f32 mag;
        jointPos[1] = lbl_803E6A28;
        mag = PSVECMag(jointPos);
        ((GameObject*)obj)->anim.rotZ = (s16)(lbl_803DC2F0 + getAngle(jointPos[0], jointPos[2]));
        ((GameObject*)obj)->anim.rotY = (s16)(lbl_803DDD70 + getAngle(mag, savedY));
        objSetMtxFn_800412d4(ObjPath_GetPointModelMtx(a, b));
    }
    ObjPath_GetPointWorldPosition(a, b, (f32*)((char*)obj + 0xc), (f32*)((char*)obj + 0x10),
                                  (f32*)((char*)obj + 0x14), 0);
    objRenderFn_8003b8f4((void*)obj, c, d, e, f, (double)lbl_803E6A2C);

    ptr = (int*)p;
    for (i = 0; i < ((DrshackleState*)p)->unk14; i++)
    {
        char* entry = *(char**)ptr;
        if (entry != NULL)
        {
            ObjPath_GetPointWorldPosition(obj, p[i + 0x1b], (f32*)(entry + 0xc),
                                          (f32*)(entry + 0x10), (f32*)(entry + 0x14), 0);
        }
        ptr++;
    }
    return 0;
}

int drshackle_func0B(int obj)
{
    int p = *(int*)&((GameObject*)obj)->anim.placementData;
    return ((DrshacklePlacement*)p)->unk19;
}

void drshackle_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0x37);
}

void drshackle_init(int obj, char* arg)
{
    char* p = ((GameObject*)obj)->extra;
    ObjGroup_AddObject(obj, 0x37);
    ((BitFlags8*)(p + 0x1a))->b0 = (GameBit_Get(*(s16*)(arg + 0x1e)) == 0);
    ((DrshackleState*)p)->unk1B = (s8)arg[0x18] % 2;
    ((GameObject*)obj)->animEventCallback = (void*)drshackle_toggleEventCallback;
    if (*(s16*)(arg + 0x1c) == 1)
    {
        ((DrshackleState*)p)->unk14 = 2;
        ((DrshackleState*)p)->unk1C = 1 - ((DrshackleState*)p)->unk1B;
    }
    else
    {
        ((DrshackleState*)p)->unk14 = 1;
    }
}

int drshackle_toggleEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    char* p = ((GameObject*)obj)->extra;
    void* q = *(void**)p;
    int i;
    if (q != 0)
    {
        *(f32*)((char*)q + 0xc) = ((GameObject*)obj)->anim.localPosX;
        *(f32*)((char*)q + 0x10) = ((GameObject*)obj)->anim.localPosY;
        *(f32*)((char*)q + 0x14) = ((GameObject*)obj)->anim.localPosZ;
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            ((BitFlags8*)(p + 0x1a))->b0 = 0;
            break;
        case 2:
            ((BitFlags8*)(p + 0x1a))->b0 = 1;
            break;
        }
    }
    return 0;
}

void drshackle_render(int obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible)
{
    u8* p = ((GameObject*)obj)->extra;
    int* ptr;
    int i;
    if (((BitFlags8*)(p + 0x1a))->b0 == 0 && visible != 0)
    {
        objRenderFn_8003b8f4((void*)obj, p2, p3, p4, p5, (double)lbl_803E6A2C);
        for (i = 0, ptr = (int*)p; i < ((DrshackleState*)p)->unk14; i++)
        {
            int* entry = *(int**)ptr;
            if (entry != 0)
            {
                ObjPath_GetPointWorldPosition(obj, p[i + 0x1b], (f32*)((char*)entry + 0xc),
                                              (f32*)((char*)entry + 0x10), (f32*)((char*)entry + 0x14), 0);
            }
            ptr++;
        }
    }
}

void drshackle_update(int obj)
{
    char* p = ((GameObject*)obj)->extra;
    int q = *(int*)&((GameObject*)obj)->anim.placementData;
    int count;
    int* list;
    int j;
    if (((DrshacklePlacement*)q)->unk1A != 0 && *(void**)p == 0)
    {
        list = ObjGroup_GetObjects(0x17, &count);
        while (count-- != 0)
        {
            int sub = *(int*)(*list + 0x4c);
            for (j = 0; j < ((DrshackleState*)p)->unk14; j++)
            {
                if (*(u8*)(sub + 0x18) == ((DrshacklePlacement*)q)->unk1A + j * 4)
                {
                    *(int*)(p + j * 4) = *list;
                    (*gObjectTriggerInterface)
                        ->runSequence(0, (void*)*(int*)(p + j * 4), -1);
                }
            }
            list++;
        }
    }
    if (((BitFlags8*)(p + 0x1a))->b0 != 0)
    {
        ((BitFlags8*)(p + 0x1a))->b0 = (GameBit_Get(((DrshacklePlacement*)q)->unk1E) == 0);
    }
}

void drshackle_hitDetect(int obj)
{
    char* p = ((GameObject*)obj)->extra;
    if (Sfx_IsPlayingFromObjectChannel(obj, 1) == 0 && ((BitFlags8*)(p + 0x1a))->b0 != 0)
    {
        f32 vec[3];
        int n;
        PSVECSubtract(&((GameObject*)obj)->anim.localPosX, (f32*)(p + 0x8), vec);
        n = 0xc8 - (int)(lbl_803E6A30 * PSVECMag(vec));
        if ((int)randomGetRange(0, (n < 1) ? 1 : ((n > 0xc8) ? 0xc8 : n)) == 0)
        {
            Sfx_PlayFromObject(obj, SFXfoot_stone_run_1);
        }
    }
}
