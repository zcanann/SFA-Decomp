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

typedef struct DrshacklePlacement
{
    u8 pad0[0xC - 0x0];
    f32 posX;          /* 0x0C */
    f32 posY;          /* 0x10 */
    f32 posZ;          /* 0x14 */
    u8 pad18[0x19 - 0x18];
    s8 unk19;          /* 0x19: reported by drshackle_func0B */
    s16 pathObjGroupBase; /* 0x1A: base id of the path objects this chain binds */
    s16 quarterTurns;  /* 0x1C: rotZ in quarter turns; ==1 also selects two slots */
    s16 activeGameBit; /* 0x1E: game bit that keeps the chain active */
} DrshacklePlacement;


typedef struct DrshackleState
{
    s32 pathSlots[2];   /* 0x00: path-object pointer slots (one per slot) */
    f32 savedPosX;      /* 0x08 */
    f32 savedPosY;      /* 0x0C */
    f32 savedPosZ;      /* 0x10 */
    s32 slotCount;      /* 0x14: number of path slots (1 or 2) */
    u8 pad18[0x19 - 0x18];
    s8 unk19;           /* 0x19 */
    u8 pad1A[0x1B - 0x1A]; /* 0x1A: BitFlags8 active flag */
    u8 pathPointA;      /* 0x1B: path-point index of slot 0 */
    u8 pathPointB;      /* 0x1C: path-point index of slot 1 */
    u8 pad1D[0x20 - 0x1D];
} DrshackleState;

STATIC_ASSERT(offsetof(DrshacklePlacement, posX) == 0x0C);
STATIC_ASSERT(offsetof(DrshacklePlacement, unk19) == 0x19);
STATIC_ASSERT(offsetof(DrshacklePlacement, pathObjGroupBase) == 0x1A);
STATIC_ASSERT(offsetof(DrshacklePlacement, quarterTurns) == 0x1C);
STATIC_ASSERT(offsetof(DrshacklePlacement, activeGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DrshackleState, savedPosX) == 0x08);
STATIC_ASSERT(offsetof(DrshackleState, slotCount) == 0x14);
STATIC_ASSERT(offsetof(DrshackleState, pathPointA) == 0x1B);
STATIC_ASSERT(offsetof(DrshackleState, pathPointB) == 0x1C);
STATIC_ASSERT(sizeof(DrshackleState) == 0x20);


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
    int* model;
    int* modelData;
    int joint1;
    u8* p = ((GameObject*)obj)->extra;
    int* q = *(int**)&((GameObject*)obj)->anim.placementData;
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
    ((DrshackleState*)p)->savedPosX = ((GameObject*)obj)->anim.localPosX;
    ((DrshackleState*)p)->savedPosY = ((GameObject*)obj)->anim.localPosY;
    ((DrshackleState*)p)->savedPosZ = ((GameObject*)obj)->anim.localPosZ;

    {
        s8* jp = (s8*)(*(int*)(*(int*)((char*)a + 0x50) + 0x2c) + b * 24);
        jp += objAnim->bankIndex;
        joint1 = jp[0x12];
    }
    model = DrShackle_GetActiveModel((void*)a);
    modelData = *(int**)model;
    mdPtr = (char*)modelData + 0x3c;

    ((GameObject*)obj)->anim.rotZ = 0;
    ((GameObject*)obj)->anim.rotY = 0;
    ObjModel_CopyJointTranslation(model, joint1, jointPos);
    ObjModel_CopyJointTranslation(model, *(s8*)(*(int*)mdPtr + joint1 * 28),
                                  parentPos);
    PSVECSubtract(parentPos, jointPos, jointPos);

    if (((DrshacklePlacement*)q)->quarterTurns != 0)
    {
        ((GameObject*)obj)->anim.rotZ =
            (s16)(((placement = (DrshacklePlacement*)q)->quarterTurns << 14) + getAngle(jointPos[2], jointPos[0]));
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

    for (i = 0, a = (int)p; i < ((DrshackleState*)p)->slotCount; i++)
    {
        char* entry = *(char**)a;
        if (entry != NULL)
        {
            ObjPath_GetPointWorldPosition(obj, p[i + 0x1b], (f32*)(entry + 0xc),
                                          (f32*)(entry + 0x10), (f32*)(entry + 0x14), 0);
        }
        a += 4;
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
    ((BitFlags8*)(p + 0x1a))->b0 = (GameBit_Get(((DrshacklePlacement*)arg)->activeGameBit) == 0);
    ((DrshackleState*)p)->pathPointA = arg[0x18] % 2;
    ((GameObject*)obj)->animEventCallback = drshackle_toggleEventCallback;
    if (((DrshacklePlacement*)arg)->quarterTurns == 1)
    {
        ((DrshackleState*)p)->slotCount = 2;
        ((DrshackleState*)p)->pathPointB = 1 - ((DrshackleState*)p)->pathPointA;
    }
    else
    {
        ((DrshackleState*)p)->slotCount = 1;
    }
}

int drshackle_toggleEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    char* p = ((GameObject*)obj)->extra;
    void* q = *(void**)p;
    int i;
    if (q != 0)
    {
        ((DrshacklePlacement*)q)->posX = ((GameObject*)obj)->anim.localPosX;
        ((DrshacklePlacement*)q)->posY = ((GameObject*)obj)->anim.localPosY;
        ((DrshacklePlacement*)q)->posZ = ((GameObject*)obj)->anim.localPosZ;
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

void drshackle_render(int obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    int* ptr;
    u8* p = ((GameObject*)obj)->extra;
    int i;
    if (((BitFlags8*)(p + 0x1a))->b0 == 0 && visible != 0)
    {
        objRenderFn_8003b8f4((void*)obj, p2, p3, p4, p5, (double)lbl_803E6A2C);
        for (i = 0; i < ((DrshackleState*)p)->slotCount; i++)
        {
            int* entry = ((int**)p)[i];
            if (entry != 0)
            {
                ObjPath_GetPointWorldPosition(obj, p[i + 0x1b], (f32*)((char*)entry + 0xc),
                                              (f32*)((char*)entry + 0x10), (f32*)((char*)entry + 0x14), 0);
            }
        }
    }
}

void drshackle_update(int obj)
{
    char* p = ((GameObject*)obj)->extra;
    int q = *(int*)&((GameObject*)obj)->anim.placementData;
    int count;
    int sub;
    int j;
    int* list;
    if (((DrshacklePlacement*)q)->pathObjGroupBase != 0 && *(void**)p == 0)
    {
        list = ObjGroup_GetObjects(0x17, &count);
        while (count-- != 0)
        {
            sub = *(int*)(*list + 0x4c);
            for (j = 0; j < ((DrshackleState*)p)->slotCount; j++)
            {
                if (*(u8*)(sub + 0x18) == ((DrshacklePlacement*)q)->pathObjGroupBase + j * 4)
                {
                    ((DrshackleState*)p)->pathSlots[j] = *list;
                    (*gObjectTriggerInterface)
                        ->runSequence(0, (void*)((DrshackleState*)p)->pathSlots[j], -1);
                }
            }
            list++;
        }
    }
    if (((BitFlags8*)(p + 0x1a))->b0 != 0)
    {
        ((BitFlags8*)(p + 0x1a))->b0 = (GameBit_Get(((DrshacklePlacement*)q)->activeGameBit) == 0);
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
