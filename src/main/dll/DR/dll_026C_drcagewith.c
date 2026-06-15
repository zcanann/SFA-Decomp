#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

typedef struct DrcagewithPlacement
{
    u8 pad0[0x5 - 0x0];
    u8 unk5;
    u8 pad6[0x1E - 0x6];
    s16 unk1E;
} DrcagewithPlacement;


typedef struct DrcagewithState
{
    u8 pad0[0x4 - 0x0];
    s32 unk4;
    f32 unk8;
    u8 padC[0x10 - 0xC];
    f32 unk10;
    f32 unk14;
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    f32 unk24;
    u8 pad28[0x34 - 0x28];
} DrcagewithState;


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
    int* q = *(int**)&((GameObject*)obj)->anim.placementData;
    u8* p;
    BitFlags8* bf31;
    f32 maxDist;
    int i;
    int spawned;
    int* nearest;
    f32 v;
    f32 clamped;
    f32 px;
    f32 div;

    maxDist = lbl_803E69F4;
    p = ((GameObject*)obj)->extra;
    bf31 = (BitFlags8*)(p + 0x31);

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
    if (*(void**)p == NULL)
    {
        if (Obj_IsLoadingLocked())
        {
            spawned = Obj_AllocObjectSetup(32, 1143);
            *(u8*)(spawned + 4) = 2;
            *(u8*)(spawned + 5) = 1;
            *(u8*)(spawned + 5) = (u8)(*(u8*)(spawned + 5) | (((DrcagewithPlacement*)q)->unk5 & 0x18));
            ((GameObject*)spawned)->anim.rootMotionScale = ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)spawned)->anim.localPosX = ((GameObject*)obj)->anim.localPosY;
            ((GameObject*)spawned)->anim.localPosY = ((GameObject*)obj)->anim.localPosZ;
            spawned = Obj_SetupObject(spawned, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                      *(int*)&((GameObject*)obj)->anim.parent);
            ((GameObject*)spawned)->anim.flags |= 0x4000;
            ((GameObject*)spawned)->unkF4 = 1;
            *(int*)p = spawned;
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
                ((DrcagewithState*)p)->unk4 = 0;
            }
            return;
        }
        v = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX);
        v = v * lbl_803E69FC;
        v = interpolate(v - ((DrcagewithState*)p)->unk24, lbl_803E6A00, timeDelta);
        clamped = (v < lbl_803E6A04 * timeDelta)
                      ? lbl_803E6A04 * timeDelta
                      : ((v > lbl_803E6A08 * timeDelta) ? lbl_803E6A08 * timeDelta : v);
        ((DrcagewithState*)p)->unk24 = ((DrcagewithState*)p)->unk24 + clamped;
        for (i = 0, div = lbl_803E6A0C; i < 9; i++)
        {
            nearest = objModelGetVecFn_800395d8(obj, i);
            if (nearest != NULL)
            {
                ((GameObject*)nearest)->anim.rotZ = ((DrcagewithState*)p)->unk24 / div;
            }
        }
        if (*(void**)p != NULL)
        {
            *(s16*)(*(int*)p + 4) = (s16)((DrcagewithState*)p)->unk24;
            nearest = (int*)ObjGroup_FindNearestObject(10, obj, &maxDist);
            if (nearest != NULL && ((GameObject*)nearest)->anim.seqId == 1049)
            {
                ((GameObject*)nearest)->unkF4 = 1;
                ((DrcagewithState*)p)->unk4 = (int)nearest;
                ((GameObject*)nearest)->anim.rotZ = *(s16*)(*(int*)p + 4);
                *(int*)(*(int*)p + 0xf4) = 1;
            }
            if (*(void**)&((DrcagewithState*)p)->unk4 != NULL &&
                (((GameObject*)((DrcagewithState*)p)->unk4)->objectFlags & 0x40) != 0)
            {
                ((DrcagewithState*)p)->unk4 = 0;
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
                GameBit_Set(((DrcagewithPlacement*)q)->unk1E, 1);
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
    u8* p = ((GameObject*)obj)->extra;
    return p[0x30];
}

void drcagewith_free(int obj, int arg)
{
    char* p = ((GameObject*)obj)->extra;
    char* x = *(char**)p;
    if (x != 0 && arg == 0 && *(void**)(x + 0x50) != 0)
    {
        char* y = *(char**)&((DrcagewithState*)p)->unk4;
        if (y != 0)
        {
            *(int*)(y + 0xf4) = 0;
        }
        *(int*)(*(char**)p + 0xf4) = 0;
        Obj_FreeObject(*(int*)p);
    }
    ObjGroup_RemoveObject(obj, 0x18);
}

int drcagewith_toggleRopeStateCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    char* p = ((GameObject*)obj)->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            ((BitFlags8*)(p + 0x31))->b1 ^= 1;
        }
    }
    return 0;
}

void drcagewith_render(void* obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible)
{
    char* p = ((GameObject*)obj)->extra;
    int* b;
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E69F0);
        if (*(int**)p != 0)
        {
            ObjPath_GetPointWorldPosition((int)obj, 0, (f32*)(*(int*)p + 0xc), (f32*)(*(int*)p + 0x10),
                                          (f32*)(*(int*)p + 0x14), 0);
            objRenderFn_8003b8f4(*(void**)p, p2, p3, p4, p5, (double)lbl_803E69F0);
            b = *(int**)&((DrcagewithState*)p)->unk4;
            if (b != 0)
            {
                *(s16*)((char*)b + 0x2) = *(s16*)(*(int*)p + 0x2);
                *(s16*)((char*)b + 0x4) = *(s16*)(*(int*)p + 0x4);
                ObjPath_GetPointWorldPosition(*(int*)p, 0, (f32*)((char*)b + 0xc), (f32*)((char*)b + 0x10),
                                              (f32*)((char*)b + 0x14), 0);
                objRenderFn_8003b8f4(b, p2, p3, p4, p5, (double)lbl_803E69F0);
            }
        }
    }
}

void drcagewith_init(int obj, char* arg)
{
    char* p = ((GameObject*)obj)->extra;
    s16 type;
    f32 fz;
    ((GameObject*)obj)->animEventCallback = (void*)drcagewith_toggleRopeStateCallback;
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
        if (GameBit_Get(*(s16*)(arg + 0x1e)) != 0)
        {
            ObjHits_DisableObject(obj);
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ((BitFlags8*)(p + 0x31))->b0 = 1;
        }
        else
        {
            GameBit_Set(0x7aa, 5);
        }
        *(s16*)obj = (s16)((s8)arg[0x18] << 8);
        ((DrcagewithState*)p)->unk8 = (f32) * (s16*)(arg + 0x1c);
        ((DrcagewithState*)p)->unk10 = (f32) * (s16*)(arg + 0x1a) / lbl_803E6A18;
        ((DrcagewithState*)p)->unk4 = 0;
        fz = lbl_803E6A1C;
        ((DrcagewithState*)p)->unk14 = fz;
        ((DrcagewithState*)p)->unk18 = fz;
        ((DrcagewithState*)p)->unk1C = fz;
        ((DrcagewithState*)p)->unk20 = fz;
        ObjGroup_AddObject(obj, 0x18);
    }
}
