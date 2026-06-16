#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

typedef struct AndrosslighSetStateState
{
    u8 pad0[0xC - 0x0];
    s8 unkC;
    u8 padD[0x10 - 0xD];
} AndrosslighSetStateState;


typedef struct AndrosslighState
{
    u8 pad0[0xC - 0x0];
    s8 unkC;
    u8 unkD;
    u8 padE[0x10 - 0xE];
} AndrosslighState;


int androssligh_getExtraSize(void) { return 0x10; }

int androssligh_getObjectTypeId(void) { return 0; }

void androssligh_free(void)
{
}

void androssligh_render(int obj)
{
    void* p = *(void**)(*(int*)&((GameObject*)obj)->extra + 4);

    if (p != NULL)
    {
        lightningRender(p);
    }
}

void androssligh_setState(int obj, int newState, u8 force)
{
    int state;

    if ((void*)obj == NULL)
    {
        return;
    }
    state = *(int*)&((GameObject*)obj)->extra;
    if (((AndrosslighSetStateState*)state)->unkC == 2)
    {
        if (force == 0)
        {
            return;
        }
    }
    ((AndrosslighSetStateState*)state)->unkC = (s8)newState;
}

void androssligh_hitDetect(void)
{
}

void androssligh_init(void)
{
}

void androssligh_update(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;

    if (*(void**)state == NULL)
    {
        *(int*)state = ObjList_FindObjectById(0x47dd9);
    }
    if (*(void**)state != NULL)
    {
        ((GameObject*)obj)->anim.localPosX = *(f32*)(*(int*)state + 0xc);
        ((GameObject*)obj)->anim.localPosY = *(f32*)(*(int*)state + 0x10);
        ((GameObject*)obj)->anim.localPosZ = *(f32*)(*(int*)state + 0x14);
    }
    ((AndrosslighState*)state)->unkD = *(u8*)&((AndrosslighState*)state)->unkC;
    switch (((AndrosslighState*)state)->unkC)
    {
    case 0:
        break;
    case 1:
        androssligh_updateBeam(obj, state);
        break;
    case 2:
        break;
    }
}

void androssligh_updateBeam(int obj, int beam)
{
    extern void PSVECAdd(f32* a, f32* b, f32* ab);
    extern void* lightningCreate(f32* pos, f32* dir, f32 a, f32 b, int angle, int c, int d);
    f32 start[3];
    f32 end[3];
    f32 tmp[3];

    start[0] = ((GameObject*)obj)->anim.localPosX - lbl_803DC528;
    start[1] = ((GameObject*)obj)->anim.localPosY;
    start[2] = ((GameObject*)obj)->anim.localPosZ;
    end[0] = ((GameObject*)obj)->anim.localPosX + lbl_803DC528;
    end[1] = start[1];
    end[2] = start[2];
    tmp[0] = start[0] - playerMapOffsetX;
    tmp[1] = start[1];
    tmp[2] = start[0] - playerMapOffsetZ;
    PSMTXMultVec(Camera_GetViewMatrix(), tmp, tmp);
    tmp[0] = -tmp[0];
    tmp[1] = -tmp[1];
    tmp[2] = -tmp[2];
    PSVECScale(tmp, tmp, lbl_803DC52C);
    PSMTXMultVec(Camera_GetInverseViewRotationMatrix(), tmp, tmp);
    PSVECAdd(start, tmp, start);
    tmp[0] = end[0] - playerMapOffsetX;
    tmp[1] = end[1];
    tmp[2] = end[0] - playerMapOffsetZ;
    PSMTXMultVec(Camera_GetViewMatrix(), tmp, tmp);
    tmp[0] = -tmp[0];
    tmp[1] = -tmp[1];
    tmp[2] = -tmp[2];
    PSVECScale(tmp, tmp, lbl_803DC52C);
    PSMTXMultVec(Camera_GetInverseViewRotationMatrix(), tmp, tmp);
    PSVECAdd(end, tmp, end);
    if (*(void**)(beam + 4) == NULL)
    {
        *(int*)(beam + 4) = (int)lightningCreate(start, end, lbl_803DC518, lbl_803DC51C,
                                                 (int)lbl_803DC520, (int)lbl_803DC524, 0);
        *(f32*)(beam + 8) = lbl_803E7608;
    }
    else
    {
        *(f32*)(beam + 8) += timeDelta;
        *(u16*)(*(int*)(beam + 4) + 0x20) = (int)(lbl_803E760C + *(f32*)(beam + 8));
        if (*(u16*)(*(int*)(beam + 4) + 0x20) >= *(u16*)(*(int*)(beam + 4) + 0x22))
        {
            mm_free((void*)*(int*)(beam + 4));
            *(int*)(beam + 4) = 0;
        }
    }
}
