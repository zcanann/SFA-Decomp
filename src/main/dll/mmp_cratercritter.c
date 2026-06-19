#include "main/dll/tricky_state.h"

extern f32 lbl_803E23DC;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E2418;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E247C;
extern f32 lbl_803E24C4;

extern char sInWaterMessage[];
extern char lbl_8031D478[];

extern int trickyFoodFn_8013db3c(u8 * arg1, u8 * arg2);
extern u8** ObjGroup_GetObjects(int kind, int* count);
extern f32 getXZDistance(f32* a, f32* b);
extern int trickyFn_8013b368(u8* arg1, u8* arg2, f32 dist);
extern void objAnimFn_8013a3f0(u8* self, int a, int b, f32 f1);
extern void trickyDebugPrint(const char* fmt, ...);

void trickyFn_8013d8f0(u8* self, u8* state)
{
    u8* nearest;
    f32 rejectDist;
    f32 minDist;
    f32 dist;
    f32 z;
    u8** objs;
    int count;
    int i;
    int waterFlag;

    nearest = NULL;
    minDist = lbl_803E2418;

    if (trickyFoodFn_8013db3c(self, state) == 0)
    {
        state[0x8] = 1;
        state[0xA] = 0;
        z = lbl_803E23DC;
        ((TrickyState*)state)->unk71C = z;
        ((TrickyState*)state)->unk720 = z;
        ((TrickyState*)state)->stateFlags &= ~0x10LL;
        ((TrickyState*)state)->stateFlags &= ~0x10000LL;
        ((TrickyState*)state)->stateFlags &= ~0x20000LL;
        ((TrickyState*)state)->stateFlags &= ~0x40000LL;
        ((TrickyState*)state)->unkD = -1;
        return;
    }

    objs = ObjGroup_GetObjects(0x4B, &count);
    rejectDist = lbl_803E24C4;
    for (i = 0; i < count; i++)
    {
        dist = getXZDistance((f32*)((u8*)((TrickyState*)state)->playerObj + 0x18),
                             (f32*)(*objs + 0x18));
        if (dist > rejectDist)
        {
            dist = getXZDistance((f32*)(self + 0x18), (f32*)(*objs + 0x18));
            if (dist < minDist)
            {
                nearest = *objs;
                minDist = dist;
            }
        }
        objs++;
    }

    if (nearest != NULL)
    {
        ((TrickyState*)state)->followObj = nearest;
        if (((TrickyState*)state)->unk28 != nearest + 0x18)
        {
            ((TrickyState*)state)->unk28 = nearest + 0x18;
            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & 0xFFFFFBFF;
            ((TrickyState*)state)->unkD2 = 0;
        }
        if (trickyFn_8013b368(self, state, lbl_803E247C) == 1) return;
    }

    if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
    {
        waterFlag = 0;
    }
    else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
    {
        waterFlag = 1;
    }
    else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
    {
        waterFlag = 1;
    }
    else
    {
        waterFlag = 0;
    }

    if (waterFlag != 0)
    {
        objAnimFn_8013a3f0(self, 8, 0, lbl_803E243C);
        ((TrickyState*)state)->unk79C = lbl_803E2440;
        ((TrickyState*)state)->unk838 = lbl_803E23DC;
        trickyDebugPrint(sInWaterMessage);
    }
    else
    {
        objAnimFn_8013a3f0(self, 0, 0, lbl_803E2444);
        trickyDebugPrint(lbl_8031D478);
    }
}
