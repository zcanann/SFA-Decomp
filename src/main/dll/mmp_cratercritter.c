#include "main/dll/tricky_state.h"
#include "main/dll/baddie/MMP_critterspit.h"
#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/vecmath.h"
#include "main/dll/mmp_cratercritter.h"
#include "main/dll/dll_00C4_tricky_api.h"

#define TRICKYWARP_OBJ_GROUP 0x4b /* DLL 0x100 trickywarp */

extern f32 lbl_803E23DC;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E2418;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E247C;
extern f32 lbl_803E24C4;
extern char sInWaterMessage[]; /* "in water\n" */
extern char lbl_8031D478[];    /* "out of water\n" (head of the 0x38C Tricky debug-string blob @0x8031D478) */
extern int trickyFn_8013b368(u8* obj, f32 dist, u8* state);
extern void objAnimFn_8013a3f0(u8* self, int a, f32 f1, int b);

#pragma peephole on
void trickyFn_8013d8f0(u8* self, u8* state)
{
    u8* nearest;
    f32 rejectDist;
    f32 minDist;
    f32 dist;
    f32 z;
    u8** objs;
    u8** objsList;
    int count;
    int i;
    int inWater;
    u8* best;

    nearest = NULL;
    best = NULL;
    minDist = lbl_803E2418;

    if (trickyFoodFn_8013db3c(self, state) == 0)
    {
        ((TrickyState*)state)->stateIndex = 1;
        ((TrickyState*)state)->substate = 0;
        z = lbl_803E23DC;
        ((TrickyState*)state)->cooldownA = z;
        ((TrickyState*)state)->cooldownB = z;
        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & (u64)~0x10u;
        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & (u64)~0x10000u;
        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & (u64)~0x20000u;
        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & (u64)~0x40000u;
        ((TrickyState*)state)->commandPhase = -1;
        return;
    }

    objsList = (u8**)ObjGroup_GetObjects(TRICKYWARP_OBJ_GROUP, &count);
    i = 0;
    objs = objsList;
    rejectDist = lbl_803E24C4;
    for (; i < count; i++)
    {
        dist = getXZDistance((f32*)((u8*)((TrickyState*)state)->playerObj + 0x18), (f32*)(*objs + 0x18));
        if (dist > rejectDist)
        {
            dist = getXZDistance((f32*)(self + 0x18), (f32*)(*objs + 0x18));
            if (dist < minDist)
            {
                best = *objs;
                minDist = dist;
            }
        }
        objs++;
    }

    nearest = best;
    if (nearest != NULL)
    {
        ((TrickyState*)state)->followObj = nearest;
        if (((TrickyState*)state)->targetPosPtr != nearest + 0x18)
        {
            ((TrickyState*)state)->targetPosPtr = nearest + 0x18;
            *(s32*)&((TrickyState*)state)->stateFlags &= ~0x400LL;
            ((TrickyState*)state)->linkedWalkGroup = 0;
        }
        if (trickyFn_8013b368(self, lbl_803E247C, state) == 1)
            return;
    }

    if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
    {
        inWater = 0;
    }
    else if (lbl_803E2410 == ((TrickyState*)state)->eventTime)
    {
        inWater = 1;
    }
    else if (((TrickyState*)state)->currentTime - ((TrickyState*)state)->eventTime > lbl_803E2414)
    {
        inWater = 1;
    }
    else
    {
        inWater = 0;
    }

    if (inWater != 0)
    {
        objAnimFn_8013a3f0(self, 8, lbl_803E243C, 0);
        ((TrickyState*)state)->cooldownC = lbl_803E2440;
        ((TrickyState*)state)->particleTimer = lbl_803E23DC;
        trickyDebugPrint(sInWaterMessage);
    }
    else
    {
        objAnimFn_8013a3f0(self, 0, lbl_803E2444, 0);
        trickyDebugPrint(lbl_8031D478);
    }
}
