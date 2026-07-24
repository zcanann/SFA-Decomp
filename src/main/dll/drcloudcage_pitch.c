#include "main/game_object.h"
#include "main/object_api.h"
#include "main/checkpoint_interface.h"
#include "main/vecmath.h"
#include "main/dll/DR/DRcloudcage.h"
#include "main/dll/DR/drcloudcage_internal.h"
#include "main/dll/dll_0255_snowbike.h"

extern s32 lbl_803DC0BC;
extern u8 lbl_803AD088[];
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AF8;
extern f32 lbl_803E5B48;
extern f32 lbl_803E5B60;
extern f32 lbl_803E5B64;

f32 fn_801EA678(GameObject* obj, int state)
{
    f32 result;
    f32 d;
    f32 templateMetric;
    f32 stateMetric;
    int rank;

    if ((lbl_803DC0BC == -1) ||
        (rank = (*gCheckpointInterface)->getRouteRank((CheckpointRankItem*)(state + 0x28)), lbl_803DC0BC > rank))
    {
        if (lbl_803DC0BC == -1)
        {
            rank = (int)Obj_GetPlayerObject();
            d = Vec_distance(&obj->anim.worldPosX, (f32*)(rank + 0x18));
            d = d * lbl_803E5AF8;
        }
        else
        {
            /* state+0x28 is the CheckpointRankItem passed to getRouteRank;
             * its linkDepth (+0x1C = 0x44) and routeProgress (+0xC = 0x34) are
             * read here. These stay raw: spelling them as nested-struct members
             * (rankItem.linkDepth / rankItem.routeProgress) shifts codegen. */
            templateMetric = lbl_803E5B48 * (f32) * (s32*)((u8*)lbl_803AD088 + 0x1c) +
                             lbl_803E5B48 * *(f32*)((u8*)lbl_803AD088 + 0xc);
            stateMetric = lbl_803E5B48 * (f32) * (s32*)(state + 0x44) + lbl_803E5B48 * *(f32*)(state + 0x34);
            d = templateMetric - stateMetric;
            d = (d >= lbl_803E5AE8) ? d : -d;
        }
        if (d <= ((DRCloudCageState*)state)->distNear)
        {
            result = ((DRCloudCageState*)state)->valNear;
        }
        else if (d >= ((DRCloudCageState*)state)->distFar)
        {
            result = ((DRCloudCageState*)state)->valFar;
        }
        else
        {
            f32 ratio = (d - ((DRCloudCageState*)state)->distNear) /
                        (((DRCloudCageState*)state)->distFar - ((DRCloudCageState*)state)->distNear);
            d = ((DRCloudCageState*)state)->valNear;
            result = ratio * (((DRCloudCageState*)state)->valFar - d) + d;
        }
        if (((DRCloudCageState*)state)->routeGateActive == 0)
        {
            d = stateMetric - templateMetric;
            d = (d >= lbl_803E5AE8) ? d : -d;
            if (d > gDrCloudCageRouteDistGate)
            {
                result = *(f32*)&lbl_803E5AE8;
            }
        }
    }
    else
    {
        rank = (*gCheckpointInterface)->getRouteRank((CheckpointRankItem*)(state + 0x28));
        if (rank == 2)
        {
            result = lbl_803E5B60;
        }
        else
        {
            result = lbl_803E5B64;
        }
    }
    return result;
}
