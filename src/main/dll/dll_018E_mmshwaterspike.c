/*
 * mmshwaterspike (DLL 0x18E) - rising water-spike hazard in Mushroom Mountain
 * (mmsh). Each instance tracks an XYZ-animator object by packed ID (stored at
 * unkF8) to read its current height; if the animator is missing it falls back to
 * hit-detect against nearby water surfaces. The spike rises toward a placement-
 * defined ceiling (maxHeight) and spawns a waterfx ripple when it surfaces.
 */
#include "main/effect_interfaces.h"
#include "main/debug.h"
#include "main/object_api.h"
#include "main/game_object.h"
#include "main/obj_list.h"
#include "main/dll/MMP/dll_013B_wallanimator.h"
#include "main/frame_timing.h"
#include "main/dll/dll_018E_mmshwaterspike.h"

#define MMSHWATERSPIKE_HIT_VOLUME_SLOT 9

extern char sWaterSpikeInvalidXyzAnimIdWarning[];
extern f32 lbl_803E4F80;
extern f32 lbl_803E4F84;
extern f32 lbl_803E4F88;

extern int hitDetectFn_80065e50(int a, f32 b, f32 c, f32 d, void* out, int e, int f);

int mmsh_waterspike_getExtraSize(void)
{
    return 0x0;
}
int mmsh_waterspike_getObjectTypeId(void)
{
    return 0x0;
}

void mmsh_waterspike_free(void)
{
}

void mmsh_waterspike_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0)
        return;
}

void mmsh_waterspike_hitDetect(void)
{
}

void mmsh_waterspike_update(int obj)
{
    void* animObj;
    int* hitPtr;
    int hitObj;
    int hitCount;
    int i;
    f32 delta;
    f32 newY;
    f32 maxY;
    f32 riseDelta;
    int* hitList;
    int placement;

    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, MMSHWATERSPIKE_HIT_VOLUME_SLOT, 1, 0);
    animObj = ObjList_FindObjectById(((GameObject*)obj)->unkF8);
    if (animObj != NULL)
    {
        riseDelta = objFn_801948c0(animObj, 3) - ((GameObject*)obj)->anim.localPosY;
    }
    else
    {
        logPrintf(sWaterSpikeInvalidXyzAnimIdWarning, ((MmshWaterspikePlacement*)placement)->xyzAnimId);
        hitCount = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                        ((GameObject*)obj)->anim.localPosZ, &hitList, 0, 0);
        if (hitCount != 0)
        {
            riseDelta = lbl_803E4F80;
            hitPtr = hitList;
            for (i = 0; i < hitCount; i++)
            {
                hitObj = *hitPtr;
                if (*(char*)(hitObj + 0x14) == 0xe)
                {
                    delta = *(f32*)hitObj - ((GameObject*)obj)->anim.localPosY;
                    if (delta > riseDelta)
                    {
                        riseDelta = delta;
                    }
                }
                hitPtr = hitPtr + 1;
            }
        }
    }
    newY = ((GameObject*)obj)->anim.localPosY + riseDelta;
    maxY = ((MmshWaterspikePlacement*)placement)->maxHeight;
    if (newY > maxY)
    {
        ((GameObject*)obj)->anim.localPosY = maxY;
    }
    else
    {
        ((GameObject*)obj)->anim.localPosY = newY;
        ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - framesThisStep;
        if (((GameObject*)obj)->unkF4 <= 0)
        {
            ((GameObject*)obj)->unkF4 = randomGetRange(0x3c, 0xf0);
            if (lbl_803E4F84 == riseDelta)
            {
                ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
                    ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ, 0, lbl_803E4F88, 3);
            }
        }
    }
    return;
}

void mmsh_waterspike_init(GameObject* obj, s16* def)
{
    register u32 packedEventIds;
    register u32 lowEventId;
    ObjHits_EnableObject((int)obj);
    (obj)->unkF4 = 0;
    packedEventIds = (u32)(u16)((MmshWaterspikeObjectDef*)def)->xyzAnimIdHigh << 16;
    lowEventId = (u32)(u16)((MmshWaterspikeObjectDef*)def)->xyzAnimIdLow;
    packedEventIds |= lowEventId;
    *(u32*)&(obj)->unkF8 = packedEventIds;
}

void mmsh_waterspike_release(void)
{
}

void mmsh_waterspike_initialise(void)
{
}

char sWaterSpikeInvalidXyzAnimIdWarning[] = "WARNING Water Spike [%d] as invalid xyzAnim ID\n";
