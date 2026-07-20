/*
 * mmshwaterspike (DLL 0x18E) - rising water-spike hazard in Mushroom Mountain
 * (mmsh). Each instance tracks an XYZ-animator object by packed ID (stored at
 * userData2) to read its current height; if the animator is missing it falls back to
 * hit-detect against nearby water surfaces. The spike rises toward a placement-
 * defined ceiling (maxHeight) and spawns a waterfx ripple when it surfaces.
 */
#include "main/dll/waterfx_interface.h"
#include "main/debug.h"
#include "main/object_api.h"
#include "main/track_dolphin_api.h"
#include "main/game_object.h"
#include "main/obj_list.h"
#include "main/dll/xyzanimator_api.h"
#include "main/frame_timing.h"
#include "main/dll/dll_018E_mmshwaterspike.h"

#define MMSHWATERSPIKE_HIT_VOLUME_SLOT 9
#define MMSHWATERSPIKE_NO_RISE -9999.0f
#define MMSHWATERSPIKE_RIPPLE_SCALE 0.5f
#define MMSHWATERSPIKE_RIPPLE_TIMER(obj) ((obj)->userData1)
#define MMSHWATERSPIKE_XYZ_ANIM_ID(obj)  ((obj)->userData2)

extern char sWaterSpikeInvalidXyzAnimIdWarning[];

int mmsh_waterspike_getExtraSize(void)
{
    return 0x0;
}
int mmsh_waterspike_getObjectTypeId(void)
{
    return 0x0;
}

void mmsh_waterspike_free(GameObject* obj)
{
}

void mmsh_waterspike_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0)
        return;
}

void mmsh_waterspike_hitDetect(void)
{
}

void mmsh_waterspike_update(GameObject* obj)
{
    GameObject* animObj;
    TrackGroundHit** hitPtr;
    TrackGroundHit* hit;
    int hitCount;
    int i;
    f32 delta;
    f32 newY;
    f32 maxY;
    f32 riseDelta;
    TrackGroundHit** hitList;
    MmshWaterspikePlacement* placement;

    placement = (MmshWaterspikePlacement*)obj->anim.placementData;
    ObjHits_SetHitVolumeSlot(&obj->anim, MMSHWATERSPIKE_HIT_VOLUME_SLOT, 1, 0);
    animObj = ObjList_FindObjectById(MMSHWATERSPIKE_XYZ_ANIM_ID(obj));
    if (animObj != NULL)
    {
        riseDelta = objFn_801948c0(animObj, 3) - obj->anim.localPosY;
    }
    else
    {
        logPrintf(sWaterSpikeInvalidXyzAnimIdWarning, placement->xyzAnimId);
        hitCount = hitDetectFn_80065e50(obj, obj->anim.localPosX, obj->anim.localPosY,
                                        obj->anim.localPosZ, &hitList, 0, 0);
        if (hitCount != 0)
        {
            riseDelta = MMSHWATERSPIKE_NO_RISE;
            hitPtr = hitList;
            for (i = 0; i < hitCount; i++)
            {
                hit = *hitPtr;
                if ((s8)hit->surfaceType == 0xe)
                {
                    delta = hit->height - obj->anim.localPosY;
                    if (delta > riseDelta)
                    {
                        riseDelta = delta;
                    }
                }
                hitPtr = hitPtr + 1;
            }
        }
    }
    newY = obj->anim.localPosY + riseDelta;
    maxY = placement->maxHeight;
    if (newY > maxY)
    {
        obj->anim.localPosY = maxY;
    }
    else
    {
        obj->anim.localPosY = newY;
        MMSHWATERSPIKE_RIPPLE_TIMER(obj) -= framesThisStep;
        if (MMSHWATERSPIKE_RIPPLE_TIMER(obj) <= 0)
        {
            MMSHWATERSPIKE_RIPPLE_TIMER(obj) = randomGetRange(0x3c, 0xf0);
            if (riseDelta == 0.0f)
            {
                (*gWaterfxInterface)->spawnRipple(
                    obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                    0, MMSHWATERSPIKE_RIPPLE_SCALE, 3);
            }
        }
    }
    return;
}

void mmsh_waterspike_init(GameObject* obj, MmshWaterspikeObjectDef* def)
{
    register u32 packedEventIds;
    register u32 lowEventId;
    ObjHits_EnableObject(obj);
    MMSHWATERSPIKE_RIPPLE_TIMER(obj) = 0;
    packedEventIds = (u32)(u16)def->xyzAnimIdHigh << 16;
    lowEventId = (u32)(u16)def->xyzAnimIdLow;
    packedEventIds |= lowEventId;
    MMSHWATERSPIKE_XYZ_ANIM_ID(obj) = packedEventIds;
}

void mmsh_waterspike_release(void)
{
}

void mmsh_waterspike_initialise(void)
{
}

char sWaterSpikeInvalidXyzAnimIdWarning[] = "WARNING Water Spike [%d] as invalid xyzAnim ID\n";
