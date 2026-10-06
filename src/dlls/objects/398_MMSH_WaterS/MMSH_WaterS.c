/*
 * MMSH_WaterS (DLL 0x18E) - water-spike hazard in Moon Mountain Pass.
 *
 * Each spike follows the Y coordinate of a shared XYZ Animator. If that
 * animator is unavailable, the spike falls back to nearby water surfaces.
 */
#include "dlls/objects/398_MMSH_WaterS.h"

#include "dlls/objects/316_XYZAnimator.h"
#include "main/debug.h"
#include "main/dll/player_state.h"
#include "main/dll/waterfx_interface.h"
#include "main/frame_timing.h"
#include "main/objhits.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define MMSH_WATER_SPIKE_HIT_VOLUME_SLOT 9
#define MMSH_WATER_SPIKE_HIT_SOURCE_SLOT 0

#define MMSH_WATER_SPIKE_MIN_SURFACE_DELTA -9999.0f

#define MMSH_WATER_SPIKE_RIPPLE_DELAY_MIN 0x3C
#define MMSH_WATER_SPIKE_RIPPLE_DELAY_MAX 0xF0
#define MMSH_WATER_SPIKE_RIPPLE_YAW 0
#define MMSH_WATER_SPIKE_RIPPLE_RADIUS    0.5f
#define MMSH_WATER_SPIKE_RIPPLE_INTENSITY 3

#define MMSH_WATER_SPIKE_GROUND_QUERY_MODE    0
#define MMSH_WATER_SPIKE_GROUND_QUERY_SUBMODE 0

#define MMSH_WATER_SPIKE_RIPPLE_TIMER(obj)    ((obj)->userData1)
#define MMSH_WATER_SPIKE_XYZ_ANIMATOR_ID(obj) ((obj)->userData2)

extern char sMMSHWaterSpikeInvalidXyzAnimatorIdWarning[];

int mmshWaterSpike_getExtraSize(void) {
    return 0;
}

int mmshWaterSpike_getObjectTypeId(void) {
    return 0;
}

void mmshWaterSpike_free(GameObject* obj) {
}

void mmshWaterSpike_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                           s8 visible) {
    if (visible == 0) {
        return;
    }
}

void mmshWaterSpike_hitDetect(void) {
}

void mmshWaterSpike_update(GameObject* obj) {
    GameObject* xyzAnimator;
    TrackGroundHit** hitCursor;
    TrackGroundHit* hit;
    int hitCount;
    int hitIndex;
    f32 surfaceDelta;
    f32 targetY;
    f32 maxHeight;
    f32 riseDelta;
    TrackGroundHit** hitList;
    const MMSHWaterSpikePlacement* placement;

    placement = (const MMSHWaterSpikePlacement*)obj->anim.placementData;
    ObjHits_SetHitVolumeSlot(&obj->anim, MMSH_WATER_SPIKE_HIT_VOLUME_SLOT, OBJHITS_ACTIVE_HITBOX_MODE,
                             MMSH_WATER_SPIKE_HIT_SOURCE_SLOT);
    xyzAnimator = ObjList_FindObjectById(MMSH_WATER_SPIKE_XYZ_ANIMATOR_ID(obj));
    if (xyzAnimator != NULL) {
        riseDelta = XyzAnimator_getCoordinate(xyzAnimator, XYZ_ANIMATOR_COORD_WORLD_Y) - obj->anim.localPosY;
    } else {
        logPrintf(sMMSHWaterSpikeInvalidXyzAnimatorIdWarning, placement->base.ident);
        hitCount = trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &hitList,
                                        MMSH_WATER_SPIKE_GROUND_QUERY_MODE, MMSH_WATER_SPIKE_GROUND_QUERY_SUBMODE);
        if (hitCount != 0) {
            riseDelta = MMSH_WATER_SPIKE_MIN_SURFACE_DELTA;
            hitCursor = hitList;
            for (hitIndex = 0; hitIndex < hitCount; hitIndex++) {
                hit = *hitCursor;
                if ((s8)hit->surfaceType == SURFACE_WATER) {
                    surfaceDelta = hit->height - obj->anim.localPosY;
                    if (surfaceDelta > riseDelta) {
                        riseDelta = surfaceDelta;
                    }
                }
                hitCursor++;
            }
        }
    }
    targetY = obj->anim.localPosY + riseDelta;
    maxHeight = placement->base.posY;
    if (targetY > maxHeight) {
        obj->anim.localPosY = maxHeight;
    } else {
        obj->anim.localPosY = targetY;
        MMSH_WATER_SPIKE_RIPPLE_TIMER(obj) -= framesThisStep;
        if (MMSH_WATER_SPIKE_RIPPLE_TIMER(obj) <= 0) {
            MMSH_WATER_SPIKE_RIPPLE_TIMER(obj) =
                randomGetRange(MMSH_WATER_SPIKE_RIPPLE_DELAY_MIN, MMSH_WATER_SPIKE_RIPPLE_DELAY_MAX);
            if (riseDelta == 0.0f) {
                (*gWaterfxInterface)
                    ->spawnCircularRipple(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                                  MMSH_WATER_SPIKE_RIPPLE_YAW, MMSH_WATER_SPIKE_RIPPLE_RADIUS,
                                  MMSH_WATER_SPIKE_RIPPLE_INTENSITY);
            }
        }
    }
}

void mmshWaterSpike_init(GameObject* obj, const MMSHWaterSpikePlacement* placement) {
    register u32 packedXyzAnimatorObjectId;
    register u32 lowXyzAnimatorObjectId;

    ObjHits_EnableObject(obj);
    MMSH_WATER_SPIKE_RIPPLE_TIMER(obj) = 0;
    packedXyzAnimatorObjectId = (u32)(u16)placement->xyzAnimatorObjectIdHigh << 16;
    lowXyzAnimatorObjectId = (u32)(u16)placement->xyzAnimatorObjectIdLow;
    packedXyzAnimatorObjectId |= lowXyzAnimatorObjectId;
    MMSH_WATER_SPIKE_XYZ_ANIMATOR_ID(obj) = packedXyzAnimatorObjectId;
}

void mmshWaterSpike_release(void) {
}

void mmshWaterSpike_initialise(void) {
}

ObjectDescriptor gMMSHWaterSpikeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mmshWaterSpike_initialise,
    (ObjectDescriptorCallback)mmshWaterSpike_release,
    0,
    (ObjectDescriptorCallback)mmshWaterSpike_init,
    (ObjectDescriptorCallback)mmshWaterSpike_update,
    (ObjectDescriptorCallback)mmshWaterSpike_hitDetect,
    (ObjectDescriptorCallback)mmshWaterSpike_render,
    (ObjectDescriptorCallback)mmshWaterSpike_free,
    (ObjectDescriptorCallback)mmshWaterSpike_getObjectTypeId,
    mmshWaterSpike_getExtraSize,
};

char sMMSHWaterSpikeInvalidXyzAnimatorIdWarning[] = "WARNING Water Spike [%d] as invalid xyzAnim ID\n";
