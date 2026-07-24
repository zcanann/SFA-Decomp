/*
 * drcloudcage - "cloud cage" trail/audio effect helper DLL.
 *
 * Provides three routines shared with the snowbike (DLL 0x255), hightop and
 * drshackle objects:
 *   fn_801E9C00  builds and fades the swirling cloud-trail ribbons. Each of the
 *                three emitters casts a transformed segment, ray-tests it
 *                (hitDetectFn_80065e50, mask 0x20), and when it strikes ground
 *                inserts a new fully-opaque point pair at the head of one of the
 *                nine trail buffers; every existing pair's alpha decays by
 *                timeDelta and exhausted trails are freed.
 *   drcloudcage_updateEngineFx  drives the wind/engine sfx channels (8,1,2,4) by distance and
 *                rotZ, clamps each channel volume, and spawns two light pulses;
 *                then advances the trails via fn_801E9C00.
 *   fn_801EA678  returns a distance/route-rank weighted scalar (pitch/intensity)
 *                from the checkpoint route rank, falling back to player distance
 *                when no rank gate (lbl_803DC0BC) is set.
 *
 * State is addressed through raw byte offsets into the owning object's extra
 * block; trail buffers begin at DRCLOUDCAGE_TRAILS_OFFSET (DRCLOUDCAGE_TRAIL_COUNT
 * records of DRCLOUDCAGE_TRAIL_STRIDE bytes), with the three active head-trail
 * pointers immediately following at +0x510/+0x514/+0x518.
 */
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/objfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/checkpoint_interface.h"
#include "main/vecmath.h"
#include "string.h"
#include "main/frame_timing.h"
#include "main/track_dolphin_api.h"
#include "main/dll/DR/DRcloudcage.h"
#include "main/dll/DR/drcloudcage_internal.h"
#include "main/dll/dll_0255_snowbike.h"

/* lbl_803DC0BC/gDrCloudCageRouteDistGate/lbl_803AD088 are shared route-rank state owned by
   drhightop; the lbl_803E5* pool and gDrCloudCagePointTemplate point template live in this
   DLL's data; timeDelta is the global frame delta. */
extern s32 lbl_803DC0BC;
extern u8 lbl_803AD088[];
struct DRCloudCagePoints;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF0;
extern f32 lbl_803E5AF4;
extern f32 lbl_803E5AF8;
extern f32 lbl_803E5AFC;
extern f32 lbl_803E5B08;
extern f32 lbl_803E5B0C;
extern f32 lbl_803E5B10;
extern f32 lbl_803E5B14;
extern f32 lbl_803E5B18;
extern f32 lbl_803E5B1C;
extern f32 lbl_803E5B20;
extern f32 lbl_803E5B24;
extern f32 lbl_803E5B28;
extern f32 lbl_803E5B2C;
extern f32 lbl_803E5B30;
extern f32 lbl_803E5B34;
extern f32 lbl_803E5B38;
extern f32 lbl_803E5B3C;
extern f32 lbl_803E5B40;
extern f32 lbl_803E5B44;
extern f32 lbl_803E5B48;
extern f32 lbl_803E5B4C;
extern f32 lbl_803E5B50;
extern f32 lbl_803E5B54;
extern f32 lbl_803E5B58;
extern f32 lbl_803E5B5C;
extern f32 lbl_803E5B60;
extern f32 lbl_803E5B64;

#define DRCLOUDCAGE_TRAIL_COUNT       9
#define DRCLOUDCAGE_TRAIL_STRIDE      8
#define DRCLOUDCAGE_TRAILS_OFFSET     0x4c8
#define DRCLOUDCAGE_PAIR_SIZE         0x10
#define DRCLOUDCAGE_TRAIL_FLAG_ACTIVE 1

typedef struct DRCloudCagePointPair
{
    f32 startX;
    f32 startY;
    f32 startZ;
    s16 startAlpha;
    u8 startColorByte;
    u8 pad0F;
    f32 endX;
    f32 endY;
    f32 endZ;
    s16 endAlpha;
    u8 endColorByte;
    u8 pad1F;
} DRCloudCagePointPair;

typedef struct DRCloudCageTrail
{
    DRCloudCagePointPair* points;
    s16 count;
    u8 flags;
    u8 pad07;
} DRCloudCageTrail;

typedef struct DRCloudCagePoints
{
    f32 m[18];
} DRCloudCagePoints;

const DRCloudCagePoints gDrCloudCagePointTemplate = {
    {-6.0f, 1.0f, 15.0f, 6.0f, 1.0f, 15.0f, -7.5f, 1.0f, 15.0f, -4.0f, 1.0f,
     15.0f, 4.0f, 1.0f, 15.0f, 7.5f, 1.0f, 15.0f}};

void fn_801E9C00(GameObject* obj, int state)
{
    f32 endZ;
    f32 endY;
    f32 endX;
    f32 startZ;
    f32 startY;
    f32 startX;
    TrackGroundHit** hits;
    MatrixTransform transform;
    f32 matrix[16];
    DRCloudCagePoints localPoints;
    u8* p;
    int trailIndex;
    DRCloudCageTrail* trail;
    int pairIndex;
    u8* points;
    DRCloudCagePointPair* pair;
    s32 a;
    f32 fade;
    int copyOffset;
    int activeOffset;
    f32* endpoint;
    u8* slot;
    f32* pStartZ;
    f32* pStartY;
    f32* pEndZ;
    f32* pEndY;
    f32* pEndX;
    int endpointIndex;
    DRCloudCageTrail* selectedTrail;
    int activeIndex;
    int nextOffset;
    int scanIndex;
    int hitIndex;
    int hitCount;
    int copyIndex;
    u8 hitDetected;
    f32 deltaY;
    f32 maxDelta;
    f32 zero;
    f32 scaleV;
    f32 minDelta;
    int baseOffset;
    int baseOffset2;

    localPoints = gDrCloudCagePointTemplate;

    for (trailIndex = 0, p = (u8*)state; trailIndex < DRCLOUDCAGE_TRAIL_COUNT;
         p += DRCLOUDCAGE_TRAIL_STRIDE, trailIndex++)
    {
        trail = (DRCloudCageTrail*)(p + DRCLOUDCAGE_TRAILS_OFFSET);
        if (trail->flags & DRCLOUDCAGE_TRAIL_FLAG_ACTIVE)
        {
            pairIndex = trail->count - 2;
            points = (u8*)trail->points;
            pair = (DRCloudCagePointPair*)((u8*)trail->points + pairIndex * DRCLOUDCAGE_PAIR_SIZE);
            fade = lbl_803E5AF0;
            for (; pairIndex >= 0; pair--, pairIndex -= 2)
            {
                pair->startAlpha = -(fade * timeDelta - pair->startAlpha);
                pair->endAlpha = pair->startAlpha;
                a = pair->startAlpha;
                if (a < 0)
                {
                    a = 0;
                }
                else if (a > 0xff)
                {
                    a = 0xff;
                }
                pair->startAlpha = a;
                a = pair->endAlpha;
                if (a < 0)
                {
                    a = 0;
                }
                else if (a > 0xff)
                {
                    a = 0xff;
                }
                pair->endAlpha = a;
            }

            pairIndex = trail->count - 2;
            pair = (DRCloudCagePointPair*)(points + pairIndex * DRCLOUDCAGE_PAIR_SIZE);
            for (; pairIndex >= 0; pair--, pairIndex -= 2)
            {
                if (pairIndex >= 2)
                {
                    if ((pair->startAlpha <= 0) && (pair->endAlpha <= 0) && (*(s16*)((u8*)pair - 4) <= 0) &&
                        (*(s16*)((u8*)pair - 0x14) <= 0))
                    {
                        trail->count -= 2;
                    }
                }
                else
                {
                    if ((pair->startAlpha <= 0) && (pair->endAlpha <= 0))
                    {
                        trail->count -= 2;
                    }
                }
            }

            /* The three active head-trail pointer slots (0x510/0x514/0x518)
             * stay raw: the spawn loop below walks them via a running `slot`
             * base (slot += 4), so naming them as fixed struct fields shifts
             * the walker's addressing/CSE. */
            if ((trail != *(DRCloudCageTrail**)(state + 0x510)) && (trail != *(DRCloudCageTrail**)(state + 0x514)) &&
                (trail != *(DRCloudCageTrail**)(state + 0x518)) && (trail->count == 0))
            {
                trail->flags &= ~DRCLOUDCAGE_TRAIL_FLAG_ACTIVE;
            }
        }
    }

    activeIndex = 0;
    baseOffset = -4;
    baseOffset2 = 8;
    slot = (u8*)state;
    pStartZ = &startZ;
    pStartY = &startY;
    pEndZ = &endZ;
    pEndY = &endY;
    pEndX = &endX;
    zero = lbl_803E5AE8;
    maxDelta = lbl_803E5AF4;
    minDelta = lbl_803E5AFC;
    scaleV = lbl_803E5AEC;
    for (; activeIndex < 3; baseOffset += 0x18, baseOffset2 += 0x18, slot += 4, activeIndex++)
    {
        activeOffset = baseOffset + 4;
        nextOffset = baseOffset2 + 4;
        transform.x = obj->anim.worldPosX;
        transform.y = obj->anim.worldPosY;
        transform.z = obj->anim.worldPosZ;
        transform.rotX = obj->anim.rotX;
        transform.rotY = obj->anim.rotY;
        transform.rotZ = (s16)(obj->anim.rotZ + ((DRCloudCageState*)state)->rotZOffset);
        transform.scale = scaleV;
        setMatrixFromObjectPos(matrix, &transform);

        Matrix_TransformPoint(matrix, ((f32*)((u8*)&localPoints + activeOffset))[0],
                              ((f32*)((u8*)&localPoints + activeOffset))[1],
                              ((f32*)((u8*)&localPoints + activeOffset))[2], &startX, pStartY, pStartZ);
        Matrix_TransformPoint(matrix, ((f32*)((u8*)&localPoints + nextOffset))[0],
                              ((f32*)((u8*)&localPoints + nextOffset))[1], ((f32*)((u8*)&localPoints + nextOffset))[2],
                              pEndX, pEndY, pEndZ);

        hitDetected = 0;
        endpointIndex = 0;
        endpoint = &startX;
        for (; endpointIndex < 2; endpoint += 3, endpointIndex++)
        {
            hitCount = hitDetectFn_80065e50(obj, endpoint[0], endpoint[1], endpoint[2], &hits, 0, 0x20);
            for (hitIndex = 0; hitIndex < hitCount; hitIndex++)
            {
                deltaY = hits[hitIndex]->height - endpoint[1];
                if (activeIndex > 0)
                {
                    if ((deltaY > zero) && (deltaY < maxDelta))
                    {
                        hitDetected = 1;
                        endpoint[1] = lbl_803E5AF8 + hits[hitIndex]->height;
                        break;
                    }
                }
                else if ((deltaY >= minDelta) && (deltaY < maxDelta))
                {
                    hitDetected = 1;
                    endpoint[1] = lbl_803E5AF8 + hits[hitIndex]->height;
                    break;
                }
            }
        }

        if (!((DRCloudCageState*)state)->stateFlags.hidden && hitDetected)
        {
            selectedTrail = *(DRCloudCageTrail**)(slot + 0x510);
            if (selectedTrail == NULL)
            {
                for (scanIndex = 0; scanIndex < DRCLOUDCAGE_TRAIL_COUNT; scanIndex++)
                {
                    selectedTrail =
                        (DRCloudCageTrail*)(state + scanIndex * DRCLOUDCAGE_TRAIL_STRIDE + DRCLOUDCAGE_TRAILS_OFFSET);
                    if (!(selectedTrail->flags & DRCLOUDCAGE_TRAIL_FLAG_ACTIVE))
                    {
                        break;
                    }
                }
                if (scanIndex >= DRCLOUDCAGE_TRAIL_COUNT)
                {
                    break;
                }
                selectedTrail->flags |= DRCLOUDCAGE_TRAIL_FLAG_ACTIVE;
                selectedTrail->count = 0;
                *(DRCloudCageTrail**)(slot + 0x510) = selectedTrail;
            }
            else
            {
                copyIndex = selectedTrail->count - 1;
                copyOffset = copyIndex * DRCLOUDCAGE_PAIR_SIZE;
                while (copyIndex >= 0)
                {
                    memcpy((u8*)selectedTrail->points + (copyIndex + 2) * DRCLOUDCAGE_PAIR_SIZE,
                           (u8*)selectedTrail->points + copyOffset, DRCLOUDCAGE_PAIR_SIZE);
                    copyOffset -= DRCLOUDCAGE_PAIR_SIZE;
                    copyIndex--;
                }
            }

            selectedTrail->points[0].startX = startX;
            selectedTrail->points[0].startY = startY;
            selectedTrail->points[0].startZ = startZ;
            selectedTrail->points[0].endX = endX;
            selectedTrail->points[0].endY = endY;
            selectedTrail->points[0].endZ = endZ;
            selectedTrail->points[0].startAlpha = 0xff;
            selectedTrail->points[0].endAlpha = 0xff;
            selectedTrail->points[0].startColorByte = ((DRCloudCageState*)state)->trailColorByte;
            selectedTrail->points[0].endColorByte = ((DRCloudCageState*)state)->trailColorByte;
            selectedTrail->count += 2;
            ((DRCloudCageState*)state)->lastSpawnPosX = obj->anim.worldPosX;
            ((DRCloudCageState*)state)->lastSpawnPosY = obj->anim.worldPosY;
            ((DRCloudCageState*)state)->lastSpawnPosZ = obj->anim.worldPosZ;
        }
        else
        {
            *(DRCloudCageTrail**)(slot + 0x510) = 0;
        }
    }
}
