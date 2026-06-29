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
 *   fn_801EA240  drives the wind/engine sfx channels (8,1,2,4) by distance and
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
#include "main/checkpoint_interface.h"
#include "main/vecmath.h"
#include "string.h"

/* lbl_803DC0BC/gDrCloudCageRouteDistGate/lbl_803AD088 are shared route-rank state owned by
   drhightop; the lbl_803E5* pool and gDrCloudCagePointTemplate point template live in this
   DLL's data; timeDelta is the global frame delta. */
extern s32 Sfx_IsPlayingFromObjectChannel(u32 obj, u32 channel);
extern void Sfx_SetObjectChannelVolume(int obj, int channel, u32 volumeByte, f32 volume);
extern int Sfx_PlayFromObject(int obj, int sfxId);
extern int Obj_GetPlayerObject(void);
extern f32 Vec_distance(int* from, int* to);
extern void objfx_spawnLightPulse(int obj, f32 a, int b, int c, int d, f32 e, void* params);
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern int hitDetectFn_80065e50(int a, f32 b, f32 c, f32 d, void* out, int e, int f);
extern s32 lbl_803DC0BC;
extern f32 gDrCloudCageRouteDistGate;
extern f32 timeDelta;
extern f32 gDrCloudCageWindVolume;
extern u8 lbl_803AD088[];
extern struct DRCloudCagePoints gDrCloudCagePointTemplate;
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

#define DRCLOUDCAGE_TRAIL_COUNT 9
#define DRCLOUDCAGE_TRAIL_STRIDE 8
#define DRCLOUDCAGE_TRAILS_OFFSET 0x4c8
#define DRCLOUDCAGE_PAIR_SIZE 0x10
#define DRCLOUDCAGE_TRAIL_FLAG_ACTIVE 1

typedef struct DRCloudCagePointPair
{
    f32 startX;
    f32 startY;
    f32 startZ;
    s16 startAlpha;
    u8 pad0E;
    u8 pad0F;
    f32 endX;
    f32 endY;
    f32 endZ;
    s16 endAlpha;
    u8 pad1E;
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

typedef struct DRCloudCageStateFlags
{
    u8 hidden : 1;
    u8 rest : 7;
} DRCloudCageStateFlags;
STATIC_ASSERT(sizeof(DRCloudCageStateFlags) == 1);

typedef struct DRCloudCageObjPos
{
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} DRCloudCageObjPos;
STATIC_ASSERT(sizeof(DRCloudCageObjPos) == 0x18);

void fn_801E9C00(int obj, int state)
{
    f32 endZ;
    f32 endY;
    f32 endX;
    f32 startZ;
    f32 startY;
    f32 startX;
    f32** hits;
    DRCloudCageObjPos transform;
    f32 matrix[16];
    DRCloudCagePoints localPoints;
    u8* p;
    int trailIndex;
    DRCloudCageTrail* trail;
    u8* points;
    DRCloudCagePointPair* pair;
    int pairIndex;
    s32 a;
    f32 fade;
    int nextOffset;
    int activeOffset;
    u8 hitDetected;
    int activeIndex;
    int endpointIndex;
    DRCloudCageTrail* selectedTrail;
    f32* pEndX;
    f32* pEndY;
    f32* pEndZ;
    f32* pStartY;
    f32* pStartZ;
    u8* slot;
    f32* endpoint;
    int scanIndex;
    int hitIndex;
    int hitCount;
    int copyIndex;
    int copyOffset;
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
            pair = (DRCloudCagePointPair*)(points + pairIndex * DRCLOUDCAGE_PAIR_SIZE);
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
                    if ((pair->startAlpha <= 0) && (pair->endAlpha <= 0) &&
                        (*(s16*)((u8*)pair - 4) <= 0) && (*(s16*)((u8*)pair - 0x14) <= 0))
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

            if ((trail != *(DRCloudCageTrail**)(state + 0x510)) &&
                (trail != *(DRCloudCageTrail**)(state + 0x514)) &&
                (trail != *(DRCloudCageTrail**)(state + 0x518)) &&
                (trail->count == 0))
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
        transform.x = ((GameObject*)obj)->anim.worldPosX;
        transform.y = ((GameObject*)obj)->anim.worldPosY;
        transform.z = ((GameObject*)obj)->anim.worldPosZ;
        transform.rotX = ((GameObject*)obj)->anim.rotX;
        transform.rotY = ((GameObject*)obj)->anim.rotY;
        transform.rotZ = (s16)(((GameObject*)obj)->anim.rotZ + *(s32*)(state + 0x410));
        transform.scale = scaleV;
        setMatrixFromObjectPos(matrix, &transform);

        Matrix_TransformPoint(matrix, ((f32*)((u8*)&localPoints + activeOffset))[0],
                              ((f32*)((u8*)&localPoints + activeOffset))[1],
                              ((f32*)((u8*)&localPoints + activeOffset))[2], &startX, pStartY,
                              pStartZ);
        Matrix_TransformPoint(matrix, ((f32*)((u8*)&localPoints + nextOffset))[0],
                              ((f32*)((u8*)&localPoints + nextOffset))[1],
                              ((f32*)((u8*)&localPoints + nextOffset))[2], pEndX, pEndY, pEndZ);

        hitDetected = 0;
        endpointIndex = 0;
        endpoint = &startX;
        for (; endpointIndex < 2; endpoint += 3, endpointIndex++)
        {
            hitCount = hitDetectFn_80065e50(obj, endpoint[0], endpoint[1], endpoint[2], &hits, 0, 0x20);
            for (hitIndex = 0; hitIndex < hitCount; hitIndex++)
            {
                deltaY = hits[hitIndex][0] - endpoint[1];
                if (activeIndex > 0)
                {
                    if ((deltaY > zero) && (deltaY < maxDelta))
                    {
                        hitDetected = 1;
                        endpoint[1] = lbl_803E5AF8 + hits[hitIndex][0];
                        break;
                    }
                }
                else if ((deltaY >= minDelta) && (deltaY < maxDelta))
                {
                    hitDetected = 1;
                    endpoint[1] = lbl_803E5AF8 + hits[hitIndex][0];
                    break;
                }
            }
        }

        if (!((DRCloudCageStateFlags*)(state + 0x428))->hidden && hitDetected)
        {
            selectedTrail = *(DRCloudCageTrail**)(slot + 0x510);
            if (selectedTrail == NULL)
            {
                for (scanIndex = 0; scanIndex < DRCLOUDCAGE_TRAIL_COUNT; scanIndex++)
                {
                    selectedTrail = (DRCloudCageTrail*)(state + scanIndex * DRCLOUDCAGE_TRAIL_STRIDE +
                                                        DRCLOUDCAGE_TRAILS_OFFSET);
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
            selectedTrail->points[0].pad0E = *(u8*)(state + 0x4b4);
            selectedTrail->points[0].pad1E = *(u8*)(state + 0x4b4);
            selectedTrail->count += 2;
            *(f32*)(state + 0x51c) = ((GameObject*)obj)->anim.worldPosX;
            *(f32*)(state + 0x520) = ((GameObject*)obj)->anim.worldPosY;
            *(f32*)(state + 0x524) = ((GameObject*)obj)->anim.worldPosZ;
        }
        else
        {
            *(DRCloudCageTrail**)(slot + 0x510) = 0;
        }
    }
}

typedef struct DRCloudCagePulseParams
{
    u8 pad[8];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    f32 unk14;
} DRCloudCagePulseParams;

void fn_801EA240(f32 distanceScale, int obj, int state, int intensity, int unused, u8 channelFlags)
{
    f32 clamped;
    f32 d;
    f32 fv;
    int vol;
    f32 v;
    DRCloudCagePulseParams pulse;

    clamped = (distanceScale < lbl_803E5AE8)
                  ? lbl_803E5AE8
                  : ((distanceScale > lbl_803E5B08) ? lbl_803E5B08 : distanceScale);
    if (channelFlags & 1)
    {
        if (Sfx_IsPlayingFromObjectChannel(obj, 8))
        {
            gDrCloudCageWindVolume = lbl_803E5B0C * clamped;
            if (gDrCloudCageWindVolume < lbl_803E5AE8)
            {
                gDrCloudCageWindVolume = -gDrCloudCageWindVolume;
            }
            if (gDrCloudCageWindVolume < *(f32*)&lbl_803E5B10)
            {
                gDrCloudCageWindVolume = lbl_803E5B10;
            }
            if (gDrCloudCageWindVolume > *(f32*)&lbl_803E5B14)
            {
                gDrCloudCageWindVolume = lbl_803E5B14;
            }
            if (*(f32*)(state + 0x424) < lbl_803E5B18)
            {
                vol = (int)(lbl_803E5B1C * clamped);
                if (vol < 0)
                {
                    vol = -vol;
                }
                if (vol > 0x7f)
                {
                    vol = 0x7f;
                }
            }
            else
            {
                vol = 0;
            }
            Sfx_SetObjectChannelVolume(obj, 8, vol & 0xff, lbl_803E5B20 + gDrCloudCageWindVolume / lbl_803E5B08);
        }
    }
    if (channelFlags & 2)
    {
        if (Sfx_IsPlayingFromObjectChannel(obj, 1))
        {
            if (*(f32*)(state + 0x424) < lbl_803E5B18)
            {
                d = 0.0f;
                if (d != clamped)
                {
                    d = clamped * (f32)((GameObject*)obj)->anim.rotZ / lbl_803E5B24;
                }
                gDrCloudCageWindVolume = d;
                fv = (f32)(f64)d;
                if (fv < 0.0f)
                {
                    gDrCloudCageWindVolume = -fv;
                }
                else if (fv > lbl_803E5AEC)
                {
                    gDrCloudCageWindVolume = lbl_803E5AEC;
                }
                vol = (int)(lbl_803E5B28 * gDrCloudCageWindVolume);
                if ((f32)vol > lbl_803E5B28)
                {
                    vol = 0x7f;
                }
                else if ((f32)vol < 0.0f)
                {
                    vol = 0;
                }
                Sfx_SetObjectChannelVolume(obj, 1, vol & 0xff, lbl_803E5B20 + gDrCloudCageWindVolume);
            }
        }
    }
    if (channelFlags & 4)
    {
        Sfx_PlayFromObject(obj, *(u16*)(state + 0x440));
        Sfx_PlayFromObject(obj, SFXsp_htop_hurry2);
        if (intensity > 5)
        {
            *(f32*)(state + 0x3f8) = *(f32*)(state + 0x3f8) + timeDelta;
        }
        else
        {
            if (*(f32*)(state + 0x3f8) > lbl_803E5B10)
            {
                *(f32*)(state + 0x3f8) = -(lbl_803E5B2C * timeDelta - *(f32*)(state + 0x3f8));
            }
        }
        if (*(f32*)(state + 0x3f8) > *(f32*)&lbl_803E5B08)
        {
            *(f32*)(state + 0x3f8) = lbl_803E5B08;
        }
        if (*(f32*)(state + 0x3f8) < *(f32*)&lbl_803E5B30)
        {
            *(f32*)(state + 0x3f8) = lbl_803E5B30;
        }
        v = *(f32*)(state + 0x3f8);
        Sfx_SetObjectChannelVolume(obj, 2, (int)v, v * lbl_803E5B38 + lbl_803E5B34);
        if (intensity > 5)
        {
            *(f32*)(state + 0x3f4) = lbl_803E5B3C + intensity;
        }
        else
        {
            if (*(f32*)(state + 0x3f4) > lbl_803E5B3C)
            {
                *(f32*)(state + 0x3f4) = -(lbl_803E5AF8 * timeDelta - *(f32*)(state + 0x3f4));
            }
        }
        if (*(f32*)(state + 0x3f4) > *(f32*)&lbl_803E5B40)
        {
            *(f32*)(state + 0x3f4) = lbl_803E5B40;
        }
        if (*(f32*)(state + 0x3f4) < *(f32*)&lbl_803E5B44)
        {
            *(f32*)(state + 0x3f4) = lbl_803E5B44;
        }
        v = *(f32*)(state + 0x3f4);
        Sfx_SetObjectChannelVolume(obj, 4, (int)v, v / lbl_803E5B48);
        pulse.unkC = lbl_803E5B4C;
        pulse.unk10 = lbl_803E5B50;
        pulse.unk14 = lbl_803E5B54;
        pulse.unk8 = lbl_803E5AE8;
        objfx_spawnLightPulse(obj, lbl_803E5AF8, 2, 0, 1, *(f32*)(state + 0x3f4) / lbl_803E5B58,
                              &pulse);
        pulse.unkC = lbl_803E5B5C;
        objfx_spawnLightPulse(obj, lbl_803E5AF8, 2, 0, 1, *(f32*)(state + 0x3f4) / lbl_803E5B58,
                              &pulse);
    }
    fn_801E9C00(obj, state);
}

f32 fn_801EA678(int obj, int state)
{
    f32 result;
    f32 d;
    f32 templateMetric;
    f32 stateMetric;
    int rank;

    if ((lbl_803DC0BC == -1) ||
        (rank = (*gCheckpointInterface)->getRouteRank((CheckpointRankItem*)(state + 0x28)),
         lbl_803DC0BC > rank))
    {
        if (lbl_803DC0BC == -1)
        {
            rank = Obj_GetPlayerObject();
            d = Vec_distance((int*)&((GameObject*)obj)->anim.worldPosX, (int*)(rank + 0x18));
            d = d * lbl_803E5AF8;
        }
        else
        {
            templateMetric = lbl_803E5B48 * (f32) * (s32*)((u8*)lbl_803AD088 + 0x1c) +
                lbl_803E5B48 * *(f32*)((u8*)lbl_803AD088 + 0xc);
            stateMetric = lbl_803E5B48 * (f32) * (s32*)(state + 0x44) +
                lbl_803E5B48 * *(f32*)(state + 0x34);
            d = templateMetric - stateMetric;
            d = (d >= lbl_803E5AE8) ? d : -d;
        }
        if (d <= *(f32*)(state + 0x1c))
        {
            result = *(f32*)(state + 0x24);
        }
        else if (d >= *(f32*)(state + 0x18))
        {
            result = *(f32*)(state + 0x20);
        }
        else
        {
            f32 ratio = (d - *(f32*)(state + 0x1c)) /
                    (*(f32*)(state + 0x18) - *(f32*)(state + 0x1c));
            d = *(f32*)((u8*)state + 0x24);
            result = ratio * (*(f32*)(state + 0x20) - d) + d;
        }
        if (*(u8*)(state + 0x434) == 0)
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
