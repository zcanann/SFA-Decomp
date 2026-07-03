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

/*
 * DRCloudCageState - file-local overlay of the DR_CloudRunner cage object's
 * extra block (obj+0xB8). Only the scalar fields this DLL reads/writes are
 * named; the rest is padding. state is passed as a raw int handle, so it is
 * cast to this type per-access (byte-neutral) rather than retyped as a
 * pointer, which would perturb cross-function base CSE.
 */
typedef struct DRCloudCageState
{
    u8 pad00[0x18];
    f32 distFar;              /* 0x18: d >= distFar clamps result to valFar */
    f32 distNear;             /* 0x1C: d <= distNear clamps result to valNear */
    f32 valFar;               /* 0x20 */
    f32 valNear;              /* 0x24 */
    u8 pad28[0x3F4 - 0x28];
    f32 channel4Vol;          /* 0x3F4: sfx channel 4 volume accumulator */
    f32 channel2Vol;          /* 0x3F8: sfx channel 2 volume accumulator */
    u8 pad3FC[0x410 - 0x3FC];
    s32 rotZOffset;           /* 0x410: added to obj rotZ before matrix build */
    u8 pad414[0x424 - 0x414];
    f32 distanceGate;         /* 0x424: distance below which wind/engine sfx play */
    DRCloudCageStateFlags stateFlags; /* 0x428: bit0 hidden */
    u8 pad429[0x434 - 0x429];
    u8 routeGateActive;       /* 0x434: 0 => route-distance gate applies */
    u8 pad435[0x440 - 0x435];
    u16 windSfxId;            /* 0x440: channel-4 wind sfx id */
    u8 pad442[0x4B4 - 0x442];
    u8 trailColorByte;        /* 0x4B4: stored into each new trail point pair */
    u8 pad4B5[0x51C - 0x4B5];
    f32 lastSpawnPosX;        /* 0x51C: obj world position at last trail spawn */
    f32 lastSpawnPosY;        /* 0x520 */
    f32 lastSpawnPosZ;        /* 0x524 */
} DRCloudCageState;
STATIC_ASSERT(offsetof(DRCloudCageState, distFar) == 0x18);
STATIC_ASSERT(offsetof(DRCloudCageState, channel4Vol) == 0x3F4);
STATIC_ASSERT(offsetof(DRCloudCageState, rotZOffset) == 0x410);
STATIC_ASSERT(offsetof(DRCloudCageState, distanceGate) == 0x424);
STATIC_ASSERT(offsetof(DRCloudCageState, stateFlags) == 0x428);
STATIC_ASSERT(offsetof(DRCloudCageState, routeGateActive) == 0x434);
STATIC_ASSERT(offsetof(DRCloudCageState, windSfxId) == 0x440);
STATIC_ASSERT(offsetof(DRCloudCageState, trailColorByte) == 0x4B4);
STATIC_ASSERT(offsetof(DRCloudCageState, lastSpawnPosX) == 0x51C);

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

            /* The three active head-trail pointer slots (0x510/0x514/0x518)
             * stay raw: the spawn loop below walks them via a running `slot`
             * base (slot += 4), so naming them as fixed struct fields shifts
             * the walker's addressing/CSE. */
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
        transform.rotZ = (s16)(((GameObject*)obj)->anim.rotZ + ((DRCloudCageState*)state)->rotZOffset);
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

        if (!((DRCloudCageState*)state)->stateFlags.hidden && hitDetected)
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
            selectedTrail->points[0].pad0E = ((DRCloudCageState*)state)->trailColorByte;
            selectedTrail->points[0].pad1E = ((DRCloudCageState*)state)->trailColorByte;
            selectedTrail->count += 2;
            ((DRCloudCageState*)state)->lastSpawnPosX = ((GameObject*)obj)->anim.worldPosX;
            ((DRCloudCageState*)state)->lastSpawnPosY = ((GameObject*)obj)->anim.worldPosY;
            ((DRCloudCageState*)state)->lastSpawnPosZ = ((GameObject*)obj)->anim.worldPosZ;
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
            if (((DRCloudCageState*)state)->distanceGate < lbl_803E5B18)
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
            if (((DRCloudCageState*)state)->distanceGate < lbl_803E5B18)
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
        Sfx_PlayFromObject(obj, ((DRCloudCageState*)state)->windSfxId);
        Sfx_PlayFromObject(obj, SFXsp_htop_hurry2);
        if (intensity > 5)
        {
            ((DRCloudCageState*)state)->channel2Vol = ((DRCloudCageState*)state)->channel2Vol + timeDelta;
        }
        else
        {
            if (((DRCloudCageState*)state)->channel2Vol > lbl_803E5B10)
            {
                ((DRCloudCageState*)state)->channel2Vol = -(lbl_803E5B2C * timeDelta - ((DRCloudCageState*)state)->channel2Vol);
            }
        }
        if (((DRCloudCageState*)state)->channel2Vol > *(f32*)&lbl_803E5B08)
        {
            ((DRCloudCageState*)state)->channel2Vol = lbl_803E5B08;
        }
        if (((DRCloudCageState*)state)->channel2Vol < *(f32*)&lbl_803E5B30)
        {
            ((DRCloudCageState*)state)->channel2Vol = lbl_803E5B30;
        }
        v = ((DRCloudCageState*)state)->channel2Vol;
        Sfx_SetObjectChannelVolume(obj, 2, (int)v, v * lbl_803E5B38 + lbl_803E5B34);
        if (intensity > 5)
        {
            ((DRCloudCageState*)state)->channel4Vol = lbl_803E5B3C + intensity;
        }
        else
        {
            if (((DRCloudCageState*)state)->channel4Vol > lbl_803E5B3C)
            {
                ((DRCloudCageState*)state)->channel4Vol = -(lbl_803E5AF8 * timeDelta - ((DRCloudCageState*)state)->channel4Vol);
            }
        }
        if (((DRCloudCageState*)state)->channel4Vol > *(f32*)&lbl_803E5B40)
        {
            ((DRCloudCageState*)state)->channel4Vol = lbl_803E5B40;
        }
        if (((DRCloudCageState*)state)->channel4Vol < *(f32*)&lbl_803E5B44)
        {
            ((DRCloudCageState*)state)->channel4Vol = lbl_803E5B44;
        }
        v = ((DRCloudCageState*)state)->channel4Vol;
        Sfx_SetObjectChannelVolume(obj, 4, (int)v, v / lbl_803E5B48);
        pulse.unkC = lbl_803E5B4C;
        pulse.unk10 = lbl_803E5B50;
        pulse.unk14 = lbl_803E5B54;
        pulse.unk8 = lbl_803E5AE8;
        objfx_spawnLightPulse(obj, lbl_803E5AF8, 2, 0, 1, ((DRCloudCageState*)state)->channel4Vol / lbl_803E5B58,
                              &pulse);
        pulse.unkC = lbl_803E5B5C;
        objfx_spawnLightPulse(obj, lbl_803E5AF8, 2, 0, 1, ((DRCloudCageState*)state)->channel4Vol / lbl_803E5B58,
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
            /* state+0x28 is the CheckpointRankItem passed to getRouteRank;
             * its linkDepth (+0x1C = 0x44) and routeProgress (+0xC = 0x34) are
             * read here. These stay raw: spelling them as nested-struct members
             * (rankItem.linkDepth / rankItem.routeProgress) shifts codegen. */
            templateMetric = lbl_803E5B48 * (f32) * (s32*)((u8*)lbl_803AD088 + 0x1c) +
                lbl_803E5B48 * *(f32*)((u8*)lbl_803AD088 + 0xc);
            stateMetric = lbl_803E5B48 * (f32) * (s32*)(state + 0x44) +
                lbl_803E5B48 * *(f32*)(state + 0x34);
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
