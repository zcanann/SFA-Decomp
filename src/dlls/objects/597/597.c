/*
 * DLL 597 - SnowBike vehicle logic, including its trail, route, attachment,
 * collision, movement, and rendering helpers.
 */
#include "dlls/object_descriptor.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXEnum.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "dolphin/os/OSReport.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/camera_interface.h"
#include "main/checkpoint_interface.h"
#include "main/dll/DR/DRcloudcage.h"
#include "main/dll/DR/DRpickup.h"
#include "main/dll/DR/DRshackle.h"
#include "main/dll/DR/drcloudcage_internal.h"
#include "main/dll/SP/dll_0287_spscarab.h"
#include "main/dll/dll_0015_curves.h"
#include "main/dll/dll_0255_snowbike.h"
#include "main/dll/dll_801e991c.h"
#include "main/dll/drhightop.h"
#include "main/dll/objfx_api.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/dll/tricky_api.h"
#include "main/frame_timing.h"
#include "main/game_ui_interface.h"
#include "main/gamebits.h"
#include "main/gametext_show_api.h"
#include "main/lightmap.h"
#include "main/lightmap_api.h"
#include "main/maketex_api.h"
#include "main/mm.h"
#include "main/obj_group.h"
#include "main/obj_path.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/pad.h"
#include "main/rcp_dolphin_api.h"
#include "main/shader_api.h"
#include "main/sky.h"
#include "main/texture.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "string.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_geom_api.h"
#include "track/intersect_render_setup_api.h"
#include "main/dll/DR/DRcradle.h"

#define SNOWBIKE_OBJGROUP           0xa
#define SNOWBIKE_AIRMETER_BGTEXTURE 0x5cd

const GXColor lbl_803E5AE0 = {5, 5, 5, 5};
const GXColor sSnowBikeTrailTevColor = {0x20, 0x20, 0x20, 0x80};

typedef union SnowBikeCheckpointRank
{
    CheckpointRankItem item;
    u8 bytes[0x38];
} SnowBikeCheckpointRank;

STATIC_ASSERT(sizeof(SnowBikeCheckpointRank) == 0x38);

SnowBikeCheckpointRank gSnowBikeLeaderRankItem;

f32 gSnowBikePathSetupPoints[19] = {
    -6.5f, 0.0f,  -13.0f, 6.5f, 0.0f, -13.0f, 6.5f, 0.0f, 13.0f, -6.5f,
    0.0f,  13.0f, 1.0f,   1.0f, 1.0f, 1.0f,   0.0f, 0.0f, 0.0f,
};

int gDrHighTopHitObjectKinds[] = {
    0x72, 0x16D, 0x170, 0x16C, 0x16F, 0x38C, 0x389, 0x38A, 0x4D3, 0x38D, 0x38E, 0x4D4,
};

/* Hittable rider, bike, and scenery object IDs. */
s16 gSnowBikeHitObjectIdTable[26] = {
    0, 365, 0, 368, 0, 364, 0, 367, 0, 905, 0, 906, 0, 1235, 0, 909, 0, 910, 0, 1236, 1175, 1176, 1180, 930, 931, 1180,
};

int gSnowBikeMountRomListTable[6] = {0x30C60, 0x30C60, 0x30C60, 0xC9E, 0xC9F, 0xCB3};

f32 gSnowBikeCollisionRadius = 15.0f;
int gSnowBikeLeaderRouteRank = -1;
f32 gSnowBikeClawBikeVelLimitZ = 8.5f;
f32 gSnowBikeCrBikeVelLimitZ = 6.0f;
f32 gSnowBikeBoostFxDamping = 1.05f;
int gSnowBikeAirRefillAmount = 5000;
int gSnowBikeBoostFxDuration = 60;
int gSnowBikeHardCollisionFxDuration = 20;
f32 gSnowBikeAirDrainRate = 4.7f;
s16 gSnowBikeWrongWayAngleThreshold = 0x4000;
f32 gDrCloudCageRouteDistGate = 2000.0f;
char sSnowBikeVelDebugFmt[] = "vel %f\n";

/* Trail renderer used by the SnowBike effects below. */

#define GX_BM_BLEND       1
#define GX_BL_SRCALPHA    4
#define GX_BL_INVSRCALPHA 5
#define GX_LO_NOOP        5
#define GX_LEQUAL         3
#define GX_ALWAYS         7
#define GX_AOP_AND        0
#define GX_CULL_NONE      0
#define GX_VA_POS         9
#define GX_VA_CLR0        11
#define GX_VA_TEX0        13
#define GX_DIRECT         1
#define GX_QUADS          0x80
#define GX_VTXFMT2        2

f32 gDrCloudCageWindVolume;
Texture* sSnowBikeTrailTexture;

#define GXWGFifo (*(volatile PPCWGPipe*)0xCC008000)

static inline void shPos3f32(const f32 x, const f32 y, const f32 z)
{
    GXWGFifo.f32 = x;
    GXWGFifo.f32 = y;
    GXWGFifo.f32 = z;
}

static inline void shColor4u8(u8 r, u8 g, u8 b, u8 a)
{
    GXWGFifo.u8 = r;
    GXWGFifo.u8 = g;
    GXWGFifo.u8 = b;
    GXWGFifo.u8 = a;
}

static inline void shTexCoord2f32(const f32 s, const f32 t)
{
    GXWGFifo.f32 = s;
    GXWGFifo.f32 = t;
}

void SnowBike_DrawTrails(int p1, char* table)
{
    u8 r;
    u8 g;
    u8 b;
    GXColor color;
    f32* verts;
    char* p;
    int i;
    int j;
    f32 texT;
    f32 texS;

    color = sSnowBikeTrailTevColor;
    selectTexture((Texture*)sSnowBikeTrailTexture, 0);
    gxTevResetStages();
    gxTevTextureTimesRasStage();
    gxTevCommitStages();
    GXSetTevColor(GX_TEVREG1, color);
    gxSetZMode_(1, GX_LEQUAL, 0);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXLoadPosMtxImm((const f32(*)[4])Camera_GetViewMatrix(), GX_PNMTX0);
    GXSetCurrentMtx(GX_PNMTX0);
    getAmbientColor(0, &r, &g, &b);
    i = 0;
    p = table;
    for (; i < 9; i++)
    {
        if (((*(u8*)(p + 0x4ce) & 1) != 0) && (*(s16*)(p + 0x4cc) >= 4))
        {
            j = 0;
            verts = *(f32**)(p + 0x4c8);
            texS = 0.0f;
            texT = 1.0f;
            while (j < *(s16*)(p + 0x4cc) - 2)
            {
                GXBegin(GX_QUADS, GX_VTXFMT2, 4);
                shPos3f32(verts[0] - playerMapOffsetX, verts[0 + 1], verts[0 + 2] - playerMapOffsetZ);
                shColor4u8(*(u8*)&r, *(u8*)&g, *(u8*)&b, (u8) * (s16*)((char*)verts + 0xc));
                shTexCoord2f32(texS, texS);
                shPos3f32(verts[4] - playerMapOffsetX, verts[4 + 1], verts[4 + 2] - playerMapOffsetZ);
                shColor4u8(*(u8*)&r, *(u8*)&g, *(u8*)&b, (u8) * (s16*)((char*)verts + 0x1c));
                shTexCoord2f32(texT, texS);
                shPos3f32(verts[0xc] - playerMapOffsetX, verts[0xc + 1], verts[0xc + 2] - playerMapOffsetZ);
                shColor4u8(*(u8*)&r, *(u8*)&g, *(u8*)&b, (u8) * (s16*)((char*)verts + 0x3c));
                shTexCoord2f32(texT, texS);
                shPos3f32(verts[8] - playerMapOffsetX, verts[8 + 1], verts[8 + 2] - playerMapOffsetZ);
                shColor4u8(*(u8*)&r, *(u8*)&g, *(u8*)&b, (u8) * (s16*)((char*)verts + 0x2c));
                shTexCoord2f32(texS, texS);
                verts += 8;
                j += 2;
            }
        }
        p += 8;
    }
}

/*
 * Cloud-cage trail and audio effects used by the SnowBike.
 *
 * Provides three routines for the vehicle's trail, sound, and pitch state:
 *   drcloudcage_updateTrails  builds and fades the swirling cloud-trail ribbons. Each of the
 *                three emitters casts a transformed segment, ray-tests it
 *                (hitDetectFn_80065e50, mask 0x20), and when it strikes ground
 *                inserts a new fully-opaque point pair at the head of one of the
 *                nine trail buffers; every existing pair's alpha decays by
 *                timeDelta and exhausted trails are freed.
 *   drcloudcage_updateEngineFx  drives the wind/engine sfx channels (8,1,2,4) by distance and
 *                rotZ, clamps each channel volume, and spawns two light pulses;
 *                then advances the trails via drcloudcage_updateTrails.
 *   drcloudcage_getRouteIntensity  returns a distance/route-rank weighted scalar (pitch/intensity)
 *                from the checkpoint route rank, falling back to player distance
 *                when no rank gate (gSnowBikeLeaderRouteRank) is set.
 *
 * State is addressed through raw byte offsets into the owning object's extra
 * block; trail buffers begin at DRCLOUDCAGE_TRAILS_OFFSET (DRCLOUDCAGE_TRAIL_COUNT
 * records of DRCLOUDCAGE_TRAIL_STRIDE bytes), with the three active head-trail
 * pointers immediately following at +0x510/+0x514/+0x518.
 */

/* Shared route-rank state used by the trail, pitch, and vehicle routines. */
struct DRCloudCagePoints;

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

void drcloudcage_updateTrails(GameObject* obj, int state)
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
            fade = 8.0f;
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
    zero = 0.0f;
    maxDelta = 20.0f;
    minDelta = -20.0f;
    scaleV = 1.0f;
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
                        endpoint[1] = 0.5f + hits[hitIndex]->height;
                        break;
                    }
                }
                else if ((deltaY >= minDelta) && (deltaY < maxDelta))
                {
                    hitDetected = 1;
                    endpoint[1] = 0.5f + hits[hitIndex]->height;
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

typedef struct DRCloudCagePulseParams
{
    u8 pad[8];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    f32 unk14;
} DRCloudCagePulseParams;

void drcloudcage_updateEngineFx(GameObject* obj, void* state, f32 distanceScale, int intensity, u8* unused,
                                u8 channelFlags)
{
    f32 clamped;
    f32 windVol;
    f32 fv;
    int vol;
    f32 channelVol;
    f32 channelVol4;
    DRCloudCagePulseParams pulse;

    clamped =
        (distanceScale < 0.0f) ? 0.0f : ((distanceScale > 70.0f) ? 70.0f : distanceScale);
    if (channelFlags & 1)
    {
        if (Sfx_IsPlayingFromObjectChannel((int)obj, 8))
        {
            gDrCloudCageWindVolume = 11.6f * clamped;
            if (gDrCloudCageWindVolume < 0.0f)
            {
                gDrCloudCageWindVolume = -gDrCloudCageWindVolume;
            }
            if (gDrCloudCageWindVolume < 40.0f)
            {
                gDrCloudCageWindVolume = 40.0f;
            }
            if (gDrCloudCageWindVolume > 200.0f)
            {
                gDrCloudCageWindVolume = 200.0f;
            }
            if (((DRCloudCageState*)state)->distanceGate < 18.0f)
            {
                vol = (int)(30.0f * clamped);
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
            Sfx_SetObjectChannelVolume((u32)obj, 8, vol & 0xff,
                                       0.1f + gDrCloudCageWindVolume / 70.0f);
        }
    }
    if (channelFlags & 2)
    {
        if (Sfx_IsPlayingFromObjectChannel((int)obj, 1))
        {
            if (((DRCloudCageState*)state)->distanceGate < 18.0f)
            {
                windVol = 0.0f;
                if (windVol != clamped)
                {
                    windVol = clamped * (f32)obj->anim.rotZ / 30000.0f;
                }
                gDrCloudCageWindVolume = windVol;
                fv = (f32)(f64)windVol;
                if (fv < 0.0f)
                {
                    gDrCloudCageWindVolume = -fv;
                }
                else if (fv > 1.0f)
                {
                    gDrCloudCageWindVolume = 1.0f;
                }
                vol = (int)(127.0f * gDrCloudCageWindVolume);
                if ((f32)vol > 127.0f)
                {
                    vol = 0x7f;
                }
                else if ((f32)vol < 0.0f)
                {
                    vol = 0;
                }
                Sfx_SetObjectChannelVolume((u32)obj, 1, vol & 0xff, 0.1f + gDrCloudCageWindVolume);
            }
        }
    }
    if (channelFlags & 4)
    {
        Sfx_PlayFromObject((u32)obj, ((DRCloudCageState*)state)->windSfxId);
        Sfx_PlayFromObject((u32)obj, SFXTRIG_tr_gal_rumblelp11);
        if (intensity > 5)
        {
            ((DRCloudCageState*)state)->channel2Vol = ((DRCloudCageState*)state)->channel2Vol + timeDelta;
        }
        else
        {
            if (((DRCloudCageState*)state)->channel2Vol > 40.0f)
            {
                ((DRCloudCageState*)state)->channel2Vol =
                    -(1.5f * timeDelta - ((DRCloudCageState*)state)->channel2Vol);
            }
        }
        if (((DRCloudCageState*)state)->channel2Vol > 70.0f)
        {
            ((DRCloudCageState*)state)->channel2Vol = 70.0f;
        }
        if (((DRCloudCageState*)state)->channel2Vol < 45.0f)
        {
            ((DRCloudCageState*)state)->channel2Vol = 45.0f;
        }
        channelVol = ((DRCloudCageState*)state)->channel2Vol;
        ((void (*)(GameObject*, u32, u8, f32))Sfx_SetObjectChannelVolume)(obj, 2, channelVol, channelVol / 256.0f + 0.3f);
        if (intensity > 5)
        {
            ((DRCloudCageState*)state)->channel4Vol = 60.0f + intensity;
        }
        else
        {
            if (((DRCloudCageState*)state)->channel4Vol > 60.0f)
            {
                ((DRCloudCageState*)state)->channel4Vol =
                    -(0.5f * timeDelta - ((DRCloudCageState*)state)->channel4Vol);
            }
        }
        if (((DRCloudCageState*)state)->channel4Vol > 80.0f)
        {
            ((DRCloudCageState*)state)->channel4Vol = 80.0f;
        }
        if (((DRCloudCageState*)state)->channel4Vol < 65.0f)
        {
            ((DRCloudCageState*)state)->channel4Vol = 65.0f;
        }
        channelVol4 = ((DRCloudCageState*)state)->channel4Vol;
        ((void (*)(GameObject*, u32, u8, f32))Sfx_SetObjectChannelVolume)(obj, 4, channelVol4, channelVol4 / 100.0f);
        pulse.unkC = -5.3f;
        pulse.unk10 = 4.4f;
        pulse.unk14 = 24.0f;
        pulse.unk8 = 0.0f;
        objfx_spawnLightPulse(obj, 0.5f, 2, 0, 1, ((DRCloudCageState*)state)->channel4Vol / 250.0f,
                              &pulse);
        pulse.unkC = 5.3f;
        objfx_spawnLightPulse(obj, 0.5f, 2, 0, 1, ((DRCloudCageState*)state)->channel4Vol / 250.0f,
                              &pulse);
    }
    drcloudcage_updateTrails(obj, (int)state);
}

f32 drcloudcage_getRouteIntensity(GameObject* obj, int state)
{
    f32 result;
    f32 d;
    f32 templateMetric;
    f32 stateMetric;
    int rank;

    if ((gSnowBikeLeaderRouteRank == -1) ||
        (rank = (*gCheckpointInterface)->getRouteRank((CheckpointRankItem*)(state + 0x28)), gSnowBikeLeaderRouteRank > rank))
    {
        if (gSnowBikeLeaderRouteRank == -1)
        {
            rank = (int)Obj_GetPlayerObject();
            d = Vec_distance(&obj->anim.worldPosX, (f32*)(rank + 0x18));
            d *= 0.5f;
        }
        else
        {
            /* state+0x28 is the CheckpointRankItem passed to getRouteRank;
             * its linkDepth (+0x1C = 0x44) and routeProgress (+0xC = 0x34) are
             * read here. These stay raw: spelling them as nested-struct members
             * (rankItem.linkDepth / rankItem.routeProgress) shifts codegen. */
            templateMetric = 100.0f * (f32) * (s32*)(gSnowBikeLeaderRankItem.bytes + 0x1c) +
                             100.0f * *(f32*)(gSnowBikeLeaderRankItem.bytes + 0xc);
            stateMetric = 100.0f * (f32) * (s32*)(state + 0x44) + 100.0f * *(f32*)(state + 0x34);
            d = templateMetric - stateMetric;
            d = (d >= 0.0f) ? d : -d;
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
            d = (d >= 0.0f) ? d : -d;
            if (d > gDrCloudCageRouteDistGate)
            {
                result = 0.0f;
            }
        }
    }
    else
    {
        rank = (*gCheckpointInterface)->getRouteRank((CheckpointRankItem*)(state + 0x28));
        if (rank == 2)
        {
            result = 7.0f;
        }
        else
        {
            result = 6.5f;
        }
    }
    return result;
}

/*
 * SnowBike shackle swing and attachment math.
 *
 * drshackle_updateAttachedPosition rides the shackle along its checkpoint
 * route while it tracks the player: on first contact it anchors to the
 * route (snapping yaw, seeding swing accel and floor offset), thereafter
 * it advances the route and blends the swing each frame.
 * drshackle_updateSwingBlend computes the per-frame swing-blend factor
 * from the yaw delta between the object and its anchor, clamps it, and
 * decides the return direction.
 *
 * Several `lbl_803E5Bxx` are plain float constants (see the inline value
 * comments).
 */

STATIC_ASSERT(offsetof(ShackleSwingState, anchorX) == 0x0C);
STATIC_ASSERT(offsetof(ShackleSwingState, collider) == 0x28);
STATIC_ASSERT(offsetof(ShackleSwingState, colliderMode) == 0x5D);
STATIC_ASSERT(offsetof(ShackleSwingState, attachment) == 0x178);
STATIC_ASSERT(offsetof(ShackleSwingState, distanceFade) == 0x3E4);
STATIC_ASSERT(offsetof(ShackleSwingState, yaw) == 0x40C);
STATIC_ASSERT(offsetof(ShackleSwingState, targetYaw) == 0x40E);
STATIC_ASSERT(offsetof(ShackleSwingState, flags) == 0x428);
STATIC_ASSERT(offsetof(ShackleSwingState, swingAccel) == 0x430);
STATIC_ASSERT(offsetof(ShackleSwingState, floorAdjustFlag) == 0x434);
STATIC_ASSERT(offsetof(ShackleSwingState, swingCommand) == 0x44C);
STATIC_ASSERT(offsetof(ShackleSwingState, swingReturn) == 0x458);
STATIC_ASSERT(offsetof(ShackleSwingState, swingBlend) == 0x45C);
STATIC_ASSERT(offsetof(ShackleSwingState, unk494) == 0x494);
STATIC_ASSERT(offsetof(ShackleSwingState, lastPitch) == 0x49C);

#define DRSHACKLE_ANGLE_STEP         0xb6
#define DRSHACKLE_SWING_BLEND_LIMIT  0x41
#define DRSHACKLE_SWING_RETURN_LEFT  0x100
#define DRSHACKLE_ANGLE_RETURN_LIMIT 0x2aaa

int drshackle_updateSwingBlend(GameObject* obj, ShackleSwingState* state)
{
    GameObject* o = (GameObject*)obj;
    ShackleSwingState* s = state;
    int hitResult;
    int yawDelta;
    f32 fade;
    f32 zero;

    zero = 0.0f;
    {
        f32 dx = o->anim.localPosX;
        f32 dz = o->anim.localPosZ;
        dx = dx - s->anchorX;
        dz = dz - s->anchorZ;
        fade = 180.0f - sqrtf(dx * dx + dz * dz);
    }

    if (s->distanceFade != zero)
    {
        fade = fade + (((fade - 40.0f) < 0.0f)
                           ? 0.0f
                           : (((fade - 40.0f) > 70.0f) ? 70.0f : (fade - 40.0f)));
    }
    if (fade < 0.0f)
    {
        fade = 0.0f;
    }

    hitResult = (*gCheckpointInterface)->advanceRoute((u8*)state, &s->collider, fade, s->colliderMode, 1, 0);

    (*gCheckpointInterface)->getRouteHeading((GameObject*)o, &s->collider);

    (*gCheckpointInterface)->queueRouteRankItem((CheckpointRankItem*)&s->collider);

    if (hitResult != 0)
    {
        s->swingBlend = 0.0f;
        return 0;
    }

    yawDelta = (s32)(u16)getAngle(o->anim.localPosX - s->anchorX, o->anim.localPosZ - s->anchorZ) - (s32)(u16)s->yaw;
    if (0x8000 < yawDelta)
    {
        yawDelta = yawDelta + -0xffff;
    }
    if (yawDelta < -0x8000)
    {
        yawDelta = yawDelta + 0xffff;
    }
    {
        s32 blendStep = yawDelta / DRSHACKLE_ANGLE_STEP;
        if (blendStep < -DRSHACKLE_SWING_BLEND_LIMIT)
        {
            blendStep = -DRSHACKLE_SWING_BLEND_LIMIT;
        }
        else if (blendStep > DRSHACKLE_SWING_BLEND_LIMIT)
        {
            blendStep = DRSHACKLE_SWING_BLEND_LIMIT;
        }
        s->swingBlend = (f32)(-blendStep);
    }
    s->swingCommand = 0;
    s->swingBlend = s->swingBlend / 56.0f;

    {
        f32 blend = s->swingBlend;
        s->swingBlend = (blend < -1.0f) ? -1.0f : ((blend > 1.0f) ? 1.0f : blend);
    }

    {
        f32 ang = drcloudcage_getRouteIntensity(o, (int)state);
        ang = -ang;
        if (s->lastPitch < ang || yawDelta > DRSHACKLE_ANGLE_RETURN_LIMIT || yawDelta < -DRSHACKLE_ANGLE_RETURN_LIMIT)
        {
            s->swingReturn = 0;
        }
        else if (s->lastPitch > ang)
        {
            s->swingReturn = DRSHACKLE_SWING_RETURN_LEFT;
        }
    }
    return 1;
}

int drshackle_updateAttachedPosition(GameObject* obj, ShackleSwingState* state)
{
    ShackleSwingState* s = state;
    ShackleFlags* flags;
    int mapBlockIdx;
    int hitResult;
    s16 angle;
    f32 floorOffset;

    flags = &s->flags;
    if (flags->active == 0)
    {
        return 0;
    }
    mapBlockIdx = objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ);
    if (mapBlockIdx > -1)
    {
        if (flags->positionAnchored == 0)
        {
            {
                f32 zero = 0.0f;
                s->unk494 = zero;
                s->unk498 = zero;
            }
            s->lastPitch = -drcloudcage_getRouteIntensity(obj, (int)state);
            hitResult = (*gCheckpointInterface)
                            ->advanceRoute((u8*)state, &s->collider, -s->lastPitch * timeDelta, s->colliderMode, 1, 0);
            (*gCheckpointInterface)->getRouteHeading(obj, &s->collider);
            (*gCheckpointInterface)->queueRouteRankItem((CheckpointRankItem*)&s->collider);
            if (hitResult != 0)
            {
                return 0;
            }

            SnowBike_ResetDynamics((int)obj, (int)state);
            angle = (s16)getAngle(obj->anim.localPosX - s->anchorX, obj->anim.localPosZ - s->anchorZ);
            obj->anim.rotX = angle;
            s->targetYaw = angle;
            s->yaw = angle;
            s->swingAccel = -0.05f;
            obj->anim.localPosX = s->anchorX;
            obj->anim.localPosY = s->anchorY;
            obj->anim.localPosZ = s->anchorZ;
            (*gPathControlInterface)->attachObject((void*)obj, (void*)s->attachment);
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosX = obj->anim.localPosX;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosY = obj->anim.localPosY;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosZ = obj->anim.localPosZ;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosX = obj->anim.worldPosX;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosY = obj->anim.worldPosY;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosZ = obj->anim.worldPosZ;

            if (s->floorAdjustFlag == 0)
            {
                hitDetectFn_800658a4(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &floorOffset,
                                     0);
                obj->anim.localPosY = obj->anim.localPosY - floorOffset;
                obj->anim.localPosY += 2.0f;
            }
            flags->positionAnchored = 1;
            return 0;
        }
        return drshackle_updateSwingBlend(obj, state) != 0;
    }

    hitResult = (*gCheckpointInterface)
                    ->advanceRoute((u8*)state, &s->collider, timeDelta * drcloudcage_getRouteIntensity(obj, (int)state), s->colliderMode,
                                   1, 0);
    (*gCheckpointInterface)->getRouteHeading(obj, &s->collider);
    (*gCheckpointInterface)->queueRouteRankItem((CheckpointRankItem*)&s->collider);
    if (hitResult != 0)
    {
        return 0;
    }

    angle = (s16)getAngle(obj->anim.localPosX - s->anchorX, obj->anim.localPosZ - s->anchorZ);
    obj->anim.rotX = angle;
    obj->anim.localPosX = s->anchorX;
    obj->anim.localPosY = s->anchorY;
    obj->anim.localPosZ = s->anchorZ;
    (*gPathControlInterface)->attachObject((void*)obj, (void*)s->attachment);
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosX = obj->anim.localPosX;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosY = obj->anim.localPosY;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosZ = obj->anim.localPosZ;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosX = obj->anim.worldPosX;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosY = obj->anim.worldPosY;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosZ = obj->anim.worldPosZ;
    flags->positionAnchored = 0;
    return 0;
}

/*
 * SnowBike "Hightop" vehicle helpers.
 *
 * Implements the per-frame logic of the snowbike vehicle: route following
 * along a checkpoint path (SnowBike_UpdateRouteFollowing / gCheckpointInterface), the air /
 * fuel meter and its UI + shutdown sequence (SnowBike_UpdateAirMeter), spawn / reset
 * latching (SnowBike_onSeqFree), the animation-event/sequence callback that seeds
 * the launch impulse from per-step velocity (SnowBike_SeqFn),
 * collision response and impact particle bursts (SnowBike_UpdateCollisionResponse), steering /
 * pitch-roll integration with rumble + camera shake (SnowBike_UpdateSteering), and the
 * exhaust/contrail particle drivers blended toward per-state targets
 * (SnowBike_UpdateExhaustFx). State lives in SnowBikeState (dll_0255_snowbike.h); flags428 is
 * a bitfield overlay byte read via the Hightop* flag structs below.
 */

typedef struct HightopFlags3
{
    u8 hi : 4;
    u8 active : 1;
    u8 lo : 3;
} HightopFlags3;

typedef struct HightopFlags
{
    u8 resetLatch : 1;
    u8 flags : 7;
} HightopFlags;

/* particle spray spawned in a burst loop (~0x32/framesThisStep) on a bike collision */
#define DRHIGHTOP_PARTFX_COLLISION_SPRAY 0x553
#define DRHIGHTOP_HIT_VOLUME_SLOT        0x15

void SnowBike_UpdateRouteFollowing(GameObject* obj, SnowBikeState* st)
{
    f32 pathStep;
    u32 gameBitSet;
    u32 absoluteHeadingDelta;
    s16 headingDelta;
    u16 routeHeading;
    s8 routeRank;

    if ((u32)(st->flags428 >> 3 & 1) == 0)
    {
        st->routeState.startCheckpointId = -1;
        st->routeState.matchedCheckpointId = -1;
        st->routeState.currentCheckpointId = -1;
        st->routeState.linkDepth = 0;
        gSnowBikeLeaderRouteRank = -1;
        gameBitSet = mainGetBit(st->gameBitPtr[0]);
        if (gameBitSet != 0)
        {
            st->routeFlags.active = 1;
        }
        if ((u32)(st->flags428 >> 3 & 1) != 0)
        {
            if ((u32)(st->flags428 >> 1 & 1) != 0)
            {
                SnowBike_resetToRomListPosition(obj);
            }
            else
            {
                (*gCheckpointInterface)
                    ->findRouteForObject(obj, &st->routeState, st->routeFilter);
            }
            (*gCheckpointInterface)->rewindRoute(&st->routeState);
        }
    }
    else
    {
        if ((u32)(st->flags428 >> 1 & 1) == 0)
        {
            routeHeading = (*gCheckpointInterface)->getRouteHeading(obj, &st->routeState);
            headingDelta = obj->anim.rotX - routeHeading;
            if (0x8000 < headingDelta)
            {
                headingDelta = headingDelta - 0xffff;
            }
            if (headingDelta < -0x8000)
            {
                headingDelta = headingDelta + 0xffff;
            }
            absoluteHeadingDelta = ((int)headingDelta >= 0) ? headingDelta : -headingDelta;
            if ((int)((u32)(((int)(absoluteHeadingDelta ^ gSnowBikeWrongWayAngleThreshold) >> 1) -
                             ((absoluteHeadingDelta ^ gSnowBikeWrongWayAngleThreshold) & absoluteHeadingDelta)) >> 0x1f) ==
                0)
            {
                pathStep = timeDelta;
            }
            else
            {
                pathStep = -timeDelta;
            }
            st->pathProgress = st->pathProgress + pathStep;
            pathStep = st->pathProgress;
            st->pathProgress =
                (pathStep < 0.0f) ? 0.0f : ((pathStep > 180.0f) ? 180.0f : pathStep);
            if (st->pathProgress > 90.0f)
            {
                gameTextShow(0x475);
            }
            (*gCheckpointInterface)->queueRouteRankItem(&st->rankItem);
            st->routeRank = (s8)(*gCheckpointInterface)->getRouteRank(&st->rankItem);
            routeRank = st->routeRank;
            if ((routeRank == 1) && (gSnowBikeLeaderRouteRank == -1))
            {
                gSnowBikeLeaderRouteRank = -1;
            }
            else
            {
                gSnowBikeLeaderRouteRank = routeRank;
                gSnowBikeLeaderRankItem.item.linkDepth = st->routeState.linkDepth;
                gSnowBikeLeaderRankItem.item.routeProgress = st->routeState.routeProgress;
            }
        }
        gameBitSet = mainGetBit(st->gameBitPtr[1]);
        if (gameBitSet != 0)
        {
            st->routeFlags.active = 0;
        }
    }
}

void SnowBike_UpdateAirMeter(u32 obj, int stateRaw)
{
    SnowBikeState* st = (SnowBikeState*)stateRaw;
    f32 rate;
    f32 lim;
    f32 td;

    if ((u32)(st->flags428 >> 5 & 1) != 0)
    {
        if (st->airMeterCurrent >= 0.0f)
        {
            td = timeDelta;
            st->airMeterCurrent -= td * gSnowBikeAirDrainRate + (f32)(s32)(st->airDrainRate * (td * PSVECMag(&st->localVelX)));
            lim = 0.0f;
            if (lim != st->airMeterRefillTimer)
            {
                rate = 200.0f;
                st->airMeterCurrent = rate * timeDelta + st->airMeterCurrent;
                st->airMeterRefillTimer = st->airMeterRefillTimer - (f32)(s32)(rate * timeDelta);
                st->airMeterRefillTimer =
                    (st->airMeterRefillTimer < lim)
                        ? lim
                        : ((st->airMeterRefillTimer > 100000.0f) ? 100000.0f : st->airMeterRefillTimer);
                st->airMeterCurrent =
                    (st->airMeterCurrent < 0.0f)
                        ? 0.0f
                        : ((st->airMeterCurrent > st->airMeterMax) ? st->airMeterMax : st->airMeterCurrent);
            }
            if (st->airMeterCurrent < 10000.0f)
            {
                Sfx_KeepAliveLoopedObjectSound((u32)obj, SFXTRIG_ar_bomb_pickup);
            }
            (*gGameUIInterface)->runAirMeter((s32)st->airMeterCurrent);
        }
        else
        {
            Sfx_StopObjectChannel((u32)obj, 0x7f);
            if (st->velLimitX > 0.1f)
            {
                if (randomGetRange(0, 10) == 0)
                {
                    Sfx_PlayFromObject(0, SFXTRIG_dn_boar1_c_117);
                }
                PSVECScale(&st->velLimitX, &st->velLimitX, 0.95f);
                if ((u32)(st->flags428 >> 7 & 1) != 0)
                {
                    if (st->velLimitX < 0.1f)
                    {
                        st->velLimitX = 0.1f;
                    }
                }
            }
            else
            {
                (*gGameUIInterface)->airMeterShutdown();
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                lim = 0.01f;
                st->velLimitX = 0.01f;
                st->velLimitY = lim;
                st->velLimitZ = lim;
            }
        }
    }
}

static void SnowBike_ResetAirMeter(SnowBikeState* st)
{
    st->airMeterMax = 70000.0f;
    st->airDrainRate = 1.0f;
    st->airMeterCurrent = 69999.0f;
    if (st->riderMode == 2)
    {
        (*gGameUIInterface)->initAirMeter((int)st->airMeterMax, SNOWBIKE_AIRMETER_BGTEXTURE);
        (*gGameUIInterface)->airMeterSetField24(4.0f);
    }
}

void SnowBike_onSeqFree(GameObject* obj)
{
    SnowBikeState* state = obj->extra;
    if ((u32)((state->flags428 >> 1) & 1) == 0)
    {
        s16 sv;
        f32 fz = 0.0f;
        state->localVelX = fz;
        state->localVelY = fz;
        state->distanceScale = -2.0f;
        ((HightopFlags*)&state->flags428)->resetLatch = 0;
        state->impactShakeTimer = fz;
        sv = obj->anim.rotX;
        state->yaw = sv;
        state->yawCurrent = sv;
        state->engineFxLevel = -0.05f;
    }
    ObjHits_EnableObject(obj);
    (*gPathControlInterface)->attachObject(obj, (char*)state + 0x178);
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosX = obj->anim.localPosX;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosY = obj->anim.localPosY;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosZ = obj->anim.localPosZ;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosX = obj->anim.worldPosX;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosY = obj->anim.worldPosY;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosZ = obj->anim.worldPosZ;
}

int SnowBike_SeqFn(GameObject* obj, int unused, ObjSeqState* seq)
{
    typedef struct HightopMatrixSeed
    {
        s16 rotX;
        s16 rotY;
        s16 rotZ;
        s16 pad;
        f32 unused;
        f32 x;
        f32 y;
        f32 z;
    } HightopMatrixSeed;

    u8 triggerType;
    int i;
    int state;
    SnowBikeState* st;
    f32 matrix[16];
    HightopMatrixSeed transform;
    f64 xSpeed;
    f64 ySpeed;
    f64 zSpeed;

    state = *(int*)&obj->extra;
    st = (SnowBikeState*)state;
    seq->freeCallback = (ObjAnimSequenceFreeCallback)SnowBike_onSeqFree;
    ObjHits_DisableObject(obj);

    for (i = 0; i < (int)(u32)seq->eventCount; i++)
    {
        triggerType = seq->eventIds[i];
        switch (triggerType)
        {
        case 2:
            if (obj->anim.seqId != 0x16c && obj->anim.seqId != 0x16f)
            {
                mainSetBits(0x499, 1);
            }
            break;
        case 3:
            (*gGameUIInterface)->airMeterShutdown();
            break;
        }
    }

    if (st->riderMode == 2)
    {
        xSpeed = (double)(float)(oneOverTimeDelta * (obj->anim.localPosX - st->refPosX));
        ySpeed = (double)(float)(oneOverTimeDelta * (obj->anim.localPosY - st->refPosY));
        zSpeed = (double)(float)(oneOverTimeDelta * (obj->anim.localPosZ - st->refPosZ));

        transform.x = 0.0f;
        transform.y = 0.0f;
        transform.z = 0.0f;
        transform.unused = 1.0f;
        transform.rotX = -obj->anim.rotX;
        transform.rotY = 0;
        transform.rotZ = 0;
        mtxRotateByVec3s(matrix, &transform);
        Matrix_TransformPoint(matrix, xSpeed, ySpeed, zSpeed, (float*)(state + 0x494), (float*)(state + 0x498),
                              (float*)(state + 0x49c));

        st->stickY = st->stickY + (framesThisStep << 3);
        if (st->stickY > 0x46)
        {
            st->stickY = 0x46;
        }

        drcloudcage_updateEngineFx((GameObject*)obj, (void*)state, st->distanceScale,
                                   (int)(850.0f * -st->engineFxLevel), (u8*)(state + 0x461), 4);
    }

    ((HightopFlags3*)&st->flags428)->active = 0;
    return 0;
}

static void SnowBike_ClampSwayAxis(f32* accum, f32 lo, f32 hi)
{
    f32 v = *accum;
    *accum = (v < lo) ? lo : ((v > hi) ? hi : v);
    v = *accum;
    if (v < 0.01f)
    {
        if (v > -0.01f)
        {
            *accum = 0.0f;
        }
    }
}

void SnowBike_UpdateCollisionResponse(GameObject* obj, int stateRaw)
{
    SnowBikeState* st = (SnowBikeState*)stateRaw;
    int hitKind;
    int hitReact;
    int burstCount;
    u32 hit;
    f32 dot;
    int hitOutB;
    u32 hitOutC;
    int hitObj;
    f32 velNrm[3];
    f32 zero;

    zero = 0.0f;
    hitReact = *(int*)&obj->anim.hitReactState;
    if (ObjHits_IsObjectEnabled((ObjAnimComponent*)obj) != 0)
    {
        if ((u32)(st->flags428 >> 1 & 1) == 0)
        {
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DRHIGHTOP_HIT_VOLUME_SLOT, 1, 0);
        }
        else
        {
            ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
            ObjHits_SyncObjectPositionIfDirty(obj);
        }
        hitKind = ObjHits_GetPriorityHit(obj, &hitObj, &hitOutB, &hitOutC);
        switch (hitKind)
        {
        case 0xd:
            if ((u32)(st->flags428 >> 1 & 1) == 0)
            {
                st->linkedObj = hitObj;
                st->collisionFxDamping = 1.0f;
            }
            break;
        case 0x15:
            if (st->collisionFxTimer == zero)
            {
                PSVECNormalize((float*)&obj->anim.velocityX, velNrm);
                dot = PSVECDotProduct(velNrm, (float*)(hitObj + 0x24));
                PSVECScale(&st->localVelX, &st->localVelX, dot * st->collisionBounceScale + 1.0f);
                st->localVelY *= 0.2f;
                st->collisionFxTimer = 20.0f;
                st->collisionFxDamping = 1.0f;
            }
            break;
        case 0x1d:
            if ((u32)(st->flags428 >> 1 & 1) == 0)
            {
                setMotionBlur(1, 0.7f);
                st->collisionFxTimer = (f32)gSnowBikeBoostFxDuration;
                st->collisionFxDamping = gSnowBikeBoostFxDamping;
                st->airMeterRefillTimer = (f32)gSnowBikeAirRefillAmount;
            }
            break;
        }
        hit = *(u32*)(hitReact + 0x50);
        if (((hit != 0) && (hitObj = hit, *(u32*)& st->linkedObj = hit, st->collisionFxTimer == zero)) &&
            (hitKind = arrayIndexOf(gDrHighTopHitObjectKinds, 0xc, (int)*(short*)(hitObj + 0x46)), hitKind != -1))
        {
            objfx_shakeCameraByDistance((GameObject*)obj, 300.0f);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x551, NULL, 4, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x552, NULL, 4, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x554, NULL, 4, -1, NULL);
            burstCount = 0x32 / framesThisStep;
            while (burstCount-- != 0)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, DRHIGHTOP_PARTFX_COLLISION_SPRAY, NULL, 2, -1, NULL);
            }
            st->collisionFxTimer = 20.0f;
            st->collisionFxDamping = 1.0f;
            if ((u32)(st->flags428 >> 1 & 1) == 0)
            {
                st->collisionFxTimer = (f32)gSnowBikeHardCollisionFxDuration;
            }
        }
    }
}

void SnowBike_UpdateSteering(short* obj, int stateRaw)
{
    SnowBikeState* st = (SnowBikeState*)stateRaw;
    void* pathState = (void*)(stateRaw + 0x178);
    f32 fa;
    f32 fb;
    int rotClamped;
    int yawDelta;
    int ival;

    (*gPathControlInterface)->update(obj, pathState, timeDelta);
    (*gPathControlInterface)->apply(obj, pathState);
    (*gPathControlInterface)->advance(obj, pathState, timeDelta);
    ival = 2;
    if (st->unk3D9 == '\0')
    {
        st->impactShakeTimer = st->impactShakeTimer + timeDelta;
        fa = st->impactShakeTimer;
        st->impactShakeTimer = (fa < 0.0f) ? 0.0f : ((fa > 120.0f) ? 120.0f : fa);
        if (st->impactShakeTimer >= 5.0f)
        {
            if ((u32)(st->flags428 >> 7 & 1) == 0)
            {
                st->unk584 = 0.0f;
            }
            ((HightopFlags*)&st->flags428)->resetLatch = 1;
        }
    }
    else
    {
        if ((u32)(st->flags428 >> 7 & 1) != 0)
        {
            ival = 0;
            fa = 0.25f;
            st->haloYawDrift = fa * (f32)(s32)obj[1];
            st->haloDriftAmpB = fa * (f32)(s32)obj[2];
            st->haloDriftPhaseA = ival;
            st->haloDriftPhaseB = ival;
            if ((u32)(st->flags428 >> 1 & 1) == 0)
            {
                doRumble(st->impactShakeTimer * fa);
                Camera_EnableViewYOffset();
                CameraShake_SetAllMagnitudes(st->impactShakeTimer / 12.0f);
                Sfx_PlayFromObject((u32)obj, SFXTRIG_tr_jbike_bombbeep);
                fb = (80.0f < 3.0f * st->impactShakeTimer) ? 80.0f
                                                                          : 3.0f * st->impactShakeTimer;
                {
                    Sfx_SetObjectSfxVolume((u32)obj, SFXTRIG_tr_jbike_bombbeep, fb, 0.1f);
                }
            }
        }
        ((HightopFlags*)&st->flags428)->resetLatch = 0;
        st->impactShakeTimer = 0.0f;
        st->dampPresetMode = st->dampPresetModeRaw;
    }
    fa = 16384.0f;
    st->haloDriftPhaseA = fa * timeDelta + (f32)(s32)st->haloDriftPhaseA;
    st->haloDriftPhaseB = fa * timeDelta + (f32)(s32)st->haloDriftPhaseB;
    st->haloYawDrift = st->haloYawDrift * powfBitEstimate(0.8f, timeDelta);
    st->haloDriftAmpB = st->haloDriftAmpB * powfBitEstimate(0.8f, timeDelta);
    st->haloPitchDrift = st->haloYawDrift * mathSinf((3.1415927f * (f32)(s32)st->haloDriftPhaseA) / 32768.0f);
    st->haloDriftB = st->haloDriftAmpB * mathSinf((3.1415927f * (f32)(s32)st->haloDriftPhaseB) / 32768.0f);
    yawDelta = (int)*obj - ((int)st->yaw & 0xffffU);
    if (0x8000 < yawDelta)
    {
        yawDelta = yawDelta + -0xffff;
    }
    if (yawDelta < -0x8000)
    {
        yawDelta = yawDelta + 0xffff;
    }
    st->yaw = *(s16*)((char*)st + 0x40e) + yawDelta;
    st->yawCurrent = st->yawCurrent + yawDelta;
    obj[1] = obj[1] + ((int)st->unk310 >> ival);
    obj[2] = obj[2] + ((int)st->unk312 >> ival);
    rotClamped = obj[1];
    if (rotClamped < -0x2000)
    {
        rotClamped = -0x2000;
    }
    else if (0x2000 < rotClamped)
    {
        rotClamped = 0x2000;
    }
    obj[1] = rotClamped;
    rotClamped = obj[2];
    if (rotClamped < -0x2000)
    {
        rotClamped = -0x2000;
    }
    else if (0x2000 < rotClamped)
    {
        rotClamped = 0x2000;
    }
    obj[2] = rotClamped;
}

void SnowBike_UpdateExhaustFx(GameObject* obj, int stateRaw)
{

    SnowBikeState* st = (SnowBikeState*)stateRaw;
    u8 flags;
    s16 motionFrame;
    f32 fa;
    f32 fb;
    f32 speed;
    f32 target558;
    f32 target530;
    f32 target534;
    f32 target548;
    f32 target54c;
    f32 target540;
    f32 target544;
    f32 k;
    MatrixTransform effect;

    speed =
        sqrtf(st->distanceScale * st->distanceScale + (st->localVelX * st->localVelX + st->localVelY * st->localVelY));
    st->timer -= timeDelta;
    fa = st->timer;
    st->timer = (fa < 0.0f) ? 0.0f : ((fa > 30.0f) ? 30.0f : fa);

    flags = st->flags428;
    if ((u32)(flags >> 7 & 1) == 0)
    {
        switch (st->dampPresetMode)
        {
        case 0xd:
            target558 = 0.005f;
            target534 = 1500.0f;
            target530 = 0.95f;
            target548 = 0.98f;
            target54c = 0.99f;
            target540 = 0.15f;
            target544 = 0.5f;
            if (((u32)(flags >> 1 & 1) == 0) && (st->timer <= 0.0f))
            {
                st->timer = (f32)(s32)randomGetRange(5, 10);
                if (PSVECMag((void*)&obj->anim.velocityX) > 3.0f)
                {
                    doRumble((f32)(s32)randomGetRange(1, 3));
                }
            }
            if (speed > 0.4f)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x80b, NULL, 2, -1, NULL);
            }
            break;
        case 3:
        default:
            target558 = 0.18f;
            target534 = 700.0f;
            target530 = 0.87f;
            target548 = 0.97f;
            target54c = 0.99f;
            target540 = 0.15f;
            target544 = 0.5f;
            break;
        case 9:
            target558 = 0.4f;
            target534 = 700.0f;
            target530 = 0.75f;
            target548 = 0.965f;
            target54c = 0.985f;
            target540 = 0.1f;
            target544 = 0.45f;
            if (speed > 0.3f)
            {
                effect.scale = 1.0f;
                effect.rotZ = 0;
                effect.rotY = 0;
                effect.rotX = 0;
                effect.x = obj->anim.localPosX;
                effect.y = 15.0f + obj->anim.localPosY;
                effect.z = obj->anim.localPosZ;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x80a, &effect, 1, -1, NULL);
            }
            break;
        }

        motionFrame = st->steerAngleDeg;
        if (((motionFrame >= 0x1e) && (motionFrame <= 0x3c)) || ((motionFrame >= 0x12c) && (motionFrame <= 0x14a)))
        {
            target558 *= 0.1f;
            target534 *= 1.5f;
            target530 += 0.1f;
            if (target530 < 0.0f)
            {
                target530 = 0.0f;
            }
            else if (target530 > 0.95f)
            {
                target530 = 0.95f;
            }
        }
    }
    else
    {
        target558 = st->unk578;
        target534 = st->unk574;
        target530 = st->unk56C;
        target548 = st->localVelXDampTarget;
        target54c = st->distanceScaleDampTarget;
        target540 = 0.1f;
        target544 = 0.5f;
    }

    if ((u32)((st->flags428 >> 1) & 1) != 0)
    {
        target558 = 0.5f;
    }
    fb = timeDelta;
    speed = 0.04f;
    st->unk558 +=
        fb * (speed *
              (((target558 < 0.005f) ? 0.005f : ((target558 > 1.0f) ? 1.0f : target558)) -
               st->unk558));
    st->unk534 += timeDelta * (0.25f * (target534 - st->unk534));
    st->unk530 += timeDelta * (0.04f * (target530 - st->unk530));
    st->localVelXDamp += timeDelta * ((k = 0.1f) * (target548 - st->localVelXDamp));
    st->distanceScaleDamp += timeDelta * (k * (target54c - st->distanceScaleDamp));
    st->turnVelScale += timeDelta * (k * (target540 - st->turnVelScale));
    st->turnForceGain += timeDelta * (k * (target544 - st->turnForceGain));
}

static s16 SnowBike_StickToSteerAngle(f32 stickX, f32 stickY)
{
    return (f32)(u16)getAngle(stickX, stickY) / 182.04f;
}

void SnowBike_UpdateLiftSway(int obj, int state)
{
    PickupFlags* flags;
    int origBit4;
    f32 rate;
    f32 target;
    f32 clampedRate;
    f32 out[3];
    f32 vec_args[4];

    flags = (PickupFlags*)&((DRPickupState*)state)->flags;
    origBit4 = flags->b4;

    if ((((DRPickupState*)state)->flags458 & 0x100) != 0)
    {
        flags->b6 = 1;
    }
    else
    {
        flags->b6 = 0;
    }

    if ((((DRPickupState*)state)->flags458 & 0x200) != 0)
    {
        flags->b4 = 1;
    }
    else
    {
        flags->b4 = 0;
    }

    if ((origBit4 == 0) && (flags->b4 != 0))
    {
        Sfx_PlayFromObject(obj, SFXTRIG_bblast16);
    }

    target = 0.0f;
    if (flags->b6 != 0)
    {
        target = ((DRPickupState*)state)->liftZVelTarget;
    }
    rate = (target - ((DRPickupState*)state)->liftZVel) * 0.05f;
    clampedRate = (rate < -0.002f) ? -0.002f : ((rate > 0.01f) ? 0.01f : rate);
    *(f32*)(state + 0x430) = clampedRate * timeDelta + *(f32*)((int)state + 0x430);

    target = 0.0f;
    if (flags->b4 != 0)
    {
        f32 vy53c = ((DRPickupState*)state)->settleVelMax;
        f32 v49c = ((DRPickupState*)state)->accumZ;
        if (v49c >= target)
        {
            f32 nv = -vy53c;
            target = (nv < -v49c * oneOverTimeDelta) ? -v49c * oneOverTimeDelta : ((nv > target) ? target : nv);
        }
        else
        {
            target =
                (vy53c < target) ? target : ((vy53c > -v49c * oneOverTimeDelta) ? -v49c * oneOverTimeDelta : vy53c);
        }
    }
    {
        f32 fz = 0.0f;
        ((DRPickupState*)state)->localOffsetX = fz;
        ((DRPickupState*)state)->localOffsetY = fz;
    }
    ((DRPickupState*)state)->localOffsetZ = (*(f32*)(state + 0x430) + target) * timeDelta;

    Matrix_TransformPoint((f32*)(state + 0x6c), ((DRPickupState*)state)->localOffsetX,
                          ((DRPickupState*)state)->localOffsetY, ((DRPickupState*)state)->localOffsetZ, &out[0],
                          &out[1], &out[2]);
    Matrix_TransformPoint((f32*)(state + 0x12c), out[0], out[1], out[2], &out[0], &out[1], &out[2]);
    PSVECAdd(out, (void*)(state + 0x494), (void*)(state + 0x494));

    ((DRPickupState*)state)->angVel414 =
        (-((DRPickupState*)state)->angAccelGain * ((DRPickupState*)state)->angAccelScale) * timeDelta +
        ((DRPickupState*)state)->angVel414;
    ((DRPickupState*)state)->angVel414 =
        powfBitEstimate(((DRPickupState*)state)->angVelDamping, timeDelta) * ((DRPickupState*)state)->angVel414;

    {
        f32 lim;
        f32 v;
        v = ((DRPickupState*)state)->angVel414;
        lim = ((DRPickupState*)state)->angVelLimit;
        ((DRPickupState*)state)->angVel414 = (v < -lim) ? -lim : ((v > lim) ? lim : v);
    }

    {
        f32 newF = (f32)(s32) * (s16*)(state + 0x40e) + ((DRPickupState*)state)->angVel414 * timeDelta;
        s32 delta;
        ((DRPickupState*)state)->angle40E = newF;
        delta = (s32)(((DRPickupState*)state)->angVel414 * ((DRPickupState*)state)->angleScale);
        delta -= (s32)(u16) * (u32*)(state + 0x410);
        if (delta > 0x8000)
        {
            delta = delta - 0xFFFF;
        }
        if (delta < -0x8000)
        {
            delta = delta + 0xFFFF;
        }
        ((DRPickupState*)state)->angAccum410 =
            (u32)(s32)((f32)delta * ((DRPickupState*)state)->angAccumGain + (f32)(s32) * (u32*)((int)state + 0x410));
    }
    {
        s32 delta = (s32) * (s16*)(state + 0x40e) - (s32)(u16) * (s16*)(state + 0x40c);
        if (delta > 0x8000)
        {
            delta = delta - 0xFFFF;
        }
        if (delta < -0x8000)
        {
            delta = delta + 0xFFFF;
        }
        ((DRPickupState*)state)->angle40C =
            (s16)((f32)delta * ((DRPickupState*)state)->angleGain + (f32)(s32) * (s16*)((int)state + 0x40c));
    }

    if (flags->b7 != 0)
    {
        ((DRPickupState*)state)->spinVel =
            (-((DRPickupState*)state)->spinDecel) * timeDelta + ((DRPickupState*)state)->spinVel;
        {
            f32 v = ((DRPickupState*)state)->spinVel;
            ((DRPickupState*)state)->spinVel =
                (v < -100.0f) ? -100.0f : ((v > 100.0f) ? 100.0f : v);
        }
        *(s16*)(obj + 0x2) = (f32)(s32) * (s16*)(obj + 0x2) + ((DRPickupState*)state)->spinVel * timeDelta;
    }

    if (flags->b1 == 0)
    {
        vec_args[0] = ((DRPickupState*)state)->angVel414;
        vec_args[1] = ((DRPickupState*)state)->accumZ;
        vec_args[2] = (f32)(s32) * (s16*)(obj + 0x4);
        vec_args[3] = (f32)(s32) * (s16*)(obj + 0x2);
        (*gCameraInterface)->releaseAction(vec_args, 0x10);
    }

    {
        f32 lim;
        f32 v;
        v = ((DRPickupState*)state)->accumX;
        lim = ((DRPickupState*)state)->clampLimitX;
        ((DRPickupState*)state)->accumX = (v < -lim) ? -lim : ((v > lim) ? lim : v);
        v = ((DRPickupState*)state)->accumX;
        if (v < 0.01f)
        {
            if (v > -0.01f)
            {
                ((DRPickupState*)state)->accumX = 0.0f;
            }
        }
    }

    {
        f32 v = ((DRPickupState*)state)->accumY;
        f32 lim = -((DRPickupState*)state)->clampLimitY;
        ((DRPickupState*)state)->accumY = (v < lim) ? lim : ((v > 1.0f) ? 1.0f : v);
        v = ((DRPickupState*)state)->accumY;
        if (v < 0.01f)
        {
            if (v > -0.01f)
            {
                ((DRPickupState*)state)->accumY = 0.0f;
            }
        }
    }

    {
        f32 lim;
        f32 v;
        v = ((DRPickupState*)state)->accumZ;
        lim = ((DRPickupState*)state)->clampLimitZ;
        ((DRPickupState*)state)->accumZ = (v < -lim) ? -lim : ((v > lim) ? lim : v);
        v = ((DRPickupState*)state)->accumZ;
        if (v < 0.01f)
        {
            if (v > -0.01f)
            {
                ((DRPickupState*)state)->accumZ = 0.0f;
            }
        }
    }
}

/* SnowBike defNos (anim.seqId), names from retail OBJECTS.bin at def+0x91; all gate
   to this DLL. The three CRSnowClawB / two IMSnowClawB entries share
   one truncated bin name apiece and are told apart by the bikeVariant ordinal that
   SnowBike_init assigns them below. IM = Ice Mountain, CR = CloudRunner Fortress. */
#define SNOWBIKE_IM_BIKE_OBJ           0x72
#define SNOWBIKE_IM_CLAWBIKE_V0_OBJ    0x16c
#define SNOWBIKE_IM_CLAWBIKE_V1_OBJ    0x16f
#define SNOWBIKE_CR_BIKE_OBJ           0x38c
#define SNOWBIKE_CR_CLAWBIKE_V0_OBJ    0x38d
#define SNOWBIKE_CR_CLAWBIKE_V1_OBJ    0x38e
#define SNOWBIKE_CR_CLAWBIKE_V2_OBJ    0x4d4

typedef struct SnowBikeSetTypeState
{
    s16 savedRotX;
    u8 pad2[0xC - 0x2];
    f32 savedPosX;
    f32 savedPosY;
    f32 savedPosZ;
    u8 pad18[0x3D3 - 0x18];
    s8 unk3D3;
    u8 pad3D4[0x3E8 - 0x3D4];
    f32 modelMtxPosX;
    f32 modelMtxPosY;
    f32 modelMtxPosZ;
    u8 pad3F4[0x400 - 0x3F4];
    f32 mountPosX;
    f32 mountPosY;
    f32 mountPosZ;
    u8 pad40C[0x414 - 0x40C];
    f32 unk414;
    u8 pad418[0x420 - 0x418];
    u8 unk420;
    s8 bikeType;
    u8 pad422[0x428 - 0x422];
    u8 flags;
    u8 pad429[0x434 - 0x429];
    u8 romListGroupIndex;
    u8 romListItemIndex;
    u8 pad436[0x448 - 0x436];
    s16 completionGameBit;
    u8 pad44A[0x494 - 0x44A];
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    u8 pad4A0[0x4B8 - 0x4A0];
    f32 airMeterMax;     /* 0x4B8 */
    f32 airMeterCurrent; /* 0x4BC */
    f32 airDrainRate;    /* 0x4C0 */
    u8 pad4C4[0x4C8 - 0x4C4];
} SnowBikeSetTypeState;

typedef struct DRcradleSnowBikeFlags
{
    u8 resetLatch : 1;   /* 0x80 */
    u8 pathActive : 1;   /* 0x40 */
    u8 uiPrompt : 1;     /* 0x20 */
    u8 impulseLatch : 1; /* 0x10 */
    u8 flags : 4;
} DRcradleSnowBikeFlags;

void SnowBike_buildOrientationMatrices(GameObject* obj, int state)
{
    MatrixTransform v;
    SnowBikeState* s = (SnowBikeState*)state;

    v.x = 0.0f;
    v.y = 0.0f;
    v.z = 0.0f;
    v.scale = 1.0f;

    v.rotX = s->yaw;
    v.rotY = 0;
    v.rotZ = 0;
    setMatrixFromObjectPos((f32*)(state + 0x6c), &v);

    v.rotX = -s->yaw;
    v.rotY = 0;
    v.rotZ = 0;
    mtxRotateByVec3s((f32*)(state + 0xac), &v);

    v.rotX = s->yawCurrent;
    v.rotY = 0;
    v.rotZ = 0;
    setMatrixFromObjectPos((f32*)(state + 0xec), &v);

    v.rotX = -s->yawCurrent;
    v.rotY = 0;
    v.rotZ = 0;
    mtxRotateByVec3s((f32*)(state + 0x12c), &v);
}

void SnowBike_ResetDynamics(int obj, register int state)
{
    f32 fz, fa, fb, fc;
    DRcradleSnowBikeFlags* flags;
    SnowBikeState* s = (SnowBikeState*)state;
    s->unk52C = 50.0f;
    s->unk530 = 0.85f;
    s->unk534 = 700.0f;
    fz = 0.0f;
    ((SnowBikeSetTypeState*)state)->unk414 = fz;
    s->unk584 = fz;
    s->localVelXDamp = 0.97f;
    s->distanceScaleDamp = 0.99f;
    s->turnVelScale = 0.1f;
    s->turnForceGain = 0.5f;
    s->unk558 = 0.2f;
    s->unk56C = 0.75f;
    flags = (DRcradleSnowBikeFlags*)(state + 0x428);
    flags->resetLatch = 0;
    s->engineFxLevel = fz;
    fa = s->baseVelLimitX;
    s->velLimitX = fa;
    s->localVelXLimit = fa;
    fb = s->baseVelLimitY;
    s->velLimitY = fb;
    s->localVelYLimit = fb;
    fc = s->baseVelLimitZ;
    s->velLimitZ = fc;
    s->distanceScaleLimit = fc;
    flags->pathActive = 0;
    flags->impulseLatch = 0;
    *(u32*)(state + 0x42c) = 0;
    s->collisionFxTimer = fz;
    s->collisionFxDamping = 1.0f;
}

void SnowBike_InitTuning(GameObject* obj, int state)
{
    f32 fa, fz;
    SnowBikeState* s = (SnowBikeState*)state;
    s->liftAccel = -0.12f;
    s->unk530 = 0.85f;
    s->unk534 = 700.0f;
    s->unk538 = -0.05f;
    s->unk53C = 0.04f;
    s->localVelXDamp = 0.97f;
    s->distanceScaleDamp = 0.99f;
    s->turnVelScale = 0.1f;
    s->turnForceGain = 0.5f;
    fa = 0.995f;
    s->localVelXDampTarget = fa;
    s->distanceScaleDampTarget = fa;
    s->unk554 = 0.08f;
    s->unk550 = 15.0f;
    s->unk570 = 5.0f;
    fz = 0.2f;
    s->unk558 = fz;
    s->unk578 = 0.01f;
    s->unk574 = 300.0f;
    s->unk56C = 0.75f;
    s->collisionBounceScale = fz;
}
typedef struct SnowBikeMountState
{
    s16 savedRotX;
    u8 pad2[0xC - 0x2];
    f32 savedPosX;
    f32 savedPosY;
    f32 savedPosZ;
    u8 pad18[0x3D3 - 0x18];
    s8 unk3D3;
    u8 pad3D4[0x3E8 - 0x3D4];
    f32 modelMtxPosX;
    f32 modelMtxPosY;
    f32 modelMtxPosZ;
    u8 pad3F4[0x400 - 0x3F4];
    f32 mountPosX;
    f32 mountPosY;
    f32 mountPosZ;
    u8 pad40C[0x414 - 0x40C];
    f32 unk414;
    u8 pad418[0x420 - 0x418];
    u8 unk420;
    u8 pad421[0x428 - 0x421];
    u8 flags;
    u8 pad429[0x434 - 0x429];
    u8 romListGroupIndex;
    u8 romListItemIndex;
    u8 pad436[0x494 - 0x436];
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
} SnowBikeMountState;

/* texture asset loaded into sSnowBikeTrailTexture (this DLL's only texture) */
#define SNOWBIKE_TEXTURE_ID 0x186
typedef struct SnowBikeRomListItem
{
    ObjPlacement base;
    u8 pad18[0x29 - 0x18];
    u8 yawByte;
} SnowBikeRomListItem;
typedef struct
{
    u8 pad0 : 2;
    u8 b20 : 1;
    u8 pad1 : 2;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} HaloSnowBikeFlags;
typedef struct
{
    u8 pad0 : 2;
    u8 b20 : 1;
    u8 pad1 : 2;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} SnowBikeFlags;
typedef struct SnowBikePlacement
{
    ObjPlacement base;
    u8 yawByte;
    u8 startFlag;
    s16 unk1a;
    u8 param1c;
    u8 param1d;
    s16 gameBitId;
    u8 pad20[0x24 - 0x20];
} SnowBikePlacement;

typedef struct
{
    s16 rot[3];
    f32 quad[4];
} SBRotQuad;

s32 SnowBike_getRouteRank(GameObject* obj)
{
    return (*gCheckpointInterface)->getRouteRank((CheckpointRankItem*)(*(int*)&obj->extra + 0x28));
}

s32 SnowBike_isAtRankGate(GameObject* obj)
{
    int result = (*gCheckpointInterface)->getRouteRank((CheckpointRankItem*)(*(int*)&obj->extra + 0x28));
    if (result == 3)
    {
        if (gSnowBikeLeaderRouteRank == -1)
        {
            return 1;
        }
    }
    return (u32)__cntlzw(gSnowBikeLeaderRouteRank - 1 - result) >> 5;
}

void SnowBike_func17(void)
{
}

void SnowBike_func16(void)
{
}

void SnowBike_resetToRomListPosition(GameObject* obj)
{
    int state = *(int*)&obj->extra;
    int* table;
    SnowBikeRomListItem* found;
    f32 zero;

    table = (int*)((int)gSnowBikeMountRomListTable + (int)(((SnowBikeMountState*)state)->romListGroupIndex) * 12);
    found = (SnowBikeRomListItem*)mapRomListFindItem(table[((SnowBikeMountState*)state)->romListItemIndex], 0, 0, 0, 0);
    if (found != NULL)
    {
        if (((SnowBikeMountState*)state)->romListGroupIndex != 0)
        {
            obj->anim.localPosX = found->base.posX;
            obj->anim.localPosY = found->base.posY;
            obj->anim.localPosZ = found->base.posZ;
            obj->anim.rotX = (s16)((found->yawByte) << 8);
        }
        (*gCheckpointInterface)->findRouteForObject(obj, (CheckpointRouteState*)(state + 0x28), 0);
        ((SnowBikeMountState*)state)->savedPosX = obj->anim.localPosX;
        ((SnowBikeMountState*)state)->savedPosY = obj->anim.localPosY;
        ((SnowBikeMountState*)state)->savedPosZ = obj->anim.localPosZ;
        ((SnowBikeMountState*)state)->savedRotX = obj->anim.rotX;
        zero = 0.0f;
        ((SnowBikeMountState*)state)->velocityX = zero;
        ((SnowBikeMountState*)state)->velocityY = zero;
        ((SnowBikeMountState*)state)->velocityZ = zero;
        (*gPathControlInterface)->attachObject((void*)obj, (void*)&((ShackleSwingState*)state)->attachment);
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosX = obj->anim.localPosX;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosY = obj->anim.localPosY;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosZ = obj->anim.localPosZ;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosX = obj->anim.worldPosX;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosY = obj->anim.worldPosY;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosZ = obj->anim.worldPosZ;
        ((SnowBikeMountState*)state)->unk3D3 = 1;
    }
}

s32 SnowBike_getRacePosition(GameObject* obj)
{
    return ((SnowBikeState*)obj->extra)->routeRank;
}

f32 SnowBike_func13(GameObject* obj, f32* out)
{
    int state = *(int*)&obj->extra;
    f32 speed;
    *out = 5.0f;
    speed = sqrtf(((SnowBikeMountState*)state)->velocityZ * ((SnowBikeMountState*)state)->velocityZ +
                  (((SnowBikeMountState*)state)->velocityX * ((SnowBikeMountState*)state)->velocityX +
                   ((SnowBikeMountState*)state)->velocityY * ((SnowBikeMountState*)state)->velocityY));
    speed *= 0.2f;
    if (speed > 1.0f)
    {
        speed = 1.0f;
    }
    return speed;
}

void SnowBike_getPlayerAnim(GameObject* obj, f32* outFloat, s32* outBool)
{
    int state = *(int*)&obj->extra;
    f32 value, r;
    *outFloat = ((SnowBikeMountState*)state)->unk414 / 400.0f;
    value = *outFloat;
    *outFloat = (value < -1.0f) ? -1.0f : ((value > 1.0f) ? 1.0f : value);
    *outBool = ((SnowBikeMountState*)state)->unk414 < 0.0f;
}

void SnowBike_setMountState(GameObject* obj, int type)
{
    int state = *(int*)&obj->extra;
    u32 bit;
    ((SnowBikeSetTypeState*)state)->bikeType = type;
    if (type == 2)
    {
        mainSetBits(((SnowBikeSetTypeState*)state)->completionGameBit, 1);
        SnowBike_ResetDynamics((int)obj, state);
        bit = (((SnowBikeSetTypeState*)state)->flags >> 5) & 1;
        if (bit != 0)
        {
            ((SnowBikeSetTypeState*)state)->airMeterMax = 70000.0f;
            ((SnowBikeSetTypeState*)state)->airDrainRate = 1.0f;
            ((SnowBikeSetTypeState*)state)->airMeterCurrent = 69999.0f;
            if (((SnowBikeSetTypeState*)state)->bikeType == 2)
            {
                (*gGameUIInterface)
                    ->initAirMeter((int)((SnowBikeSetTypeState*)state)->airMeterMax, SNOWBIKE_AIRMETER_BGTEXTURE);
                (*gGameUIInterface)->airMeterSetField24(4.0f);
            }
        }
        if (obj->anim.seqId == SNOWBIKE_IM_BIKE_OBJ)
        {
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->lateralResponseWeight = 0x14;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->axialResponseWeight = 0x14;
        }
    }
}

s32 SnowBike_getMountState(GameObject* obj)
{
    return ((SnowBikeState*)obj->extra)->riderMode;
}

void SnowBike_getCameraPosition(GameObject* obj, f32* x, f32* y, f32* z)
{
    int state = *(int*)&obj->extra;
    ((SnowBikeMountState*)state)->mountPosX = obj->anim.localPosX;
    ((SnowBikeMountState*)state)->mountPosY = obj->anim.localPosY;
    ((SnowBikeMountState*)state)->mountPosZ = obj->anim.localPosZ;
    *x = ((SnowBikeMountState*)state)->mountPosX;
    *y = ((SnowBikeMountState*)state)->mountPosY;
    *z = ((SnowBikeMountState*)state)->mountPosZ;
}

int SnowBike_getDismountSide(void)
{
    return 0x2;
}

int SnowBike_canDismount(void)
{
    return 0x0;
}

void SnowBike_getRiderPosition(GameObject* obj, f32* x, f32* y, f32* z)
{
    int state = *(int*)&obj->extra;
    *x = ((SnowBikeMountState*)state)->modelMtxPosX;
    *y = ((SnowBikeMountState*)state)->modelMtxPosY;
    *z = ((SnowBikeMountState*)state)->modelMtxPosZ;
}

u8 SnowBike_getMountSide(GameObject* obj)
{
    return ((SnowBikeState*)obj->extra)->playerInRange;
}

u32 SnowBike_canMount(GameObject* obj)
{
    int state = *(int*)&obj->extra;
    u32 bit = (((SnowBikeMountState*)state)->flags >> 1) & 1;
    if (bit != 0)
    {
        return 0;
    }
    return ((SnowBikeMountState*)state)->unk420;
}

int SnowBike_getExtraSize(void)
{
    return 0x59c;
}

int SnowBike_getObjectTypeId(void)
{
    return 0x3;
}

void SnowBike_free(GameObject* obj)
{
    char* p;
    int i;
    u32 bit;
    int state;

    state = *(int*)&obj->extra;
    ObjGroup_RemoveObject((int)obj, SNOWBIKE_OBJGROUP);
    i = 0;
    p = (char*)state;
    for (; i < 9; i++)
    {
        mm_free(*(void**)(p + 0x4c8));
        p += 8;
    }
    bit = (((SnowBikeMountState*)state)->flags >> 5) & 1;
    if (bit != 0)
    {
        (*gGameUIInterface)->airMeterShutdown();
    }
}

void SnowBike_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    void* path;

    path = (obj)->extra;
    SnowBike_DrawTrails((int)obj, (char*)path);
    if (visible == -1)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)1.0f);
        ObjPath_GetPointWorldPosition(obj, 0, (f32*)((char*)path + 0x3e8),
                                      (f32*)((char*)path + 0x3ec), (f32*)((char*)path + 0x3f0), 0);
    }
    else
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)1.0f);
        ObjPath_GetPointWorldPosition(obj, 0, (f32*)((char*)path + 0x3e8),
                                      (f32*)((char*)path + 0x3ec), (f32*)((char*)path + 0x3f0), 0);
    }
}

void SnowBike_hitDetect(GameObject* obj)
{
    SnowBikeState* state;
    u8* other;
    int vol;
    f32 mag;
    f32 shakeScale;
    f32 velScale;
    f32 velScaleDefault;
    f32 value;
    f32 clamped;
    f32 limit;
    f32 dummy;

    state = obj->extra;
    other = *(u8**)obj->anim.hitReactState;
    if (obj->pendingParentObj != NULL)
    {
        return;
    }
    if (state->riderMode == 2)
    {
        SnowBike_UpdateSteering((short*)obj, (int)state);
        state->savedRotY = obj->anim.rotY;
        state->savedRotZ = obj->anim.rotZ;
        obj->anim.rotY = (f32)obj->anim.rotY + state->haloPitchDrift;
        obj->anim.rotZ = (f32)obj->anim.rotZ + (state->unk410 + state->haloDriftB);
    }
    if (state->unk3D9 == 4 || state->unk3D6 != 0)
    {
        obj->anim.velocityY =
            oneOverTimeDelta * (obj->anim.localPosY - obj->anim.previousLocalPosY);
        state->localVelY = obj->anim.velocityY;
    }
    if (state->unk3D6 != 0 ||
        ((((ObjHitsPriorityState*)obj->anim.hitReactState)->flags & 8) != 0 &&
         arrayIndexOf((int*)gSnowBikeHitObjectIdTable, 10, ((GameObject*)other)->anim.seqId) == -1) ||
        (*(void**)&state->linkedObj != NULL && state->collisionFxDamping <= 1.0f))
    {
    mag = PSVECMag((f32*)((int)obj + 0x24));
    if (mag > 1.0f)
    {
        if (!((HaloSnowBikeFlags*)&state->flags428)->b02)
        {
            doRumble(3.0f * mag);
        }
        state->engineFxLevel *= 0.25f;
        if (obj->anim.seqId == SNOWBIKE_IM_BIKE_OBJ || obj->anim.seqId == SNOWBIKE_CR_BIKE_OBJ)
        {
            vol = (int)(25.0f * mag);
            if (vol > 80)
            {
                vol = 80;
            }
            else if (vol < 30)
            {
                vol = 30;
            }
            if (Sfx_IsPlayingFromObjectChannel((int)obj, 32) == 0)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_tr_jbike_bombbeep);
                Sfx_SetObjectSfxVolume((int)obj, SFXTRIG_tr_jbike_bombbeep, vol, 127.0f);
            }
        }
    }
    if (!((HaloSnowBikeFlags*)&state->flags428)->b02 && mag > 3.0f)
    {
        Camera_EnableViewYOffset();
        shakeScale = 0.5f;
        CameraShake_SetAllMagnitudes(mag * shakeScale);
    }
    if (*(void**)&state->linkedObj != NULL)
    {
        velScale = 0.75f;
        OSReport(sSnowBikeVelDebugFmt, mag);
        if (((GameObject*)state->linkedObj)->anim.seqId == SNOWBIKE_CR_CLAWBIKE_V0_OBJ || ((GameObject*)state->linkedObj)->anim.seqId == SNOWBIKE_CR_CLAWBIKE_V1_OBJ ||
            ((GameObject*)state->linkedObj)->anim.seqId == SNOWBIKE_CR_CLAWBIKE_V2_OBJ)
        {
            velScale = 0.95f;
        }
        obj->anim.velocityX =
            velScale *
            (oneOverTimeDelta * (obj->anim.localPosX - obj->anim.previousLocalPosX));
        obj->anim.velocityZ =
            velScale *
            (oneOverTimeDelta * (obj->anim.localPosZ - obj->anim.previousLocalPosZ));
    }
    else
    {
        velScaleDefault = 0.95f;
        obj->anim.velocityX =
            velScaleDefault *
            (oneOverTimeDelta * (obj->anim.localPosX - obj->anim.previousLocalPosX));
        obj->anim.velocityZ =
            velScaleDefault *
            (oneOverTimeDelta * (obj->anim.localPosZ - obj->anim.previousLocalPosZ));
    }
    Matrix_TransformPoint((f32*)((u8*)state + 0x12c), obj->anim.velocityX, 0.0f,
                          obj->anim.velocityZ, &state->localVelX, &dummy, &state->distanceScale);
    }
{
    f32 limit;
    f32 value = state->localVelX;
    f32 clamped;
    limit = state->localVelXLimit;
    if (value < -limit)
    {
        clamped = -limit;
    }
    else if (value > limit)
    {
        clamped = limit;
    }
    else
    {
        clamped = value;
    }
    state->localVelX = clamped;
}
    if (state->localVelX < 0.01f && state->localVelX > -0.01f)
    {
        state->localVelX = 0.0f;
    }
    value = state->localVelY;
    limit = state->localVelYLimit;
    if (value < -limit)
    {
        clamped = -limit;
    }
    else if (value > 1.0f)
    {
        clamped = 1.0f;
    }
    else
    {
        clamped = value;
    }
    state->localVelY = clamped;
    if (state->localVelY < 0.01f && state->localVelY > -0.01f)
    {
        state->localVelY = 0.0f;
    }
    {
        f32 limit;
        f32 value = state->distanceScale;
        f32 clamped;
        limit = state->distanceScaleLimit;
        if (value < -limit)
        {
            clamped = -limit;
        }
        else if (value > limit)
        {
            clamped = limit;
        }
        else
        {
            clamped = value;
        }
        state->distanceScale = clamped;
    }
    if (state->distanceScale < 0.01f && state->distanceScale > -0.01f)
    {
        state->distanceScale = 0.0f;
    }
    state->refPosX = obj->anim.localPosX;
    state->refPosY = obj->anim.localPosY;
    state->refPosZ = obj->anim.localPosZ;
    state->linkedObj = 0;
}

void SnowBike_buildOrientationMatrices(GameObject* obj, int state);

void SnowBike_update(GameObject* obj)
{
    u8* state = obj->extra;
    f32 mtx1[16];
    f32 mtx2[16];
    SBRotQuad rq1;
    SBRotQuad rq2;
    f32 vec1[3];
    f32 vec2[3];
    f32 dummy1;
    f32 dummy2;
    s8 mode;
    int t;
    f32 fz;
    f32 damp;
    f32 value;
    f32 clamped;
    SnowBikeState* s = (SnowBikeState*)state;

    if (obj->anim.mapEventSlot == -1)
    {
        if (mainGetBit(GAMEBIT_DIM_CrossedBlizzard) != 0)
        {
            s->playerInRange = 0;
        }
        if (mainGetBit(GAMEBIT_SnowBikeRelated01FB) != 0)
        {
            Obj_SetModelSlotIndex(obj, 0x13);
        }
    }
    *(u8*)&obj->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    obj->anim.rotY = s->savedRotY;
    obj->anim.rotZ = s->savedRotZ;
    if (((SnowBikeFlags*)(state + 0x428))->b04 || mainGetBit(s->gameBitId) != 0)
    {
        ((SnowBikeFlags*)(state + 0x428))->b04 = 1;
        return;
    }
    mode = s->riderMode;
    switch (mode)
    {
    case 0:
    {
        {
            *(u8*)&obj->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            if ((*(u8*)&obj->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
            {
                s->playerInRange = 1;
            }
            else
            {
                s->playerInRange = 0;
            }
            Sfx_StopObjectChannel((int)obj, 0x57);
        }
    }
    break;
    case 2:
    {
        SnowBike_UpdateRouteFollowing(obj, (SnowBikeState*)state);
        if (((SnowBikeFlags*)(state + 0x428))->b02)
        {
            if (drshackle_updateAttachedPosition(obj, (ShackleSwingState*)state) != 0)
            {
                SnowBike_UpdateExhaustFx(obj, (int)state);
                SnowBike_buildOrientationMatrices(obj, (int)state);
                if (s->collisionFxTimer)
                {
                    PSVECScale((f32*)(state + 0x464), (f32*)(state + 0x47c),
                               s->collisionFxDamping);
                    PSVECScale((f32*)(state + 0x494), (f32*)(state + 0x494),
                               s->collisionFxDamping);
                    s->collisionFxTimer -= timeDelta;
                    if (s->collisionFxTimer <= 0.0f)
                    {
                        if (Rcp_GetMotionBlurEnabled() != 0)
                        {
                            setMotionBlur(0, 0.0f);
                        }
                        s->collisionFxTimer = 0.0f;
                    }
                }
                else
                {
                    s->localVelXLimit = s->velLimitX;
                    s->localVelYLimit = s->velLimitY;
                    s->distanceScaleLimit = s->velLimitZ;
                }
                fz = 0.0f;
                rq1.quad[1] = fz;
                rq1.quad[2] = fz;
                rq1.quad[3] = fz;
                rq1.quad[0] = 1.0f;
                rq1.rot[0] = -s->yaw;
                rq1.rot[1] = -obj->anim.rotY;
                rq1.rot[2] = -obj->anim.rotZ;
                mtxRotateByVec3s(mtx1, rq1.rot);
                Matrix_TransformPoint(mtx1, 0.0f,
                                      s->liftAccel * s->turnForceGain,
                                      0.0f, &vec1[0], &dummy1, &vec1[2]);
                vec1[0] = vec1[0] * s->turnVelScale;
                vec1[1] = 0.0f;
                PSVECScale(vec1, vec1, timeDelta);
                PSVECAdd((f32*)(state + 0x494), vec1, (f32*)(state + 0x494));
                s->localVelY =
                    s->liftAccel * timeDelta + s->localVelY;
                damp = powfBitEstimate(s->localVelXDamp, timeDelta);
                s->localVelX *= damp;
                damp = powfBitEstimate(s->distanceScaleDamp, timeDelta);
                s->distanceScale *= damp;
                SnowBike_UpdateLiftSway((int)obj, (int)state);
                Matrix_TransformPoint((f32*)(state + 0xec), s->localVelX,
                                      s->localVelY, s->distanceScale,
                                      &obj->anim.velocityX, &obj->anim.velocityY,
                                      &obj->anim.velocityZ);
                objApplyVelocity(obj);
            }
        }
        else
        {
            setAButtonIcon(0x10);
            setBButtonIcon(0x11);
            s->stickX = padGetStickX(0);
            s->stickY = (f32)padGetStickY(0);
            s->buttonsHeld = getButtonsHeld(0);
            s->buttonsJustPressed = getButtonsJustPressed(0);
            s->buttonsJustPressedIfNotBusy = getButtonsJustPressedIfNotBusy(0);
            s->steerAngleDeg =
                (f32)(u16)getAngle(s->stickX, (f32) - (int)s->stickY) /
                182.04f;
            s->stickX = s->stickX / 56.0f;
            value = s->stickX;
            if (value < -1.0f)
            {
                clamped = -1.0f;
            }
            else if (value > 1.0f)
            {
                clamped = 1.0f;
            }
            else
            {
                clamped = value;
            }
            s->stickX = clamped;
            SnowBike_UpdateExhaustFx(obj, (int)state);
            SnowBike_buildOrientationMatrices(obj, (int)state);
            if (s->collisionFxTimer)
            {
                PSVECScale((f32*)(state + 0x464), (f32*)(state + 0x47c), s->collisionFxDamping);
                PSVECScale((f32*)(state + 0x494), (f32*)(state + 0x494), s->collisionFxDamping);
                s->collisionFxTimer -= timeDelta;
                if (s->collisionFxTimer <= 0.0f)
                {
                    if (Rcp_GetMotionBlurEnabled() != 0)
                    {
                        setMotionBlur(0, 0.0f);
                    }
                    s->collisionFxTimer = 0.0f;
                }
            }
            else
            {
                s->localVelXLimit = s->velLimitX;
                s->localVelYLimit = s->velLimitY;
                s->distanceScaleLimit = s->velLimitZ;
            }
            fz = 0.0f;
            rq2.quad[1] = fz;
            rq2.quad[2] = fz;
            rq2.quad[3] = fz;
            rq2.quad[0] = 1.0f;
            rq2.rot[0] = -s->yaw;
            rq2.rot[1] = -obj->anim.rotY;
            rq2.rot[2] = -obj->anim.rotZ;
            mtxRotateByVec3s(mtx2, rq2.rot);
            Matrix_TransformPoint(mtx2, 0.0f,
                                  s->liftAccel * s->turnForceGain,
                                  0.0f, &vec2[0], &dummy2, &vec2[2]);
            vec2[0] = vec2[0] * s->turnVelScale;
            vec2[1] = 0.0f;
            PSVECScale(vec2, vec2, timeDelta);
            PSVECAdd((f32*)(state + 0x494), vec2, (f32*)(state + 0x494));
            s->localVelY =
                s->liftAccel * timeDelta + s->localVelY;
            damp = powfBitEstimate(s->localVelXDamp, timeDelta);
            s->localVelX *= damp;
            damp = powfBitEstimate(s->distanceScaleDamp, timeDelta);
            s->distanceScale *= damp;
            SnowBike_UpdateLiftSway((int)obj, (int)state);
            Matrix_TransformPoint((f32*)(state + 0xec), s->localVelX,
                                  s->localVelY, s->distanceScale,
                                  &obj->anim.velocityX, &obj->anim.velocityY,
                                  &obj->anim.velocityZ);
            objApplyVelocity(obj);
        }
        SnowBike_UpdateAirMeter((int)obj, (int)state);
        drcloudcage_updateEngineFx(obj, state, s->distanceScale,
                                   (int)(850.0f * -s->engineFxLevel), state + 0x461, 7);
        SnowBike_UpdateCollisionResponse(obj, (int)state);
        obj->anim.rotX = s->yaw;
    }
    break;
    }
}

void SnowBike_InitTuning(GameObject* obj, int state);

void SnowBike_init(GameObject* obj, SnowBikePlacement* params, int flag)
{
    f32 fv;
    f32 fz;
    s16 rot;
    u8* path;
    int i;
    u8* alloc;
    GXColor pathParam;
    char* base[1];
    u8* state;
    SnowBikeState* s;

    base[0] = (char*)gSnowBikePathSetupPoints;
    pathParam = lbl_803E5AE0;
    state = obj->extra;
    s = (SnowBikeState*)state;

    if (obj->anim.mapEventSlot == 0x13)
    {
        alloc = mmAlloc(36, 5, 0);
        memcpy(alloc, params, 36);
        *(u8**)&obj->anim.placementData = alloc;
        obj->anim.flags |= OBJANIM_FLAG_OWNS_PLACEMENT_DATA;
        Obj_ClearModelSlotIndex(obj);
    }
    rot = params->yawByte << 8;
    s->yawCurrent = rot;
    s->yaw = rot;
    obj->anim.rotX = rot;
    SnowBike_InitTuning(obj, (int)state);
    if (flag == 0)
    {
        if (((SnowBikeFlags*)(state + 0x428))->b20)
        {
            s->airMeterMax = 70000.0f;
            s->airDrainRate = 1.0f;
            s->airMeterCurrent = 69999.0f;
            if (s->riderMode == 2)
            {
                (*gGameUIInterface)
                    ->initAirMeter((int)s->airMeterMax, SNOWBIKE_AIRMETER_BGTEXTURE);
                (*gGameUIInterface)->airMeterSetField24(4.0f);
            }
        }
    }
    if (params->startFlag != 0)
    {
        ((SnowBikeFlags*)(state + 0x428))->b02 = 1;
    }
    s->checkpointIndexA = -1;
    s->checkpointIndexB = -1;
    s->checkpointIndexC = -1;
    s->routeFilter = params->param1c;
    s->unk05D = params->param1d;
    s->posSnapshotX = obj->anim.localPosX;
    s->posSnapshotY = obj->anim.localPosY;
    s->posSnapshotZ = obj->anim.localPosZ;
    obj->animEventCallback = SnowBike_SeqFn;
    ObjGroup_AddObject((int)obj, SNOWBIKE_OBJGROUP);
    if (flag == 0)
    {
        i = 0;
        for (path = state; i < 9; i++)
        {
            *(u8**)(path + 0x4c8) = mmAlloc(1600, 26, 0);
            path += 8;
        }
    }
    s->homePosX = obj->anim.worldPosX;
    s->homePosY = obj->anim.worldPosY;
    s->homePosZ = obj->anim.worldPosZ;
    s->pathProgress = 0.0f;
    s->unk448 = params->unk1a;
    s->gameBitId = params->gameBitId;
    if (mainGetBit(s->gameBitId) != 0)
    {
        ((SnowBikeFlags*)(state + 0x428))->b04 = 1;
    }
    s->unk438 = 30.0f;
    fz = 0.0f;
    s->unk3F4 = fz;
    s->unk3F8 = fz;
    s->unk018 = 400.0f;
    s->unk01C = fz;
    s->unk020 = 3.0f;
    s->unk024 = 6.0f;
    s->collisionHitType = -1;
    fv = 4.0f;
    s->velLimitX = fv;
    s->velLimitY = fv;
    s->modelId = 0x436;
    switch (obj->anim.seqId)
    {
    case SNOWBIKE_IM_BIKE_OBJ:
    default:
        s->bikeType = 1;
        s->velLimitZ = 6.0f;
        s->modelId = 282;
        break;
    case SNOWBIKE_IM_CLAWBIKE_V0_OBJ:
        s->bikeType = 1;
        s->bikeVariant = 0;
        s->unk01C = 200.0f;
        s->unk018 = 600.0f;
        s->collisionHitType = 1;
        s->velLimitZ = 8.0f;
        break;
    case SNOWBIKE_IM_CLAWBIKE_V1_OBJ:
        s->bikeType = 1;
        s->unk058 = 1;
        s->bikeVariant = 1;
        s->collisionHitType = 2;
        s->velLimitZ = 8.0f;
        break;
    case SNOWBIKE_CR_BIKE_OBJ:
        s->bikeType = 0;
        s->velLimitZ = gSnowBikeCrBikeVelLimitZ;
        s->modelId = 282;
        break;
    case SNOWBIKE_CR_CLAWBIKE_V0_OBJ:
        s->bikeType = 0;
        s->bikeVariant = 0;
        s->unk01C = 200.0f;
        s->unk018 = 600.0f;
        s->velLimitZ = 1.2f * gSnowBikeClawBikeVelLimitZ;
        break;
    case SNOWBIKE_CR_CLAWBIKE_V1_OBJ:
        s->bikeType = 0;
        s->bikeVariant = 1;
        s->unk01C = 100.0f;
        s->unk018 = 500.0f;
        s->velLimitZ = 1.1f * gSnowBikeClawBikeVelLimitZ;
        break;
    case SNOWBIKE_CR_CLAWBIKE_V2_OBJ:
        s->bikeType = 0;
        s->bikeVariant = 2;
        s->unk01C = 100.0f;
        s->unk018 = 500.0f;
        s->velLimitZ = gSnowBikeClawBikeVelLimitZ;
        break;
    }
    fv = s->velLimitX;
    s->localVelXLimit = fv;
    s->baseVelLimitX = fv;
    fv = s->velLimitY;
    s->localVelYLimit = fv;
    s->baseVelLimitY = fv;
    fv = s->velLimitZ;
    s->distanceScaleLimit = fv;
    s->baseVelLimitZ = fv;
    s->gameBitPtr = (s16*)((int)base[0] + 0xa4 + s->bikeType * 6);
    if (s->bikeType == 0)
    {
        if (!((SnowBikeFlags*)(state + 0x428))->b02)
        {
            ((SnowBikeFlags*)(state + 0x428))->b20 = 1;
            s->airMeterRefillTimer = 0.0f;
        }
        s->unk538 = -0.1f;
    }
    else
    {
        s->unk538 = -0.05f;
    }
    path = state + 0x178;
    path[0x25b] = 1;
    (*gPathControlInterface)->init(path, 0, 0x48607, 1);
    (*gPathControlInterface)->setup(path, 4, base[0], base[0] + 0x30, &pathParam);
    if (((SnowBikeFlags*)(state + 0x428))->b02 && s->collisionHitType != -1)
    {
        curves_setLocalPointCollisionEx((CurvesCollisionState*)path, 1, (f32*)(base[0] + 0x40), &gSnowBikeCollisionRadius, 8,
                                        s->collisionHitType);
    }
    else
    {
        (*gPathControlInterface)->setLocalPointCollision(path, 1, base[0] + 0x40, &gSnowBikeCollisionRadius, 8);
    }
    path[0x264] = 10.0f + gSnowBikeCollisionRadius;
    (*gPathControlInterface)->attachObject((void*)obj, path);
}

void SnowBike_release(void)
{
    if (sSnowBikeTrailTexture != 0)
    {
        textureFree((Texture*)((u8*)sSnowBikeTrailTexture));
        sSnowBikeTrailTexture = 0;
    }
}

void SnowBike_initialise(void)
{
    if (sSnowBikeTrailTexture == 0)
    {
        sSnowBikeTrailTexture = textureLoadAsset(SNOWBIKE_TEXTURE_ID);
    }
}

ObjectDescriptor24 gSnowBikeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_24_SLOTS,
    (ObjectDescriptorCallback)SnowBike_initialise,
    (ObjectDescriptorCallback)SnowBike_release,
    NULL,
    (ObjectDescriptorCallback)SnowBike_init,
    (ObjectDescriptorCallback)SnowBike_update,
    (ObjectDescriptorCallback)SnowBike_hitDetect,
    (ObjectDescriptorCallback)SnowBike_render,
    (ObjectDescriptorCallback)SnowBike_free,
    (ObjectDescriptorCallback)SnowBike_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)SnowBike_getExtraSize,
    (ObjectDescriptorCallback)SnowBike_canMount,
    (ObjectDescriptorCallback)SnowBike_getMountSide,
    (ObjectDescriptorCallback)SnowBike_getRiderPosition,
    (ObjectDescriptorCallback)SnowBike_canDismount,
    (ObjectDescriptorCallback)SnowBike_getDismountSide,
    (ObjectDescriptorCallback)SnowBike_getCameraPosition,
    (ObjectDescriptorCallback)SnowBike_getMountState,
    (ObjectDescriptorCallback)SnowBike_setMountState,
    (ObjectDescriptorCallback)SnowBike_getPlayerAnim,
    (ObjectDescriptorCallback)SnowBike_func13,
    (ObjectDescriptorCallback)SnowBike_getRacePosition,
    (ObjectDescriptorCallback)SnowBike_resetToRomListPosition,
    (ObjectDescriptorCallback)SnowBike_func16,
    (ObjectDescriptorCallback)SnowBike_func17,
};
