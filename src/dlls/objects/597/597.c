#include "dlls/object_descriptor.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXEnum.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/mtx/vec.h"
#include "dolphin/os/OSReport.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/camera_interface.h"
#include "main/checkpoint_interface.h"
#include "main/dll/SP/dll_0287_spscarab.h"
#include "main/dll/dll_0015_curves.h"
#include "main/dll/dll_0255_snowbike.h"
#include "main/dll/objfx_api.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/dll/tricky_api.h"
#include "main/frame_timing.h"
#include "main/game_ui_interface.h"
#include "main/gamebits.h"
#include "main/gametext_show_api.h"
#include "main/lightmap_api.h"
#include "main/maketex_api.h"
#include "main/mm.h"
#include "main/objtype.h"
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

#define SNOWBIKE_OBJGROUP           0xa
#define SNOWBIKE_AIRMETER_BGTEXTURE 0x5cd
#define SNOWBIKE_TRAIL_TEXTURE      0x186

#define SNOWBIKE_IM_BIKE_OBJ        0x72
#define SNOWBIKE_IM_CLAWBIKE_V0_OBJ 0x16c
#define SNOWBIKE_IM_CLAWBIKE_V1_OBJ 0x16f
#define SNOWBIKE_CR_BIKE_OBJ        0x38c
#define SNOWBIKE_CR_CLAWBIKE_V0_OBJ 0x38d
#define SNOWBIKE_CR_CLAWBIKE_V1_OBJ 0x38e
#define SNOWBIKE_CR_CLAWBIKE_V2_OBJ 0x4d4

#define SNOWBIKE_MOUNT_STATE_RIDING 2

#define SNOWBIKE_BUTTON_ACCELERATE 0x100
#define SNOWBIKE_BUTTON_BRAKE      0x200

#define SNOWBIKE_SOUNDFLAG_ENGINE 1
#define SNOWBIKE_SOUNDFLAG_HISS   2
#define SNOWBIKE_SOUNDFLAG_JETS   4

#define SNOWBIKE_TRAIL_COUNT       9
#define SNOWBIKE_TRAIL_FLAG_ACTIVE 1
#define SNOWBIKE_TRAILS_OFFSET     0x4c8
STATIC_ASSERT(offsetof(SnowBikeState, trails) == SNOWBIKE_TRAILS_OFFSET);

#define SNOWBIKE_SETUP_RADII_OFFSET           0x30
#define SNOWBIKE_SETUP_COLLISION_POINT_OFFSET 0x40
#define SNOWBIKE_SETUP_GAMEBITS_OFFSET        0xa4

#define SNOWBIKE_SWING_ANGLE_STEP         0xb6
#define SNOWBIKE_SWING_BLEND_LIMIT        0x41
#define SNOWBIKE_SWING_ANGLE_RETURN_LIMIT 0x2aaa

#define SNOWBIKE_PARTFX_IMPACT_A        0x551
#define SNOWBIKE_PARTFX_IMPACT_B        0x552
#define SNOWBIKE_PARTFX_COLLISION_SPRAY 0x553
#define SNOWBIKE_PARTFX_IMPACT_C        0x554
#define SNOWBIKE_PARTFX_SPLASH          0x80a
#define SNOWBIKE_PARTFX_ICE_SPRAY       0x80b
#define SNOWBIKE_HIT_VOLUME_SLOT        0x15
#define SNOWBIKE_TRAIL_POINT_CAPACITY   100
#define SNOWBIKE_TEXT_WRONG_WAY         0x475

#define CLAMP_EXPR(value, low, high) ((value) < (low) ? (low) : ((value) > (high) ? (high) : (value)))

typedef struct SnowBikeSegmentTypes
{
    s8 types[4];
} SnowBikeSegmentTypes;

typedef struct SnowBikePathSetup
{
    Vec terrainPoints[4];
    f32 terrainRadii[4];
    Vec collisionPoint;
} SnowBikePathSetup;
STATIC_ASSERT(offsetof(SnowBikePathSetup, terrainRadii) == SNOWBIKE_SETUP_RADII_OFFSET);
STATIC_ASSERT(offsetof(SnowBikePathSetup, collisionPoint) == SNOWBIKE_SETUP_COLLISION_POINT_OFFSET);

typedef struct SnowBikeLeaderRankItem
{
    CheckpointRankItem item;
    u8 pad20[0x18];
} SnowBikeLeaderRankItem;

typedef struct SnowBikeTrailTemplate
{
    f32 points[18];
} SnowBikeTrailTemplate;

typedef struct SnowBikeRomListItem
{
    ObjPlacement base;
    u8 pad18[0x29 - 0x18];
    u8 yawByte;
} SnowBikeRomListItem;

typedef struct SnowBikePlacement
{
    ObjPlacement base;
    u8 yawByte;
    u8 cpuDriven;
    s16 completionGameBit;
    u8 routeFilter;
    u8 routeMode;
    s16 finishedGameBit;
    u8 pad20[0x24 - 0x20];
} SnowBikePlacement;

const SnowBikeSegmentTypes sSnowBikeSegmentTypes = {{5, 5, 5, 5}};
const GXColor sSnowBikeTrailTevColor = {0x20, 0x20, 0x20, 0x80};

SnowBikeLeaderRankItem gSnowBikeLeaderRankItem;

SnowBikePathSetup gSnowBikePathSetup = {
    {{-6.5f, 0.0f, -13.0f}, {6.5f, 0.0f, -13.0f}, {6.5f, 0.0f, 13.0f}, {-6.5f, 0.0f, 13.0f}},
    {1.0f, 1.0f, 1.0f, 1.0f},
    {0.0f, 0.0f, 0.0f},
};

int gSnowBikeCollisionObjectIds[12] = {
    0x72, 0x16D, 0x170, 0x16C, 0x16F, 0x38C, 0x389, 0x38A, 0x4D3, 0x38D, 0x38E, 0x4D4,
};

int gSnowBikeRiderObjectIds[10] = {365, 368, 364, 367, 905, 906, 1235, 909, 910, 1236};

s16 gSnowBikeRaceGameBits[2][3] = {{1175, 1176, 1180}, {930, 931, 1180}};

int gSnowBikeCheckpointRomListIds[2][3] = {{0x30C60, 0x30C60, 0x30C60}, {0xC9E, 0xC9F, 0xCB3}};

f32 gSnowBikeCollisionRadius = 15.0f;
int gSnowBikeLeaderRouteRank = -1;
f32 gSnowBikeClawBikeVelLimitZ = 8.5f;
f32 gSnowBikeCrBikeVelLimitZ = 6.0f;
f32 gSnowBikeBoostVelScale = 1.05f;
int gSnowBikeAirRefillAmount = 5000;
int gSnowBikeBoostDuration = 60;
int gSnowBikeHardCollisionDuration = 20;
f32 gSnowBikeAirDrainRate = 4.7f;
s16 gSnowBikeWrongWayAngleThreshold = 0x4000;
f32 gSnowBikeRouteDistGate = 2000.0f;
char sSnowBikeVelDebugFmt[] = "vel %f\n";

f32 gSnowBikeWindVolume;
Texture* sSnowBikeTrailTexture;

const SnowBikeTrailTemplate gSnowBikeTrailPointTemplate = {{
    -6.0f, 1.0f, 15.0f, 6.0f, 1.0f, 15.0f,
    -7.5f, 1.0f, 15.0f, -4.0f, 1.0f, 15.0f,
    4.0f, 1.0f, 15.0f, 7.5f, 1.0f, 15.0f,
}};

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

static inline void SnowBike_SyncHitReactPosition(GameObject* obj)
{
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosX = obj->anim.localPosX;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosY = obj->anim.localPosY;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosZ = obj->anim.localPosZ;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosX = obj->anim.worldPosX;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosY = obj->anim.worldPosY;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosZ = obj->anim.worldPosZ;
}

void SnowBike_DrawTrails(GameObject* obj, SnowBikeState* state)
{
    u8 r;
    u8 g;
    u8 b;
    GXColor color;
    SnowBikeTrailPoint* point;
    u8* p;
    SnowBikeTrail* trail;
    int i;
    int j;
    f32 texT;
    f32 texS;

    color = sSnowBikeTrailTevColor;
    selectTexture(sSnowBikeTrailTexture, 0);
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
    skyGetSunColor(0, &r, &g, &b);
    for (i = 0, p = (u8*)state; i < SNOWBIKE_TRAIL_COUNT; p += sizeof(SnowBikeTrail), i++)
    {
        trail = (SnowBikeTrail*)(p + SNOWBIKE_TRAILS_OFFSET);
        if ((trail->flags & SNOWBIKE_TRAIL_FLAG_ACTIVE) && trail->count >= 4)
        {
            j = 0;
            point = trail->points;
            texS = 0.0f;
            texT = 1.0f;
            while (j < trail->count - 2)
            {
                GXBegin(GX_QUADS, GX_VTXFMT2, 4);
                shPos3f32(point[0].x - playerMapOffsetX, point[0].y, point[0].z - playerMapOffsetZ);
                shColor4u8(r, g, b, point[0].alpha);
                shTexCoord2f32(texS, texS);
                shPos3f32(point[1].x - playerMapOffsetX, point[1].y, point[1].z - playerMapOffsetZ);
                shColor4u8(r, g, b, point[1].alpha);
                shTexCoord2f32(texT, texS);
                shPos3f32(point[3].x - playerMapOffsetX, point[3].y, point[3].z - playerMapOffsetZ);
                shColor4u8(r, g, b, point[3].alpha);
                shTexCoord2f32(texT, texS);
                shPos3f32(point[2].x - playerMapOffsetX, point[2].y, point[2].z - playerMapOffsetZ);
                shColor4u8(r, g, b, point[2].alpha);
                shTexCoord2f32(texS, texS);
                point += 2;
                j += 2;
            }
        }
    }
}
void SnowBike_UpdateTrails(GameObject* obj, SnowBikeState* state)
{
    TrackGroundHit** hits;
    MatrixTransform transform;
    Vec pos[2];
    f32 matrix[16];
    SnowBikeTrailTemplate localPoints;
    int trailIndex;
    int endpointIndex;
    SnowBikeTrail* selectedTrail;
    int i;
    u32 k;
    u32 k2;
    int start;
    int end;
    SnowBikeTrail* trail;
    SnowBikeTrailPoint* point;
    int pointIndex;
    SnowBikeTrailPoint* points;
    SnowBikeTrailPoint* tail;
    int tailIndex;
    int copyIndex;
    int scanIndex;
    int hitIndex;
    int hitCount;
    u8 hitDetected;
    f32 deltaY;

    localPoints = gSnowBikeTrailPointTemplate;

    for (trailIndex = 0; trailIndex < SNOWBIKE_TRAIL_COUNT; trailIndex++)
    {
        trail = &state->trails[trailIndex];
        if (trail->flags & SNOWBIKE_TRAIL_FLAG_ACTIVE)
        {
            pointIndex = trail->count - 2;
            points = trail->points;
            point = &points[pointIndex];
            for (; pointIndex >= 0; point -= 2, pointIndex -= 2)
            {
                point[0].alpha = point[0].alpha - 8.0f * timeDelta;
                point[1].alpha = point[0].alpha;
                point[0].alpha = CLAMP_EXPR(point[0].alpha, 0, 255);
                point[1].alpha = CLAMP_EXPR(point[1].alpha, 0, 255);
            }

            tailIndex = trail->count - 2;
            tail = &points[tailIndex];
            for (; tailIndex >= 0; tail -= 2, tailIndex -= 2)
            {
                if (tailIndex >= 2)
                {
                    if (tail[0].alpha <= 0 && tail[1].alpha <= 0 && tail[-1].alpha <= 0 && tail[-2].alpha <= 0)
                    {
                        trail->count -= 2;
                    }
                }
                else if (tail[0].alpha <= 0 && tail[1].alpha <= 0)
                {
                    trail->count -= 2;
                }
            }

            if (trail != state->activeTrails[0] && trail != state->activeTrails[1] && trail != state->activeTrails[2] &&
                trail->count == 0)
            {
                trail->flags &= ~SNOWBIKE_TRAIL_FLAG_ACTIVE;
            }
        }
    }

    for (i = 0, k = 0, k2 = 3; i < 3; k += 6, k2 += 6, i++)
    {
        start = k;
        end = k2;
        transform.x = obj->anim.worldPosX;
        transform.y = obj->anim.worldPosY;
        transform.z = obj->anim.worldPosZ;
        transform.rotX = obj->anim.rotX;
        transform.rotY = obj->anim.rotY;
        transform.rotZ = obj->anim.rotZ + state->rollOffset;
        transform.scale = 1.0f;
        setMatrixFromObjectPos(matrix, &transform);
        Matrix_TransformPoint(matrix, localPoints.points[start], localPoints.points[start + 1],
                              localPoints.points[start + 2], &pos[0].x, &pos[0].y, &pos[0].z);
        Matrix_TransformPoint(matrix, localPoints.points[end], localPoints.points[end + 1],
                              localPoints.points[end + 2], &pos[1].x, &pos[1].y, &pos[1].z);

        hitDetected = 0;
        for (endpointIndex = 0; endpointIndex < 2; endpointIndex++)
        {
            hitCount = trackGetHeight(obj, pos[endpointIndex].x, pos[endpointIndex].y, pos[endpointIndex].z, &hits, 0,
                                      0x20);
            for (hitIndex = 0; hitIndex < hitCount; hitIndex++)
            {
                deltaY = hits[hitIndex]->height - pos[endpointIndex].y;
                if (i > 0)
                {
                    if (deltaY > 0.0f && deltaY < 20.0f)
                    {
                        hitDetected = 1;
                        pos[endpointIndex].y = 0.5f + hits[hitIndex]->height;
                        break;
                    }
                }
                else if (deltaY >= -20.0f && deltaY < 20.0f)
                {
                    hitDetected = 1;
                    pos[endpointIndex].y = 0.5f + hits[hitIndex]->height;
                    break;
                }
            }
        }

        if (!state->flags.airborne && hitDetected)
        {
            selectedTrail = state->activeTrails[i];
            if (selectedTrail == NULL)
            {
                for (scanIndex = 0; scanIndex < SNOWBIKE_TRAIL_COUNT; scanIndex++)
                {
                    selectedTrail = &state->trails[scanIndex];
                    if (!(selectedTrail->flags & SNOWBIKE_TRAIL_FLAG_ACTIVE))
                    {
                        break;
                    }
                }
                if (scanIndex >= SNOWBIKE_TRAIL_COUNT)
                {
                    break;
                }
                selectedTrail->flags |= SNOWBIKE_TRAIL_FLAG_ACTIVE;
                selectedTrail->count = 0;
                state->activeTrails[i] = selectedTrail;
            }
            else
            {
                for (copyIndex = selectedTrail->count - 1; copyIndex >= 0; copyIndex--)
                {
                    memcpy(&selectedTrail->points[copyIndex + 2], &selectedTrail->points[copyIndex],
                           sizeof(SnowBikeTrailPoint));
                }
            }

            selectedTrail->points[0].x = pos[0].x;
            selectedTrail->points[0].y = pos[0].y;
            selectedTrail->points[0].z = pos[0].z;
            selectedTrail->points[1].x = pos[1].x;
            selectedTrail->points[1].y = pos[1].y;
            selectedTrail->points[1].z = pos[1].z;
            selectedTrail->points[0].alpha = 255;
            selectedTrail->points[1].alpha = 255;
            selectedTrail->points[0].surfaceType = state->groundSurfaceType;
            selectedTrail->points[1].surfaceType = state->groundSurfaceType;
            selectedTrail->count += 2;
            state->lastTrailPosX = obj->anim.worldPosX;
            state->lastTrailPosY = obj->anim.worldPosY;
            state->lastTrailPosZ = obj->anim.worldPosZ;
        }
        else
        {
            state->activeTrails[i] = NULL;
        }
    }
}

static void SnowBike_ClampWindVolume(volume, limit)
f32 volume;
f32 limit;
{
    if (volume < 0.0f)
    {
        gSnowBikeWindVolume = -volume;
    }
    else if (volume > limit)
    {
        gSnowBikeWindVolume = limit;
    }
}

void SnowBike_UpdateEngineFx(GameObject* obj, SnowBikeState* state, f32 forwardSpeed, int yJoy, s8* unused,
                             u8 soundFlags)
{
    f32 speed;
    int volume;
    MatrixTransform pulse;

    speed = CLAMP_EXPR(forwardSpeed, 0.0f, 70.0f);
    if (soundFlags & SNOWBIKE_SOUNDFLAG_ENGINE)
    {
        if (Sfx_IsPlayingFromObjectChannel(obj, 8))
        {
            gSnowBikeWindVolume = 11.6f * speed;
            if (gSnowBikeWindVolume < 0.0f)
            {
                gSnowBikeWindVolume = -gSnowBikeWindVolume;
            }
            if (gSnowBikeWindVolume < 40.0f)
            {
                gSnowBikeWindVolume = 40.0f;
            }
            if (gSnowBikeWindVolume > 200.0f)
            {
                gSnowBikeWindVolume = 200.0f;
            }
            if (state->airTime < 18.0f)
            {
                volume = 30.0f * speed;
                if (volume < 0)
                {
                    volume = -volume;
                }
                if (volume > 127)
                {
                    volume = 127;
                }
            }
            else
            {
                volume = 0;
            }
            Sfx_SetObjectChannelVolume(obj, 8, volume, 0.1f + gSnowBikeWindVolume / 70.0f);
        }
    }
    if (soundFlags & SNOWBIKE_SOUNDFLAG_HISS)
    {
        if (Sfx_IsPlayingFromObjectChannel(obj, 1))
        {
            if (state->airTime < 18.0f)
            {
                gSnowBikeWindVolume = speed != 0.0f ? speed * obj->anim.rotZ / 30000.0f : 0.0f;
                SnowBike_ClampWindVolume(gSnowBikeWindVolume, 1.0f);
                volume = 127.0f * gSnowBikeWindVolume;
                if (volume > 127.0f)
                {
                    volume = 127;
                }
                else if (volume < 0.0f)
                {
                    volume = 0;
                }
                Sfx_SetObjectChannelVolume(obj, 1, volume, 0.1f + gSnowBikeWindVolume);
            }
        }
    }
    if (soundFlags & SNOWBIKE_SOUNDFLAG_JETS)
    {
        Sfx_PlayFromObject(obj, state->engineSfxId);
        Sfx_PlayFromObject(obj, SFXTRIG_tr_gal_rumblelp11);
        if (yJoy > 5)
        {
            state->jetsVolume += timeDelta;
        }
        else if (state->jetsVolume > 40.0f)
        {
            state->jetsVolume -= 1.5f * timeDelta;
        }
        if (state->jetsVolume > 70.0f)
        {
            state->jetsVolume = 70.0f;
        }
        if (state->jetsVolume < 45.0f)
        {
            state->jetsVolume = 45.0f;
        }
        Sfx_SetObjectChannelVolume(obj, 2, state->jetsVolume, state->jetsVolume / 256.0f + 0.3f);
        if (yJoy > 5)
        {
            state->rumbleVolume = 60.0f + yJoy;
        }
        else if (state->rumbleVolume > 60.0f)
        {
            state->rumbleVolume -= 0.5f * timeDelta;
        }
        if (state->rumbleVolume > 80.0f)
        {
            state->rumbleVolume = 80.0f;
        }
        if (state->rumbleVolume < 65.0f)
        {
            state->rumbleVolume = 65.0f;
        }
        Sfx_SetObjectChannelVolume(obj, 4, state->rumbleVolume, state->rumbleVolume / 100.0f);
        pulse.x = -5.3f;
        pulse.y = 4.4f;
        pulse.z = 24.0f;
        pulse.scale = 0.0f;
        objfx_spawnLightPulse(obj, 0.5f, 2, 0, 1, state->rumbleVolume / 250.0f, &pulse);
        pulse.x = 5.3f;
        objfx_spawnLightPulse(obj, 0.5f, 2, 0, 1, state->rumbleVolume / 250.0f, &pulse);
    }
    SnowBike_UpdateTrails(obj, state);
}

f32 SnowBike_GetRouteIntensity(GameObject* obj, SnowBikeState* state)
{
    f32 result;
    f32 d;
    f32 leaderMetric;
    f32 stateMetric;
    int rank;

    if ((gSnowBikeLeaderRouteRank == -1) ||
        (rank = (*gCheckpointInterface)->getRouteRank(&state->rankItem), gSnowBikeLeaderRouteRank > rank))
    {
        if (gSnowBikeLeaderRouteRank == -1)
        {
            GameObject* playerObj = Obj_GetPlayerObject();
            d = Vec_distance(&obj->anim.worldPosX, &playerObj->anim.worldPosX);
            d *= 0.5f;
        }
        else
        {
            leaderMetric = 100.0f * gSnowBikeLeaderRankItem.item.linkDepth + 100.0f * gSnowBikeLeaderRankItem.item.routeProgress;
            stateMetric = 100.0f * state->routeState.linkDepth + 100.0f * state->routeState.routeProgress;
            d = leaderMetric - stateMetric;
            d = (d >= 0.0f) ? d : -d;
        }
        if (d <= state->cpuSpeedNearDist)
        {
            result = state->cpuSpeedNear;
        }
        else if (d >= state->cpuSpeedFarDist)
        {
            result = state->cpuSpeedFar;
        }
        else
        {
            f32 ratio = (d - state->cpuSpeedNearDist) / (state->cpuSpeedFarDist - state->cpuSpeedNearDist);
            d = state->cpuSpeedNear;
            result = ratio * (state->cpuSpeedFar - d) + d;
        }
        if (state->bikeType == 0)
        {
            d = stateMetric - leaderMetric;
            d = (d >= 0.0f) ? d : -d;
            if (d > gSnowBikeRouteDistGate)
            {
                result = 0.0f;
            }
        }
    }
    else
    {
        rank = (*gCheckpointInterface)->getRouteRank(&state->rankItem);
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

int SnowBike_UpdateSwingBlend(GameObject* obj, SnowBikeState* state)
{
    f32 dx;
    f32 dz;
    int routeDone;
    f32 speed;
    int yawDelta;
    int steer;

    dx = obj->anim.localPosX;
    dz = obj->anim.localPosZ;
    dx -= state->routeCursor.x;
    dz -= state->routeCursor.z;
    speed = 180.0f - sqrtf(SQUARE(dx) + SQUARE(dz));
    if (state->impactTimer)
    {
        speed += CLAMP_EXPR(speed - 40.0f, 0.0f, 70.0f);
    }
    if (speed < 0.0f)
    {
        speed = 0.0f;
    }

    routeDone = (*gCheckpointInterface)->advanceRoute(&state->routeCursor, &state->routeState, speed, state->routeMode, 1, 0);
    (*gCheckpointInterface)->getRouteHeading(obj, &state->routeState);
    (*gCheckpointInterface)->queueRouteRankItem(&state->rankItem);
    if (routeDone != 0)
    {
        state->stickX = 0.0f;
        return 0;
    }

    yawDelta = getAngle(obj->anim.localPosX - state->routeCursor.x, obj->anim.localPosZ - state->routeCursor.z) & 0xffff;
    yawDelta -= state->velYaw & 0xffff;
    if (yawDelta > 0x8000)
    {
        yawDelta -= 0xffff;
    }
    if (yawDelta < -0x8000)
    {
        yawDelta += 0xffff;
    }
    steer = CLAMP_EXPR(yawDelta / SNOWBIKE_SWING_ANGLE_STEP, -SNOWBIKE_SWING_BLEND_LIMIT, SNOWBIKE_SWING_BLEND_LIMIT);
    state->stickX = -steer;
    state->steerAngleDeg = 0;
    state->stickX /= 56.0f;
    state->stickX = CLAMP_EXPR(state->stickX, -1.0f, 1.0f);

    {
        f32 maxSpeed = -SnowBike_GetRouteIntensity(obj, state);
        if (state->localVel.z < maxSpeed || yawDelta > SNOWBIKE_SWING_ANGLE_RETURN_LIMIT ||
            yawDelta < -SNOWBIKE_SWING_ANGLE_RETURN_LIMIT)
        {
            state->buttonsHeld = 0;
        }
        else if (state->localVel.z > maxSpeed)
        {
            state->buttonsHeld = SNOWBIKE_BUTTON_ACCELERATE;
        }
    }
    return 1;
}

int SnowBike_UpdateAttachedPosition(GameObject* obj, SnowBikeState* state)
{
    SnowBikeFlags* flags;
    int mapBlockIdx;
    int routeDone;
    s16 angle;
    f32 floorOffset;

    flags = &state->flags;
    if (flags->raceActive == 0)
    {
        return 0;
    }
    mapBlockIdx = objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ);
    if (mapBlockIdx > -1)
    {
        if (flags->routeAnchored == 0)
        {
            state->localVel.x = 0.0f;
            state->localVel.y = 0.0f;
            state->localVel.z = -SnowBike_GetRouteIntensity(obj, state);
            routeDone = (*gCheckpointInterface)
                            ->advanceRoute(&state->routeCursor, &state->routeState, -state->localVel.z * timeDelta,
                                           state->routeMode, 1, 0);
            (*gCheckpointInterface)->getRouteHeading(obj, &state->routeState);
            (*gCheckpointInterface)->queueRouteRankItem(&state->rankItem);
            if (routeDone != 0)
            {
                return 0;
            }

            SnowBike_ResetDynamics(obj, state);
            angle = getAngle(obj->anim.localPosX - state->routeCursor.x, obj->anim.localPosZ - state->routeCursor.z);
            obj->anim.rotX = angle;
            state->yaw = angle;
            state->velYaw = angle;
            state->throttle = -0.05f;
            obj->anim.localPosX = state->routeCursor.x;
            obj->anim.localPosY = state->routeCursor.y;
            obj->anim.localPosZ = state->routeCursor.z;
            (*gPathControlInterface)->attachObject(obj, &state->pathState);
            SnowBike_SyncHitReactPosition(obj);

            if (state->bikeType == 0)
            {
                trackGetNearestGroundOffset(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                                            &floorOffset, 0);
                obj->anim.localPosY = obj->anim.localPosY - floorOffset;
                obj->anim.localPosY += 2.0f;
            }
            flags->routeAnchored = 1;
            return 0;
        }
        return SnowBike_UpdateSwingBlend(obj, state) != 0;
    }

    routeDone = (*gCheckpointInterface)
                    ->advanceRoute(&state->routeCursor, &state->routeState,
                                   timeDelta * SnowBike_GetRouteIntensity(obj, state), state->routeMode, 1, 0);
    (*gCheckpointInterface)->getRouteHeading(obj, &state->routeState);
    (*gCheckpointInterface)->queueRouteRankItem(&state->rankItem);
    if (routeDone != 0)
    {
        return 0;
    }

    angle = getAngle(obj->anim.localPosX - state->routeCursor.x, obj->anim.localPosZ - state->routeCursor.z);
    obj->anim.rotX = angle;
    obj->anim.localPosX = state->routeCursor.x;
    obj->anim.localPosY = state->routeCursor.y;
    obj->anim.localPosZ = state->routeCursor.z;
    (*gPathControlInterface)->attachObject(obj, &state->pathState);
    SnowBike_SyncHitReactPosition(obj);
    flags->routeAnchored = 0;
    return 0;
}

void SnowBike_UpdateRouteFollowing(GameObject* obj, SnowBikeState* state)
{
    f32 wrongWayStep;
    u32 gameBitSet;
    u32 absHeadingDelta;
    s16 headingDelta;
    u16 routeHeading;
    s8 raceRank;

    if (state->flags.raceActive == 0)
    {
        state->routeState.startCheckpointId = -1;
        state->routeState.matchedCheckpointId = -1;
        state->routeState.currentCheckpointId = -1;
        state->routeState.linkDepth = 0;
        gSnowBikeLeaderRouteRank = -1;
        gameBitSet = mainGetBit(state->raceGameBits[0]);
        if (gameBitSet != 0)
        {
            state->flags.raceActive = 1;
        }
        if (state->flags.raceActive != 0)
        {
            if (state->flags.cpuDriven != 0)
            {
                SnowBike_resetToRomListPosition(obj);
            }
            else
            {
                (*gCheckpointInterface)->findRouteForObject(obj, &state->routeState, state->routeFilter);
            }
            (*gCheckpointInterface)->rewindRoute(&state->routeState);
        }
    }
    else
    {
        if (state->flags.cpuDriven == 0)
        {
            routeHeading = (*gCheckpointInterface)->getRouteHeading(obj, &state->routeState);
            headingDelta = obj->anim.rotX - routeHeading;
            if (headingDelta > 0x8000)
            {
                headingDelta = headingDelta - 0xffff;
            }
            if (headingDelta < -0x8000)
            {
                headingDelta = headingDelta + 0xffff;
            }
            absHeadingDelta = ((int)headingDelta >= 0) ? headingDelta : -headingDelta;
            gameBitSet = (int)absHeadingDelta > gSnowBikeWrongWayAngleThreshold;
            if ((int)gameBitSet == 0)
            {
                wrongWayStep = timeDelta;
            }
            else
            {
                wrongWayStep = -timeDelta;
            }
            state->wrongWayTimer += wrongWayStep;
            wrongWayStep = state->wrongWayTimer;
            state->wrongWayTimer = CLAMP_EXPR(wrongWayStep, 0.0f, 180.0f);
            if (state->wrongWayTimer > 90.0f)
            {
                gameTextShow(SNOWBIKE_TEXT_WRONG_WAY);
            }
            (*gCheckpointInterface)->queueRouteRankItem(&state->rankItem);
            state->raceRank = (*gCheckpointInterface)->getRouteRank(&state->rankItem);
            raceRank = state->raceRank;
            if ((raceRank == 1) && (gSnowBikeLeaderRouteRank == -1))
            {
                gSnowBikeLeaderRouteRank = -1;
            }
            else
            {
                gSnowBikeLeaderRouteRank = raceRank;
                gSnowBikeLeaderRankItem.item.linkDepth = state->routeState.linkDepth;
                gSnowBikeLeaderRankItem.item.routeProgress = state->routeState.routeProgress;
            }
        }
        gameBitSet = mainGetBit(state->raceGameBits[1]);
        if (gameBitSet != 0)
        {
            state->flags.raceActive = 0;
        }
    }
}

void SnowBike_UpdateAirMeter(GameObject* obj, SnowBikeState* state)
{
    f32 rate;
    f32 lim;
    f32 td;

    if (state->flags.airMeterActive != 0)
    {
        if (state->airMeterCurrent >= 0.0f)
        {
            td = timeDelta;
            state->airMeterCurrent -=
                td * gSnowBikeAirDrainRate + (f32)(s32)(state->airDrainRate * (td * PSVECMag(&state->localVel)));
            lim = 0.0f;
            if (lim != state->airMeterRefillTimer)
            {
                rate = 200.0f;
                state->airMeterCurrent = rate * timeDelta + state->airMeterCurrent;
                state->airMeterRefillTimer = state->airMeterRefillTimer - (f32)(s32)(rate * timeDelta);
                state->airMeterRefillTimer = CLAMP_EXPR(state->airMeterRefillTimer, lim, 100000.0f);
                state->airMeterCurrent = CLAMP_EXPR(state->airMeterCurrent, 0.0f, state->airMeterMax);
            }
            if (state->airMeterCurrent < 10000.0f)
            {
                Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_ar_bomb_pickup);
            }
            (*gGameUIInterface)->runAirMeter((s32)state->airMeterCurrent);
        }
        else
        {
            Sfx_StopObjectChannel(obj, 0x7f);
            if (state->velLimit.x > 0.1f)
            {
                if (randomGetRange(0, 10) == 0)
                {
                    Sfx_PlayFromObject(0, SFXTRIG_dn_boar1_c_117);
                }
                PSVECScale(&state->velLimit, &state->velLimit, 0.95f);
                if (state->flags.airborne != 0)
                {
                    if (state->velLimit.x < 0.1f)
                    {
                        state->velLimit.x = 0.1f;
                    }
                }
            }
            else
            {
                (*gGameUIInterface)->airMeterShutdown();
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                lim = 0.01f;
                state->velLimit.x = 0.01f;
                state->velLimit.y = lim;
                state->velLimit.z = lim;
            }
        }
    }
}

static void SnowBike_ResetAirMeter(SnowBikeState* state)
{
    state->airMeterMax = 70000.0f;
    state->airDrainRate = 1.0f;
    state->airMeterCurrent = 69999.0f;
    if (state->mountState == SNOWBIKE_MOUNT_STATE_RIDING)
    {
        (*gGameUIInterface)->initAirMeter((int)state->airMeterMax, SNOWBIKE_AIRMETER_BGTEXTURE);
        (*gGameUIInterface)->airMeterSetField24(4.0f);
    }
}

void SnowBike_onSeqFree(GameObject* obj)
{
    SnowBikeState* state = obj->extra;

    if (state->flags.cpuDriven == 0)
    {
        s16 yaw;

        state->localVel.x = 0.0f;
        state->localVel.y = 0.0f;
        state->localVel.z = -2.0f;
        state->flags.airborne = 0;
        state->airTime = 0.0f;
        yaw = obj->anim.rotX;
        state->yaw = yaw;
        state->velYaw = yaw;
        state->throttle = -0.05f;
    }
    ObjHits_EnableObject(obj);
    (*gPathControlInterface)->attachObject(obj, &state->pathState);
    SnowBike_SyncHitReactPosition(obj);
}

int SnowBike_SeqFn(GameObject* obj, int unused, ObjSeqState* seq)
{
    u8 eventId;
    int i;
    SnowBikeState* state;
    f32 matrix[16];
    MatrixTransform transform;
    f64 velX;
    f64 velY;
    f64 velZ;

    state = obj->extra;
    seq->freeCallback = (ObjAnimSequenceFreeCallback)SnowBike_onSeqFree;
    ObjHits_DisableObject(obj);

    for (i = 0; i < (int)(u32)seq->eventCount; i++)
    {
        eventId = seq->eventIds[i];
        switch (eventId)
        {
        case 2:
            if (obj->anim.romDefNo != SNOWBIKE_IM_CLAWBIKE_V0_OBJ && obj->anim.romDefNo != SNOWBIKE_IM_CLAWBIKE_V1_OBJ)
            {
                mainSetBits(0x499, 1);
            }
            break;
        case 3:
            (*gGameUIInterface)->airMeterShutdown();
            break;
        }
    }

    if (state->mountState == SNOWBIKE_MOUNT_STATE_RIDING)
    {
        velX = (f32)(oneOverTimeDelta * (obj->anim.localPosX - state->prevPosX));
        velY = (f32)(oneOverTimeDelta * (obj->anim.localPosY - state->prevPosY));
        velZ = (f32)(oneOverTimeDelta * (obj->anim.localPosZ - state->prevPosZ));

        transform.x = 0.0f;
        transform.y = 0.0f;
        transform.z = 0.0f;
        transform.scale = 1.0f;
        transform.rotX = -obj->anim.rotX;
        transform.rotY = 0;
        transform.rotZ = 0;
        mtxRotateByVec3s(matrix, &transform);
        Matrix_TransformPoint(matrix, velX, velY, velZ, &state->localVel.x, &state->localVel.y, &state->localVel.z);

        state->stickY = state->stickY + (framesThisStep << 3);
        if (state->stickY > 0x46)
        {
            state->stickY = 0x46;
        }

        SnowBike_UpdateEngineFx(obj, state, state->localVel.z, (int)(850.0f * -state->throttle), &state->unk461,
                                SNOWBIKE_SOUNDFLAG_JETS);
    }

    state->flags.raceActive = 0;
    return 0;
}

static void SnowBike_SnapSmallToZero(f32* value)
{
    f32 v = *value;

    if (v < 0.01f)
    {
        if (v > -0.01f)
        {
            *value = 0.0f;
        }
    }
}

void SnowBike_UpdateCollisionResponse(GameObject* obj, SnowBikeState* state)
{
    int hitKind;
    ObjHitsPriorityState* hitReact;
    int burstCount;
    GameObject* hit;
    f32 dot;
    int hitOutB;
    u32 hitOutC;
    GameObject* hitObj;
    Vec velNrm;
    f32 zero;

    zero = 0.0f;
    hitReact = (ObjHitsPriorityState*)obj->anim.hitReactState;
    if (ObjHits_IsObjectEnabled(&obj->anim) != 0)
    {
        if (state->flags.cpuDriven == 0)
        {
            ObjHits_SetHitVolumeSlot(&obj->anim, SNOWBIKE_HIT_VOLUME_SLOT, 1, 0);
        }
        else
        {
            ObjHits_ClearHitVolumes(&obj->anim);
            ObjHits_SyncObjectPositionIfDirty(obj);
        }
        hitKind = ObjHits_GetPriorityHit(obj, &hitObj, &hitOutB, &hitOutC);
        switch (hitKind)
        {
        case 0xd:
            if (state->flags.cpuDriven == 0)
            {
                state->collidedObject = hitObj;
                state->impactVelScale = 1.0f;
            }
            break;
        case 0x15:
            if (state->impactTimer == zero)
            {
                PSVECNormalize(&obj->anim.velocity, &velNrm);
                dot = PSVECDotProduct(&velNrm, &hitObj->anim.velocity);
                PSVECScale(&state->localVel, &state->localVel, dot * state->collisionBounceScale + 1.0f);
                state->localVel.y *= 0.2f;
                state->impactTimer = 20.0f;
                state->impactVelScale = 1.0f;
            }
            break;
        case 0x1d:
            if (state->flags.cpuDriven == 0)
            {
                setMotionBlur(1, 0.7f);
                state->impactTimer = gSnowBikeBoostDuration;
                state->impactVelScale = gSnowBikeBoostVelScale;
                state->airMeterRefillTimer = gSnowBikeAirRefillAmount;
            }
            break;
        }
        hit = (GameObject*)hitReact->lastHitObject;
        if (((hit != NULL) && (hitObj = hit, state->collidedObject = hit, state->impactTimer == zero)) &&
            (hitKind = arrayIndexOf(gSnowBikeCollisionObjectIds, 0xc, hitObj->anim.romDefNo), hitKind != -1))
        {
            objfx_shakeCameraByDistance(obj, 300.0f);
            (*gPartfxInterface)->spawnObject(obj, SNOWBIKE_PARTFX_IMPACT_A, NULL, 4, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, SNOWBIKE_PARTFX_IMPACT_B, NULL, 4, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, SNOWBIKE_PARTFX_IMPACT_C, NULL, 4, -1, NULL);
            burstCount = 0x32 / framesThisStep;
            while (burstCount-- != 0)
            {
                (*gPartfxInterface)->spawnObject(obj, SNOWBIKE_PARTFX_COLLISION_SPRAY, NULL, 2, -1, NULL);
            }
            state->impactTimer = 20.0f;
            state->impactVelScale = 1.0f;
            if (state->flags.cpuDriven == 0)
            {
                state->impactTimer = gSnowBikeHardCollisionDuration;
            }
        }
    }
}

void SnowBike_UpdateSteering(GameObject* obj, SnowBikeState* state)
{
    CurvesCollisionState* pathState = &state->pathState;
    f32 fa;
    f32 volume;
    int rotClamped;
    int yawDelta;
    int tiltShift;

    (*gPathControlInterface)->update(obj, pathState, timeDelta);
    (*gPathControlInterface)->apply(obj, pathState);
    (*gPathControlInterface)->advance(obj, pathState, timeDelta);
    tiltShift = 2;
    if (state->pathState.surfaceCounter == 0)
    {
        state->airTime = state->airTime + timeDelta;
        fa = state->airTime;
        state->airTime = CLAMP_EXPR(fa, 0.0f, 120.0f);
        if (state->airTime >= 5.0f)
        {
            if (state->flags.airborne == 0)
            {
                state->pitchVel = 0.0f;
            }
            state->flags.airborne = 1;
        }
    }
    else
    {
        if (state->flags.airborne != 0)
        {
            tiltShift = 0;
            fa = 0.25f;
            state->wobbleAmpY = fa * obj->anim.rotY;
            state->wobbleAmpZ = fa * obj->anim.rotZ;
            state->wobblePhaseY = tiltShift;
            state->wobblePhaseZ = tiltShift;
            if (state->flags.cpuDriven == 0)
            {
                doRumble(state->airTime * fa);
                CameraShake_Enable();
                CameraShake_SetOffset(state->airTime / 12.0f);
                Sfx_PlayFromObject(obj, SFXTRIG_tr_jbike_bombbeep);
                volume = (80.0f < 3.0f * state->airTime) ? 80.0f : 3.0f * state->airTime;
                Sfx_SetObjectSfxVolume(obj, SFXTRIG_tr_jbike_bombbeep, volume, 0.1f);
            }
        }
        state->flags.airborne = 0;
        state->airTime = 0.0f;
        state->groundSurfaceType = state->pathState.segmentHits.surfaceTypes[0];
    }
    fa = 16384.0f;
    state->wobblePhaseY = fa * timeDelta + (f32)state->wobblePhaseY;
    state->wobblePhaseZ = fa * timeDelta + (f32)state->wobblePhaseZ;
    state->wobbleAmpY = state->wobbleAmpY * powfBitEstimate(0.8f, timeDelta);
    state->wobbleAmpZ = state->wobbleAmpZ * powfBitEstimate(0.8f, timeDelta);
    state->wobbleY = state->wobbleAmpY * mathSinf((3.1415927f * state->wobblePhaseY) / 32768.0f);
    state->wobbleZ = state->wobbleAmpZ * mathSinf((3.1415927f * state->wobblePhaseZ) / 32768.0f);
    yawDelta = obj->anim.rotX - (state->yaw & 0xffff);
    if (yawDelta > 0x8000)
    {
        yawDelta -= 0xffff;
    }
    if (yawDelta < -0x8000)
    {
        yawDelta += 0xffff;
    }
    state->yaw += yawDelta;
    state->velYaw = state->velYaw + yawDelta;
    obj->anim.rotY = obj->anim.rotY + (state->pathState.tiltPitch >> tiltShift);
    obj->anim.rotZ = obj->anim.rotZ + (state->pathState.tiltRoll >> tiltShift);
    rotClamped = obj->anim.rotY;
    if (rotClamped < -0x2000)
    {
        rotClamped = -0x2000;
    }
    else if (rotClamped > 0x2000)
    {
        rotClamped = 0x2000;
    }
    obj->anim.rotY = rotClamped;
    rotClamped = obj->anim.rotZ;
    if (rotClamped < -0x2000)
    {
        rotClamped = -0x2000;
    }
    else if (rotClamped > 0x2000)
    {
        rotClamped = 0x2000;
    }
    obj->anim.rotZ = rotClamped;
}

void SnowBike_UpdateExhaustFx(GameObject* obj, SnowBikeState* state)
{
    s16 steerAngle;
    f32 fa;
    f32 fb;
    f32 speed;
    f32 yawFollowGain;
    f32 turnDamping;
    f32 turnVelLimit;
    f32 localVelXDamp;
    f32 localVelZDamp;
    f32 turnVelScale;
    f32 turnForceGain;
    f32 k;
    MatrixTransform effect;

    speed = sqrtf(state->localVel.z * state->localVel.z +
                  (state->localVel.x * state->localVel.x + state->localVel.y * state->localVel.y));
    state->surfaceRumbleTimer -= timeDelta;
    fa = state->surfaceRumbleTimer;
    state->surfaceRumbleTimer = CLAMP_EXPR(fa, 0.0f, 30.0f);

    if (state->flags.airborne == 0)
    {
        switch (state->groundSurfaceType)
        {
        case 0xd:
            yawFollowGain = 0.005f;
            turnVelLimit = 1500.0f;
            turnDamping = 0.95f;
            localVelXDamp = 0.98f;
            localVelZDamp = 0.99f;
            turnVelScale = 0.15f;
            turnForceGain = 0.5f;
            if ((state->flags.cpuDriven == 0) && (state->surfaceRumbleTimer <= 0.0f))
            {
                state->surfaceRumbleTimer = randomGetRange(5, 10);
                if (PSVECMag(&obj->anim.velocity) > 3.0f)
                {
                    doRumble(randomGetRange(1, 3));
                }
            }
            if (speed > 0.4f)
            {
                (*gPartfxInterface)->spawnObject(obj, SNOWBIKE_PARTFX_ICE_SPRAY, NULL, 2, -1, NULL);
            }
            break;
        case 3:
        default:
            yawFollowGain = 0.18f;
            turnVelLimit = 700.0f;
            turnDamping = 0.87f;
            localVelXDamp = 0.97f;
            localVelZDamp = 0.99f;
            turnVelScale = 0.15f;
            turnForceGain = 0.5f;
            break;
        case 9:
            yawFollowGain = 0.4f;
            turnVelLimit = 700.0f;
            turnDamping = 0.75f;
            localVelXDamp = 0.965f;
            localVelZDamp = 0.985f;
            turnVelScale = 0.1f;
            turnForceGain = 0.45f;
            if (speed > 0.3f)
            {
                effect.scale = 1.0f;
                effect.rotZ = 0;
                effect.rotY = 0;
                effect.rotX = 0;
                effect.x = obj->anim.localPosX;
                effect.y = 15.0f + obj->anim.localPosY;
                effect.z = obj->anim.localPosZ;
                (*gPartfxInterface)->spawnObject(obj, SNOWBIKE_PARTFX_SPLASH, &effect, 1, -1, NULL);
            }
            break;
        }

        steerAngle = state->steerAngleDeg;
        if (((steerAngle >= 0x1e) && (steerAngle <= 0x3c)) || ((steerAngle >= 0x12c) && (steerAngle <= 0x14a)))
        {
            yawFollowGain *= 0.1f;
            turnVelLimit *= 1.5f;
            turnDamping += 0.1f;
            if (turnDamping < 0.0f)
            {
                turnDamping = 0.0f;
            }
            else if (turnDamping > 0.95f)
            {
                turnDamping = 0.95f;
            }
        }
    }
    else
    {
        yawFollowGain = state->yawFollowGainAirborne;
        turnVelLimit = state->turnVelLimitAirborne;
        turnDamping = state->turnDampingAirborne;
        localVelXDamp = state->localVelXDampAirborne;
        localVelZDamp = state->localVelZDampAirborne;
        turnVelScale = 0.1f;
        turnForceGain = 0.5f;
    }

    if (state->flags.cpuDriven != 0)
    {
        yawFollowGain = 0.5f;
    }
    fb = timeDelta;
    speed = 0.04f;
    state->yawFollowGain += fb * (speed * (CLAMP_EXPR(yawFollowGain, 0.005f, 1.0f) - state->yawFollowGain));
    state->turnVelLimit += timeDelta * (0.25f * (turnVelLimit - state->turnVelLimit));
    state->turnDamping += timeDelta * (0.04f * (turnDamping - state->turnDamping));
    state->localVelXDamp += timeDelta * ((k = 0.1f) * (localVelXDamp - state->localVelXDamp));
    state->localVelZDamp += timeDelta * (k * (localVelZDamp - state->localVelZDamp));
    state->turnVelScale += timeDelta * (k * (turnVelScale - state->turnVelScale));
    state->turnForceGain += timeDelta * (k * (turnForceGain - state->turnForceGain));
}

static f32 SnowBike_GetStickAngleDeg(f32 stickX, f32 stickY)
{
    return (f32)(u16)getAngle(stickX, stickY) / 182.04f;
}

void SnowBike_UpdateLiftSway(GameObject* obj, SnowBikeState* state)
{
    SnowBikeFlags* flags;
    int wasBraking;
    f32 rate;
    f32 target;
    f32 clampedRate;
    Vec thrust;
    f32 cameraArgs[4];
    s32 delta;

    flags = &state->flags;
    wasBraking = flags->braking;

    if ((state->buttonsHeld & SNOWBIKE_BUTTON_ACCELERATE) != 0)
    {
        flags->accelerating = 1;
    }
    else
    {
        flags->accelerating = 0;
    }

    if ((state->buttonsHeld & SNOWBIKE_BUTTON_BRAKE) != 0)
    {
        flags->braking = 1;
    }
    else
    {
        flags->braking = 0;
    }

    if ((wasBraking == 0) && (flags->braking != 0))
    {
        Sfx_PlayFromObject(obj, SFXTRIG_bblast16);
    }

    target = 0.0f;
    if (flags->accelerating != 0)
    {
        target = state->throttleTarget;
    }
    rate = (target - state->throttle) * 0.05f;
    clampedRate = CLAMP_EXPR(rate, -0.002f, 0.01f);
    state->throttle += clampedRate * timeDelta;

    target = 0.0f;
    if (flags->braking != 0)
    {
        f32 brakeDecel = state->brakeDecel;
        f32 localVelZ = state->localVel.z;
        if (localVelZ >= target)
        {
            f32 decel = -brakeDecel;
            target = CLAMP_EXPR(decel, -localVelZ * oneOverTimeDelta, target);
        }
        else
        {
            target = CLAMP_EXPR(brakeDecel, target, -localVelZ * oneOverTimeDelta);
        }
    }
    state->thrust.x = 0.0f;
    state->thrust.y = 0.0f;
    state->thrust.z = (state->throttle + target) * timeDelta;

    Matrix_TransformPoint(state->yawMatrix, state->thrust.x, state->thrust.y, state->thrust.z, &thrust.x, &thrust.y,
                          &thrust.z);
    Matrix_TransformPoint(state->invHeadingMatrix, thrust.x, thrust.y, thrust.z, &thrust.x, &thrust.y, &thrust.z);
    PSVECAdd(&thrust, &state->localVel, &state->localVel);

    state->yawVel = (-state->stickX * state->turnAccel) * timeDelta + state->yawVel;
    state->yawVel = powfBitEstimate(state->turnDamping, timeDelta) * state->yawVel;

    {
        f32 lim;
        f32 v;
        v = state->yawVel;
        lim = state->turnVelLimit;
        state->yawVel = CLAMP_EXPR(v, -lim, lim);
    }

    state->yaw += state->yawVel * timeDelta;
    delta = (s32)(state->yawVel * state->rollScale);
    delta -= (u16)state->rollOffset;
    if (delta > 0x8000)
    {
        delta = delta - 0xffff;
    }
    if (delta < -0x8000)
    {
        delta = delta + 0xffff;
    }
    state->rollOffset += (f32)delta * state->rollGain;

    delta = state->yaw - (u16)state->velYaw;
    if (delta > 0x8000)
    {
        delta = delta - 0xffff;
    }
    if (delta < -0x8000)
    {
        delta = delta + 0xffff;
    }
    state->velYaw += (f32)delta * state->yawFollowGain;

    if (flags->airborne != 0)
    {
        state->pitchVel = (-state->pitchDecel) * timeDelta + state->pitchVel;
        {
            f32 v = state->pitchVel;
            state->pitchVel = CLAMP_EXPR(v, -100.0f, 100.0f);
        }
        obj->anim.rotY = (f32)obj->anim.rotY + state->pitchVel * timeDelta;
    }

    if (flags->cpuDriven == 0)
    {
        cameraArgs[0] = state->yawVel;
        cameraArgs[1] = state->localVel.z;
        cameraArgs[2] = (f32)obj->anim.rotZ;
        cameraArgs[3] = (f32)obj->anim.rotY;
        (*gCameraInterface)->releaseAction(cameraArgs, 0x10);
    }

    {
        f32 lim;
        f32 v;
        v = state->localVel.x;
        lim = state->localVelLimit.x;
        state->localVel.x = CLAMP_EXPR(v, -lim, lim);
        SnowBike_SnapSmallToZero(&state->localVel.x);
    }

    {
        f32 v = state->localVel.y;
        f32 lim = -state->localVelLimit.y;
        state->localVel.y = CLAMP_EXPR(v, lim, 1.0f);
        SnowBike_SnapSmallToZero(&state->localVel.y);
    }

    {
        f32 lim;
        f32 v;
        v = state->localVel.z;
        lim = state->localVelLimit.z;
        state->localVel.z = CLAMP_EXPR(v, -lim, lim);
        SnowBike_SnapSmallToZero(&state->localVel.z);
    }
}

void SnowBike_buildOrientationMatrices(GameObject* obj, SnowBikeState* state)
{
    MatrixTransform transform;

    transform.x = 0.0f;
    transform.y = 0.0f;
    transform.z = 0.0f;
    transform.scale = 1.0f;

    transform.rotX = state->yaw;
    transform.rotY = 0;
    transform.rotZ = 0;
    setMatrixFromObjectPos(state->yawMatrix, &transform);

    transform.rotX = -state->yaw;
    transform.rotY = 0;
    transform.rotZ = 0;
    mtxRotateByVec3s(state->invYawMatrix, &transform);

    transform.rotX = state->velYaw;
    transform.rotY = 0;
    transform.rotZ = 0;
    setMatrixFromObjectPos(state->headingMatrix, &transform);

    transform.rotX = -state->velYaw;
    transform.rotY = 0;
    transform.rotZ = 0;
    mtxRotateByVec3s(state->invHeadingMatrix, &transform);
}

void SnowBike_ResetDynamics(GameObject* obj, SnowBikeState* state)
{
    f32 zero;
    f32 limitX;
    f32 limitY;
    f32 limitZ;
    SnowBikeFlags* flags;

    state->turnAccel = 50.0f;
    state->turnDamping = 0.85f;
    state->turnVelLimit = 700.0f;
    zero = 0.0f;
    state->yawVel = zero;
    state->pitchVel = zero;
    state->localVelXDamp = 0.97f;
    state->localVelZDamp = 0.99f;
    state->turnVelScale = 0.1f;
    state->turnForceGain = 0.5f;
    state->yawFollowGain = 0.2f;
    state->turnDampingAirborne = 0.75f;
    flags = &state->flags;
    flags->airborne = 0;
    state->throttle = zero;
    limitX = state->baseVelLimit.x;
    state->velLimit.x = limitX;
    state->localVelLimit.x = limitX;
    limitY = state->baseVelLimit.y;
    state->velLimit.y = limitY;
    state->localVelLimit.y = limitY;
    limitZ = state->baseVelLimit.z;
    state->velLimit.z = limitZ;
    state->localVelLimit.z = limitZ;
    flags->accelerating = 0;
    flags->braking = 0;
    state->collidedObject = NULL;
    state->impactTimer = zero;
    state->impactVelScale = 1.0f;
}

void SnowBike_InitTuning(GameObject* obj, SnowBikeState* state)
{
    f32 damp;
    f32 gain;

    state->gravity = -0.12f;
    state->turnDamping = 0.85f;
    state->turnVelLimit = 700.0f;
    state->throttleTarget = -0.05f;
    state->brakeDecel = 0.04f;
    state->localVelXDamp = 0.97f;
    state->localVelZDamp = 0.99f;
    state->turnVelScale = 0.1f;
    state->turnForceGain = 0.5f;
    damp = 0.995f;
    state->localVelXDampAirborne = damp;
    state->localVelZDampAirborne = damp;
    state->rollGain = 0.08f;
    state->rollScale = 15.0f;
    state->pitchDecel = 5.0f;
    gain = 0.2f;
    state->yawFollowGain = gain;
    state->yawFollowGainAirborne = 0.01f;
    state->turnVelLimitAirborne = 300.0f;
    state->turnDampingAirborne = 0.75f;
    state->collisionBounceScale = gain;
}

s32 SnowBike_getRouteRank(GameObject* obj)
{
    SnowBikeState* state = obj->extra;

    return (*gCheckpointInterface)->getRouteRank(&state->rankItem);
}

s32 SnowBike_isAtRankGate(GameObject* obj)
{
    SnowBikeState* state = obj->extra;
    int rank = (*gCheckpointInterface)->getRouteRank(&state->rankItem);

    if (rank == 3)
    {
        if (gSnowBikeLeaderRouteRank == -1)
        {
            return 1;
        }
    }
    return (u32)__cntlzw(gSnowBikeLeaderRouteRank - 1 - rank) >> 5;
}

void SnowBike_func17(void)
{
}

void SnowBike_func16(void)
{
}

void SnowBike_resetToRomListPosition(GameObject* obj)
{
    SnowBikeState* state = obj->extra;
    int* romListIds;
    SnowBikeRomListItem* found;
    f32 zero;

    romListIds = gSnowBikeCheckpointRomListIds[state->bikeType];
    found = (SnowBikeRomListItem*)mapRomListFindItem(romListIds[state->bikeVariant], 0, 0, 0, 0);
    if (found != NULL)
    {
        if (state->bikeType != 0)
        {
            obj->anim.localPosX = found->base.posX;
            obj->anim.localPosY = found->base.posY;
            obj->anim.localPosZ = found->base.posZ;
            obj->anim.rotX = found->yawByte << 8;
        }
        (*gCheckpointInterface)->findRouteForObject(obj, &state->routeState, 0);
        state->routeCursor.x = obj->anim.localPosX;
        state->routeCursor.y = obj->anim.localPosY;
        state->routeCursor.z = obj->anim.localPosZ;
        state->routeCursor.rotX = obj->anim.rotX;
        zero = 0.0f;
        state->localVel.x = zero;
        state->localVel.y = zero;
        state->localVel.z = zero;
        (*gPathControlInterface)->attachObject(obj, &state->pathState);
        SnowBike_SyncHitReactPosition(obj);
        state->pathState.subtype = 1;
    }
}

s32 SnowBike_getRacePosition(GameObject* obj)
{
    return ((SnowBikeState*)obj->extra)->raceRank;
}

f32 SnowBike_func13(GameObject* obj, f32* out)
{
    SnowBikeState* state = obj->extra;
    f32 speed;

    *out = 5.0f;
    speed = sqrtf(state->localVel.z * state->localVel.z +
                  (state->localVel.x * state->localVel.x + state->localVel.y * state->localVel.y));
    speed *= 0.2f;
    if (speed > 1.0f)
    {
        speed = 1.0f;
    }
    return speed;
}

void SnowBike_getPlayerAnim(GameObject* obj, f32* outFloat, s32* outBool)
{
    SnowBikeState* state = obj->extra;
    f32 value;

    *outFloat = state->yawVel / 400.0f;
    value = *outFloat;
    *outFloat = CLAMP_EXPR(value, -1.0f, 1.0f);
    *outBool = state->yawVel < 0.0f;
}

void SnowBike_setMountState(GameObject* obj, int type)
{
    SnowBikeState* state = obj->extra;
    u32 bit;

    state->mountState = type;
    if (type == SNOWBIKE_MOUNT_STATE_RIDING)
    {
        mainSetBits(state->completionGameBit, 1);
        ((void (*)(GameObject*, SnowBikeState*))SnowBike_ResetDynamics)(obj, state);
        bit = state->flags.airMeterActive;
        if (bit != 0)
        {
            SnowBike_ResetAirMeter(state);
        }
        if (obj->anim.romDefNo == SNOWBIKE_IM_BIKE_OBJ)
        {
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->lateralResponseWeight = 0x14;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->axialResponseWeight = 0x14;
        }
    }
}

s32 SnowBike_getMountState(GameObject* obj)
{
    return ((SnowBikeState*)obj->extra)->mountState;
}

void SnowBike_getCameraPosition(GameObject* obj, f32* x, f32* y, f32* z)
{
    SnowBikeState* state = obj->extra;

    state->cameraPosX = obj->anim.localPosX;
    state->cameraPosY = obj->anim.localPosY;
    state->cameraPosZ = obj->anim.localPosZ;
    *x = state->cameraPosX;
    *y = state->cameraPosY;
    *z = state->cameraPosZ;
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
    SnowBikeState* state = obj->extra;

    *x = state->attachPosX;
    *y = state->attachPosY;
    *z = state->attachPosZ;
}

u8 SnowBike_getMountSide(GameObject* obj)
{
    return ((SnowBikeState*)obj->extra)->playerInRange;
}

u32 SnowBike_canMount(GameObject* obj)
{
    SnowBikeState* state = obj->extra;
    u32 bit = state->flags.cpuDriven;

    if (bit != 0)
    {
        return 0;
    }
    return state->playerInRange;
}

int SnowBike_getExtraSize(void)
{
    return sizeof(SnowBikeState);
}

int SnowBike_getObjectTypeId(void)
{
    return 0x3;
}

void SnowBike_free(GameObject* obj)
{
    int i;
    u32 bit;
    SnowBikeState* state;

    state = obj->extra;
    objFreeObjectType(obj, SNOWBIKE_OBJGROUP);
    for (i = 0; i < SNOWBIKE_TRAIL_COUNT; i++)
    {
        mm_free(state->trails[i].points);
    }
    bit = state->flags.airMeterActive;
    if (bit != 0)
    {
        (*gGameUIInterface)->airMeterShutdown();
    }
}

void SnowBike_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    SnowBikeState* state;

    state = obj->extra;
    SnowBike_DrawTrails(obj, state);
    if (visible == -1)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        ObjPath_GetPointWorldPosition(obj, 0, &state->attachPosX, &state->attachPosY, &state->attachPosZ, 0);
    }
    else
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        ObjPath_GetPointWorldPosition(obj, 0, &state->attachPosX, &state->attachPosY, &state->attachPosZ, 0);
    }
}

void SnowBike_hitDetect(GameObject* obj)
{
    SnowBikeState* state;
    GameObject* other;
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
    other = ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitObject;
    if (obj->pendingParentObj != NULL)
    {
        return;
    }
    if (state->mountState == SNOWBIKE_MOUNT_STATE_RIDING)
    {
        SnowBike_UpdateSteering(obj, state);
        state->savedRotY = obj->anim.rotY;
        state->savedRotZ = obj->anim.rotZ;
        obj->anim.rotY = (f32)obj->anim.rotY + state->wobbleY;
        obj->anim.rotZ = (f32)obj->anim.rotZ + (state->rollOffset + state->wobbleZ);
    }
    if (state->pathState.surfaceCounter == 4 || state->pathState.localPointHitMask != 0)
    {
        obj->anim.velocityY = oneOverTimeDelta * (obj->anim.localPosY - obj->anim.previousLocalPosY);
        state->localVel.y = obj->anim.velocityY;
    }
    if (state->pathState.localPointHitMask != 0 ||
        ((((ObjHitsPriorityState*)obj->anim.hitReactState)->flags & 8) != 0 &&
         arrayIndexOf(gSnowBikeRiderObjectIds, 10, other->anim.romDefNo) == -1) ||
        (state->collidedObject != NULL && state->impactVelScale <= 1.0f))
    {
        mag = PSVECMag(&obj->anim.velocity);
        if (mag > 1.0f)
        {
            if (!state->flags.cpuDriven)
            {
                doRumble(3.0f * mag);
            }
            state->throttle *= 0.25f;
            if (obj->anim.romDefNo == SNOWBIKE_IM_BIKE_OBJ || obj->anim.romDefNo == SNOWBIKE_CR_BIKE_OBJ)
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
                if (Sfx_IsPlayingFromObjectChannel(obj, 32) == 0)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_tr_jbike_bombbeep);
                    Sfx_SetObjectSfxVolume(obj, SFXTRIG_tr_jbike_bombbeep, vol, 127.0f);
                }
            }
        }
        if (!state->flags.cpuDriven && mag > 3.0f)
        {
            CameraShake_Enable();
            shakeScale = 0.5f;
            CameraShake_SetOffset(mag * shakeScale);
        }
        if (state->collidedObject != NULL)
        {
            velScale = 0.75f;
            OSReport(sSnowBikeVelDebugFmt, mag);
            if (state->collidedObject->anim.romDefNo == SNOWBIKE_CR_CLAWBIKE_V0_OBJ ||
                state->collidedObject->anim.romDefNo == SNOWBIKE_CR_CLAWBIKE_V1_OBJ ||
                state->collidedObject->anim.romDefNo == SNOWBIKE_CR_CLAWBIKE_V2_OBJ)
            {
                velScale = 0.95f;
            }
            obj->anim.velocityX = velScale * (oneOverTimeDelta * (obj->anim.localPosX - obj->anim.previousLocalPosX));
            obj->anim.velocityZ = velScale * (oneOverTimeDelta * (obj->anim.localPosZ - obj->anim.previousLocalPosZ));
        }
        else
        {
            velScaleDefault = 0.95f;
            obj->anim.velocityX =
                velScaleDefault * (oneOverTimeDelta * (obj->anim.localPosX - obj->anim.previousLocalPosX));
            obj->anim.velocityZ =
                velScaleDefault * (oneOverTimeDelta * (obj->anim.localPosZ - obj->anim.previousLocalPosZ));
        }
        Matrix_TransformPoint(state->invHeadingMatrix, obj->anim.velocityX, 0.0f, obj->anim.velocityZ,
                              &state->localVel.x, &dummy, &state->localVel.z);
    }
    {
        f32 limit;
        f32 value = state->localVel.x;
        f32 clamped;
        limit = state->localVelLimit.x;
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
        state->localVel.x = clamped;
    }
    if (state->localVel.x < 0.01f && state->localVel.x > -0.01f)
    {
        state->localVel.x = 0.0f;
    }
    value = state->localVel.y;
    limit = state->localVelLimit.y;
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
    state->localVel.y = clamped;
    if (state->localVel.y < 0.01f && state->localVel.y > -0.01f)
    {
        state->localVel.y = 0.0f;
    }
    {
        f32 limit;
        f32 value = state->localVel.z;
        f32 clamped;
        limit = state->localVelLimit.z;
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
        state->localVel.z = clamped;
    }
    if (state->localVel.z < 0.01f && state->localVel.z > -0.01f)
    {
        state->localVel.z = 0.0f;
    }
    state->prevPosX = obj->anim.localPosX;
    state->prevPosY = obj->anim.localPosY;
    state->prevPosZ = obj->anim.localPosZ;
    state->collidedObject = NULL;
}

void SnowBike_update(GameObject* obj)
{
    SnowBikeState* state = obj->extra;
    f32 cpuMatrix[16];
    f32 playerMatrix[16];
    MatrixTransform cpuTransform;
    MatrixTransform playerTransform;
    Vec cpuForce;
    Vec playerForce;
    f32 dummy1;
    f32 dummy2;
    s8 mountState;
    f32 zero;
    f32 damp;
    f32 value;
    f32 clamped;

    if (obj->anim.mapEventSlot == -1)
    {
        if (mainGetBit(GAMEBIT_DIM_CrossedBlizzard) != 0)
        {
            state->playerInRange = 0;
        }
        if (mainGetBit(GAMEBIT_SnowBikeRelated01FB) != 0)
        {
            Obj_SetModelSlotIndex(obj, 0x13);
        }
    }
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    obj->anim.rotY = state->savedRotY;
    obj->anim.rotZ = state->savedRotZ;
    if (state->flags.finished || mainGetBit(state->finishedGameBit) != 0)
    {
        state->flags.finished = 1;
        return;
    }
    mountState = state->mountState;
    switch (mountState)
    {
    case 0:
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
        {
            state->playerInRange = 1;
        }
        else
        {
            state->playerInRange = 0;
        }
        Sfx_StopObjectChannel(obj, 0x57);
        break;
    case SNOWBIKE_MOUNT_STATE_RIDING:
        SnowBike_UpdateRouteFollowing(obj, state);
        if (state->flags.cpuDriven)
        {
            if (SnowBike_UpdateAttachedPosition(obj, state) != 0)
            {
                SnowBike_UpdateExhaustFx(obj, state);
                ((void (*)(GameObject*, SnowBikeState*))SnowBike_buildOrientationMatrices)(obj, state);
                if (state->impactTimer)
                {
                    PSVECScale(&state->velLimit, &state->localVelLimit, state->impactVelScale);
                    PSVECScale(&state->localVel, &state->localVel, state->impactVelScale);
                    state->impactTimer -= timeDelta;
                    if (state->impactTimer <= 0.0f)
                    {
                        if (Rcp_GetMotionBlurEnabled() != 0)
                        {
                            setMotionBlur(0, 0.0f);
                        }
                        state->impactTimer = 0.0f;
                    }
                }
                else
                {
                    state->localVelLimit.x = state->velLimit.x;
                    state->localVelLimit.y = state->velLimit.y;
                    state->localVelLimit.z = state->velLimit.z;
                }
                zero = 0.0f;
                cpuTransform.x = zero;
                cpuTransform.y = zero;
                cpuTransform.z = zero;
                cpuTransform.scale = 1.0f;
                cpuTransform.rotX = -state->yaw;
                cpuTransform.rotY = -obj->anim.rotY;
                cpuTransform.rotZ = -obj->anim.rotZ;
                mtxRotateByVec3s(cpuMatrix, &cpuTransform);
                Matrix_TransformPoint(cpuMatrix, 0.0f, state->gravity * state->turnForceGain, 0.0f, &cpuForce.x,
                                      &dummy1, &cpuForce.z);
                cpuForce.x = cpuForce.x * state->turnVelScale;
                cpuForce.y = 0.0f;
                PSVECScale(&cpuForce, &cpuForce, timeDelta);
                PSVECAdd(&state->localVel, &cpuForce, &state->localVel);
                state->localVel.y = state->gravity * timeDelta + state->localVel.y;
                damp = powfBitEstimate(state->localVelXDamp, timeDelta);
                state->localVel.x *= damp;
                damp = powfBitEstimate(state->localVelZDamp, timeDelta);
                state->localVel.z *= damp;
                SnowBike_UpdateLiftSway(obj, state);
                Matrix_TransformPoint(state->headingMatrix, state->localVel.x, state->localVel.y, state->localVel.z,
                                      &obj->anim.velocityX, &obj->anim.velocityY, &obj->anim.velocityZ);
                objApplyVelocity(obj);
            }
        }
        else
        {
            setAButtonIcon(0x10);
            setBButtonIcon(0x11);
            state->stickX = padGetStickX(0);
            state->stickY = (f32)padGetStickY(0);
            state->buttonsHeld = getButtonsHeld(0);
            state->buttonsJustPressed = getButtonsJustPressed(0);
            state->buttonsJustPressedIfNotBusy = getButtonsJustPressedIfNotBusy(0);
            state->steerAngleDeg = SnowBike_GetStickAngleDeg(state->stickX, -state->stickY);
            state->stickX = state->stickX / 56.0f;
            value = state->stickX;
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
            state->stickX = clamped;
            SnowBike_UpdateExhaustFx(obj, state);
            ((void (*)(GameObject*, SnowBikeState*))SnowBike_buildOrientationMatrices)(obj, state);
            if (state->impactTimer)
            {
                PSVECScale(&state->velLimit, &state->localVelLimit, state->impactVelScale);
                PSVECScale(&state->localVel, &state->localVel, state->impactVelScale);
                state->impactTimer -= timeDelta;
                if (state->impactTimer <= 0.0f)
                {
                    if (Rcp_GetMotionBlurEnabled() != 0)
                    {
                        setMotionBlur(0, 0.0f);
                    }
                    state->impactTimer = 0.0f;
                }
            }
            else
            {
                state->localVelLimit.x = state->velLimit.x;
                state->localVelLimit.y = state->velLimit.y;
                state->localVelLimit.z = state->velLimit.z;
            }
            zero = 0.0f;
            playerTransform.x = zero;
            playerTransform.y = zero;
            playerTransform.z = zero;
            playerTransform.scale = 1.0f;
            playerTransform.rotX = -state->yaw;
            playerTransform.rotY = -obj->anim.rotY;
            playerTransform.rotZ = -obj->anim.rotZ;
            mtxRotateByVec3s(playerMatrix, &playerTransform);
            Matrix_TransformPoint(playerMatrix, 0.0f, state->gravity * state->turnForceGain, 0.0f, &playerForce.x,
                                  &dummy2, &playerForce.z);
            playerForce.x = playerForce.x * state->turnVelScale;
            playerForce.y = 0.0f;
            PSVECScale(&playerForce, &playerForce, timeDelta);
            PSVECAdd(&state->localVel, &playerForce, &state->localVel);
            state->localVel.y = state->gravity * timeDelta + state->localVel.y;
            damp = powfBitEstimate(state->localVelXDamp, timeDelta);
            state->localVel.x *= damp;
            damp = powfBitEstimate(state->localVelZDamp, timeDelta);
            state->localVel.z *= damp;
            SnowBike_UpdateLiftSway(obj, state);
            Matrix_TransformPoint(state->headingMatrix, state->localVel.x, state->localVel.y, state->localVel.z,
                                  &obj->anim.velocityX, &obj->anim.velocityY, &obj->anim.velocityZ);
            objApplyVelocity(obj);
        }
        SnowBike_UpdateAirMeter(obj, state);
        SnowBike_UpdateEngineFx(obj, state, state->localVel.z, (int)(850.0f * -state->throttle), &state->unk461,
                                SNOWBIKE_SOUNDFLAG_ENGINE | SNOWBIKE_SOUNDFLAG_HISS | SNOWBIKE_SOUNDFLAG_JETS);
        SnowBike_UpdateCollisionResponse(obj, state);
        obj->anim.rotX = state->yaw;
        break;
    }
}

void SnowBike_init(GameObject* obj, SnowBikePlacement* params, int flag)
{
    f32 limit;
    f32 zero;
    s16 yaw;
    int i;
    u8* placement;
    SnowBikeSegmentTypes segmentTypes;
    u8* base[1];
    CurvesCollisionState* pathState;
    SnowBikeState* state;

    base[0] = (u8*)&gSnowBikePathSetup;
    segmentTypes = sSnowBikeSegmentTypes;
    state = obj->extra;

    if (obj->anim.mapEventSlot == 0x13)
    {
        placement = mmAlloc(sizeof(SnowBikePlacement), 5, 0);
        memcpy(placement, params, sizeof(SnowBikePlacement));
        obj->anim.placementData = (s16*)placement;
        obj->anim.flags |= OBJANIM_FLAG_OWNS_PLACEMENT_DATA;
        Obj_ClearModelSlotIndex(obj);
    }
    yaw = params->yawByte << 8;
    state->velYaw = yaw;
    state->yaw = yaw;
    obj->anim.rotX = yaw;
    ((void (*)(GameObject*, SnowBikeState*))SnowBike_InitTuning)(obj, state);
    if (flag == 0)
    {
        if (state->flags.airMeterActive)
        {
            SnowBike_ResetAirMeter(state);
        }
    }
    if (params->cpuDriven != 0)
    {
        state->flags.cpuDriven = 1;
    }
    state->routeState.startCheckpointId = -1;
    state->routeState.matchedCheckpointId = -1;
    state->routeState.currentCheckpointId = -1;
    state->routeFilter = params->routeFilter;
    state->routeMode = params->routeMode;
    state->routeCursor.x = obj->anim.localPosX;
    state->routeCursor.y = obj->anim.localPosY;
    state->routeCursor.z = obj->anim.localPosZ;
    obj->animEventCallback = SnowBike_SeqFn;
    objAddObjectType(obj, SNOWBIKE_OBJGROUP);
    if (flag == 0)
    {
        for (i = 0; i < SNOWBIKE_TRAIL_COUNT; i++)
        {
            state->trails[i].points = mmAlloc(SNOWBIKE_TRAIL_POINT_CAPACITY * sizeof(SnowBikeTrailPoint), 26, 0);
        }
    }
    state->lastTrailPosX = obj->anim.worldPosX;
    state->lastTrailPosY = obj->anim.worldPosY;
    state->lastTrailPosZ = obj->anim.worldPosZ;
    state->wrongWayTimer = 0.0f;
    state->completionGameBit = params->completionGameBit;
    state->finishedGameBit = params->finishedGameBit;
    if (mainGetBit(state->finishedGameBit) != 0)
    {
        state->flags.finished = 1;
    }
    state->unk438 = 30.0f;
    zero = 0.0f;
    state->rumbleVolume = zero;
    state->jetsVolume = zero;
    state->cpuSpeedFarDist = 400.0f;
    state->cpuSpeedNearDist = zero;
    state->cpuSpeedFar = 3.0f;
    state->cpuSpeedNear = 6.0f;
    state->collisionHitType = -1;
    limit = 4.0f;
    state->velLimit.x = limit;
    state->velLimit.y = limit;
    state->engineSfxId = 0x436;
    switch (obj->anim.romDefNo)
    {
    case SNOWBIKE_IM_BIKE_OBJ:
    default:
        state->bikeType = 1;
        state->velLimit.z = 6.0f;
        state->engineSfxId = 282;
        break;
    case SNOWBIKE_IM_CLAWBIKE_V0_OBJ:
        state->bikeType = 1;
        state->bikeVariant = 0;
        state->cpuSpeedNearDist = 200.0f;
        state->cpuSpeedFarDist = 600.0f;
        state->collisionHitType = 1;
        state->velLimit.z = 8.0f;
        break;
    case SNOWBIKE_IM_CLAWBIKE_V1_OBJ:
        state->bikeType = 1;
        state->routeBranchFlag = 1;
        state->bikeVariant = 1;
        state->collisionHitType = 2;
        state->velLimit.z = 8.0f;
        break;
    case SNOWBIKE_CR_BIKE_OBJ:
        state->bikeType = 0;
        state->velLimit.z = gSnowBikeCrBikeVelLimitZ;
        state->engineSfxId = 282;
        break;
    case SNOWBIKE_CR_CLAWBIKE_V0_OBJ:
        state->bikeType = 0;
        state->bikeVariant = 0;
        state->cpuSpeedNearDist = 200.0f;
        state->cpuSpeedFarDist = 600.0f;
        state->velLimit.z = 1.2f * gSnowBikeClawBikeVelLimitZ;
        break;
    case SNOWBIKE_CR_CLAWBIKE_V1_OBJ:
        state->bikeType = 0;
        state->bikeVariant = 1;
        state->cpuSpeedNearDist = 100.0f;
        state->cpuSpeedFarDist = 500.0f;
        state->velLimit.z = 1.1f * gSnowBikeClawBikeVelLimitZ;
        break;
    case SNOWBIKE_CR_CLAWBIKE_V2_OBJ:
        state->bikeType = 0;
        state->bikeVariant = 2;
        state->cpuSpeedNearDist = 100.0f;
        state->cpuSpeedFarDist = 500.0f;
        state->velLimit.z = gSnowBikeClawBikeVelLimitZ;
        break;
    }
    limit = state->velLimit.x;
    state->localVelLimit.x = limit;
    state->baseVelLimit.x = limit;
    limit = state->velLimit.y;
    state->localVelLimit.y = limit;
    state->baseVelLimit.y = limit;
    limit = state->velLimit.z;
    state->localVelLimit.z = limit;
    state->baseVelLimit.z = limit;
    state->raceGameBits = (s16*)((u32)base[0] + SNOWBIKE_SETUP_GAMEBITS_OFFSET + state->bikeType * 6);
    if (state->bikeType == 0)
    {
        if (!state->flags.cpuDriven)
        {
            state->flags.airMeterActive = 1;
            state->airMeterRefillTimer = 0.0f;
        }
        state->throttleTarget = -0.1f;
    }
    else
    {
        state->throttleTarget = -0.05f;
    }
    pathState = &state->pathState;
    pathState->subtype = 1;
    (*gPathControlInterface)->init(pathState, 0, 0x48607, 1);
    (*gPathControlInterface)->setup(pathState, 4, base[0], base[0] + SNOWBIKE_SETUP_RADII_OFFSET, &segmentTypes);
    if (state->flags.cpuDriven && state->collisionHitType != -1)
    {
        curves_setLocalPointCollisionEx(pathState, 1, (f32*)(base[0] + SNOWBIKE_SETUP_COLLISION_POINT_OFFSET),
                                        &gSnowBikeCollisionRadius, 8, state->collisionHitType);
    }
    else
    {
        (*gPathControlInterface)
            ->setLocalPointCollision(pathState, 1, base[0] + SNOWBIKE_SETUP_COLLISION_POINT_OFFSET,
                                     &gSnowBikeCollisionRadius, 8);
    }
    pathState->activeTimer = 10.0f + gSnowBikeCollisionRadius;
    (*gPathControlInterface)->attachObject(obj, pathState);
}

void SnowBike_release(void)
{
    if (sSnowBikeTrailTexture != NULL)
    {
        textureFree(sSnowBikeTrailTexture);
        sSnowBikeTrailTexture = NULL;
    }
}

void SnowBike_initialise(void)
{
    if (sSnowBikeTrailTexture == NULL)
    {
        sSnowBikeTrailTexture = textureLoadAsset(SNOWBIKE_TRAIL_TEXTURE);
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
