/*
 * swarmbaddie (DLL 0x00E0) - the swarming flying baddie (a "wisp"-class
 * pest).
 *
 * A swarmbaddie follows a ROM curve path (allocated per-instance via the
 * rom-curve interface) while bobbing on yaw/roll sine waves. When the
 * player comes within chaseRadius it switches to CHASE mode and steers its
 * velocity toward the player instead of the path; it falls back to the path
 * when the player gets too far (the PATH_NEEDS_LINK/CHASE flag pair in
 * state->flags). Per-tick it scans for priority hits, drives a looping sfx
 * whose channel volume tracks an attack envelope + sine wobble, and emits
 * particle fx (0x336). The shared pressure-switch resource (DAT_803de6d0)
 * is acquired/freed through the pi_dolphin helpers.
 */
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_play_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/curve.h"
#include "main/dll/hagabonstate_struct.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/curve_walker.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/objhits.h"
#include "main/obj_group.h"
#include "main/mm.h"
#include "string.h"
#include "main/frame_timing.h"
#include "main/dll/dll_00E0_swarmbaddie.h"

int gSwarmBaddieCurveInitData[2] = {2, 3};

STATIC_ASSERT(sizeof(HagabonState) == 0x28);
STATIC_ASSERT(offsetof(HagabonState, wavePhaseA) == 0x20);
STATIC_ASSERT(offsetof(HagabonState, flags) == 0x26);

#define SWARMBADDIE_HIT_VOLUME_SLOT 10

/* object group this object belongs to */
#define SWARMBADDIE_OBJGROUP 3
#define SWARMBADDIE_PARTFX   0x336

#define SWARMBADDIE_FLAG_PATH_NEEDS_LINK 0x01
#define SWARMBADDIE_FLAG_CHASE_PLAYER    0x02
#define SWARMBADDIE_FLAG_CHASE_LOCKOUT   0x04 /* strayed too far; block re-chase until back near path */
#define SWARMBADDIE_FLAG_CHASE_MASK      0x06

#define SWARM_BADDIE_DEG_TO_ANGLE 182.0f
#define SWARM_BADDIE_PI 3.1415927f
#define SWARM_BADDIE_S16_ANGLE_SCALE 32768.0f
int gSwarmBaddieLastCurvePoint;

void SwarmBaddie_updateMovement(GameObject* obj, SwarmBaddieState* state)
{
    RomCurveWalker* curve;
    int pathEnded;
    f32 step;

    curve = state->curve;
    pathEnded = Curve_AdvanceAlongPath(&curve->curve, state->curveStep);
    if (((pathEnded != 0) || (curve->atSegmentEnd != gSwarmBaddieLastCurvePoint)) &&
        ((*gRomCurveInterface)->goNextPoint((void*)curve) != 0) &&
        ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, 400.0f, gSwarmBaddieCurveInitData, -1) !=
         0))
    {
        state->flags &= ~SWARMBADDIE_FLAG_PATH_NEEDS_LINK;
    }
    gSwarmBaddieLastCurvePoint = curve->atSegmentEnd;
    if ((state->flags & SWARMBADDIE_FLAG_CHASE_PLAYER) != 0)
    {
        step = 0.003f;
        (obj)->anim.velocityX = step * (state->player->anim.localPosX - (obj)->anim.localPosX) + (obj)->anim.velocityX;
        (obj)->anim.velocityY =
            step * ((30.0f + state->player->anim.localPosY) - (obj)->anim.localPosY) + (obj)->anim.velocityY;
        (obj)->anim.velocityZ = step * (state->player->anim.localPosZ - (obj)->anim.localPosZ) + (obj)->anim.velocityZ;
    }
    else
    {
        step = 0.003f;
        (obj)->anim.velocityX = step * (curve->posX - (obj)->anim.localPosX) + (obj)->anim.velocityX;
        (obj)->anim.velocityY = step * (curve->posY - (obj)->anim.localPosY) + (obj)->anim.velocityY;
        (obj)->anim.velocityZ = step * (curve->posZ - (obj)->anim.localPosZ) + (obj)->anim.velocityZ;
    }

    (obj)->anim.velocityX = (obj)->anim.velocityX * (step = 0.9f);
    (obj)->anim.velocityY *= step;
    (obj)->anim.velocityZ *= step;

    if ((obj)->anim.velocityX > 0.8f)
    {
        (obj)->anim.velocityX = 0.8f;
    }
    if ((obj)->anim.velocityY > 0.8f)
    {
        (obj)->anim.velocityY = 0.8f;
    }
    if ((obj)->anim.velocityZ > 0.8f)
    {
        (obj)->anim.velocityZ = 0.8f;
    }
    if ((obj)->anim.velocityX < -0.8f)
    {
        (obj)->anim.velocityX = -0.8f;
    }
    if ((obj)->anim.velocityY < -0.8f)
    {
        (obj)->anim.velocityY = -0.8f;
    }
    if ((obj)->anim.velocityZ < -0.8f)
    {
        (obj)->anim.velocityZ = -0.8f;
    }

    objMove(obj, (obj)->anim.velocityX * timeDelta, (obj)->anim.velocityY * timeDelta,
            (obj)->anim.velocityZ * timeDelta);

    state->yawWavePhase += (s16)(32.0f * timeDelta);
    state->rollWavePhase += (s16)(23.0f * timeDelta);

    (obj)->anim.rotX +=
        (s16)(4.0f *
              (SWARM_BADDIE_DEG_TO_ANGLE * mathSinf((SWARM_BADDIE_PI * state->yawWavePhase) / SWARM_BADDIE_S16_ANGLE_SCALE)));

    (obj)->anim.rotZ +=
        (s16)(4.0f *
              (SWARM_BADDIE_DEG_TO_ANGLE * mathSinf((SWARM_BADDIE_PI * state->rollWavePhase) / SWARM_BADDIE_S16_ANGLE_SCALE)));
}

int SwarmBaddie_getExtraSize(void)
{
    return sizeof(SwarmBaddieState);
}
int SwarmBaddie_getObjectTypeId(void)
{
    return 0x9;
}

void SwarmBaddie_free(GameObject* obj)
{
    SwarmBaddieState* state = (obj)->extra;
    ObjGroup_RemoveObject((int)obj, SWARMBADDIE_OBJGROUP);
    if (state->curve != NULL)
    {
        mm_free(state->curve);
        state->curve = NULL;
    }
}

void SwarmBaddie_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0)
        return;
}

void SwarmBaddie_hitDetect(void)
{
}


void SwarmBaddie_update(GameObject* obj)
{
    SwarmBaddieState* state;
    struct
    {
        f32 x, y, z;
    } delta;
    f32* deltaValues = &delta.x;
    f32 volume;
    RomCurveWalker* curve;
    int hitObject;
    int hitPosXBits;
    int hitPosYBits;
    int hitPosZBits;
    int hitSphereIndex;
    int hitVolume;

    state = obj->extra;
    curve = state->curve;
    if (ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &hitSphereIndex, (u32*)&hitVolume, (f32*)&hitPosXBits,
                                           (f32*)&hitPosYBits, (f32*)&hitPosZBits) != 0)
    {
        state->hitVolumeEnvelope = (2.0f);
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, SWARMBADDIE_HIT_VOLUME_SLOT, 1, 0);
    ObjHits_EnableObject(obj);
    if (state->hitVolumeEnvelope > (1.0f))
    {
        state->hitVolumeEnvelope = state->hitVolumeEnvelope - (0.005f);
    }
    volume = state->hitVolumeEnvelope;
    Sfx_SetObjectChannelVolume(
        (u32)obj, 0x40, 63.0f * volume,
        0.05f * mathSinf((SWARM_BADDIE_PI * (f32)(state->yawWavePhase + state->rollWavePhase)) /
                         SWARM_BADDIE_S16_ANGLE_SCALE) + volume);
    (*gPartfxInterface)->spawnObject((void*)obj, SWARMBADDIE_PARTFX, NULL, 2, -1, &state->hitVolumeEnvelope);
    state->player = Obj_GetPlayerObject();
    if (state->player != NULL)
    {
        delta.x = state->player->anim.worldPosX - (obj)->anim.worldPosX;
        delta.y = state->player->anim.worldPosY - (obj)->anim.worldPosY;
        delta.z = state->player->anim.worldPosZ - (obj)->anim.worldPosZ;
        state->playerDistance = sqrtf(delta.z * delta.z + (delta.x * delta.x + delta.y * delta.y));
    }
    if (curve != NULL)
    {
        delta.x = curve->posX - (obj)->anim.worldPosX;
        delta.y = curve->posY - (obj)->anim.worldPosY;
        delta.z = curve->posZ - (obj)->anim.worldPosZ;
        state->pathDistance = sqrtf(delta.z * delta.z + (delta.x * delta.x + delta.y * delta.y));
    }
    if (((state->flags & SWARMBADDIE_FLAG_CHASE_PLAYER) != 0) && (state->pathDistance > 250.0f))
    {
        state->flags = state->flags & ~SWARMBADDIE_FLAG_CHASE_PLAYER;
        state->flags = state->flags | SWARMBADDIE_FLAG_CHASE_LOCKOUT;
    }
    if (((state->flags & SWARMBADDIE_FLAG_CHASE_LOCKOUT) != 0) && (state->pathDistance < 60.0f))
    {
        state->flags = state->flags & ~SWARMBADDIE_FLAG_CHASE_LOCKOUT;
    }
    if (((state->flags & SWARMBADDIE_FLAG_CHASE_MASK) == 0) && (state->player != NULL) &&
        (state->playerDistance < state->chaseRadius))
    {
        state->flags = state->flags | SWARMBADDIE_FLAG_CHASE_PLAYER;
    }
    SwarmBaddie_updateMovement(obj, state);
}

void SwarmBaddie_init(GameObject* obj, SwarmBaddiePlacement* placement, int initialised)
{
    SwarmBaddieState* state = (obj)->extra;
    state->curveStep = (f32)(s32)placement->curveStepParam / 50.0f;
    state->chaseRadius = 4.0f * (f32)(s32)placement->chaseRadiusScale;
    state->hitVolumeEnvelope = (1.0f);
    if (initialised == 0)
    {
        state->curve = mmAlloc(sizeof(RomCurveWalker), 0x1A, 0);
        if (state->curve != NULL)
        {
            memset(state->curve, 0, sizeof(RomCurveWalker));
        }
        if ((*gRomCurveInterface)
                ->initCurve((void*)state->curve, (void*)obj, state->chaseRadius, gSwarmBaddieCurveInitData, -1) == 0)
        {
            state->flags |= SWARMBADDIE_FLAG_PATH_NEEDS_LINK;
        }
        Sfx_PlayFromObject((int)obj, SFXTRIG_en_grumb4_c);
    }
    (obj)->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void SwarmBaddie_release(void)
{
}

void SwarmBaddie_initialise(void)
{
}

ObjectDescriptor gSwarmBaddieObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)SwarmBaddie_initialise,
    (ObjectDescriptorCallback)SwarmBaddie_release,
    0,
    (ObjectDescriptorCallback)SwarmBaddie_init,
    (ObjectDescriptorCallback)SwarmBaddie_update,
    (ObjectDescriptorCallback)SwarmBaddie_hitDetect,
    (ObjectDescriptorCallback)SwarmBaddie_render,
    (ObjectDescriptorCallback)SwarmBaddie_free,
    (ObjectDescriptorCallback)SwarmBaddie_getObjectTypeId,
    SwarmBaddie_getExtraSize,
};
