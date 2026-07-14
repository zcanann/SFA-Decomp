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

STATIC_ASSERT(sizeof(HagabonState) == 0x28);
STATIC_ASSERT(offsetof(HagabonState, wavePhaseA) == 0x20);
STATIC_ASSERT(offsetof(HagabonState, flags) == 0x26);

#define SWARMBADDIE_HIT_VOLUME_SLOT 10

/* object group this object belongs to */
#define SWARMBADDIE_OBJGROUP 3
#define SWARMBADDIE_PARTFX   0x336

#define SWARMBADDIE_OBJFLAG_HITDETECT_DISABLED 0x2000

#define SWARMBADDIE_FLAG_PATH_NEEDS_LINK 0x01
#define SWARMBADDIE_FLAG_CHASE_PLAYER    0x02
#define SWARMBADDIE_FLAG_CHASE_LOCKOUT   0x04 /* strayed too far; block re-chase until back near path */
#define SWARMBADDIE_FLAG_CHASE_MASK      0x06

__declspec(section ".sdata2") f32 lbl_803E2678 = 400.0f;
__declspec(section ".sdata2") f32 lbl_803E267C = 0.003f;
__declspec(section ".sdata2") f32 lbl_803E2680 = 30.0f;
__declspec(section ".sdata2") f32 lbl_803E2684 = 0.9f;
__declspec(section ".sdata2") f32 lbl_803E2688 = 0.8f;
__declspec(section ".sdata2") f32 lbl_803E268C = -0.8f;
__declspec(section ".sdata2") f32 lbl_803E2690 = 32.0f;
__declspec(section ".sdata2") f32 lbl_803E2694 = 23.0f;
__declspec(section ".sdata2") f32 lbl_803E2698 = 4.0f;
__declspec(section ".sdata2") f32 gSwarmBaddieDegToAngle = 182.0f;
__declspec(section ".sdata2") f32 gSwarmBaddiePi = 3.1415927f;
__declspec(section ".sdata2") f32 gSwarmBaddieS16AngleScale = 32768.0f;
extern f32 lbl_803E26B0;
extern f32 lbl_803E26B4;
extern f32 lbl_803E26B8;
extern f32 lbl_803E26BC;
extern f32 lbl_803E26C0;
extern f32 lbl_803E26C4;
extern f32 lbl_803E26C8;
extern f32 lbl_803E26CC;
extern int lbl_803DBC78;
extern int gSwarmBaddieLastCurvePoint;

void fn_8014EE8C(GameObject* obj, SwarmBaddieState* state)
{
    RomCurveWalker* curve;
    int done;
    f32 step;

    curve = state->curve;
    done = Curve_AdvanceAlongPath(&curve->curve, state->curveStep);
    if (((done != 0) || (curve->atSegmentEnd != gSwarmBaddieLastCurvePoint)) &&
        ((*gRomCurveInterface)->goNextPoint((void*)curve) != 0) &&
        ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, lbl_803E2678, &lbl_803DBC78, -1) != 0))
    {
        state->flags &= ~SWARMBADDIE_FLAG_PATH_NEEDS_LINK;
    }
    gSwarmBaddieLastCurvePoint = curve->atSegmentEnd;
    if ((state->flags & SWARMBADDIE_FLAG_CHASE_PLAYER) != 0)
    {
        step = lbl_803E267C;
        (obj)->anim.velocityX = step * (state->player->anim.localPosX - (obj)->anim.localPosX) + (obj)->anim.velocityX;
        (obj)->anim.velocityY =
            step * ((lbl_803E2680 + state->player->anim.localPosY) - (obj)->anim.localPosY) + (obj)->anim.velocityY;
        (obj)->anim.velocityZ = step * (state->player->anim.localPosZ - (obj)->anim.localPosZ) + (obj)->anim.velocityZ;
    }
    else
    {
        step = lbl_803E267C;
        (obj)->anim.velocityX = step * (curve->posX - (obj)->anim.localPosX) + (obj)->anim.velocityX;
        (obj)->anim.velocityY = step * (curve->posY - (obj)->anim.localPosY) + (obj)->anim.velocityY;
        (obj)->anim.velocityZ = step * (curve->posZ - (obj)->anim.localPosZ) + (obj)->anim.velocityZ;
    }

    (obj)->anim.velocityX = (obj)->anim.velocityX * (step = lbl_803E2684);
    (obj)->anim.velocityY *= step;
    (obj)->anim.velocityZ *= step;

    if ((obj)->anim.velocityX > *(f32*)&lbl_803E2688)
    {
        (obj)->anim.velocityX = lbl_803E2688;
    }
    if ((obj)->anim.velocityY > *(f32*)&lbl_803E2688)
    {
        (obj)->anim.velocityY = lbl_803E2688;
    }
    if ((obj)->anim.velocityZ > *(f32*)&lbl_803E2688)
    {
        (obj)->anim.velocityZ = lbl_803E2688;
    }
    if ((obj)->anim.velocityX < *(f32*)&lbl_803E268C)
    {
        (obj)->anim.velocityX = lbl_803E268C;
    }
    if ((obj)->anim.velocityY < *(f32*)&lbl_803E268C)
    {
        (obj)->anim.velocityY = lbl_803E268C;
    }
    if ((obj)->anim.velocityZ < *(f32*)&lbl_803E268C)
    {
        (obj)->anim.velocityZ = lbl_803E268C;
    }

    objMove((GameObject*)obj, (obj)->anim.velocityX * timeDelta, (obj)->anim.velocityY * timeDelta,
            (obj)->anim.velocityZ * timeDelta);

    state->yawWavePhase += (s16)(lbl_803E2690 * timeDelta);
    state->rollWavePhase += (s16)(lbl_803E2694 * timeDelta);

    (obj)->anim.rotX +=
        (s16)(lbl_803E2698 *
              (gSwarmBaddieDegToAngle * mathSinf((gSwarmBaddiePi * state->yawWavePhase) / gSwarmBaddieS16AngleScale)));

    (obj)->anim.rotZ +=
        (s16)(lbl_803E2698 *
              (gSwarmBaddieDegToAngle * mathSinf((gSwarmBaddiePi * state->rollWavePhase) / gSwarmBaddieS16AngleScale)));
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
    void** state = (obj)->extra;
    ObjGroup_RemoveObject((int)obj, SWARMBADDIE_OBJGROUP);
    if (*state != NULL)
    {
        mm_free(*state);
        *state = NULL;
    }
}

void SwarmBaddie_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
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
    } d;
    f32* dp = &d.x;
    f32 volume;
    RomCurveWalker* oldTarget;
    int hitD;
    int hitE;
    int hitC;
    int hitF;
    int hitB;
    int hitA;

    state = *(SwarmBaddieState**)&(obj)->extra;
    oldTarget = state->curve;
    if (ObjHits_GetPriorityHitWithPosition(obj, &hitD, &hitB, (u32*)&hitA, (f32*)&hitE, (f32*)&hitC,
                                           (f32*)&hitF) != 0)
    {
        state->hitVolumeEnvelope = lbl_803E26B0;
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, SWARMBADDIE_HIT_VOLUME_SLOT, 1, 0);
    ObjHits_EnableObject((int)obj);
    if (state->hitVolumeEnvelope > lbl_803E26B4)
    {
        state->hitVolumeEnvelope = state->hitVolumeEnvelope - lbl_803E26B8;
    }
    volume = state->hitVolumeEnvelope;
    Sfx_SetObjectChannelVolumeScaleFirstLegacy(
        lbl_803E26C0 *
                mathSinf((gSwarmBaddiePi * (f32)(state->yawWavePhase + state->rollWavePhase)) /
                         gSwarmBaddieS16AngleScale) +
            volume,
        (int)obj, 0x40, (int)(lbl_803E26BC * volume));
    (*gPartfxInterface)->spawnObject((void*)obj, SWARMBADDIE_PARTFX, NULL, 2, -1, &state->hitVolumeEnvelope);
    state->player = Obj_GetPlayerObject();
    if (state->player != NULL)
    {
        d.x = state->player->anim.worldPosX - (obj)->anim.worldPosX;
        d.y = state->player->anim.worldPosY - (obj)->anim.worldPosY;
        d.z = state->player->anim.worldPosZ - (obj)->anim.worldPosZ;
        state->playerDistance = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
    }
    if (oldTarget != NULL)
    {
        d.x = oldTarget->posX - (obj)->anim.worldPosX;
        d.y = oldTarget->posY - (obj)->anim.worldPosY;
        d.z = oldTarget->posZ - (obj)->anim.worldPosZ;
        state->pathDistance = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
    }
    if (((state->flags & SWARMBADDIE_FLAG_CHASE_PLAYER) != 0) && (state->pathDistance > lbl_803E26C4))
    {
        state->flags = state->flags & ~SWARMBADDIE_FLAG_CHASE_PLAYER;
        state->flags = state->flags | SWARMBADDIE_FLAG_CHASE_LOCKOUT;
    }
    if (((state->flags & SWARMBADDIE_FLAG_CHASE_LOCKOUT) != 0) && (state->pathDistance < lbl_803E26C8))
    {
        state->flags = state->flags & ~SWARMBADDIE_FLAG_CHASE_LOCKOUT;
    }
    if (((state->flags & SWARMBADDIE_FLAG_CHASE_MASK) == 0) && (state->player != NULL) &&
        (state->playerDistance < state->chaseRadius))
    {
        state->flags = state->flags | SWARMBADDIE_FLAG_CHASE_PLAYER;
    }
    fn_8014EE8C(obj, state);
}

void SwarmBaddie_init(GameObject* obj, int data, int skip_alloc)
{
    SwarmBaddieState* state = (obj)->extra;
    state->curveStep = (f32)(s32) * (s16*)(data + 0x1A) / lbl_803E26CC;
    state->chaseRadius = lbl_803E2698 * (f32)(s32) * (s8*)(data + 0x19);
    state->hitVolumeEnvelope = lbl_803E26B4;
    if (skip_alloc == 0)
    {
        state->curve = mmAlloc(0x108, 0x1A, 0);
        if (state->curve != NULL)
        {
            memset(state->curve, 0, 0x108);
        }
        if ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, state->chaseRadius, &lbl_803DBC78, -1) ==
            0)
        {
            *(u8*)&state->flags |= SWARMBADDIE_FLAG_PATH_NEEDS_LINK;
        }
        Sfx_PlayFromObject((int)obj, SFXTRIG_en_grumb4_c);
    }
    (obj)->objectFlags |= SWARMBADDIE_OBJFLAG_HITDETECT_DISABLED;
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

__declspec(section ".sdata2") f32 lbl_803E26B0 = 2.0f;
__declspec(section ".sdata2") f32 lbl_803E26B4 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E26B8 = 0.005f;
__declspec(section ".sdata2") f32 lbl_803E26BC = 63.0f;
__declspec(section ".sdata2") f32 lbl_803E26C0 = 0.05f;
__declspec(section ".sdata2") f32 lbl_803E26C4 = 250.0f;
__declspec(section ".sdata2") f32 lbl_803E26C8 = 60.0f;
__declspec(section ".sdata2") f32 lbl_803E26CC = 50.0f;
