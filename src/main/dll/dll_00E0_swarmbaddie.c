/*
 * swarmbaddie (DLL 0x00E0) - the swarming flying baddie (a "wisp"-class
 * pest) plus the hagabon variant's object descriptor.
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
 *
 * This TU exports both gSwarmBaddieObjDescriptor and gHagabonObjDescriptor;
 * the hagabon_* and wispbaddie_* callbacks live in the sibling DLLs.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll/swarmbaddiestate_struct.h"
#include "main/dll/hagabonstate_struct.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/curve_walker.h"
#include "main/dll/pressureSwitch.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/objlib.h"
#include "main/mm.h"
#include "string.h"
extern u32 FUN_80006b0c();
extern u32 FUN_80006b14();
extern u32 DAT_803de6d0;
extern int ObjHits_GetPriorityHitWithPosition();
extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern void Sfx_SetObjectChannelVolume(f32 volumeScale, int obj, int channel, int volume);
extern void* Obj_GetPlayerObject(void);
extern int Curve_AdvanceAlongPath(int curve, f32 t);
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern f32 sqrtf(f32 x);
extern float mathSinf(float x);
extern f32 timeDelta;
extern f32 lbl_803E2678;
extern f32 lbl_803E267C;
extern f32 lbl_803E2680;
extern f32 lbl_803E2684;
extern f32 lbl_803E2688;
extern f32 lbl_803E268C;
extern f32 lbl_803E2690;
extern f32 lbl_803E2694;
extern f32 lbl_803E2698;
extern f32 gSwarmBaddieDegToAngle;
extern f32 gSwarmBaddiePi;
extern f32 gSwarmBaddieS16AngleScale;
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

STATIC_ASSERT(sizeof(HagabonState) == 0x28);
STATIC_ASSERT(offsetof(HagabonState, wavePhaseA) == 0x20);
STATIC_ASSERT(offsetof(HagabonState, flags) == 0x26);

void pressureSwitch_freeSharedResource(void)
{
    if (DAT_803de6d0 != 0)
    {
        FUN_80006b0c(DAT_803de6d0);
        DAT_803de6d0 = 0;
    }
}

void pressureSwitch_ensureSharedResource(void)
{
    if (DAT_803de6d0 == 0)
    {
        DAT_803de6d0 = FUN_80006b14(0x5a);
    }
}

void hagabon_release(void);

void hagabon_initialise(void);

void swarmbaddie_hitDetect(void)
{
}

void swarmbaddie_release(void)
{
}

void swarmbaddie_initialise(void)
{
}

#define SWARMBADDIE_FLAG_PATH_NEEDS_LINK 0x01
#define SWARMBADDIE_FLAG_CHASE_PLAYER 0x02
#define SWARMBADDIE_FLAG_CHASE_LOCKOUT 0x04 /* strayed too far; block re-chase until back near path */
#define SWARMBADDIE_FLAG_CHASE_MASK 0x06

void hagabon_hitDetect(int obj);

void swarmbaddie_free(int obj)
{
    void** state = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 3);
    if (*state != NULL)
    {
        mm_free(*state);
        *state = NULL;
    }
}

void hagabon_free(int obj);

void swarmbaddie_init(int obj, int data, int skip_alloc)
{
    SwarmBaddieState* state = ((GameObject*)obj)->extra;
    state->curveStep = (f32)(s32) * (s16*)(data + 0x1A) / lbl_803E26CC;
    state->chaseRadius = lbl_803E2698 * (f32)(s32) * (s8*)(data + 0x19);
    state->hitVolumeEnvelope = lbl_803E26B4;
    if (skip_alloc == 0)
    {
        *(void**)&state->curve = mmAlloc(0x108, 0x1A, 0);
        if (*(void**)&state->curve != NULL)
        {
            memset(*(void**)&state->curve, 0, 0x108);
        }
        if ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, state->chaseRadius,
                                             &lbl_803DBC78, -1) == 0)
        {
            *(u8*)&state->flags |= SWARMBADDIE_FLAG_PATH_NEEDS_LINK;
        }
        Sfx_PlayFromObject(obj, SFXfox_treadwater422);
    }
    ((GameObject*)obj)->objectFlags |= 0x2000;
}

void hagabon_init(int obj, int data, int skip_alloc);

void hagabon_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

int hagabon_getExtraSize(void);
int hagabon_getObjectTypeId(void);
int swarmbaddie_getExtraSize(void) { return sizeof(SwarmBaddieState); }
int swarmbaddie_getObjectTypeId(void) { return 0x9; }

void swarmbaddie_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void fn_8014EE8C(int obj, SwarmBaddieState* state)
{
    int curve;
    RomCurveWalker* walker;
    int done;
    f32 step;

    curve = state->curve;
    walker = (RomCurveWalker*)curve;
    done = Curve_AdvanceAlongPath(curve, state->curveStep);
    if (((done != 0) || (walker->atSegmentEnd != gSwarmBaddieLastCurvePoint)) &&
        ((*gRomCurveInterface)->goNextPoint((void*)curve) != 0) &&
        ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, lbl_803E2678,
                                          &lbl_803DBC78, -1) != 0))
    {
        state->flags &= ~SWARMBADDIE_FLAG_PATH_NEEDS_LINK;
    }
    gSwarmBaddieLastCurvePoint = walker->atSegmentEnd;
    if ((state->flags & SWARMBADDIE_FLAG_CHASE_PLAYER) != 0)
    {
        step = lbl_803E267C;
        ((GameObject*)obj)->anim.velocityX = step * (state->player->anim.localPosX - ((GameObject*)obj)->anim.localPosX)
            +
            ((GameObject*)obj)->anim.velocityX;
        ((GameObject*)obj)->anim.velocityY =
            step * ((lbl_803E2680 + state->player->anim.localPosY) - ((GameObject*)obj)->anim.localPosY) +
            ((GameObject*)obj)->anim.velocityY;
        ((GameObject*)obj)->anim.velocityZ = step * (state->player->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ)
            +
            ((GameObject*)obj)->anim.velocityZ;
    }
    else
    {
        step = lbl_803E267C;
        ((GameObject*)obj)->anim.velocityX = step * (walker->posX - ((GameObject*)obj)->anim.localPosX) +
            ((GameObject*)obj)->anim.velocityX;
        ((GameObject*)obj)->anim.velocityY = step * (walker->posY - ((GameObject*)obj)->anim.localPosY) +
            ((GameObject*)obj)->anim.velocityY;
        ((GameObject*)obj)->anim.velocityZ = step * (walker->posZ - ((GameObject*)obj)->anim.localPosZ) +
            ((GameObject*)obj)->anim.velocityZ;
    }

    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (step = lbl_803E2684);
    ((GameObject*)obj)->anim.velocityY *= step;
    ((GameObject*)obj)->anim.velocityZ *= step;

    if (((GameObject*)obj)->anim.velocityX > *(f32*)&lbl_803E2688)
    {
        ((GameObject*)obj)->anim.velocityX = lbl_803E2688;
    }
    if (((GameObject*)obj)->anim.velocityY > *(f32*)&lbl_803E2688)
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E2688;
    }
    if (((GameObject*)obj)->anim.velocityZ > *(f32*)&lbl_803E2688)
    {
        ((GameObject*)obj)->anim.velocityZ = lbl_803E2688;
    }
    if (((GameObject*)obj)->anim.velocityX < *(f32*)&lbl_803E268C)
    {
        ((GameObject*)obj)->anim.velocityX = lbl_803E268C;
    }
    if (((GameObject*)obj)->anim.velocityY < *(f32*)&lbl_803E268C)
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E268C;
    }
    if (((GameObject*)obj)->anim.velocityZ < *(f32*)&lbl_803E268C)
    {
        ((GameObject*)obj)->anim.velocityZ = lbl_803E268C;
    }

    objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);

    state->yawWavePhase += (s16)(lbl_803E2690 * timeDelta);
    state->rollWavePhase += (s16)(lbl_803E2694 * timeDelta);

    ((GameObject*)obj)->anim.rotX += (s16)(lbl_803E2698 *
        (gSwarmBaddieDegToAngle *
            mathSinf((gSwarmBaddiePi * state->yawWavePhase) / gSwarmBaddieS16AngleScale)));

    ((GameObject*)obj)->anim.rotZ += (s16)(lbl_803E2698 *
        (gSwarmBaddieDegToAngle *
            mathSinf((gSwarmBaddiePi * state->rollWavePhase) / gSwarmBaddieS16AngleScale)));
}

void swarmbaddie_update(int obj)
{
    SwarmBaddieState* state;
    struct
    {
        f32 x, y, z;
    } d;
    f32* dp = &d.x;
    f32 volume;
    int oldTarget;
    int hitD;
    int hitE;
    int hitC;
    int hitF;
    int hitB;
    int hitA;

    state = *(SwarmBaddieState**)&((GameObject*)obj)->extra;
    oldTarget = state->curve;
    if (ObjHits_GetPriorityHitWithPosition(obj, &hitD, &hitB, &hitA, &hitE, &hitC, &hitF) != 0)
    {
        state->hitVolumeEnvelope = lbl_803E26B0;
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
    ObjHits_EnableObject(obj);
    if (state->hitVolumeEnvelope > lbl_803E26B4)
    {
        state->hitVolumeEnvelope = state->hitVolumeEnvelope - lbl_803E26B8;
    }
    volume = state->hitVolumeEnvelope;
    Sfx_SetObjectChannelVolume(
        lbl_803E26C0 * mathSinf((gSwarmBaddiePi *
                (f32)(state->yawWavePhase + state->rollWavePhase)) /
            gSwarmBaddieS16AngleScale) +
        volume,
        obj, 0x40, (int)(lbl_803E26BC * volume));
    (*gPartfxInterface)->spawnObject((void*)obj, 0x336, NULL, 2, -1,
                                     &state->hitVolumeEnvelope);
    state->player = Obj_GetPlayerObject();
    if (state->player != NULL)
    {
        d.x = state->player->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        d.y = state->player->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        d.z = state->player->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        state->playerDistance = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
    }
    if ((void*)oldTarget != NULL)
    {
        RomCurveWalker* walker = (RomCurveWalker*)oldTarget;
        d.x = walker->posX - ((GameObject*)obj)->anim.worldPosX;
        d.y = walker->posY - ((GameObject*)obj)->anim.worldPosY;
        d.z = walker->posZ - ((GameObject*)obj)->anim.worldPosZ;
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

void hagabon_update(int obj);

ObjectDescriptor gHagabonObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)hagabon_initialise,
    (ObjectDescriptorCallback)hagabon_release,
    0,
    (ObjectDescriptorCallback)hagabon_init,
    (ObjectDescriptorCallback)hagabon_update,
    (ObjectDescriptorCallback)hagabon_hitDetect,
    (ObjectDescriptorCallback)hagabon_render,
    (ObjectDescriptorCallback)hagabon_free,
    (ObjectDescriptorCallback)hagabon_getObjectTypeId,
    hagabon_getExtraSize,
};

ObjectDescriptor gSwarmBaddieObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)swarmbaddie_initialise,
    (ObjectDescriptorCallback)swarmbaddie_release,
    0,
    (ObjectDescriptorCallback)swarmbaddie_init,
    (ObjectDescriptorCallback)swarmbaddie_update,
    (ObjectDescriptorCallback)swarmbaddie_hitDetect,
    (ObjectDescriptorCallback)swarmbaddie_render,
    (ObjectDescriptorCallback)swarmbaddie_free,
    (ObjectDescriptorCallback)swarmbaddie_getObjectTypeId,
    swarmbaddie_getExtraSize,
};
