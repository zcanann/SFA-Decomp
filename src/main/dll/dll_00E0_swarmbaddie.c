#include "main/audio/sfx_ids.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/pressureSwitch.h"
#include "main/effect_interfaces.h"
#include "main/mapEvent.h"
#include "main/game_object.h"
#include "main/objfx.h"



extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined8 ObjGroup_RemoveObject();

extern undefined4 DAT_803de6d0;

/*
 * --INFO--
 *
 * Function: FUN_8014e1dc
 * EN v1.0 Address: 0x8014E1DC
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8014E604
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void pressureSwitch_freeSharedResource(void)
{
    if (DAT_803de6d0 != 0)
    {
        FUN_80006b0c(DAT_803de6d0);
        DAT_803de6d0 = 0;
    }
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014e210
 * EN v1.0 Address: 0x8014E210
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8014E638
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void pressureSwitch_ensureSharedResource(void)
{
    if (DAT_803de6d0 == 0)
    {
        DAT_803de6d0 = FUN_80006b14(0x5a);
    }
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_8014e248
 * EN v1.0 Address: 0x8014E248
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x8014EBD8
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8014e374
 * EN v1.0 Address: 0x8014E374
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8014ED20
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8014e3a8
 * EN v1.0 Address: 0x8014E3A8
 * EN v1.0 Size: 1264b
 * EN v1.1 Address: 0x8014ED54
 * EN v1.1 Size: 1168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8014ede0
 * EN v1.0 Address: 0x8014EDE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8014F6E0
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8014ede4
 * EN v1.0 Address: 0x8014EDE4
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x8014F988
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
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

void wispbaddie_hitDetect(void);

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void mm_free(void* p);
extern f32 lbl_803E2678;
extern f32 lbl_803E267C;
extern f32 lbl_803E2680;
extern f32 lbl_803E2684;
extern f32 lbl_803E2688;
extern f32 lbl_803E268C;
extern f32 lbl_803E2690;
extern f32 lbl_803E2694;
extern f32 lbl_803E2698;
extern f32 lbl_803E269C;
extern f32 lbl_803E26A0;
extern f32 lbl_803E26A4;
extern f32 lbl_803E26B0;
extern f32 lbl_803E26B4;
extern f32 lbl_803E26B8;
extern f32 lbl_803E26BC;
extern f32 lbl_803E26C0;
extern f32 lbl_803E26C4;
extern f32 lbl_803E26C8;
extern f32 lbl_803E26CC;
extern int lbl_803DBC78;
extern void* mmAlloc(int size, int heap, int flags);
extern void* memset(void* dst, int val, u32 n);
extern EffectInterface** gPartfxInterface;
extern int lbl_803DDA60;
extern f32 timeDelta;
extern int Obj_GetPlayerObject(void);
extern int Curve_AdvanceAlongPath(int curve, f32 t);
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
extern void Sfx_SetObjectChannelVolume(f32 volumeScale, int obj, int channel, int volume);


#define SWARMBADDIE_FLAG_PATH_NEEDS_LINK 0x01
#define SWARMBADDIE_FLAG_CHASE_PLAYER 0x02

typedef struct SwarmBaddieState
{
    int curve;
    int player;
    f32 curveStep;
    f32 playerDistance;
    f32 pathDistance;
    f32 chaseRadius;
    f32 hitVolumeEnvelope;
    u8 flags;
    u8 pad1d;
    s16 yawWavePhase;
    s16 rollWavePhase;
    u8 pad22[2];
} SwarmBaddieState;

/* Per-object extra state for Hagabon (hagabon_getExtraSize == 0x28). */
typedef struct HagabonState
{
    int curve;
    int player;
    f32 curveStep;
    f32 animSpeed;
    f32 playerDistance;
    f32 pathDistance;
    f32 chaseRadius;
    u8 pad1C[4];
    u16 wavePhaseA; /* yaw wave */
    u16 wavePhaseB; /* shared bob wave */
    u16 wavePhaseC; /* pitch wave */
    u8 flags;
    u8 pad27;
} HagabonState;

STATIC_ASSERT(sizeof(HagabonState) == 0x28);
STATIC_ASSERT(offsetof(HagabonState, wavePhaseA) == 0x20);
STATIC_ASSERT(offsetof(HagabonState, flags) == 0x26);


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

void wispbaddie_free(int obj);

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
            *(u8*)&state->flags |= 0x1;
        }
        Sfx_PlayFromObject(obj, SFXfox_treadwater422);
    }
    ((GameObject*)obj)->objectFlags |= 0x2000;
}

void hagabon_init(int obj, int data, int skip_alloc);

void hagabon_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

/* 8b "li r3, N; blr" returners. */
int hagabon_getExtraSize(void);
int hagabon_getObjectTypeId(void);
int swarmbaddie_getExtraSize(void) { return 0x24; }
int swarmbaddie_getObjectTypeId(void) { return 0x9; }
int wispbaddie_getExtraSize(void);

void swarmbaddie_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
void wispbaddie_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void fn_8014EE8C(int obj, SwarmBaddieState* state)
{
    int curve;
    int done;
    f32 step;
    f32 wave;

    curve = state->curve;
    done = Curve_AdvanceAlongPath(curve, state->curveStep);
    if (((done != 0) || (*(int*)(curve + 0x10) != lbl_803DDA60)) &&
        ((*gRomCurveInterface)->goNextPoint((void*)curve) != 0) &&
        ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, lbl_803E2678,
                                          &lbl_803DBC78, -1) != 0))
    {
        state->flags &= ~SWARMBADDIE_FLAG_PATH_NEEDS_LINK;
    }
    lbl_803DDA60 = *(int*)(curve + 0x10);
    if ((state->flags & SWARMBADDIE_FLAG_CHASE_PLAYER) != 0)
    {
        step = lbl_803E267C;
        ((GameObject*)obj)->anim.velocityX = step * (*(f32*)(state->player + 0xc) - ((GameObject*)obj)->anim.localPosX)
            +
            ((GameObject*)obj)->anim.velocityX;
        ((GameObject*)obj)->anim.velocityY =
            step * ((lbl_803E2680 + *(f32*)(state->player + 0x10)) - ((GameObject*)obj)->anim.localPosY) +
            ((GameObject*)obj)->anim.velocityY;
        ((GameObject*)obj)->anim.velocityZ = step * (*(f32*)(state->player + 0x14) - ((GameObject*)obj)->anim.localPosZ)
            +
            ((GameObject*)obj)->anim.velocityZ;
    }
    else
    {
        step = lbl_803E267C;
        ((GameObject*)obj)->anim.velocityX = step * (*(f32*)(curve + 0x68) - ((GameObject*)obj)->anim.localPosX) +
            ((GameObject*)obj)->anim.velocityX;
        ((GameObject*)obj)->anim.velocityY = step * (*(f32*)(curve + 0x6c) - ((GameObject*)obj)->anim.localPosY) +
            ((GameObject*)obj)->anim.velocityY;
        ((GameObject*)obj)->anim.velocityZ = step * (*(f32*)(curve + 0x70) - ((GameObject*)obj)->anim.localPosZ) +
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

    *(s16*)obj += (s16)(lbl_803E2698 *
        (lbl_803E269C *
            mathSinf((lbl_803E26A0 * (f32)state->yawWavePhase) / lbl_803E26A4)));

    ((GameObject*)obj)->anim.rotZ += (s16)(lbl_803E2698 *
        (lbl_803E269C *
            mathSinf((lbl_803E26A0 * (f32)state->rollWavePhase) / lbl_803E26A4)));
}

void fn_8014F620(int obj, int* state);

void swarmbaddie_update(int obj)
{
    int hitObj;
    SwarmBaddieState* state;
    f32 d[3];
    f32 sqz;
    f32 sqx;
    f32 sqy;
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
        lbl_803E26C0 * mathSinf((lbl_803E26A0 *
                (f32)(state->yawWavePhase + state->rollWavePhase)) /
            lbl_803E26A4) +
        volume,
        obj, 0x40, (int)(lbl_803E26BC * volume));
    (*gPartfxInterface)->spawnObject((void*)obj, 0x336, NULL, 2, -1,
                                     &state->hitVolumeEnvelope);
    state->player = Obj_GetPlayerObject();
    if (*(void**)&state->player != NULL)
    {
        d[0] = *(f32*)(state->player + 0x18) - ((GameObject*)obj)->anim.worldPosX;
        d[1] = *(f32*)(state->player + 0x1c) - ((GameObject*)obj)->anim.worldPosY;
        d[2] = *(f32*)(state->player + 0x20) - ((GameObject*)obj)->anim.worldPosZ;
        sqz = d[2] * d[2];
        sqx = d[0] * d[0];
        sqy = d[1] * d[1];
        state->playerDistance = sqrtf(sqz + (sqx + sqy));
    }
    if ((void*)oldTarget != NULL)
    {
        d[0] = *(f32*)&((GameObject*)oldTarget)->anim.dll - ((GameObject*)obj)->anim.worldPosX;
        d[1] = *(f32*)&((GameObject*)oldTarget)->anim.jointPoseData - ((GameObject*)obj)->anim.worldPosY;
        d[2] = *(f32*)(oldTarget + 0x70) - ((GameObject*)obj)->anim.worldPosZ;
        sqz = d[2] * d[2];
        sqx = d[0] * d[0];
        sqy = d[1] * d[1];
        state->pathDistance = sqrtf(sqz + (sqx + sqy));
    }
    if (((state->flags & 2) != 0) && (state->pathDistance > lbl_803E26C4))
    {
        state->flags = state->flags & ~2;
        state->flags = state->flags | 4;
    }
    if (((state->flags & 4) != 0) && (state->pathDistance < lbl_803E26C8))
    {
        state->flags = state->flags & ~4;
    }
    if (((state->flags & 6) == 0) && (*(void**)&state->player != NULL) &&
        (state->playerDistance < state->chaseRadius))
    {
        state->flags = state->flags | 2;
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
