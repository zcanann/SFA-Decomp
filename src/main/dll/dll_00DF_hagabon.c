/*
 * hagabon (DLL 0xDF) - a flying baddie that patrols a rom curve path and,
 * when the player closes in, breaks off to chase. Shares its TU pool and the
 * pressureSwitch shared-resource helpers with swarmbaddie (DLL 0xE0); each TU
 * carries a duplicate of the pressureSwitch helpers and the two object
 * descriptors so the linker can resolve the canonical sibling from either DLL.
 *
 * fn_8014E1DC is the per-frame motion integrator: it advances the curve walker
 * (relinking via gRomCurveInterface when a point is exhausted), drives the
 * yaw/pitch/roll body wobble from three sine-wave phase accumulators, steers
 * the velocity toward either the player (HAGABON_FLAG_CHASE) or the curve
 * target, clamps + damps the velocity, moves the object, and turns it to face
 * the player.
 *
 * hagabon_update handles the dormant-until-armed state (unkF4): while waiting it
 * polls its placement game bit / the map-event save-time gate, then fades in.
 * Once active it fades out on a priority hit, plays the swipe/lock/creak sfx,
 * adds map time and sets the placement game bit, and re-evaluates chase state.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll/hagabonstate_struct.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/pressureSwitch.h"
#include "main/mapEvent.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/objlib.h"
#include "main/mm.h"
#include "string.h"

typedef struct HagabonPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 mapEventId;         /* 0x14: map-event id for save-time gating / addTime */
    u8 pad18[0x19 - 0x18];
    s8 chaseRadiusScale;    /* 0x19 */
    s16 curveStepRaw;       /* 0x1A */
    s16 timeReward;         /* 0x1C: minutes added to the map timer on a hit */
    s16 startInactive;      /* 0x1E: when nonzero the baddie never auto-chases */
    s16 armGameBit;         /* 0x20: -1 = none; bit that arms/latches the spawn */
    u8 pad22[0x28 - 0x22];
} HagabonPlacement;

/* HagabonState.flags */
#define HAGABON_FLAG_PATH_NEEDS_LINK 0x01
#define HAGABON_FLAG_CHASE           0x02
#define HAGABON_FLAG_PATH_RETURN     0x04
#define HAGABON_FLAG_FADE_IN         0x08
#define HAGABON_FLAG_FADE_OUT        0x10

extern int FUN_80006b0c(int handle);
extern int FUN_80006b14(int id);
extern u32 DAT_803de6d0;   /* pressureSwitch shared resource handle */
extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern void Sfx_StopFromObject(int obj, u16 sfxId);
extern void Sfx_StopObjectChannel(u32 obj, u32 channel);
extern void objRenderFn_8003b8f4(int* obj);
extern void objParticleFn_80099d84(int obj, f32 scale, int kind, f32 fextra, int light);
extern f32 lbl_803DDA58;          /* last-seen curve point cache, shared with swarmbaddie */
extern f32 lbl_803E2608;
extern f32 lbl_803E260C;
extern f32 lbl_803E2610;
extern f32 lbl_803E2614;
extern f32 lbl_803E2618;
extern f32 gHagabonPi;
extern f32 lbl_803E2620;
extern const f32 lbl_803E2624;
extern f32 lbl_803E2628;
extern f32 lbl_803E262C;
extern f32 lbl_803E2630;
extern f32 lbl_803E2634;
extern f32 lbl_803E2638;
extern f32 lbl_803E263C;
extern f32 lbl_803E2650;
extern f32 gHagabonAlphaMax;
extern f32 lbl_803E2658;
extern f32 lbl_803E265C;
extern f32 lbl_803E2660;
extern f32 lbl_803E2664;
extern f32 lbl_803E2668;
extern f32 lbl_803E266C;
extern f32 lbl_803E2670;
extern f32 lbl_803E2674;
extern int lbl_803DBC70;
extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern void* Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32* a, f32* b);
extern int Curve_AdvanceAlongPath(int curve, f32 t);
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern f32 sqrtf(f32 x);
extern float mathSinf(float x);
extern int getAngle(float y, float x);
STATIC_ASSERT(sizeof(HagabonState) == 0x28);
STATIC_ASSERT(offsetof(HagabonState, wavePhaseA) == 0x20);
STATIC_ASSERT(offsetof(HagabonState, flags) == 0x26);

void swarmbaddie_hitDetect(void);
void swarmbaddie_release(void);
void swarmbaddie_initialise(void);
void swarmbaddie_free(int obj);
void swarmbaddie_init(int obj, int data, int skip_alloc);
int swarmbaddie_getExtraSize(void);
int swarmbaddie_getObjectTypeId(void);
void swarmbaddie_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void swarmbaddie_update(int obj);

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

void hagabon_release(void)
{
}

void hagabon_initialise(void)
{
}

void fn_8014E1DC(int obj, HagabonState* state)
{
    int curve;
    GameObject* player;
    int angleDelta;
    int angle;
    u8* flags;
    char animEvents[32];
    f32 waveA;
    f32 waveB;
    f32 damp;
    f32 maxSpeed;
    f32 minSpeed;

    curve = state->curve;
    flags = &state->flags;

    if (((Curve_AdvanceAlongPath(curve, state->curveStep) != 0) ||
            (*(int*)(curve + 0x10) != *(int*)&lbl_803DDA58)) &&
        ((*gRomCurveInterface)->goNextPoint((void*)curve) != 0) &&
        ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, lbl_803E2608,
                                          &lbl_803DBC70, -1) != 0))
    {
        *flags &= ~HAGABON_FLAG_PATH_NEEDS_LINK;
    }

    *(int*)&lbl_803DDA58 = *(int*)(curve + 0x10);

    state->wavePhaseA += (s32)(lbl_803E260C * timeDelta);
    state->wavePhaseB += (s32)(lbl_803E2610 * timeDelta);
    state->wavePhaseC += (s32)(lbl_803E2614 * timeDelta);

    waveA = mathSinf((gHagabonPi * (f32)(u32)state->wavePhaseB) /
        lbl_803E2620
    )
    ;
    waveB = mathSinf((gHagabonPi * (f32)(u32)state->wavePhaseA) /
        lbl_803E2620
    )
    ;
    waveA = waveB + waveA;
    ((GameObject*)obj)->anim.rotZ = lbl_803E2618 * waveA;

    waveA = mathSinf((gHagabonPi * (f32)(u32)state->wavePhaseC) /
        lbl_803E2620
    )
    ;
    waveB = mathSinf((gHagabonPi * (f32)(u32)state->wavePhaseA) /
        lbl_803E2620
    )
    ;
    waveA = waveB + waveA;
    ((GameObject*)obj)->anim.rotY = lbl_803E2618 * waveA;

    if ((*flags & HAGABON_FLAG_CHASE) != 0)
    {
        ((GameObject*)obj)->anim.velocityX += lbl_803E2624 * (state->player->anim.localPosX - ((GameObject*)obj)->anim.
            localPosX);
        ((GameObject*)obj)->anim.velocityY += lbl_803E2624 *
        ((lbl_803E2628 + state->player->anim.localPosY) -
            ((GameObject*)obj)->anim.localPosY);
        ((GameObject*)obj)->anim.velocityZ += lbl_803E2624 * (state->player->anim.localPosZ - ((GameObject*)obj)->anim.
            localPosZ);
    }
    else if ((*flags & HAGABON_FLAG_PATH_RETURN) != 0)
    {
        ((GameObject*)obj)->anim.velocityX += lbl_803E2624 * (*(f32*)(curve + 0x68) - ((GameObject*)obj)->anim.localPosX);
        ((GameObject*)obj)->anim.velocityY += lbl_803E2624 * (*(f32*)(curve + 0x6c) - ((GameObject*)obj)->anim.localPosY);
        ((GameObject*)obj)->anim.velocityZ += lbl_803E2624 * (*(f32*)(curve + 0x70) - ((GameObject*)obj)->anim.localPosZ);
    }
    else
    {
        ((GameObject*)obj)->anim.velocityX += lbl_803E2624 * (*(f32*)(curve + 0x68) - ((GameObject*)obj)->anim.localPosX);
        waveA = mathSinf((gHagabonPi * (f32)(u32)state->wavePhaseB) /
            lbl_803E2620
        )
        ;
        waveB = mathSinf((gHagabonPi * (f32)(u32)state->wavePhaseA) /
            lbl_803E2620
        )
        ;
        waveA = waveB + waveA;
        waveB = ((lbl_803E262C * waveA) +
                *(f32*)(curve + 0x6c)) -
            ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)obj)->anim.velocityY += waveB * lbl_803E2624;
        ((GameObject*)obj)->anim.velocityZ += lbl_803E2624 * (*(f32*)(curve + 0x70) - ((GameObject*)obj)->anim.localPosZ);
    }

    ((GameObject*)obj)->anim.velocityX *= (damp = lbl_803E2630);
    ((GameObject*)obj)->anim.velocityY *= damp;
    ((GameObject*)obj)->anim.velocityZ *= damp;

    if (((GameObject*)obj)->anim.velocityX > lbl_803E2634)
    {
        ((GameObject*)obj)->anim.velocityX = *(f32*)&lbl_803E2634;
    }
    if (((GameObject*)obj)->anim.velocityY > lbl_803E2634)
    {
        ((GameObject*)obj)->anim.velocityY = *(f32*)&lbl_803E2634;
    }
    if (((GameObject*)obj)->anim.velocityZ > lbl_803E2634)
    {
        ((GameObject*)obj)->anim.velocityZ = *(f32*)&lbl_803E2634;
    }

    if (((GameObject*)obj)->anim.velocityX < lbl_803E2638)
    {
        ((GameObject*)obj)->anim.velocityX = *(f32*)&lbl_803E2638;
    }
    if (((GameObject*)obj)->anim.velocityY < lbl_803E2638)
    {
        ((GameObject*)obj)->anim.velocityY = *(f32*)&lbl_803E2638;
    }
    if (((GameObject*)obj)->anim.velocityZ < lbl_803E2638)
    {
        ((GameObject*)obj)->anim.velocityZ = *(f32*)&lbl_803E2638;
    }

    objMove(obj,
            ((GameObject*)obj)->anim.velocityX * timeDelta,
            ((GameObject*)obj)->anim.velocityY * timeDelta,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, state->animSpeed, timeDelta,
                                                                (ObjAnimEventList*)animEvents);

    player = state->player;
    angle = (u16)getAngle(((GameObject*)obj)->anim.worldPosX - player->anim.worldPosX,
                          ((GameObject*)obj)->anim.worldPosZ - player->anim.worldPosZ);
    angleDelta = angle - ((int)((GameObject*)obj)->anim.rotX & 0xffff);
    if (angleDelta > 0x8000)
    {
        angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000)
    {
        angleDelta += 0xffff;
    }

    ((GameObject*)obj)->anim.rotX += (s32)(((f32)angleDelta * timeDelta) / lbl_803E263C);
}

void hagabon_hitDetect(int obj)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    if (hitState->lastHitObject != 0)
    {
        Sfx_PlayFromObject(obj, SFXand_swipe2);
    }
}

void hagabon_free(int obj)
{
    void** state = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 3);
    Sfx_StopFromObject(obj, SFXstaff_proj_outofmagic);
    if (*state != NULL)
    {
        mm_free(*state);
        *state = NULL;
    }
}

void hagabon_init(int obj, int data, int skip_alloc)
{
    HagabonState* state = ((GameObject*)obj)->extra;
    HagabonPlacement* placement = (HagabonPlacement*)data;
    state->curveStep = (f32)(s32)placement->curveStepRaw / lbl_803E266C;
    state->animSpeed = lbl_803E2670;
    state->chaseRadius = lbl_803E2674 * (f32)(s32)placement->chaseRadiusScale;
    if (skip_alloc == 0)
    {
        *(void**)&state->curve = mmAlloc(0x108, 0x1A, 0);
        if (*(void**)&state->curve != NULL)
        {
            memset(*(void**)&state->curve, 0, 0x108);
        }
        if ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, state->chaseRadius,
                                             &lbl_803DBC70, -1) == 0)
        {
            state->flags |= HAGABON_FLAG_PATH_NEEDS_LINK;
        }
    }
    if (placement->armGameBit != -1)
    {
        if (GameBit_Get(placement->armGameBit) != 0)
        {
            ((GameObject*)obj)->unkF4 = 1;
        }
    }
}

void hagabon_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    HagabonState* state = *(HagabonState**)&((GameObject*)obj)->extra;
    s32 v = visible;
    if (v != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
            ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)
                (obj, p2, p3, p4, p5, lbl_803E2650);
            if ((state->flags & HAGABON_FLAG_FADE_OUT) != 0)
            {
                objParticleFn_80099d84(obj, lbl_803E2650, 3,
                                       (f32)(u32)((GameObject*)obj)->anim.alpha / gHagabonAlphaMax, 0);
            }
            if ((state->flags & HAGABON_FLAG_FADE_IN) != 0)
            {
                objParticleFn_80099d84(obj, lbl_803E2650, 4,
                                       (f32)(u32)((GameObject*)obj)->anim.alpha / gHagabonAlphaMax, 0);
            }
            break;
        }
    }
}

int hagabon_getExtraSize(void) { return 0x28; }
int hagabon_getObjectTypeId(void) { return 0xb; }

#pragma fp_contract off
void hagabon_update(int obj)
{
    GameObject* player;
    HagabonState* state;
    int oldCurve;
    int data;
    f32 lightPos[3];
    f32 effectPos[3];
    f32 d[3];
    f32 dist;
    int hitObject;
    int hitSphereIndex;
    u32 hitVolume;

    state = *(HagabonState**)&((GameObject*)obj)->extra;
    oldCurve = state->curve;
    data = *(int*)&((GameObject*)obj)->anim.placementData;

    if (((GameObject*)obj)->unkF4 != 0)
    {
        if ((((HagabonPlacement*)data)->armGameBit != -1) && (GameBit_Get(((HagabonPlacement*)data)->armGameBit) != 0))
        {
            return;
        }
        if ((*gMapEventInterface)->shouldNotSaveTime(((HagabonPlacement*)data)->mapEventId) == 0)
        {
            return;
        }
        ((GameObject*)obj)->unkF4 = 0;
        ((GameObject*)obj)->anim.alpha = 1;
        state->flags |= HAGABON_FLAG_FADE_IN;
        Sfx_PlayFromObject(obj, SFXfox_treadwater122);
        return;
    }

    player = Obj_GetPlayerObject();
    dist = Vec_distance((f32*)(obj + 0x18), &player->anim.worldPosX);
    if (dist < lbl_803E2658)
    {
        Sfx_PlayFromObject(obj, SFXstaff_proj_outofmagic);
    }
    else if (dist > lbl_803E265C)
    {
        Sfx_StopFromObject(obj, SFXstaff_proj_outofmagic);
    }

    if ((((GameObject*)obj)->anim.alpha != 0) &&
        ((state->flags & (HAGABON_FLAG_FADE_IN | HAGABON_FLAG_FADE_OUT)) != 0))
    {
        if ((state->flags & HAGABON_FLAG_FADE_OUT) != 0)
        {
            ((GameObject*)obj)->anim.alpha = (f32)(u32)((GameObject*)obj)->anim.alpha - timeDelta;
            if (((GameObject*)obj)->anim.alpha <= 6)
            {
                ((GameObject*)obj)->unkF4 = 1;
                ((GameObject*)obj)->anim.alpha = 0;
                state->flags &= ~HAGABON_FLAG_FADE_OUT;
                Sfx_StopFromObject(obj, SFXstaff_proj_outofmagic);
            }
            ObjHits_DisableObject(obj);
        }
        if ((state->flags & HAGABON_FLAG_FADE_IN) != 0)
        {
            ((GameObject*)obj)->anim.alpha = (f32)(u32)((GameObject*)obj)->anim.alpha + timeDelta;
            if (((GameObject*)obj)->anim.alpha >= 0xf9)
            {
                ((GameObject*)obj)->anim.alpha = 0xff;
                state->flags &= ~HAGABON_FLAG_FADE_IN;
            }
        }
    }
    else
    {
        if (ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &hitSphereIndex, &hitVolume,
                                               &lightPos[0], &lightPos[1], &lightPos[2]) != 0)
        {
            Sfx_StopObjectChannel(obj, 0x7f);
            state->flags |= HAGABON_FLAG_FADE_OUT;
            Sfx_PlayFromObject(obj, SFXdoor_unlocked);
            Sfx_PlayFromObject(obj, SFXdoor_creak);
            Sfx_PlayFromObject(obj, SFXfox_treadwater222);
            Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
            lightPos[0] += playerMapOffsetX;
            lightPos[2] += playerMapOffsetZ;
            objLightFn_8009a1dc((void*)obj, lbl_803E2660, effectPos, 3, 0);
            (*gMapEventInterface)->addTime(((HagabonPlacement*)data)->mapEventId,
                                                   (f32)(s32)(((HagabonPlacement*)data)->timeReward * 0x3c));
            if (((HagabonPlacement*)data)->armGameBit != -1)
            {
                GameBit_Set(((HagabonPlacement*)data)->armGameBit, 1);
            }
        }
        ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
        ObjHits_EnableObject(obj);
    }

    state->player = Obj_GetPlayerObject();
    player = state->player;
    if (player != 0)
    {
        f32* dp = d;
        dp[0] = player->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        dp[1] = player->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        dp[2] = player->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        state->playerDistance = sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1]));
    }
    if ((void*)oldCurve != NULL)
    {
        f32* dp = d;
        dp[0] = *(f32*)&((GameObject*)oldCurve)->anim.dll - ((GameObject*)obj)->anim.worldPosX;
        dp[1] = *(f32*)&((GameObject*)oldCurve)->anim.jointPoseData - ((GameObject*)obj)->anim.worldPosY;
        dp[2] = *(f32*)(oldCurve + 0x70) - ((GameObject*)obj)->anim.worldPosZ;
        state->pathDistance = sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1]));
    }
    if (((state->flags & HAGABON_FLAG_CHASE) != 0) && (state->pathDistance > lbl_803E2664))
    {
        state->flags &= ~HAGABON_FLAG_CHASE;
        state->flags |= HAGABON_FLAG_PATH_RETURN;
    }
    if (((state->flags & HAGABON_FLAG_PATH_RETURN) != 0) && (state->pathDistance < lbl_803E2668))
    {
        state->flags &= ~HAGABON_FLAG_PATH_RETURN;
    }
    if (((state->flags & (HAGABON_FLAG_CHASE | HAGABON_FLAG_PATH_RETURN)) == 0) &&
        (((HagabonPlacement*)data)->startInactive == 0) &&
        (state->player != 0) && (state->playerDistance < state->chaseRadius))
    {
        state->flags |= HAGABON_FLAG_CHASE;
    }
    fn_8014E1DC(obj, state);
}
#pragma fp_contract reset

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
