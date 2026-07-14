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
 * Hagabon_update handles the dormant-until-armed state (unkF4): while waiting it
 * polls its placement game bit / the map-event save-time gate, then fades in.
 * Once active it fades out on a priority hit, plays the swipe/lock/creak sfx,
 * adds map time and sets the placement game bit, and re-evaluates chase state.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll/objfx_api.h"
#include "main/frame_timing.h"
#include "main/vecmath_distance_api.h"
#include "main/audio/sfx.h"
#include "main/shader_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_00DF_hagabon.h"
#include "main/dll/rom_curve_interface.h"
#include "main/mapEvent.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/obj_group.h"
#include "main/mm.h"
#include "string.h"

int lbl_803DBC70[2] = {2, 3};
#define HAGABON_HIT_VOLUME_SLOT 10

/* object group this object belongs to */
#define HAGABON_OBJGROUP 3

typedef struct HagabonPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 mapEventId; /* 0x14: map-event id for save-time gating / addTime */
    u8 pad18[0x19 - 0x18];
    s8 chaseRadiusScale; /* 0x19 */
    s16 curveStepRaw;    /* 0x1A */
    s16 timeReward;      /* 0x1C: minutes added to the map timer on a hit */
    s16 startInactive;   /* 0x1E: when nonzero the baddie never auto-chases */
    s16 armGameBit;      /* 0x20: -1 = none; bit that arms/latches the spawn */
    u8 pad22[0x28 - 0x22];
} HagabonPlacement;

/* HagabonState.flags */
#define HAGABON_FLAG_PATH_NEEDS_LINK 0x01
#define HAGABON_FLAG_CHASE           0x02
#define HAGABON_FLAG_PATH_RETURN     0x04
#define HAGABON_FLAG_FADE_IN         0x08
#define HAGABON_FLAG_FADE_OUT        0x10

extern f32 lbl_803DDA58; /* last-seen curve point cache, shared with swarmbaddie */
__declspec(section ".sdata2") f32 lbl_803E2608 = 400.0f;
__declspec(section ".sdata2") f32 lbl_803E260C = 128.0f;
__declspec(section ".sdata2") f32 lbl_803E2610 = 256.0f;
__declspec(section ".sdata2") f32 lbl_803E2614 = 512.0f;
__declspec(section ".sdata2") f32 lbl_803E2618 = 1000.0f;
__declspec(section ".sdata2") f32 gHagabonPi = 3.1415927f;
__declspec(section ".sdata2") f32 lbl_803E2620 = 32768.0f;
union HagabonConstF32 { f32 f; };
__declspec(section ".sdata2") const union HagabonConstF32 lbl_803E2624 = { 0.001f };
__declspec(section ".sdata2") f32 lbl_803E2628 = 60.0f;
__declspec(section ".sdata2") f32 lbl_803E262C = 10.0f;
__declspec(section ".sdata2") f32 lbl_803E2630 = 0.9f;
__declspec(section ".sdata2") f32 lbl_803E2634 = 0.5f;
__declspec(section ".sdata2") f32 lbl_803E2638 = -0.5f;
__declspec(section ".sdata2") f32 lbl_803E263C = 12.0f;
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
extern int Curve_AdvanceAlongPath(int curve, f32 t);
STATIC_ASSERT(sizeof(HagabonState) == 0x28);
STATIC_ASSERT(offsetof(HagabonState, wavePhaseA) == 0x20);
STATIC_ASSERT(offsetof(HagabonState, flags) == 0x26);

void fn_8014E1DC(GameObject* obj, HagabonState* state)
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

    if (((Curve_AdvanceAlongPath(curve, state->curveStep) != 0) || (*(int*)(curve + 0x10) != *(int*)&lbl_803DDA58)) &&
        ((*gRomCurveInterface)->goNextPoint((void*)curve) != 0) &&
        ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, lbl_803E2608, lbl_803DBC70, -1) != 0))
    {
        *flags &= ~HAGABON_FLAG_PATH_NEEDS_LINK;
    }

    *(int*)&lbl_803DDA58 = *(int*)(curve + 0x10);

    *(u16*)&state->wavePhaseA += (u16)(lbl_803E260C * timeDelta);
    *(u16*)&state->wavePhaseB += (u16)(lbl_803E2610 * timeDelta);
    *(u16*)&state->wavePhaseC += (u16)(lbl_803E2614 * timeDelta);

    waveA = mathSinf((gHagabonPi * (f32)(u32)state->wavePhaseB) / lbl_803E2620);
    waveB = mathSinf((gHagabonPi * (f32)(u32)state->wavePhaseA) / lbl_803E2620);
    waveA = waveB + waveA;
    obj->anim.rotZ = lbl_803E2618 * waveA;

    waveA = mathSinf((gHagabonPi * (f32)(u32)state->wavePhaseC) / lbl_803E2620);
    waveB = mathSinf((gHagabonPi * (f32)(u32)state->wavePhaseA) / lbl_803E2620);
    waveA = waveB + waveA;
    obj->anim.rotY = lbl_803E2618 * waveA;

    if ((*flags & HAGABON_FLAG_CHASE) != 0)
    {
        obj->anim.velocityX +=
            lbl_803E2624.f * (state->player->anim.localPosX - obj->anim.localPosX);
        obj->anim.velocityY +=
            lbl_803E2624.f * ((lbl_803E2628 + state->player->anim.localPosY) - obj->anim.localPosY);
        obj->anim.velocityZ +=
            lbl_803E2624.f * (state->player->anim.localPosZ - obj->anim.localPosZ);
    }
    else if ((*flags & HAGABON_FLAG_PATH_RETURN) != 0)
    {
        obj->anim.velocityX +=
            lbl_803E2624.f * (*(f32*)(curve + 0x68) - obj->anim.localPosX);
        obj->anim.velocityY +=
            lbl_803E2624.f * (*(f32*)(curve + 0x6c) - obj->anim.localPosY);
        obj->anim.velocityZ +=
            lbl_803E2624.f * (*(f32*)(curve + 0x70) - obj->anim.localPosZ);
    }
    else
    {
        obj->anim.velocityX +=
            lbl_803E2624.f * (*(f32*)(curve + 0x68) - obj->anim.localPosX);
        waveA = mathSinf((gHagabonPi * (f32)(u32)state->wavePhaseB) / lbl_803E2620);
        waveB = mathSinf((gHagabonPi * (f32)(u32)state->wavePhaseA) / lbl_803E2620);
        waveA = waveB + waveA;
        waveA = ((lbl_803E262C * waveA) + *(f32*)(curve + 0x6c)) - obj->anim.localPosY;
        obj->anim.velocityY += lbl_803E2624.f * waveA;
        obj->anim.velocityZ +=
            lbl_803E2624.f * (*(f32*)(curve + 0x70) - obj->anim.localPosZ);
    }

    obj->anim.velocityX *= (damp = lbl_803E2630);
    obj->anim.velocityY *= damp;
    obj->anim.velocityZ *= damp;

    if (obj->anim.velocityX > lbl_803E2634)
    {
        obj->anim.velocityX = *(f32*)&lbl_803E2634;
    }
    if (obj->anim.velocityY > lbl_803E2634)
    {
        obj->anim.velocityY = *(f32*)&lbl_803E2634;
    }
    if (obj->anim.velocityZ > lbl_803E2634)
    {
        obj->anim.velocityZ = *(f32*)&lbl_803E2634;
    }

    if (obj->anim.velocityX < lbl_803E2638)
    {
        obj->anim.velocityX = *(f32*)&lbl_803E2638;
    }
    if (obj->anim.velocityY < lbl_803E2638)
    {
        obj->anim.velocityY = *(f32*)&lbl_803E2638;
    }
    if (obj->anim.velocityZ < lbl_803E2638)
    {
        obj->anim.velocityZ = *(f32*)&lbl_803E2638;
    }

    objMove((GameObject*)obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
            obj->anim.velocityZ * timeDelta);
    ObjAnim_AdvanceCurrentMove((int)obj, state->animSpeed, timeDelta,
                                                                (ObjAnimEventList*)animEvents);

    player = state->player;
    angle = (u16)getAngle(obj->anim.worldPosX - player->anim.worldPosX,
                          obj->anim.worldPosZ - player->anim.worldPosZ);
    angleDelta = angle - ((int)obj->anim.rotX & 0xffff);
    if (angleDelta > 0x8000)
    {
        angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000)
    {
        angleDelta += 0xffff;
    }

    obj->anim.rotX += (s32)(((f32)angleDelta * timeDelta) / lbl_803E263C);
}

int Hagabon_getExtraSize(void)
{
    return 0x28;
}
int Hagabon_getObjectTypeId(void)
{
    return 0xb;
}

#pragma opt_common_subs off
void Hagabon_free(GameObject* obj)
{
    void** state = obj->extra;
    ObjGroup_RemoveObject((int)obj, HAGABON_OBJGROUP);
    Sfx_StopFromObject((int)obj, SFXTRIG_en_twiggysnap11);
    if (*state != NULL)
    {
        mm_free(*state);
        *state = NULL;
    }
}
#pragma opt_common_subs reset

#pragma opt_common_subs off
void Hagabon_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    HagabonState* state = *(HagabonState**)&obj->extra;
    s32 v = visible;
    if (v != 0)
    {
        switch (obj->unkF4)
        {
        case 0:
            objRenderModelAndHitVolumes(obj, lbl_803E2650);
            if ((state->flags & HAGABON_FLAG_FADE_OUT) != 0)
            {
                objParticleFn_80099d84((GameObject*)obj, lbl_803E2650, 3,
                                       (f32)(u32)obj->anim.alpha / gHagabonAlphaMax, 0);
            }
            if ((state->flags & HAGABON_FLAG_FADE_IN) != 0)
            {
                objParticleFn_80099d84((GameObject*)obj, lbl_803E2650, 4,
                                       (f32)(u32)obj->anim.alpha / gHagabonAlphaMax, 0);
            }
            break;
        }
    }
}
#pragma opt_common_subs reset

void Hagabon_hitDetect(GameObject* obj)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
    if (hitState->lastHitObject != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_32b);
    }
}

#pragma fp_contract off
void Hagabon_update(int obj)
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
    u8 flags;

    state = *(HagabonState**)&((GameObject*)obj)->extra;
    oldCurve = state->curve;
    data = *(int*)&((GameObject*)obj)->anim.placementData;

    if (((GameObject*)obj)->unkF4 != 0)
    {
        if ((((HagabonPlacement*)data)->armGameBit != -1) && (mainGetBit(((HagabonPlacement*)data)->armGameBit) != 0))
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
        Sfx_PlayFromObject(obj, SFXTRIG_dn_seal4_c);
        return;
    }

    player = Obj_GetPlayerObject();
    dist = Vec_distance((f32*)(obj + 0x18), &player->anim.worldPosX);
    if (dist < lbl_803E2658)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_en_twiggysnap11);
    }
    else if (dist > lbl_803E265C)
    {
        Sfx_StopFromObject(obj, SFXTRIG_en_twiggysnap11);
    }

    if ((((GameObject*)obj)->anim.alpha != 0) &&
        (((flags = state->flags) & (HAGABON_FLAG_FADE_IN | HAGABON_FLAG_FADE_OUT)) != 0))
    {
        if ((flags & HAGABON_FLAG_FADE_OUT) != 0)
        {
            ((GameObject*)obj)->anim.alpha = (f32)(u32)((GameObject*)obj)->anim.alpha - timeDelta;
            if (((GameObject*)obj)->anim.alpha <= 6)
            {
                ((GameObject*)obj)->unkF4 = 1;
                ((GameObject*)obj)->anim.alpha = 0;
                state->flags &= ~HAGABON_FLAG_FADE_OUT;
                Sfx_StopFromObject(obj, SFXTRIG_en_twiggysnap11);
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
        if (ObjHits_GetPriorityHitWithPosition((GameObject*)(obj), &hitObject, &hitSphereIndex, &hitVolume,
                                               &lightPos[0], &lightPos[1], &lightPos[2]) != 0)
        {
            Sfx_StopObjectChannel(obj, 0x7f);
            state->flags |= HAGABON_FLAG_FADE_OUT;
            Sfx_PlayFromObject(obj, SFXTRIG_en_rfall5_c);
            Sfx_PlayFromObject(obj, SFXTRIG_wp_iceywindlp16_233);
            Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_238);
            Sfx_PlayFromObject(obj, SFXTRIG_wp_stftest122_1f2);
            lightPos[0] += playerMapOffsetX;
            lightPos[2] += playerMapOffsetZ;
            objLightFn_8009a1dc((void*)obj, lbl_803E2660, effectPos, 3, 0);
            (*gMapEventInterface)
                ->addTime(((HagabonPlacement*)data)->mapEventId,
                          (f32)(s32)(((HagabonPlacement*)data)->timeReward * 0x3c));
            if (((HagabonPlacement*)data)->armGameBit != -1)
            {
                mainSetBits(((HagabonPlacement*)data)->armGameBit, 1);
            }
        }
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, HAGABON_HIT_VOLUME_SLOT, 1, 0);
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
        (((HagabonPlacement*)data)->startInactive == 0) && (state->player != 0) &&
        (state->playerDistance < state->chaseRadius))
    {
        state->flags |= HAGABON_FLAG_CHASE;
    }
    fn_8014E1DC((GameObject*)obj, state);
}
#pragma fp_contract reset

void Hagabon_init(GameObject* obj, int data, int skip_alloc)
{
    HagabonState* state = obj->extra;
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
        if ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, state->chaseRadius, lbl_803DBC70, -1) ==
            0)
        {
            state->flags |= HAGABON_FLAG_PATH_NEEDS_LINK;
        }
    }
    if (placement->armGameBit != -1)
    {
        if (mainGetBit(placement->armGameBit) != 0)
        {
            obj->unkF4 = 1;
        }
    }
}

void Hagabon_release(void)
{
}

void Hagabon_initialise(void)
{
}

ObjectDescriptor gHagabonObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)Hagabon_initialise,
    (ObjectDescriptorCallback)Hagabon_release,
    0,
    (ObjectDescriptorCallback)Hagabon_init,
    (ObjectDescriptorCallback)Hagabon_update,
    (ObjectDescriptorCallback)Hagabon_hitDetect,
    (ObjectDescriptorCallback)Hagabon_render,
    (ObjectDescriptorCallback)Hagabon_free,
    (ObjectDescriptorCallback)Hagabon_getObjectTypeId,
    Hagabon_getExtraSize,
};

__declspec(section ".sdata2") f32 lbl_803E2650 = 1.0f;
__declspec(section ".sdata2") f32 gHagabonAlphaMax = 255.0f;
__declspec(section ".sdata2") f32 lbl_803E2658 = 300.0f;
__declspec(section ".sdata2") f32 lbl_803E265C = 350.0f;
__declspec(section ".sdata2") f32 lbl_803E2660 = 0.014f;
__declspec(section ".sdata2") f32 lbl_803E2664 = 250.0f;
__declspec(section ".sdata2") f32 lbl_803E2668 = 30.0f;
__declspec(section ".sdata2") f32 lbl_803E266C = 100.0f;
__declspec(section ".sdata2") f32 lbl_803E2670 = 0.005f;
__declspec(section ".sdata2") f32 lbl_803E2674 = 4.0f;
