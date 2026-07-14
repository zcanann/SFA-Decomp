/*
 * DLL 0x107 - unreachable wind-lift/blow-vent object (no OBJECTS.bin def
 * references it: retail cut content). TU = 0x80185868..0x8018646C.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/camera_interface.h"
#include "main/vecmath.h"
#include "main/dll/windlift107state_struct.h"
#include "main/dll/portalspelldoorstate_struct.h"
#include "main/dll/scarabstate_struct.h"
#include "main/game_object.h"
#include "main/dll/player_state.h"
#include "main/obj_group.h"
#include "main/obj_message.h"
#include "main/obj_query.h"
#include "main/objprint_api.h"
#include "main/object_api.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/objhits.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/pad.h"
#include "main/audio/sfx.h"
#include "main/pad.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#define UNUSED_HIT_VOLUME_SLOT 0xe

/* object group this object joins */
#define UNUSED_OBJGROUP 0x10

#define PAD_BUTTON_A               0x100
#define UNUSED107_PARTFX           0x51c
#define UNUSED107_MSG_PLAYER_BURST 0x60004  /* knock the player back with a burst hit */
#define UNUSED107_MSG_PLAYER_GRAB  0x100010 /* tells player to grab/hold this object */

STATIC_ASSERT(sizeof(ScarabState) == 0x34);

STATIC_ASSERT(sizeof(WindLift107State) == 0x2c);

STATIC_ASSERT(sizeof(PortalSpellDoorState) == 0x10);

/* .sdata2 constant pool */
static const f32 lbl_803E3A58 = 0.0f;
static const f32 lbl_803E3A5C = 1.0f;
static const f32 lbl_803E3A60 = 2.2f;
static const f32 lbl_803E3A64 = 0.75f;
static const f32 lbl_803E3A68 = -2.2f;
static const f32 lbl_803E3A6C = -0.75f;
static const f32 lbl_803E3A70 = -10.0f;
static const f32 gWindLift107LaunchGravity = -0.12f;
static const f64 lbl_803E3A78 = 4503601774854144.0;
static const f32 gWindLift107RadiusScale = 10.0f;
static const f32 gWindLift107DefaultRadius = 50.0f;

#pragma dont_inline on
extern void* lbl_803DDAD0;
extern void* lbl_803DDAD4;

#pragma opt_common_subs off
void fn_80185868(GameObject* obj, f32 arg)
{

    struct
    {
        u8 pad[8];
        f32 val;
        u8 pad2[12];
    } stk;
    WindLift107State* sub;
    f32 fz;

    sub = (obj)->extra;
    stk.val = sub->radius;
    (*(VtableFn*)(*(int*)lbl_803DDAD0 + 4))(obj, 0xf, 0, 2, -1, 0);
    (*(VtableFn*)(*(int*)lbl_803DDAD4 + 4))(obj, 0, stk.pad, 2, -1, 0);
    Sfx_PlayFromObject((int)obj, SFXTRIG_wp_crthit6);
    fz = lbl_803E3A58;
    (obj)->anim.velocityX = fz;
    (obj)->anim.velocityZ = fz;
    sub->ventState = 0x32;
    sub->liftTimer = 800;
    sub->launchPhase = 0;
    sub->rideState = 0;
    (obj)->unkF8 = 0;
    (obj)->unkF4 = 2;
    ObjHits_EnableObject((int)obj);
    ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    sub->spitTimer = 0;
    if (arg < sub->radius)
    {
        ObjMsg_SendToObject(Obj_GetPlayerObject(), UNUSED107_MSG_PLAYER_BURST, obj, 0);
    }
    ObjHitbox_SetCapsuleBounds((ObjAnimComponent*)obj, sub->radius, -5, 10);
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, UNUSED_HIT_VOLUME_SLOT, 1, 0);
    ObjHits_EnableObject((int)obj);
}
#pragma opt_common_subs reset
#pragma dont_inline reset

int dll_107_getExtraSize_ret_44(void)
{
    return 0x2c;
}
int dll_107_getObjectTypeId(void)
{
    return 0x0;
}

void dll_107_free(int* obj)
{
    (*gModgfxInterface)->detachSource(obj);
    Resource_Release(lbl_803DDAD0);
    lbl_803DDAD0 = NULL;
    Resource_Release(lbl_803DDAD4);
    lbl_803DDAD4 = NULL;
}

void dll_107_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 renderState)
{
    WindLift107State* state;
    s16 spitTimer;

    state = (obj)->extra;
    if (state->ventState != 0 && state->ventState <= 50)
    {
        goto end;
    }
    switch (state->holdTimer)
    {
    case 0:
        break;
    default:
        goto end;
    }
    if ((obj)->unkF8 != 0)
    {
        if (renderState == -1)
        {
        }
        else
        {
            goto end;
        }
    }
    else
    {
        if (renderState == 0)
        {
            goto end;
        }
    }
    spitTimer = state->spitTimer;
    if (spitTimer != 0)
    {
        if (spitTimer < 60)
        {
            state->glowPulse = state->glowPulse + framesThisStep * 10;
            if (state->glowPulse > 0x80)
            {
                state->glowPulse = 0;
            }
            fn_8003B5E0(200, 30, 30, state->glowPulse);
        }
        else if (spitTimer < 240)
        {
            state->glowPulse = state->glowPulse + framesThisStep * 5;
            if (state->glowPulse > 0x80)
            {
                state->glowPulse = 0;
            }
            fn_8003B5E0(200, 30, 30, state->glowPulse);
        }
    }
    objRenderModelAndHitVolumesFwdLegacy(obj, p2, p3, p4, p5, lbl_803E3A5C);
end:;
}

void dll_107_hitDetect_nop(void)
{
}

#pragma opt_common_subs off
void dll_107_update(GameObject* obj)
{

    typedef struct
    {
        s16 ang;
        s16 b;
        s16 c;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } WindLiftRot;
    typedef struct
    {
        u8 pad[8];
        f32 val;
        u8 pad2[12];
    } WindLiftStk;

    WindLiftRot rot;
    WindLiftStk stkA;
    WindLiftStk stkB;
    WindLiftStk stkC;
    f32 spd;
    u8 yawBuf[4];
    GameObject* player;
    int p4c;
    WindLift107State* state;
    PlayerState* playerState;
    WindLift107State* windLiftState;
    f32 dist;
    ObjHitsPriorityState* hitState;
    u8 ph;
    char on;
    u8 held;

    p4c = *(int*)&(obj)->anim.placementData;
    spd = lbl_803E3A5C;
    (*gSkyInterface)->getClockTime(&spd);
    state = (obj)->extra;
    player = Obj_GetPlayerObject();
    playerState = player->extra;
    dist = Vec_distance((void*)&player->anim.worldPosX, &(obj)->anim.worldPosX);
    if (state->liftTimer <= 0)
    {
        state->ventState = 1;
        state->launchPhase = 0;
        *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        {
            f32 fz = lbl_803E3A58;
            (obj)->anim.velocityX = fz;
            (obj)->anim.velocityZ = fz;
        }
    }
    if (state->spitTimer != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_70);
        state->spitTimer -= framesThisStep;
        if ((int)randomGetRange(0, 2) == 2)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, UNUSED107_PARTFX, NULL, 1, -1, NULL);
        }
        if (state->spitTimer <= 0)
        {
            fn_80185868(obj, dist);
            return;
        }
    }
    if (state->holdTimer != 0)
    {
        state->holdTimer = state->holdTimer - (s16)(int)(timeDelta * spd);
        if (state->holdTimer <= 0)
        {
            state->holdTimer = 0;
            state->ventState = 0;
            ObjHits_EnableObject((int)obj);
            *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            (obj)->unkF4 = 0;
        }
        return;
    }
    if (state->ventState != 0)
    {
        Sfx_StopObjectChannel((int)obj, SFXen_firlp6);
        state->ventState -= framesThisStep;
        if (state->ventState <= 0)
        {
            if (state->holdReload != 0)
            {
                state->holdTimer = state->holdReload;
            }
            else
            {
                state->holdTimer = 1;
            }
        }
        if (state->ventState <= 50)
        {
            return;
        }
    }
    if (*(s8*)&state->launchPhase == 0)
    {
        if (*(s8*)&state->rideState == 0)
        {
            int cam = (*gCameraInterface)->getOverrideTarget();
            on = 0;
            if ((void*)cam != (void*)obj && (*(u8*)&(obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0 &&
                (obj)->unkF8 == 0)
            {
                buttonDisable(0, PAD_BUTTON_A);
                Obj_GetYawDeltaToObject(obj, player, (f32*)yawBuf);
                state->yawLow = -32768;
                state->yawHigh = 0;
                on = 1;
            }
            *(s8*)&state->rideState = on;
            if (*(s8*)&state->rideState != 0)
            {
                state->riding = 1;
                state->spitTimer = 600;
            }
            if ((obj)->unkF8 == 0)
            {
                ObjHits_EnableObject((int)obj);
                *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            }
            (obj)->anim.previousLocalPosX = (obj)->anim.localPosX;
            (obj)->anim.previousLocalPosY = (obj)->anim.localPosZ;
            (obj)->anim.previousLocalPosZ = (obj)->anim.localPosZ;
        }
        else
        {
            u8 st21;
            ObjHits_DisableObject((int)obj);
            ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->localPosX = (obj)->anim.localPosX;
            ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->localPosY = (obj)->anim.localPosY;
            ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->localPosZ = (obj)->anim.localPosZ;
            *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
            if ((getButtonsJustPressed(0) & PAD_BUTTON_A) != 0)
            {
                state->riding = 0;
            }
            if (*(s8*)&state->riding != 0)
            {
                state->ventState = 0;
                state->holdTimer = 0;
                ObjMsg_SendToObject(player, UNUSED107_MSG_PLAYER_GRAB, obj,
                                    (state->yawHigh << 0x10) | ((u16)state->yawLow));
            }
            if ((obj)->unkF8 == 1)
            {
                state->rideState = 2;
            }
            st21 = state->rideState;
            if ((s8)st21 == 2 && (obj)->unkF8 == 0 && player->anim.currentMove != 0x447)
            {
                state->rideState = 0;
                state->launchPhase = 1;
                {
                    f32 fz = lbl_803E3A58;
                    (obj)->anim.velocityX = fz;
                    (obj)->anim.velocityY = lbl_803E3A64 * playerState->baddie.inputMagnitude + lbl_803E3A60;
                    (obj)->anim.velocityZ = lbl_803E3A6C * playerState->baddie.inputMagnitude + lbl_803E3A68;
                    rot.x = fz;
                    rot.y = fz;
                    rot.z = fz;
                }
                rot.scale = lbl_803E3A5C;
                rot.c = 0;
                rot.b = 0;
                rot.ang = player->anim.rotX;
                vecRotateZXY(&rot.ang, &(obj)->anim.velocityX);
                Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_6a);
            }
            else if ((s8)st21 == 2 && (obj)->unkF8 == 0)
            {
                f32 fz;
                state->rideState = 0;
                state->launchPhase = 2;
                fz = lbl_803E3A58;
                (obj)->anim.velocityX = fz;
                (obj)->anim.velocityY = fz;
                (obj)->anim.velocityZ = fz;
                Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_6a);
            }
        }
    }
    ph = state->launchPhase;
    if ((s8)ph == 0 && *(s8*)&state->rideState == 0)
    {
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
        {
            windLiftState = obj->extra;
            stkA.val = windLiftState->radius;
            (*(VtableFn*)(*(int*)lbl_803DDAD4 + 4))(obj, 0, stkA.pad, 2, -1, 0);
            windLiftState->spitTimer = 1;
            return;
        }
    }
    else if ((s8)ph != 0)
    {
        state->liftTimer -= framesThisStep;
        if (*(s8*)&state->launchPhase == 1)
        {
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, UNUSED_HIT_VOLUME_SLOT, 3, 0);
            if ((obj)->anim.velocityY > lbl_803E3A70)
            {
                (obj)->anim.velocityY = gWindLift107LaunchGravity * timeDelta + (obj)->anim.velocityY;
            }
            ObjHits_EnableObject((int)obj);
        }
        hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
        held = hitState->contactFlags;
        if ((s8)held != 0 && *(s8*)&state->launchPhase == 1)
        {
            (obj)->anim.velocityY = lbl_803E3A58;
            state->launchPhase = 0;
            windLiftState = obj->extra;
            stkB.val = windLiftState->radius;
            (*(VtableFn*)(*(int*)lbl_803DDAD4 + 4))(obj, 0, stkB.pad, 2, -1, 0);
            windLiftState->spitTimer = 1;
            return;
        }
        if ((s8)held != 0 && *(s8*)&state->launchPhase == 2)
        {
            state->launchPhase = 0;
            windLiftState = obj->extra;
            stkC.val = windLiftState->radius;
            (*(VtableFn*)(*(int*)lbl_803DDAD4 + 4))(obj, 0, stkC.pad, 2, -1, 0);
            windLiftState->spitTimer = 1;
            (obj)->anim.velocityY = lbl_803E3A58;
            return;
        }
        (obj)->anim.localPosX = (obj)->anim.velocityX * timeDelta + (obj)->anim.localPosX;
        (obj)->anim.localPosY = (obj)->anim.velocityY * timeDelta + (obj)->anim.localPosY;
        (obj)->anim.localPosZ = (obj)->anim.velocityZ * timeDelta + (obj)->anim.localPosZ;
    }
    (obj)->anim.worldPosX = (obj)->anim.localPosX;
    (obj)->anim.worldPosY = (obj)->anim.localPosY;
    (obj)->anim.worldPosZ = (obj)->anim.localPosZ;
    state->timer -= framesThisStep;
    if (*(s8*)&state->rideState != 0)
    {
        if (getXZDistance(&(obj)->anim.worldPosX, (f32*)(p4c + 8)) >= (f32)(state->maxDist * state->maxDist))
        {
            f32 fz = lbl_803E3A58;
            (obj)->anim.velocityX = fz;
            (obj)->anim.velocityZ = fz;
            state->ventState = 500;
            state->launchPhase = 0;
            (obj)->unkF8 = 0;
            ObjHits_EnableObject((int)obj);
            *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
        }
    }
}
#pragma opt_common_subs reset

typedef struct WindLift107Placement
{
    u8 pad0[0x18 - 0x0];
    s8 rotXParam;    /* 0x18: <<8 -> anim.rotX seed */
    s8 radiusParam;  /* 0x19: * gWindLift107RadiusScale -> radius */
    u8 pad1a[0x1c - 0x1a];
    s16 reloadParam; /* 0x1c: hold/reload scale (* 0x34BC0) */
    s16 unk1e;       /* 0x1e */
    s16 maxDist;     /* 0x20 */
} WindLift107Placement;

void dll_107_init(int obj, int pArg)
{
    WindLift107Placement* p = (WindLift107Placement*)pArg;
    WindLift107State* sub;
    int p54;
    int p64;

    sub = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = 0;
    p54 = *(int*)(obj + 0x54);
    *(int*)&((ObjHitsPriorityState*)p54)->skeletonHitMask = 16;
    p54 = *(int*)&((GameObject*)obj)->anim.hitReactState;
    *(int*)&((ObjHitsPriorityState*)p54)->objectHitMask = 16;
    ObjHits_DisableObject(obj);
    ObjGroup_AddObject(obj, UNUSED_OBJGROUP);
    sub->ventState = 0;
    sub->launchPhase = 0;
    {
        s16 v = p->reloadParam;
        if (v == 0)
        {
            sub->holdReload = 0;
        }
        else
        {
            sub->holdReload = v * 0x34BC0;
        }
    }
    sub->holdTimer = 0;
    sub->unk25 = 0;
    lbl_803DDAD0 = Resource_Acquire(91, 1);
    lbl_803DDAD4 = Resource_Acquire(170, 1);
    sub->timer = 100;
    sub->unk18 = 400;
    ((GameObject*)obj)->anim.rotX = (s16)(p->rotXParam << 8);
    sub->unk14 = p->unk1e;
    sub->maxDist = p->maxDist;
    if (sub->maxDist == 0)
    {
        sub->maxDist = 30;
    }
    sub->liftTimer = 800;
    sub->spitTimer = 0;
    sub->glowPulse = 0xff;
    sub->unk27 = 0;
    if (p->radiusParam != '\0')
    {
        sub->radius = gWindLift107RadiusScale * (f32)(s32)p->radiusParam;
    }
    else
    {
        sub->radius = gWindLift107DefaultRadius;
    }
    ((GameObject*)obj)->unkF4 = 0;
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        p64 = *(int*)&((GameObject*)obj)->anim.modelState;
        *(u32*)(p64 + 0x30) |= 0x8000LL;
    }
}

void dll_107_release_nop(void)
{
}

void dll_107_initialise_nop(void)
{
}
