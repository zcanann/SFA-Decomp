/*
 * DLL 0x107 - unreachable wind-lift/blow-vent object (no OBJECTS.bin def
 * references it: retail cut content). TU = 0x80185868..0x8018646C.
 */
#include "main/dll/CF/windlift.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/camera_interface.h"
#include "main/vecmath.h"
#include "main/dll/windlift107state_struct.h"
#include "main/dll/portalspelldoorstate_struct.h"
#include "main/dll/scarabstate_struct.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
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

static const f32 gWindLift107LaunchGravity = -0.12f;
static const f32 gWindLift107RadiusScale = 10.0f;
static const f32 gWindLift107DefaultRadius = 50.0f;

void* gWindLift107Resource170;
void* gWindLift107Resource91;

void windLift107_finishSpitBurst(GameObject* obj, f32 playerDistance)
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
    (*(VtableFn*)(*(int*)gWindLift107Resource91 + 4))(obj, 0xf, 0, 2, -1, 0);
    (*(VtableFn*)(*(int*)gWindLift107Resource170 + 4))(obj, 0, stk.pad, 2, -1, 0);
    Sfx_PlayFromObject((int)obj, SFXTRIG_wp_crthit6);
    fz = 0.0f;
    (obj)->anim.velocityX = fz;
    (obj)->anim.velocityZ = fz;
    sub->ventState = 0x32;
    sub->liftTimer = 800;
    sub->launchPhase = 0;
    sub->rideState = 0;
    (obj)->userData2 = 0;
    (obj)->userData1 = 2;
    ObjHits_EnableObject(obj);
    ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    sub->spitTimer = 0;
    if (playerDistance < sub->radius)
    {
        ObjMsg_SendToObject(Obj_GetPlayerObject(), UNUSED107_MSG_PLAYER_BURST, obj, 0);
    }
    ObjHitbox_SetCapsuleBounds((ObjAnimComponent*)obj, sub->radius, -5, 10);
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, UNUSED_HIT_VOLUME_SLOT, 1, 0);
    ObjHits_EnableObject(obj);
}

int windLift107_getExtraSize(void)
{
    return sizeof(WindLift107State);
}
int windLift107_getObjectTypeId(void)
{
    return 0x0;
}

void windLift107_free(GameObject* obj)
{
    (*gModgfxInterface)->detachSource(obj);
    Resource_Release(gWindLift107Resource91);
    gWindLift107Resource91 = NULL;
    Resource_Release(gWindLift107Resource170);
    gWindLift107Resource170 = NULL;
}

void windLift107_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 renderState)
{
    WindLift107State* state;
    s16 spitTimer;

    state = (obj)->extra;
    if (state->ventState != 0 && state->ventState <= 50)
    {
        return;
    }
    switch (state->holdTimer)
    {
    case 0:
        break;
    default:
        return;
    }
    if ((obj)->userData2 != 0)
    {
        if (renderState == -1)
        {
        }
        else
        {
            return;
        }
    }
    else
    {
        if (renderState == 0)
        {
            return;
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
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void windLift107_hitDetect(void)
{
}

void windLift107_update(GameObject* obj)
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
    spd = 1.0f;
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
            f32 fz = 0.0f;
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
            windLift107_finishSpitBurst(obj, dist);
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
            ObjHits_EnableObject(obj);
            *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            (obj)->userData1 = 0;
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
                (obj)->userData2 == 0)
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
            if ((obj)->userData2 == 0)
            {
                ObjHits_EnableObject(obj);
                *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            }
            (obj)->anim.previousLocalPosX = (obj)->anim.localPosX;
            (obj)->anim.previousLocalPosY = (obj)->anim.localPosZ;
            (obj)->anim.previousLocalPosZ = (obj)->anim.localPosZ;
        }
        else
        {
            u8 st21;
            ObjHits_DisableObject(obj);
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
            if ((obj)->userData2 == 1)
            {
                state->rideState = 2;
            }
            st21 = state->rideState;
            if ((s8)st21 == 2 && (obj)->userData2 == 0 && player->anim.currentMove != 0x447)
            {
                state->rideState = 0;
                state->launchPhase = 1;
                {
                    f32 fz = 0.0f;
                    (obj)->anim.velocityX = fz;
                    (obj)->anim.velocityY = 0.75f * playerState->baddie.inputMagnitude + 2.2f;
                    (obj)->anim.velocityZ = -0.75f * playerState->baddie.inputMagnitude + -2.2f;
                    rot.x = fz;
                    rot.y = fz;
                    rot.z = fz;
                }
                rot.scale = 1.0f;
                rot.c = 0;
                rot.b = 0;
                rot.ang = player->anim.rotX;
                vecRotateZXY(&rot.ang, &(obj)->anim.velocityX);
                Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_6a);
            }
            else if ((s8)st21 == 2 && (obj)->userData2 == 0)
            {
                f32 fz;
                state->rideState = 0;
                state->launchPhase = 2;
                fz = 0.0f;
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
            (*(VtableFn*)(*(int*)gWindLift107Resource170 + 4))(obj, 0, stkA.pad, 2, -1, 0);
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
            if ((obj)->anim.velocityY > -10.0f)
            {
                (obj)->anim.velocityY = gWindLift107LaunchGravity * timeDelta + (obj)->anim.velocityY;
            }
            ObjHits_EnableObject(obj);
        }
        hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
        held = hitState->contactFlags;
        if ((s8)held != 0 && *(s8*)&state->launchPhase == 1)
        {
            (obj)->anim.velocityY = 0.0f;
            state->launchPhase = 0;
            windLiftState = obj->extra;
            stkB.val = windLiftState->radius;
            (*(VtableFn*)(*(int*)gWindLift107Resource170 + 4))(obj, 0, stkB.pad, 2, -1, 0);
            windLiftState->spitTimer = 1;
            return;
        }
        if ((s8)held != 0 && *(s8*)&state->launchPhase == 2)
        {
            state->launchPhase = 0;
            windLiftState = obj->extra;
            stkC.val = windLiftState->radius;
            (*(VtableFn*)(*(int*)gWindLift107Resource170 + 4))(obj, 0, stkC.pad, 2, -1, 0);
            windLiftState->spitTimer = 1;
            (obj)->anim.velocityY = 0.0f;
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
            f32 fz = 0.0f;
            (obj)->anim.velocityX = fz;
            (obj)->anim.velocityZ = fz;
            state->ventState = 500;
            state->launchPhase = 0;
            (obj)->userData2 = 0;
            ObjHits_EnableObject(obj);
            *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
        }
    }
}

struct WindLift107Placement
{
    ObjPlacement base; /* 0x00 */
    s8 rotXParam;    /* 0x18: <<8 -> anim.rotX seed */
    s8 radiusParam;  /* 0x19: * gWindLift107RadiusScale -> radius */
    u8 pad1a[0x1c - 0x1a];
    s16 reloadParam; /* 0x1c: hold/reload scale (* 0x34BC0) */
    s16 unk1e;       /* 0x1e */
    s16 maxDist;     /* 0x20 */
};

STATIC_ASSERT(offsetof(WindLift107Placement, rotXParam) == 0x18);
STATIC_ASSERT(offsetof(WindLift107Placement, maxDist) == 0x20);
STATIC_ASSERT(sizeof(WindLift107Placement) == 0x24);

void windLift107_init(GameObject* obj, WindLift107Placement* placement)
{
    WindLift107State* state;

    state = obj->extra;
    obj->anim.rotX = 0;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->skeletonHitMask = 16;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->objectHitMask = 16;
    ObjHits_DisableObject(obj);
    ObjGroup_AddObject((int)obj, UNUSED_OBJGROUP);
    state->ventState = 0;
    state->launchPhase = 0;
    {
        s16 v = placement->reloadParam;
        if (v == 0)
        {
            state->holdReload = 0;
        }
        else
        {
            state->holdReload = v * 0x34BC0;
        }
    }
    state->holdTimer = 0;
    state->unk25 = 0;
    gWindLift107Resource91 = Resource_Acquire(91, 1);
    gWindLift107Resource170 = Resource_Acquire(170, 1);
    state->timer = 100;
    state->unk18 = 400;
    obj->anim.rotX = (s16)(placement->rotXParam << 8);
    state->unk14 = placement->unk1e;
    state->maxDist = placement->maxDist;
    if (state->maxDist == 0)
    {
        state->maxDist = 30;
    }
    state->liftTimer = 800;
    state->spitTimer = 0;
    state->glowPulse = 0xff;
    state->unk27 = 0;
    if (placement->radiusParam != '\0')
    {
        state->radius = gWindLift107RadiusScale * (f32)(s32)placement->radiusParam;
    }
    else
    {
        state->radius = gWindLift107DefaultRadius;
    }
    obj->userData1 = 0;
    if (obj->anim.modelState != NULL)
    {
        obj->anim.modelState->flags |= 0x8000LL;
    }
}

void windLift107_release(void)
{
}

void windLift107_initialise(void)
{
}
