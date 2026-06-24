/*
 * DLL 0x107 - unreachable wind-lift/blow-vent object (no OBJECTS.bin def
 * references it: retail cut content). TU = 0x80185868..0x8018646C.
 */
#include "main/camera_interface.h"
#include "main/dll/windlift107state_struct.h"
#include "main/dll/portalspelldoorstate_struct.h"
#include "main/dll/scarabstate_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objhits.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/pad.h"
#include "main/audio/sfx.h"
#include "main/sfa_shared_decls.h"

STATIC_ASSERT(sizeof(ScarabState) == 0x34);

STATIC_ASSERT(sizeof(WindLift107State) == 0x2c);

STATIC_ASSERT(sizeof(PortalSpellDoorState) == 0x10);

extern void ObjHitbox_SetCapsuleBounds(int objPtr, s16 radius, s16 verticalMin, s16 verticalMax);
extern void ObjGroup_AddObject(u32 obj, int group);
extern u32 ObjMsg_SendToObject();
extern u32 Obj_GetYawDeltaToObject();
extern f32 timeDelta;
extern u8 framesThisStep;
extern int Obj_GetPlayerObject(void);
extern int randomGetRange(int lo, int hi);
extern void vecRotateZXY(void* rotation, f32* outVec);
extern f32 Vec_distance(f32* a, f32* b);

#pragma dont_inline on
extern ModgfxInterface** gModgfxInterface;
extern void* lbl_803DDAD0;
extern void* lbl_803DDAD4;

#pragma opt_common_subs off
void fn_80185868(int obj, f32 arg)
{
    extern void* lbl_803DDAD0;
    extern void* lbl_803DDAD4;
    extern f32 lbl_803E3A58;

    struct
    {
        u8 pad[8];
        f32 val;
        u8 pad2[12];
    } stk;
    WindLift107State* sub;
    f32 fz;

    sub = ((GameObject*)obj)->extra;
    stk.val = sub->radius;
    (*(VtableFn*)(*(int*)lbl_803DDAD0 + 4))(obj, 0xf, 0, 2, -1, 0);
    (*(VtableFn*)(*(int*)lbl_803DDAD4 + 4))(obj, 0, stk.pad, 2, -1, 0);
    Sfx_PlayFromObject(obj, SFXmn_eggylaugh116);
    fz = lbl_803E3A58;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    sub->ventState = 0x32;
    sub->liftTimer = 800;
    sub->launchPhase = 0;
    sub->rideState = 0;
    ((GameObject*)obj)->unkF8 = 0;
    ((GameObject*)obj)->unkF4 = 2;
    ObjHits_EnableObject(obj);
    ObjHits_MarkObjectPositionDirty(obj);
    sub->spitTimer = 0;
    if (arg < sub->radius)
    {
        ObjMsg_SendToObject(Obj_GetPlayerObject(), 0x60004, obj, 0);
    }
    ObjHitbox_SetCapsuleBounds(obj, sub->radius, -5, 10);
    ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
    ObjHits_EnableObject(obj);
}
#pragma opt_common_subs reset
#pragma dont_inline reset

void fn_80185A24(int obj, int p2, int p3, int p4, int p5, s8 renderState)
{
    extern void fn_8003B5E0(int a, int b, int c, u8 d);
    extern void objRenderFn_8003b8f4(int p1, int p2, int p3, int p4, int p5, f32 scale);
    extern f32 lbl_803E3A5C;
    WindLift107State* state;
    s16 t;

    state = ((GameObject*)obj)->extra;
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
    if (((GameObject*)obj)->unkF8 != 0)
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
    t = state->spitTimer;
    if (t != 0)
    {
        if (t < 60)
        {
            state->glowPulse = state->glowPulse + framesThisStep * 10;
            if (state->glowPulse > 0x80)
            {
                state->glowPulse = 0;
            }
            fn_8003B5E0(200, 30, 30, state->glowPulse);
        }
        else if (t < 240)
        {
            state->glowPulse = state->glowPulse + framesThisStep * 5;
            if (state->glowPulse > 0x80)
            {
                state->glowPulse = 0;
            }
            fn_8003B5E0(200, 30, 30, state->glowPulse);
        }
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E3A5C);
end:;
}

#pragma opt_common_subs off
void fn_80185B74(int obj)
{
    extern void* lbl_803DDAD4;
    extern f32 lbl_803E3A58;
    extern f32 lbl_803E3A5C;
    extern f32 lbl_803E3A60;
    extern f32 lbl_803E3A64;
    extern f32 lbl_803E3A68;
    extern f32 lbl_803E3A6C;
    extern f32 lbl_803E3A70;
    extern f32 gWindLift107LaunchGravity;
    extern f64 lbl_803E3A78;



    extern f32 getXZDistance(f32* a, f32* b);
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
    int player;
    int p4c;
    WindLift107State* state;
    int sub;
    f32 dist;
    ObjHitsPriorityState* hitState;
    u8 ph;
    char on;
    u8 held;

    p4c = *(int*)&((GameObject*)obj)->anim.placementData;
    spd = lbl_803E3A5C;
    (*gSkyInterface)->getClockTime(&spd);
    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    sub = *(int*)&((GameObject*)player)->extra;
    dist = Vec_distance((void*)&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
    if (state->liftTimer <= 0)
    {
        state->ventState = 1;
        state->launchPhase = 0;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        {
            f32 fz = lbl_803E3A58;
            ((GameObject*)obj)->anim.velocityX = fz;
            ((GameObject*)obj)->anim.velocityZ = fz;
        }
    }
    if (state->spitTimer != 0)
    {
        Sfx_PlayFromObject(obj, SFXmn_dimspit6);
        state->spitTimer -= framesThisStep;
        if ((int)randomGetRange(0, 2) == 2)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x51c, NULL, 1, -1, NULL);
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
            ObjHits_EnableObject(obj);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            ((GameObject*)obj)->unkF4 = 0;
        }
        return;
    }
    if (state->ventState != 0)
    {
        Sfx_StopObjectChannel(obj, SFXen_firlp6);
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
            if ((void*)cam != (void*)obj &&
                (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0 && ((GameObject*)obj)->unkF8 == 0)
            {
                buttonDisable(0, 0x100);
                Obj_GetYawDeltaToObject(obj, player, yawBuf);
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
            if (((GameObject*)obj)->unkF8 == 0)
            {
                ObjHits_EnableObject(obj);
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            }
            ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosZ;
            ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
        }
        else
        {
            u8 st21;
            ObjHits_DisableObject(obj);
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->localPosX = ((GameObject*)obj)->anim.localPosX;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->localPosY = ((GameObject*)obj)->anim.localPosY;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->localPosZ = ((GameObject*)obj)->anim.localPosZ;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
            if ((getButtonsJustPressed(0) & 0x100) != 0)
            {
                state->riding = 0;
            }
            if (*(s8*)&state->riding != 0)
            {
                state->ventState = 0;
                state->holdTimer = 0;
                ObjMsg_SendToObject(player, 0x100010, obj,
                                    (state->yawHigh << 0x10) | ((u16)state->yawLow));
            }
            if (((GameObject*)obj)->unkF8 == 1)
            {
                state->rideState = 2;
            }
            st21 = state->rideState;
            if ((s8)st21 == 2 && ((GameObject*)obj)->unkF8 == 0 && ((GameObject*)player)->anim.currentMove != 0x447)
            {
                state->rideState = 0;
                state->launchPhase = 1;
                {
                    f32 fz = lbl_803E3A58;
                    ((GameObject*)obj)->anim.velocityX = fz;
                    ((GameObject*)obj)->anim.velocityY = lbl_803E3A64 * *(f32*)(sub + 0x298) + lbl_803E3A60;
                    ((GameObject*)obj)->anim.velocityZ = lbl_803E3A6C * *(f32*)(sub + 0x298) + lbl_803E3A68;
                    rot.x = fz;
                    rot.y = fz;
                    rot.z = fz;
                }
                rot.scale = lbl_803E3A5C;
                rot.c = 0;
                rot.b = 0;
                rot.ang = ((GameObject*)player)->anim.rotX;
                vecRotateZXY(&rot, &((GameObject*)obj)->anim.velocityX);
                Sfx_PlayFromObject(obj, SFXmn_dimbos46);
            }
            else if ((s8)st21 == 2 && ((GameObject*)obj)->unkF8 == 0)
            {
                f32 fz;
                state->rideState = 0;
                state->launchPhase = 2;
                fz = lbl_803E3A58;
                ((GameObject*)obj)->anim.velocityX = fz;
                ((GameObject*)obj)->anim.velocityY = fz;
                ((GameObject*)obj)->anim.velocityZ = fz;
                Sfx_PlayFromObject(obj, SFXmn_dimbos46);
            }
        }
    }
    ph = state->launchPhase;
    if ((s8)ph == 0 && *(s8*)&state->rideState == 0)
    {
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
        {
            sub = *(int*)&((GameObject*)obj)->extra;
            stkA.val = ((WindLift107State*)sub)->radius;
            (*(VtableFn*)(*(int*)lbl_803DDAD4 + 4))(obj, 0, stkA.pad, 2, -1, 0);
            ((WindLift107State*)sub)->spitTimer = 1;
            return;
        }
    }
    else if ((s8)ph != 0)
    {
        state->liftTimer -= framesThisStep;
        if (*(s8*)&state->launchPhase == 1)
        {
            ObjHits_SetHitVolumeSlot(obj, 0xe, 3, 0);
            if (((GameObject*)obj)->anim.velocityY > lbl_803E3A70)
            {
                ((GameObject*)obj)->anim.velocityY = gWindLift107LaunchGravity * timeDelta + ((GameObject*)obj)->anim.velocityY;
            }
            ObjHits_EnableObject(obj);
        }
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        held = hitState->contactFlags;
        if ((s8)held != 0 && *(s8*)&state->launchPhase == 1)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E3A58;
            state->launchPhase = 0;
            sub = *(int*)&((GameObject*)obj)->extra;
            stkB.val = ((WindLift107State*)sub)->radius;
            (*(VtableFn*)(*(int*)lbl_803DDAD4 + 4))(obj, 0, stkB.pad, 2, -1, 0);
            ((WindLift107State*)sub)->spitTimer = 1;
            return;
        }
        if ((s8)held != 0 && *(s8*)&state->launchPhase == 2)
        {
            state->launchPhase = 0;
            sub = *(int*)&((GameObject*)obj)->extra;
            stkC.val = ((WindLift107State*)sub)->radius;
            (*(VtableFn*)(*(int*)lbl_803DDAD4 + 4))(obj, 0, stkC.pad, 2, -1, 0);
            ((WindLift107State*)sub)->spitTimer = 1;
            ((GameObject*)obj)->anim.velocityY = lbl_803E3A58;
            return;
        }
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)->anim.
            localPosX;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.
            localPosY;
        ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)->anim.
            localPosZ;
    }
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
    state->timer -= framesThisStep;
    if (*(s8*)&state->rideState != 0)
    {
        if (getXZDistance((void*)&((GameObject*)obj)->anim.worldPosX, (void*)(p4c + 8)) >=
            (f32)(state->maxDist * state->maxDist))
        {
            f32 fz = lbl_803E3A58;
            ((GameObject*)obj)->anim.velocityX = fz;
            ((GameObject*)obj)->anim.velocityZ = fz;
            state->ventState = 500;
            state->launchPhase = 0;
            ((GameObject*)obj)->unkF8 = 0;
            ObjHits_EnableObject(obj);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            ObjHits_ClearHitVolumes(obj);
        }
    }
}
#pragma opt_common_subs reset

void fn_801862CC(int obj, int p)
{
    extern void* lbl_803DDAD0;
    extern void* lbl_803DDAD4;
    extern f32 lbl_803E3A78;
    extern f32 gWindLift107RadiusScale;
    extern f32 gWindLift107DefaultRadius;
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
    ObjGroup_AddObject(obj, 16);
    sub->ventState = 0;
    sub->launchPhase = 0;
    {
        s16 v = *(s16*)(p + 0x1c);
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
    ((GameObject*)obj)->anim.rotX = (s16)(*(char*)(p + 0x18) << 8);
    sub->unk14 = *(s16*)(p + 0x1e);
    sub->maxDist = *(s16*)(p + 0x20);
    if (sub->maxDist == 0)
    {
        sub->maxDist = 30;
    }
    sub->liftTimer = 800;
    sub->spitTimer = 0;
    sub->glowPulse = 0xff;
    sub->unk27 = 0;
    if (*(char*)(p + 0x19) != '\0')
    {
        sub->radius = gWindLift107RadiusScale * (f32)(s32) * (char*)(p + 0x19);
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

void dll_107_hitDetect_nop(void)
{
}

void dll_107_release_nop(void)
{
}

void dll_107_initialise_nop(void)
{
}

int dll_107_getExtraSize_ret_44(void) { return 0x2c; }
int dll_107_getObjectTypeId(void) { return 0x0; }

void fn_801859D4(int* obj)
{
    (*gModgfxInterface)->detachSource(obj);
    Resource_Release(lbl_803DDAD0);
    lbl_803DDAD0 = NULL;
    Resource_Release(lbl_803DDAD4);
    lbl_803DDAD4 = NULL;
}
