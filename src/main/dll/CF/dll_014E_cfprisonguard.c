/*
 * cfprisonguard (DLL 0x14E) - SharpClaw prison guard at CF. update
 * gates the guard on its placement event, walks him between his post
 * and the alarm, and frees the prisoners when the player is caught;
 * render ramps the alarm particle. Carved from the sandwormBoss
 * 10-DLL container.
 */

#include "main/dll/bit80_struct.h"
#include "main/render.h"
#include "main/dll/CF/dll_014E_cfprisonguard.h"
#include "main/game_object.h"
#include "main/object_update_list.h"
#include "main/dll/player_api.h"
#include "main/obj_message.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/objseq.h"
#include "main/object_api.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/object_render_legacy.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/gamebit_ids.h"

typedef struct CfPrisonGuardMapData
{
    u8 pad0[0x8 - 0x0];
    f32 posX; /* 0x08 */
    f32 posY; /* 0x0C */
    f32 posZ; /* 0x10 */
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 watchRadius; /* 0x1A: distance the guard reacts within */
    s16 unk1C;
    s16 disableEvent; /* 0x1E: game bit retiring the guard */
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} CfPrisonGuardMapData;

typedef struct CfPrisonGuardFlags39
{
    u8 pulse : 1; /* 0x80: cleared every update */
    u8 rest : 7;
} CfPrisonGuardFlags39;

STATIC_ASSERT(sizeof(CfPrisonGuardState) == 0x3c);

extern f32 lbl_803E4268;
extern f32 lbl_803E4280;
extern f32 lbl_803E4260;
extern f32 lbl_803E4264;
extern f32 lbl_803E4284;
extern int waterfx_consumePendingImpactNearPoint(f32* vec, f32 r);
extern void objParticleFn_80099d84(int obj, f32 a, int b, f32 c, int d);

/* CFPrisonGuard_SeqFn: drive the guard state machine - ramp/reset the
 * alarm on cues, bail when captured or freed, watch player distance and
 * water impacts to chase or stand down, with idle digging SFX and a
 * queued-message drain. */
int CFPrisonGuard_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    GameObject* player;
    CfPrisonGuardState* sub = ((GameObject*)obj)->extra;
    s8 gb50;
    s8 gb48;
    s8 moved;
    f32 dist;
    int msgB;
    int msgA;
    int payload = 0;
    u8* def = *(u8**)&((GameObject*)obj)->anim.placementData;
    switch (animUpdate->triggerCommand)
    {
    case 0x29:
        sub->alarmRamp = lbl_803E4260;
        break;
    case 4:
        sub->guardState = 6;
        return 0;
    case 5:
        sub->alarmRamp = lbl_803E4264 * framesThisStep + sub->alarmRamp;
        break;
    }
    if (((GameObject*)obj)->seqIndex < 0)
    {
        return 0;
    }
    ObjHits_EnableObject(obj);
    gb50 = mainGetBit(GAMEBIT_CF_UncleFlewOff); /* the old CloudRunner has flown off */
    gb48 = mainGetBit(0x48);                    /* the caged guardian has broken out */
    if ((sub->flags & 2) != 0 && mainGetBit(GAMEBIT_CFPerchRelated004D) != 0)
    {
        sub->flags &= ~0x2;
        return 4;
    }
    if (gb50 != 0)
    {
        return 4;
    }
    if (gb50 != 0 || sub->guardState == 5)
    {
        sub->guardState = 5;
        return 0;
    }
    moved = 0;
    player = Obj_GetPlayerObject();
    switch (sub->guardState)
    {
    case 0:
        fn_8003B228((GameObject*)(obj), sub);
    dist = Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX);
        if (gb48 == 0)
        {
            if (dist < (f32)((CfPrisonGuardMapData*)def)->watchRadius ||
                waterfx_consumePendingImpactNearPoint(&((GameObject*)obj)->anim.localPosX, lbl_803E4268) != 0)
            {
                if (objGetAnimState80A((GameObject*)(player)) != 0x40)
                {
                    moved = 1;
                    sub->guardState = 4;
                }
                else
                {
                    ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                    sub->guardState = 5;
                    sub->stateTimer = 0x14;
                    (*gObjectTriggerInterface)->runSequence(2, obj, -1);
                    return 4;
                }
            }
        }
        break;
    case 2:
        if ((sub->stateTimer -= framesThisStep) <= 0)
        {
            sub->guardState = 1;
        }
        fn_8003B228((GameObject*)(obj), sub);
        break;
    case 1:
        dist = Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX);
        if (gb48 == 0)
        {
            if (dist < (f32)((CfPrisonGuardMapData*)def)->watchRadius)
            {
                if (objGetAnimState80A((GameObject*)(player)) != 0x40)
                {
                    moved = 1;
                    sub->guardState = 4;
                }
                else
                {
                    sub->guardState = 2;
                }
            }
        }
        break;
    case 3:
        if ((sub->stateTimer -= framesThisStep) <= 0)
        {
            sub->guardState = 0;
        }
        break;
    case 5:
        return 0;
    case 6:
        return 0;
    case 7:
        moved = 1;
        sub->guardState = 4;
        break;
    }
    if (((GameObject*)obj)->anim.currentMove == 0x103 || ((GameObject*)obj)->anim.currentMove == 0x2e)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_foot_water_roll);
    }
    else
    {
        Sfx_StopObjectChannel((int)obj, 0x10);
    }
    if (gb50 != 0 && sub->capturedLatch == 0)
    {
        moved = 1;
    }
    if (moved != 0)
    {
        return 4;
    }
    sub->capturedLatch = gb50;
    animUpdate->sequenceEventActive = 0;
    while (ObjMsg_Pop(obj, (u32*)&msgA, (u32*)&msgB, (u32*)&payload) != 0)
    {
    }
    if (animUpdate->triggerCommand == 1)
    {
        getLActionsInt6(obj, obj, 0x18, 0, 0, 0);
        animUpdate->triggerCommand = 0;
    }
    return 0;
}

int CFPrisonGuard_getExtraSize(void)
{
    return 0x3c;
}

int CFPrisonGuard_getObjectTypeId(void)
{
    return 0x49;
}

void CFPrisonGuard_free(void)
{
}

/* CFPrisonGuard_render: draw the guard when visible, ramp the alarm
 * timer each frame, and spawn a one-shot particle while it is below
 * the threshold. */
void CFPrisonGuard_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    CfPrisonGuardState* sub = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        ((void (*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E4280);
    }
    if (visible != 0)
    {
        f32 t = sub->alarmRamp;
        if (t > lbl_803E4260)
        {
            sub->alarmRamp = lbl_803E4264 * (f32)(u32)framesThisStep + t;
            if (sub->alarmRamp < lbl_803E4284)
            {
                objParticleFn_80099d84((int)obj, lbl_803E4280, 3, sub->alarmRamp, 0);
            }
        }
    }
}

void CFPrisonGuard_hitDetect(int* obj)
{
    CfPrisonGuardState* state = ((GameObject*)obj)->extra;
    if (ObjHits_GetPriorityHit((GameObject*)(obj), NULL, NULL, NULL) == 19)
    {
        state->guardState = 7;
    }
}

void CFPrisonGuard_update(int* obj)
{
    CfPrisonGuardState* sub;
    GameObject* player;
    u8* def;
    int bit44;
    f32 dist;

    sub = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((u32)sub->flags39 >> 7) & 1u)
    {
        ((CfPrisonGuardFlags39*)&sub->flags39)->pulse = 0;
    }
    if (mainGetBit(((CfPrisonGuardMapData*)def)->disableEvent) != 0)
    {
        ((GameObject*)obj)->anim.resetHitboxFlags =
            (u8)(((GameObject*)obj)->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ObjHits_DisableObject(obj);
        Obj_RemoveFromUpdateList((u8*)obj);
        return;
    }
    /* 0x44: the free-the-prisoner event - once set, the guard no
       longer chases (it also arms the cage switch, see cfprisoncage) */
    bit44 = mainGetBit(GAMEBIT_ITEM_PrisonKey_Got);
    dist = Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX);
    if (sub->flags == 1)
    {
        waterfx_consumePendingImpactNearPoint(&((GameObject*)obj)->anim.localPosX, lbl_803E4268);
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        sub->flags = 2;
    }
    if (bit44 == 0)
    {
        if (sub->guardState != 4)
        {
            if (dist < (f32)(s32)((CfPrisonGuardMapData*)def)->watchRadius)
            {
            }
            else if (waterfx_consumePendingImpactNearPoint(&((GameObject*)obj)->anim.localPosX, lbl_803E4268) == 0)
            {
                return;
            }
        }
        if (objGetAnimState80A((GameObject*)(player)) != 0x40)
        {
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
        }
    }
}

/* CFPrisonGuard_init: set up the guard's substate (SeqFn callback,
 * message queue), seed its header from the spawn params, and apply the
 * alarm-active gating bits. */
void CFPrisonGuard_init(int* obj, u8* params)
{
    CfPrisonGuardState* sub = ((GameObject*)obj)->extra;
    sub->flags = 1;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)params[0x18] << 8);
    ((GameObject*)obj)->animEventCallback = CFPrisonGuard_SeqFn;
    ObjMsg_AllocQueue(obj, 4);
    sub->capturedLatch = 1;
    if (mainGetBit(GAMEBIT_CFPerchRelated004D) != 0)
    {
        sub->flags = (u8)(sub->flags | 4);
    }
    ((GameObject*)obj)->anim.resetHitboxFlags =
        (u8)(((GameObject*)obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
    ((Bit80*)&sub->flags39)->top = 1;
}

void CFPrisonGuard_release(void)
{
}

void CFPrisonGuard_initialise(void)
{
}
