/*
 * cfprisonguard (DLL 0x14E) - SharpClaw prison guard at CF. update
 * gates the guard on its placement event, walks him between his post
 * and the alarm, and frees the prisoners when the player is caught;
 * render ramps the alarm particle. Carved from the sandwormBoss
 * 10-DLL container.
 */

#include "main/dll/bit80_struct.h"
#include "main/dll/cfprisonguardstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/objseq.h"
#include "main/dll/VF/vf_shared.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"

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

extern int getLActions();
extern int ObjHits_DisableObject();
extern int ObjHits_EnableObject();
extern int ObjMsg_Pop();
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern int Obj_RemoveFromUpdateList(int* obj);

extern f32 lbl_803E4268;
extern int waterfx_consumePendingImpactNearPoint(f32* vec, f32 r);
extern int objGetAnimState80A(void* obj);
extern f32 lbl_803E4280;
extern f32 lbl_803E4260;
extern f32 lbl_803E4264;
extern f32 lbl_803E4284;
extern void objParticleFn_80099d84(int obj, f32 a, int b, f32 c, int d);


/* cfprisonguard_SeqFn: drive the guard state machine - ramp/reset the
 * alarm on cues, bail when captured or freed, watch player distance and
 * water impacts to chase or stand down, with idle digging SFX and a
 * queued-message drain. */
int cfprisonguard_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    char* player;
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
    gb50 = GameBit_Get(0x50); /* the old CloudRunner has flown off */
    gb48 = GameBit_Get(0x48); /* the caged guardian has broken out */
    if ((sub->flags & 2) != 0 && GameBit_Get(0x4d) != 0)
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
        fn_8003B228(obj, sub);
        dist = Vec_distance((char*)obj + 0x18, player + 0x18);
        if (gb48 == 0)
        {
            if (dist < (f32)((CfPrisonGuardMapData*)def)->watchRadius
                || waterfx_consumePendingImpactNearPoint(&((GameObject*)obj)->anim.localPosX, lbl_803E4268) != 0)
            {
                if (objGetAnimState80A(player) != 0x40)
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
        fn_8003B228(obj, sub);
        break;
    case 1:
        dist = Vec_distance((char*)obj + 0x18, player + 0x18);
        if (gb48 == 0)
        {
            if (dist < (f32)((CfPrisonGuardMapData*)def)->watchRadius)
            {
                if (objGetAnimState80A(player) != 0x40)
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
        Sfx_PlayFromObject((int)obj, SFXsk_doggydig11);
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
    while (ObjMsg_Pop(obj, &msgA, &msgB, &payload) != 0)
    {
    }
    if (animUpdate->triggerCommand == 1)
    {
        getLActions(obj, obj, 0x18, 0, 0, 0);
        animUpdate->triggerCommand = 0;
    }
    return 0;
}

int cfprisonguard_getExtraSize(void) { return 0x3c; }

int cfprisonguard_getObjectTypeId(void) { return 0x49; }

void cfprisonguard_free(void)
{
}

/* cfprisonguard_render: draw the guard when visible, ramp the alarm
 * timer each frame, and spawn a one-shot particle while it is below
 * the threshold. */
void cfprisonguard_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
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

void cfprisonguard_hitDetect(int* obj)
{
    CfPrisonGuardState* state = ((GameObject*)obj)->extra;
    if (ObjHits_GetPriorityHit(obj, NULL, NULL, NULL) == 19)
    {
        state->guardState = 7;
    }
}

void cfprisonguard_update(int* obj)
{
    CfPrisonGuardState* sub;
    int* player;
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
    if (GameBit_Get(((CfPrisonGuardMapData*)def)->disableEvent) != 0)
    {
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ObjHits_DisableObject(obj);
        Obj_RemoveFromUpdateList(obj);
        return;
    }
    /* 0x44: the free-the-prisoner event - once set, the guard no
       longer chases (it also arms the cage switch, see cfprisoncage) */
    bit44 = GameBit_Get(0x44);
    dist = Vec_distance((char*)obj + 0x18, (char*)player + 0x18);
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
        if (objGetAnimState80A(player) != 0x40)
        {
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
        }
    }
}

/* cfprisonguard_init: set up the guard's substate (SeqFn callback,
 * message queue), seed its header from the spawn params, and apply the
 * alarm-active gating bits. */
void cfprisonguard_init(int* obj, u8* params)
{
    CfPrisonGuardState* sub = ((GameObject*)obj)->extra;
    sub->flags = 1;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)params[0x18] << 8);
    ((GameObject*)obj)->animEventCallback = cfprisonguard_SeqFn;
    ObjMsg_AllocQueue(obj, 4);
    sub->capturedLatch = 1;
    if (GameBit_Get(0x4d) != 0)
    {
        sub->flags = (u8)(sub->flags | 4);
    }
    ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
    ((Bit80*)&sub->flags39)->top = 1;
}

void cfprisonguard_release(void)
{
}

void cfprisonguard_initialise(void)
{
}
