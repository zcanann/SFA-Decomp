/*
 * DLL 0x107 - unreachable wind-lift/blow-vent object (no OBJECTS.bin def
 * references it: retail cut content). Re-split (descriptor forensics,
 * docs/boundary_audit.md): TU = 0x80185868..0x8018646C, formerly the
 * middle of windlift.c (the real CFWindLift DLL is 0x149).
 */
#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"
#include "main/objhits_types.h"
#include "main/dll/CF/windlift.h"
#include "main/dll/CF/lanternfirefly_state.h"
#include "main/resource.h"
#include "global.h"

typedef struct PortalspelldoorPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
} PortalspelldoorPlacement;


typedef struct LanternFireFlyPlacement
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 stateId;
    s16 timer;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} LanternFireFlyPlacement;


/* scarab_getExtraSize == 0x34 (collectible money beetle). */
typedef struct ScarabState
{
    f32 velX; /* 0x00 */
    f32 velZ; /* 0x04 */
    f32 riseAmount; /* 0x08 */
    f32 baseY; /* 0x0c: def spawn height */
    s16 despawnTimer; /* 0x10 */
    u8 pad12[2];
    s16 mode; /* 0x14 */
    s16 yawSpeed; /* 0x16 */
    s16 spawnYaw; /* 0x18 */
    s16 fleeTimer; /* 0x1a */
    s16 riseLimit; /* 0x1c */
    s16 pickupSfx; /* 0x1e */
    s16 particleId; /* 0x20 */
    s16 unk22; /* 0x22 */
    u8 phase; /* 0x24 */
    u8 pad25[2];
    u8 moneyKind; /* 0x27 */
    u8 flags28; /* 0x28: 1 = collected, waiting on the money message */
    u8 pad29[3];
    s16 msgParamA; /* 0x2c */
    s16 msgParamB; /* 0x2e */
    f32 msgParamC; /* 0x30 */
} ScarabState;

STATIC_ASSERT (
sizeof
(ScarabState)
==
0x34
);

/* dll_107_getExtraSize == 0x2c (CF wind lift / blow vent). */
typedef struct WindLift107State
{
    int holdTimer; /* 0x00: countdown while the vent is plugged */
    int holdReload; /* 0x04 */
    f32 radius; /* 0x08 */
    s16 yawLow; /* 0x0c */
    s16 yawHigh; /* 0x0e */
    s16 ventState; /* 0x10 */
    s16 maxDist; /* 0x12 */
    s16 unk14; /* 0x14 */
    s16 unk16; /* 0x16 */
    s16 unk18; /* 0x18 */
    s16 liftTimer; /* 0x1a */
    u8 pad1C[2];
    s16 spitTimer; /* 0x1e */
    u8 pad20;
    u8 rideState; /* 0x21 */
    u8 riding; /* 0x22 */
    u8 launchPhase; /* 0x23 */
    u8 pad24;
    u8 unk25; /* 0x25 */
    u8 glowPulse; /* 0x26 */
    u8 unk27; /* 0x27 */
    u8 pad28[4];
} WindLift107State;

STATIC_ASSERT (
sizeof
(WindLift107State)
==
0x2c
);

/* portalspelldoor_getExtraSize == 0x10. */
typedef struct PortalSpellDoorState
{
    u8 pad00[4];
    f32 openAmount; /* 0x04 */
    int openTimer; /* 0x08 */
    u8 flags0C; /* 0x0c: bit 7 = open (via PortalFlags cast) */
    u8 pad0D[3];
} PortalSpellDoorState;

STATIC_ASSERT (
sizeof
(PortalSpellDoorState)
==
0x10
);


extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined8 ObjHits_MarkObjectPositionDirty();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 Obj_GetYawDeltaToObject();


extern f32 timeDelta;
extern u8 framesThisStep;
extern u32 lbl_803E39F0;
extern f32 lbl_803E39F4;
extern f32 lbl_803E39F8;
extern f32 lbl_803E39FC;
extern f32 lbl_803E3A00;
extern f32 lbl_803E3A08;
extern f32 lbl_803E3A0C;
extern f32 lbl_803E3A10;
extern f32 lbl_803E3A14;
extern f32 lbl_803E3A18;
extern f32 lbl_803E3A1C;
extern f32 lbl_803E3A20;
extern f32 lbl_803E3A24;
extern f32 lbl_803E3A28;
extern f32 lbl_803E3A2C;
extern f32 lbl_803E3A30;
extern f32 lbl_803E3A34;
extern f32 lbl_803E3A38;
extern f32 lbl_803E3A3C;
extern f32 lbl_803E3A40;
extern f32 lbl_803DBDD0;
extern f32 lbl_803E3AA0;
extern f32 lbl_803E3AA4;
extern f32 lbl_803E3AA8;
extern f32 lbl_803E3AB8;
extern f32 lbl_803E3ABC;
extern f32 lbl_803E3AC0;
extern f32 lbl_803E3AC4;
extern f32 lbl_803DBDC4;
extern f32 lbl_803DBDC8;
extern f32 lbl_803DBDCC;
extern u32 lbl_802C2298[3];
extern u32 lbl_802C22A4[3];

extern int Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int obj);
extern void Sfx_KeepAliveLoopedObjectSoundLimited(int obj, int sfx, int limit);
extern f32 sqrtf(f32 x);
extern s16 getAngle(f32 dx, f32 dz);
extern u32 randomGetRange(int min, int max);
extern void objHitDetectFn_80062e84(int obj, int a, int b);
extern void vecRotateZXY(void* rotation, f32* outVec);
extern int gameBitIncrement(int eventId);
extern f32 Vec_distance(void* a, void* b);
extern void playerAddMoney(int player, u8 b);
extern int objHitboxFn_801843c0(int obj);
extern int objBboxFn_800640cc(int p1, int p2, f32 r, int p4, void* p5, int obj, int p7, int p8, int p9, int p10);
extern int ViewFrustum_IsSphereVisible(f32* pos, f32 radius);
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, void* out, int p5, int p6);
extern int hitDetect_calcSweptSphereBounds(void* bounds, void* start, void* end, void* sphere, int n);
extern int hitDetectFn_800691c0(int obj, void* p2, int p3, int p4);
extern int hitDetectFn_80067958(int obj, void* p2, void* p3, int p4, void* p5, int p6);
extern int fn_801845FC(int obj, int p2, int p3, void* p4);

/*
 * --INFO--
 *
 * Function: FUN_80184a54
 * EN v1.0 Address: 0x80184A54
 * EN v1.0 Size: 3668b
 * EN v1.1 Address: 0x80184E88
 * EN v1.1 Size: 3476b
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
 * Function: fn_80185868
 * EN v1.0 Address: 0x80185A48
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x80185DC0
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_80185868(int obj, f32 arg)
{
    extern void* lbl_803DDAD0;
    extern void* lbl_803DDAD4;
    extern f32 lbl_803E3A58;
    extern void Sfx_PlayFromObject(int obj, int sfx);
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
    (*(code*)(*(int*)lbl_803DDAD0 + 4))(obj, 0xf, 0, 2, -1, 0);
    (*(code*)(*(int*)lbl_803DDAD4 + 4))(obj, 0, stk.pad, 2, -1, 0);
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
    ObjHitbox_SetCapsuleBounds(obj, (int)sub->radius, -5, 10);
    ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
    ObjHits_EnableObject(obj);
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: fn_80185A24
 * EN v1.0 Address: 0x80185C9C
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x80185F7C
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80185A24(int obj, int p2, int p3, int p4, int p5, s8 renderState)
{
    extern void fn_8003B5E0(int a, int b, int c, int d);
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

/*
 * --INFO--
 *
 * Function: fn_80185B74
 * EN v1.0 Address: 0x80185DC4
 * EN v1.0 Size: 2392b
 * EN v1.1 Address: 0x801860CC
 * EN v1.1 Size: 1880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma opt_common_subs off
void fn_80185B74(int obj)
{
    extern void* lbl_803DDAD4;
    extern void* gSHthorntailAnimationInterface;
    extern EffectInterface** gPartfxInterface;
    extern f32 lbl_803E3A58;
    extern f32 lbl_803E3A5C;
    extern f32 lbl_803E3A60;
    extern f32 lbl_803E3A64;
    extern f32 lbl_803E3A68;
    extern f32 lbl_803E3A6C;
    extern f32 lbl_803E3A70;
    extern f32 lbl_803E3A74;
    extern f64 lbl_803E3A78;
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern void Sfx_StopObjectChannel(int obj, int channel);
    extern int buttonDisable(int p1, int p2);
    extern u32 getButtonsJustPressed(int controller);
    extern f32 getXZDistance(void* a, void* b);
    extern void ObjHits_ClearHitVolumes(int obj);
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
    u8 ph;
    char on;
    u8 held;

    p4c = *(int*)&((GameObject*)obj)->anim.placementData;
    spd = lbl_803E3A5C;
    (*(code*)(*(int*)gSHthorntailAnimationInterface + 0x18))(&spd);
    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    sub = *(int*)&((GameObject*)player)->extra;
    dist = Vec_distance((void*)&((GameObject*)player)->anim.worldPosX, (void*)&((GameObject*)obj)->anim.worldPosX);
    if (state->liftTimer <= 0)
    {
        state->ventState = 1;
        state->launchPhase = 0;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
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
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
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
                (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0 && ((GameObject*)obj)->unkF8 == 0)
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
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
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
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
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
                rot.ang = *(s16*)player;
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
            (*(code*)(*(int*)lbl_803DDAD4 + 4))(obj, 0, stkA.pad, 2, -1, 0);
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
                ((GameObject*)obj)->anim.velocityY = lbl_803E3A74 * timeDelta + ((GameObject*)obj)->anim.velocityY;
            }
            ObjHits_EnableObject(obj);
        }
        held = ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->contactFlags;
        if ((s8)held != 0 && *(s8*)&state->launchPhase == 1)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E3A58;
            state->launchPhase = 0;
            sub = *(int*)&((GameObject*)obj)->extra;
            stkB.val = ((WindLift107State*)sub)->radius;
            (*(code*)(*(int*)lbl_803DDAD4 + 4))(obj, 0, stkB.pad, 2, -1, 0);
            ((WindLift107State*)sub)->spitTimer = 1;
            return;
        }
        if ((s8)held != 0 && *(s8*)&state->launchPhase == 2)
        {
            state->launchPhase = 0;
            sub = *(int*)&((GameObject*)obj)->extra;
            stkC.val = ((WindLift107State*)sub)->radius;
            (*(code*)(*(int*)lbl_803DDAD4 + 4))(obj, 0, stkC.pad, 2, -1, 0);
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
    state->unk16 -= framesThisStep;
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
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
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
    extern f32 lbl_803E3A80;
    extern f32 lbl_803E3A84;
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
    sub->unk16 = 100;
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
        sub->radius = lbl_803E3A80 * (f32)(s32) * (char*)(p + 0x19);
    }
    else
    {
        sub->radius = lbl_803E3A84;
    }
    ((GameObject*)obj)->unkF4 = 0;
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        p64 = *(int*)&((GameObject*)obj)->anim.modelState;
        *(u32*)(p64 + 0x30) |= 0x8000LL;
    }
}

/* Trivial 4b 0-arg blr leaves. */
void dll_107_hitDetect_nop(void)
{
}

void dll_107_release_nop(void)
{
}

void dll_107_initialise_nop(void)
{
}

/* 8b "li r3, N; blr" returners. */
int dll_107_getExtraSize_ret_44(void) { return 0x2c; }
int dll_107_getObjectTypeId(void) { return 0x0; }

extern ModgfxInterface** gModgfxInterface;
extern void* lbl_803DDAD0;
extern void* lbl_803DDAD4;

void fn_801859D4(int* obj)
{
    (*gModgfxInterface)->detachSource(obj);
    Resource_Release(lbl_803DDAD0);
    lbl_803DDAD0 = NULL;
    Resource_Release(lbl_803DDAD4);
    lbl_803DDAD4 = NULL;
}
