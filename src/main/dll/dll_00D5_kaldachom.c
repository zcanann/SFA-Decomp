/*
 * kaldachom (DLL 0x00D5, object type 0x49) - the "Kaldachom" / mouth-flytrap
 * ground baddie. Driven through gBaddieControlInterface (movement/combat
 * dispatch) and gPlayerInterface; combat (kaldachom_updateCombat) handles
 * the player's hit response, knockback, hit-point decrement and death
 * transition (substate 1 = stun, 2 = dead). Mouth-point projectiles are
 * spawned from anim events (kaldachom_handleAnimEvents) at the upper/lower
 * mouth path points, and a dust object is spawned while loading is locked.
 * The render path scrolls a texture by a sine-driven phase and refreshes the
 * mouth path points. State-machine handler tables A/B are populated at
 * initialise time and stepped by gPlayerInterface slot 8 each update.
 */
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/dll_00D5_kaldachom.h"
#include "main/dll/cf_doorlight.h"
#include "main/dll/texscroll2.h"
#include "main/mapEventTypes.h"
#include "main/obj_placement.h"
#include "main/objfx.h"
#include "main/objtexture.h"
#include "main/resource.h"
#include "main/objhits.h"
#include "main/audio/sfx.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/sfx_trigger_ids.h"

/* object group this object belongs to */
#define KALDACHOM_OBJGROUP 3

#define KALDACHOM_OBJFLAG_HITDETECT_DISABLED 0x2000

extern int randomGetRange(int lo, int hi);
extern int Obj_AllocObjectSetup();
extern int Obj_SetupObject();
extern u32 Obj_SetModelColorFadeRecursive();
extern u32 ObjHitbox_SetSphereRadius();
extern u8 Obj_IsLoadingLocked();
extern u32 Obj_GetPlayerObject();
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjPath_GetPointWorldPosition(int obj, int pointIndex, float* outX, float* outY, float* outZ, int useInputPosition);
extern u32 fn_8003B5E0();
extern void objRenderFn_8003b8f4(int* obj);
extern u32 objParticleFn_80099d84();
extern f32 sqrtf(f32);

extern void fn_802961FC(int a, u8 type);

/* this DLL's data/sdata2 pool: lbl_803E30xx are float constants, the
   lbl_803DDAxx are mutable scratch globals (fx spawn position / radius). */
extern u32 gKaldachomCombatParams[];
extern f32 gKaldachomDustSpawnScratch;
extern f32 gKaldachomMouthSpawnScratch;
extern void* gKaldaChomStateHandlersB[];
extern void* gKaldaChomStateHandlersA[];
extern u32* gPlayerInterface;
extern u32* gBaddieControlInterface;
extern void* gKaldachomEffectResource;
extern f32 timeDelta;
extern f32 lbl_803E3060;
extern f32 lbl_803E307C;
extern f32 lbl_803E3078;
extern f32 lbl_803E308C;
extern f32 lbl_803E30A0;
extern f32 lbl_803E30A4;
extern f32 lbl_803E30A8;
extern f32 lbl_803E30AC;
extern f32 lbl_803E30B0;
extern f32 gKaldachomPi;
extern f32 lbl_803E30B8;
extern f32 lbl_803E30BC;
extern f32 lbl_803E30C0;
extern f32 lbl_803E30C4;
extern f32 lbl_803E30C8;
extern f32 lbl_803E30CC;
extern u8 gKaldachomHitLightWork[0x18];

#pragma dont_inline on
void kaldaChomFn_8016821c(int obj, KaldaChomControl* control)
{
    u8 loadLocked;
    int placement;
    int work;

    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    gKaldachomDustSpawnScratch =
        lbl_803E30A0 + (float)(int)*(char*)(placement + 0x28) / lbl_803E30A4;
    control->hitFlashTimer = lbl_803E308C;
    Sfx_PlayFromObject(obj, SFXkr_land2);
    work = 0x28;
    do
    {
        (*gPartfxInterface)->spawnObject((void*)obj, 0x717, 0, 4, 0xffffffff, &gKaldachomDustSpawnScratch);
        work--;
    }
    while (work != 0);
    if ((control->spawnedDustObj == NULL) && (loadLocked = Obj_IsLoadingLocked(), loadLocked != '\0'))
    {
        work = Obj_AllocObjectSetup(0x24, 0x55e);
        ((ObjPlacement*)work)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)work)->posY = lbl_803E30A8 + ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)work)->posZ = ((GameObject*)obj)->anim.localPosZ;
        ((ObjPlacement*)work)->color[0] = ((ObjPlacement*)placement)->color[0];
        ((ObjPlacement*)work)->color[1] = ((ObjPlacement*)placement)->color[1];
        ((ObjPlacement*)work)->color[2] = ((ObjPlacement*)placement)->color[2];
        ((ObjPlacement*)work)->color[3] = ((ObjPlacement*)placement)->color[3];
        work = Obj_SetupObject(work, 5, 0xffffffff, 0xffffffff, 0);
        control->spawnedDustObj = (void*)work;
        ((GameObject*)control->spawnedDustObj)->anim.rootMotionScale = gKaldachomDustSpawnScratch;
    }
}

void kaldaChomFn_80168374(int obj, int state, u8 useUpperMouthPoint)
{
    KaldaChomControl* control;
    int ref;
    u8* setup;
    f32 r;
    f32 spd;
    f32 h;
    f32 mouthY;

    control = ((CampfireState*)state)->control;
    ref = *(int*)&((GameObject*)obj)->anim.placementData;
    if (Obj_IsLoadingLocked() != 0)
    {
        h = lbl_803E30A0 + (f32)(s32) * (s8*)(ref + 0x28) / lbl_803E30A4;
        ref = Obj_AllocObjectSetup(0x24, 0x51b);
        if (useUpperMouthPoint != 0)
        {
            ((ObjPlacement*)ref)->posX = control->upperMouthPosX;
            ((ObjPlacement*)ref)->posY = control->upperMouthPosY;
            ((ObjPlacement*)ref)->posZ = control->upperMouthPosZ;
        }
        else
        {
            ((ObjPlacement*)ref)->posX = control->lowerMouthPosX;
            ((ObjPlacement*)ref)->posY = control->lowerMouthPosY;
            ((ObjPlacement*)ref)->posZ = control->lowerMouthPosZ;
        }
        ((ObjPlacement*)ref)->color[0] = 1;
        ((ObjPlacement*)ref)->color[1] = 4;
        ((ObjPlacement*)ref)->color[2] = 0xff;
        ((ObjPlacement*)ref)->color[3] = 0xff;
        setup = (u8*)Obj_SetupObject(ref, 5, 0xffffffff, 0xffffffff, 0);
        if (setup != NULL)
        {
            spd = lbl_803E30AC * (((GroundBaddieState*)state)->baddie.targetDistance / (f32)(u32)(
                (GroundBaddieState*)state)->aggroRange);
            ((GameObject*)setup)->anim.velocityX =
                (((GameObject*)((GroundBaddieState*)state)->baddie.targetObj)->anim.localPosX - ((ObjPlacement*)ref)->posX) /
                spd;
            r = (f32)(s32)
            randomGetRange(-0xa, 0xa);
            mouthY = lbl_803E30A8 * h + ((GameObject*)((GroundBaddieState*)state)->baddie.targetObj)->anim.localPosY;
            ((GameObject*)setup)->anim.velocityY = (mouthY + r - ((ObjPlacement*)ref)->posY) / spd;
            ((GameObject*)setup)->anim.velocityZ =
                (((GameObject*)((GroundBaddieState*)state)->baddie.targetObj)->anim.localPosZ - ((ObjPlacement*)ref)->posZ) /
                spd;
        }
    }
}

#pragma dont_inline off
void kaldachom_handleAnimEvents(int obj, int p2, int p3)
{
    KaldaChomControl* control = ((CampfireState*)p2)->control;
    GroundBaddieState* eventState = (GroundBaddieState*)p3;
    int n;

    gKaldachomMouthSpawnScratch = lbl_803E30A0 + (f32)(s32)(s8) * (u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x28) /
        lbl_803E30A4;

    if (((s32)eventState->baddie.eventFlags & 0x1) != 0)
    {
        eventState->baddie.eventFlags &= ~0x1;
        Sfx_PlayFromObject(obj, SFXkr_climb1);
    }
    if (((s32)eventState->baddie.eventFlags & 0x80) != 0)
    {
        control->climbFxIndex = randomGetRange(0, 2);
        eventState->baddie.eventFlags &= ~0x80;
        Sfx_PlayFromObject(obj, SFXkr_climb2);
        for (n = (2 - control->climbFxIndex) * 10; n != 0; n--)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 1809, 0, 4, -1, &gKaldachomMouthSpawnScratch);
        }
    }
    if (((s32)eventState->baddie.eventFlags & 0x40) != 0)
    {
        eventState->baddie.eventFlags &= ~0x40;
        kaldaChomFn_80168374(obj, p2, 0);
    }
    if (((s32)eventState->baddie.eventFlags & 0x800) != 0)
    {
        eventState->baddie.eventFlags &= ~0x800;
        kaldaChomFn_80168374(obj, p2, 1);
    }
    if (((s32)eventState->baddie.eventFlags & 0x200) != 0)
    {
        eventState->baddie.eventFlags &= ~0x200;
        Sfx_PlayFromObject(obj, SFXkr_land1);
    }
    if (((s32)eventState->baddie.eventFlags & 0x400) != 0)
    {
        control->climbFxIndex = 3;
        n = 10;
        do
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 1808, 0, 4, -1, &gKaldachomMouthSpawnScratch);
            n--;
        }
        while (n != 0);
        eventState->baddie.eventFlags &= ~0x400;
    }
}

typedef struct KaldaCombatParams
{
    u32 unk00;
    u32 unk04;
    u32 unk08;
    u32 unk0C;
} KaldaCombatParams;

typedef struct KaldaCombatStack
{
    f32 dx;
    f32 dy;
    f32 dz;
    KaldaCombatParams p;
} KaldaCombatStack;

void kaldachom_updateCombat(int obj, int stateWithBaddieData, int state)
{
    KaldaChomControl* control;
    int playerObj;
    int result;
    u8 rnd;
    KaldaCombatStack st;
    u16 hitType;
    u16 hitAux1;
    u16 hitAux2;

    control = ((CampfireState*)stateWithBaddieData)->control;
    st.p = *(KaldaCombatParams*)gKaldachomCombatParams;
    playerObj = Obj_GetPlayerObject();
    if (((GroundBaddieState*)state)->baddie.targetObj != NULL)
    {
        int target = *(int*)&((GroundBaddieState*)state)->baddie.targetObj;
        st.dx = ((GameObject*)target)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        st.dy = ((GameObject*)target)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        st.dz = ((GameObject*)target)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        ((GroundBaddieState*)state)->baddie.targetDistance = sqrtf(st.dz * st.dz + (st.dx * st.dx + st.dy * st.dy));
    }
    (*(void (**)(int, int, int, int, int, int, int, int))(*(int*)gBaddieControlInterface + 0x54))(
        obj, state, stateWithBaddieData + 0x35c, ((GroundBaddieState*)stateWithBaddieData)->gameBitB, 0, 0, 0, 4);
    (*(void (**)(int, int, int, u16*, u16*, u16*))(*(int*)gBaddieControlInterface + 0x14))(
        obj, playerObj, 4, &hitType, &hitAux1, &hitAux2);
    if ((hitType == 1) || (hitType == 2))
    {
        result = (*(int (**)(int, int, int, int, int, int, int, void*))(*(int*)gBaddieControlInterface + 0x50))(
            obj, state, stateWithBaddieData + 0x35c, ((GroundBaddieState*)stateWithBaddieData)->gameBitB, 0, 0, 1,
            gKaldachomHitLightWork);
        if (result != 0)
        {
            if ((result != 0x10) && (result != 0x11))
            {
                objLightFn_8009a1dc((void*)obj, lbl_803E30BC, gKaldachomHitLightWork, 3, 0);
                (*(void (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, state, 4);
                ((GroundBaddieState*)state)->baddie.hitPoints -= 1;
                Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
                Sfx_PlayFromObject(obj, SFXen_blkscrp6);
            }
            if (*(s8*)&((GroundBaddieState*)state)->baddie.hitPoints < 1)
            {
                ((GroundBaddieState*)state)->baddie.substate = 2;
            }
        }
    }
    else
    {
        result = (*(int (**)(int, int, int, int, int, int, int, void*))(*(int*)gBaddieControlInterface + 0x50))(
            obj, state, stateWithBaddieData + 0x35c, ((GroundBaddieState*)stateWithBaddieData)->gameBitB, 0, 0, 1,
            gKaldachomHitLightWork);
        if (result != 0)
        {
            if (result != 0x11)
            {
                if ((result != 0x10) && (control->hitFlashTimer < lbl_803E30C0))
                {
                    kaldaChomFn_8016821c(obj, control);
                    *(f32*)(gKaldachomHitLightWork + 8) = lbl_803E3078;
                    *(u16*)(gKaldachomHitLightWork + 4) = 0;
                    *(u16*)(gKaldachomHitLightWork + 2) = 0;
                    *(u16*)(gKaldachomHitLightWork + 0) = 0;
                    (*(void (**)(int, int, void*, int, int, void*))(*(int*)gKaldachomEffectResource + 4))(
                        0, 1, gKaldachomHitLightWork, 0x401, -1, (KaldaCombatParams*)((u8*)&st + 0xc));
                    fn_802961FC(playerObj, 2);
                    (*(void (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, state, 5);
                    objLightFn_8009a1dc((void*)obj, lbl_803E30BC, gKaldachomHitLightWork, 4, 0);
                    Sfx_PlayFromObject(obj, SFXTRIG_swdout1);
                }
            }
            else
            {
                if (((GroundBaddieState*)state)->baddie.substate != 1)
                {
                    (*(void (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, state, 6);
                    ((GroundBaddieState*)state)->baddie.moveJustStartedB = 1;
                    ((GroundBaddieState*)state)->baddie.moveJustStartedA = 1;
                    ((GroundBaddieState*)state)->baddie.substate = 1;
                    objLightFn_8009a1dc((void*)obj, lbl_803E30BC, gKaldachomHitLightWork, 1, 0);
                    Sfx_PlayFromObject(obj, SFXen_blkscrp6);
                    Sfx_PlayFromObject(obj, SFXTRIG_baddie_rach_call3);
                }
            }
        }
        if (*(s8*)&((GroundBaddieState*)state)->baddie.hitPoints < 1)
        {
            ((GroundBaddieState*)state)->baddie.substate = 2;
        }
    }

    if (control->spawnedDustObj != NULL)
    {
        if (control->hitFlashTimer <= *(const f32*)&lbl_803E3060)
        {
            f32 zeroConst = *(const f32*)&lbl_803E3060;
            ((GameObject*)control->spawnedDustObj)->anim.alpha = 0;
            control->hitFlashTimer = zeroConst;
        }
        else
        {
            rnd = randomGetRange(0, (u8)(s32)control->hitFlashTimer);
            ((GameObject*)control->spawnedDustObj)->anim.alpha = rnd;
            ((GameObject*)control->spawnedDustObj)->anim.rotZ = ((GameObject*)obj)->anim.rotZ;
            ((GameObject*)control->spawnedDustObj)->anim.rotY = ((GameObject*)obj)->anim.rotY;
            ((GameObject*)control->spawnedDustObj)->anim.rotX = ((GameObject*)obj)->anim.rotX;
            control->hitFlashTimer = control->hitFlashTimer - lbl_803E30C4 * timeDelta;
        }
    }
}

void kaldachom_func0B(void)
{
}

s16 kaldachom_setScale(int* obj) { return ((CampfireState*)((GameObject*)obj)->extra)->controlMode; }
int kaldachom_getExtraSize(void) { return sizeof(CampfireState); }
int kaldachom_getObjectTypeId(void) { return 0x49; }

void kaldachom_free(int obj)
{
    u32 state;

    state = *(u32*)&((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, KALDACHOM_OBJGROUP);
    (*(VtableFn*)(*gBaddieControlInterface + 0x40))(obj, state, 0x20);
}

void kaldachom_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state;
    KaldaChomControl* control;

    state = *(int*)&((GameObject*)obj)->extra;
    if (visible != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
        if (((GroundBaddieState*)state)->glowAlpha != lbl_803E3060)
        {
            fn_8003B5E0(200, 0, 0, (int)((GroundBaddieState*)state)->glowAlpha);
        }
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)
            (obj, p2, p3, p4, p5, lbl_803E3078);
        if ((((GroundBaddieState*)state)->flags400 & 0x60) != 0)
        {
            objParticleFn_80099d84(obj, lbl_803E3078, 3, ((GroundBaddieState*)state)->glowAlpha, 0);
        }
        control = ((CampfireState*)state)->control;
        ObjPath_GetPointWorldPosition(obj, 2, &control->upperMouthPosX, &control->upperMouthPosY,
                                      &control->upperMouthPosZ, 0);
        ObjPath_GetPointWorldPosition(obj, 1, &control->lowerMouthPosX, &control->lowerMouthPosY,
                                      &control->lowerMouthPosZ, 0);
        break;
        }
    }
}

void kaldachom_hitDetect(void)
{
}

void kaldachom_update(int obj)
{
    int cond;
    u32 player;
    int texture;
    int ref;
    int state;
    f32 scrollPhase;

    state = *(int*)&((GameObject*)obj)->extra;
    ref = *(int*)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if ((((CampfireState*)state)->unk270 != 3) &&
            (cond = (*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)ref)->mapId), cond != 0))
        {
            (*(void (**)(int, int, int, int, int, int, int, double))(*(int*)gBaddieControlInterface + 0x58))(obj, ref, state, 8, 6, 0, 0x26, (double)lbl_803E30C8);
            ((GroundBaddieState*)state)->targetState = 0;
            Sfx_PlayFromObject(obj, SFXkr_pullup1);
            ObjAnim_SetCurrentMove(obj, 4, lbl_803E3060, 0x10);
            ((GroundBaddieState*)state)->baddie.moveDone = 0;
            ((GameObject*)obj)->anim.alpha = 0xff;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.
                resetHitboxMode | INTERACT_FLAG_DISABLED;
        }
    }
    else
    {
        ref = (*(int (**)(int, int, int))(*(int*)gBaddieControlInterface + 0x30))(obj, state, 0);
        if (ref == 0)
        {
            *(u16*)&((GroundBaddieState*)state)->targetState = 0;
        }
        else
        {
            kaldachom_updateCombat(obj, state, state);
            if (((CampfireState*)state)->targetState == 0)
            {
                texture = (int)((CampfireState*)state)->control;
                ((KaldaChomControl*)texture)->pullupSfxTimer = ((KaldaChomControl*)texture)->pullupSfxTimer - timeDelta;
                if (((KaldaChomControl*)texture)->pullupSfxTimer <= lbl_803E3060)
                {
                    Sfx_PlayFromObject(obj, SFXkr_pullup2);
                    ((KaldaChomControl*)texture)->pullupSfxTimer = (f32)(int)
                    randomGetRange(300, 600);
                }
                player = Obj_GetPlayerObject();
                *(u32*)&((GroundBaddieState*)state)->baddie.targetObj = player;
                if (((CampfireState*)state)->controlMode != 6)
                {
                    (*(void (**)(int, int, double, int))(*(int*)gPlayerInterface + 0x30))(obj, state, (double)timeDelta, 5);
                }
                ref = (int)(*(void* (**)(int, int, double, int))(*(int*)gBaddieControlInterface + 0x48))
                    (obj, state, (f64)(f32)(u32)((CampfireState*)state)->aggroRange, 0x8000);
                if ((void*)ref != NULL)
                {
                    (*(void (**)(int, int, int, int, int, int, int, int, int))(*(int*)gBaddieControlInterface + 0x28))
                        (obj, state, state + 0x35c, (int)((CampfireState*)state)->gameBitB, 0, 0, 0, 4, 0xffffffff);
                    *(u8*)&((GroundBaddieState*)state)->baddie.hasTarget = 0;
                    *(u16*)&((GroundBaddieState*)state)->targetState = 1;
                }
            }
            else
            {
                ref = (int)((CampfireState*)state)->control;
                texture = (int)objFindTexture((void*)obj, 0, 0);
                ((KaldaChomControl*)ref)->textureScrollAngle += 0x1000;
                scrollPhase = mathSinf((gKaldachomPi * (f32)(s32)((KaldaChomControl*)ref)->textureScrollAngle) / lbl_803E30B8
                )
                ;
                scrollPhase = lbl_803E3078 + scrollPhase;
                ((ObjTextureRuntimeSlot*)texture)->textureId = (int)(lbl_803E30B0 * scrollPhase);
                player = Obj_GetPlayerObject();
                *(u32*)&((GroundBaddieState*)state)->baddie.targetObj = player;
                kaldachom_handleAnimEvents(obj, state, state);
                (*(void (**)(int, int, double, int))(*(int*)gBaddieControlInterface + 0x2c))(obj, state, (double)lbl_803E3060, 0xffffffff);
                if (((CampfireState*)state)->controlMode != 6)
                {
                    (*(void (**)(int, int, double, int))(*(int*)gPlayerInterface + 0x30))(obj, state, (double)timeDelta, 5);
                }
                ((GroundBaddieState*)state)->savedObjC0 = *(int*)&((GameObject*)obj)->pendingParentObj;
                *(u32*)&((GameObject*)obj)->pendingParentObj = 0;
                (*(void (**)(double, int, int, double, void*, void*))(*(int*)gPlayerInterface + 8))
                ((double)timeDelta, obj, state, (double)timeDelta, &gKaldaChomStateHandlersA,
                 &gKaldaChomStateHandlersB);
                *(u32*)&((GameObject*)obj)->pendingParentObj = ((GroundBaddieState*)state)->savedObjC0;
            }
        }
    }
}

void kaldachom_init(int obj, int data, int skip_alloc)
{
    int state;
    KaldaChomControl* control;
    int player;
    u8 initMode;

    state = *(int*)&((GameObject*)obj)->extra;
    initMode = 6;
    if (skip_alloc != 0)
    {
        initMode |= 1;
    }
    (*(void (**)(int, int, int, int, int, int, u8, double))(*(int*)gBaddieControlInterface + 0x58))(obj, data, state, 8, 6, 0, initMode, (double)lbl_803E30C8);
    ((GameObject*)obj)->animEventCallback = NULL;
    control = ((CampfireState*)state)->control;
    ObjAnim_SetCurrentMove(obj, 4, lbl_803E3060, 0x10);
    ((GameObject*)obj)->anim.currentMoveProgress = lbl_803E307C;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED;
    (*(VtableFn*)(*gPlayerInterface + 0x14))(obj, state, 0);
    *(u16*)&((GroundBaddieState*)state)->baddie.substate = 0;
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E307C;
    ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E3060;
    player = Obj_GetPlayerObject();
    ((CampfireState*)state)->targetObj = player;
    ((GroundBaddieState*)state)->baddie.physicsActive = 0;
    ObjHits_DisableObject(obj);
    control->pullupSfxTimer = (f32)(int)
    randomGetRange(300, 600);
    control->idleAnimTimer = (f32)(int)
    randomGetRange(0, 499);
    control->unk3C = lbl_803E3060;
    control->spawnedDustObj = NULL;
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | KALDACHOM_OBJFLAG_HITDETECT_DISABLED;
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E30A0 + (f32)(s32) * (s8*)(data + 0x28) / lbl_803E30A4;
    ObjHitbox_SetSphereRadius(obj, (int)(lbl_803E30CC * ((GameObject*)obj)->anim.rootMotionScale));
    if (skip_alloc == 0)
    {
        gKaldachomEffectResource = Resource_Acquire(0x5a, 1);
    }
}

void kaldachom_release(void)
{
}

void kaldachom_initialise(void)
{
    gKaldaChomStateHandlersA[0] = kaldachom_stateHandlerA00;
    gKaldaChomStateHandlersA[1] = kaldachom_stateHandlerA01;
    gKaldaChomStateHandlersA[2] = kaldachom_stateHandlerA02;
    gKaldaChomStateHandlersA[3] = kaldachom_stateHandlerA03;
    gKaldaChomStateHandlersA[4] = kaldachom_stateHandlerA04;
    gKaldaChomStateHandlersA[5] = kaldachom_stateHandlerA05;
    gKaldaChomStateHandlersA[6] = kaldachom_stateHandlerA06;
    gKaldaChomStateHandlersA[7] = kaldachom_stateHandlerA07;
    gKaldaChomStateHandlersB[0] = kaldachom_stateHandlerB00;
    gKaldaChomStateHandlersB[1] = kaldachom_stateHandlerB01;
    gKaldaChomStateHandlersB[2] = kaldachom_stateHandlerB02;
    gKaldaChomStateHandlersB[3] = kaldachom_stateHandlerB03;
    gKaldaChomStateHandlersB[4] = kaldachom_stateHandlerB04;
    gKaldaChomStateHandlersB[5] = kaldachom_stateHandlerB05;
}

ObjectDescriptor12 gKaldaChomObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)kaldachom_initialise,
    (ObjectDescriptorCallback)kaldachom_release,
    0,
    (ObjectDescriptorCallback)kaldachom_init,
    (ObjectDescriptorCallback)kaldachom_update,
    (ObjectDescriptorCallback)kaldachom_hitDetect,
    (ObjectDescriptorCallback)kaldachom_render,
    (ObjectDescriptorCallback)kaldachom_free,
    (ObjectDescriptorCallback)kaldachom_getObjectTypeId,
    kaldachom_getExtraSize,
    (ObjectDescriptorCallback)kaldachom_setScale,
    (ObjectDescriptorCallback)kaldachom_func0B,
};
