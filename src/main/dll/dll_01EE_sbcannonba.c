/* === moved from main/dll/DB/DBstealerworm.c [801E341C-801E34C0) (TU re-split, docs/boundary_audit.md) === */
#include "main/game_object.h"
#include "main/dll_000A_expgfx.h"
#include "main/objseq.h"

/* SB_Propeller_getExtraSize == 0x10. */
typedef struct SBPropellerState
{
    f32 smokeTimer; /* 0x00: countdown to the next smoke burst */
    f32 spinBlend; /* 0x04 */
    int spinRate; /* 0x08: init 1200 */
    s8 health; /* 0x0c: init 4 */
    u8 pad0D[3];
} SBPropellerState;

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

/* SB_ShipHead_getExtraSize == 0x10. */
typedef struct SBShipHeadState
{
    int target; /* 0x00: the 0x8c galleon-side object */
    s8 health; /* 0x04: init 4 */
    u8 pad05[3];
    f32 swayA; /* 0x08 */
    f32 swayB; /* 0x0c */
} SBShipHeadState;

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

extern u32 randomGetRange(int min, int max);
extern int ObjHits_GetPriorityHit();

extern EffectInterface** gPartfxInterface;

/*
 * --INFO--
 *
 * Function: SB_Galleon_animEventCallback
 * EN v1.0 Address: 0x801E1AAC
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x801E18DC
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int ObjList_GetObjects(int* start, int* end);
extern f32 timeDelta;


/*
 * --INFO--
 *
 * Function: fn_801E1588
 * EN v1.0 Address: 0x801E1588
 * EN v1.0 Size: 1316b
 * EN v1.1 Address: 0x801E1B78
 * EN v1.1 Size: 1316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */




/*
 * --INFO--
 *
 * Function: SB_Propeller_update
 * EN v1.0 Address: 0x801E21B4
 * EN v1.0 Size: 1364b
 * EN v1.1 Address: 0x801E2BBC
 * EN v1.1 Size: 1212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Obj_SetModelColorFadeRecursive(int obj, int a, int b, int c, int d, int e);
extern u8 framesThisStep;


/*
 * --INFO--
 *
 * Function: SB_Propeller_init
 * EN v1.0 Address: 0x801E2708
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801E3078
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: SB_ShipHead_render
 * EN v1.0 Address: 0x801E27C4
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x801E314C
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: SB_ShipHead_update
 * EN v1.0 Address: 0x801E2940
 * EN v1.0 Size: 1892b
 * EN v1.1 Address: 0x801E32D4
 * EN v1.1 Size: 1384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Sfx_StopObjectChannel(int obj, int ch);
extern u8 Obj_IsLoadingLocked(void);
extern void Obj_GetWorldPosition(int obj, f32* x, f32* y, f32* z);
extern f32 sqrtf(f32);



/* Trivial 4b 0-arg blr leaves. */









/* 8b "li r3, N; blr" returners. */
int SB_ShipGun_getExtraSize(void);

/* sda21 accessors. */
extern u32 gSbGalleon;

/* Pattern wrappers. */

/* 16b chained patterns. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);



/* ObjGroup_RemoveObject(x, N) wrappers. */

/* SB_Propeller_hitDetect: guard on 0x46 == 0x69c, copy halfword from sda21 ptr. */

/* SB_ShipGun_free: expgfx interface freeObject callback. */
void SB_ShipGun_free(int param_1);

/* SB_Galleon_setScale: state machine; advance counter, optionally play sfx. */

/* SB_Galleon_hitDetect: per-step expgfx spawn loop. */
extern f32 lbl_803E57FC;




/*
 * --INFO--
 *
 * Function: SB_Galleon_update
 * EN v1.0 Address: 0x801E21AC
 * EN v1.0 Size: 568b
 */


/*
 * --INFO--
 *
 * Function: SB_Galleon_init
 * EN v1.0 Address: 0x801E23E4
 * EN v1.0 Size: 388b
 */



/* SB_Galleon_free: textureFree manager textures, ObjGroup_RemoveObject, kill music, set bit. */


/* SB_ShipHead_init: add to group, alloc msg queue, set state + bias positions. */


/* SB_ShipGun_render: conditional render with multiple flag checks. */
extern f32 lbl_803E5888;

void SB_ShipGun_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

/* SB_Galleon_modelMtxFn: returns -2 / -1 / state byte depending on flags. */

/* SB_Galleon_func0E: state byte == 1 -> compute from 0x7c; else return 0x640. */

#include "ghidra_import.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/TREX/TREX_levelcontrol.h"
#include "main/objhits_types.h"

typedef struct SBShipGunPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    u8 pad24[0x28 - 0x24];
} SBShipGunPlacement;


typedef struct SBShipGunState
{
    u8 pad0[0x3 - 0x0];
    s8 unk3;
    u8 pad4[0xC - 0x4];
    u8 unkC;
    u8 unkD;
    u8 unkE;
    u8 padF[0x10 - 0xF];
} SBShipGunState;


typedef struct SBCannonBallState
{
    u8 pad0[0x4 - 0x0];
    f32 velocityY;
    f32 velocityZ;
    f32 posX;
    f32 posY;
    f32 posZ;
    s16 unk18;
    s8 flags;
    u8 pad1B[0x1C - 0x1B];
    f32 impactCooldown;
    void* modelLight;
    u8 pad24[0x28 - 0x24];
} SBCannonBallState;


extern void ModelLightStruct_free(void* effect);


/*
 * --INFO--
 *
 * Function: SB_ShipGun_update
 * EN v1.0 Address: 0x801E34C0
 * EN v1.0 Size: 2312b
 * EN v1.1 Address: 0x801E3AB0
 * EN v1.1 Size: 2132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int ObjList_GetObjects(int* outIndex, int* outCount);
extern void Obj_SetModelColorFadeRecursive(int obj, int p2, int p3, int p4, int p5, int p6);
extern void Sfx_StopObjectChannel();
extern s16 getAngle(f32 dx, f32 dz);
extern void Obj_GetWorldPosition(int obj, float* x, float* y, float* z);
extern void vecRotateZXY(void* a, void* b);
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 mag);
extern f32 lbl_803E588C;
extern f32 lbl_803E5890;
extern f32 lbl_803E5894;
extern f32 lbl_803E5898;
extern f32 lbl_803E589C;
extern f32 lbl_803E58A0;
extern f32 lbl_803E58A4;
extern f32 lbl_803E58A8;
extern f32 lbl_803E58AC;

void SB_ShipGun_update(int obj);


/* Trivial 4b 0-arg blr leaves. */
void SB_CannonBall_release(void)
{
}

void SB_CannonBall_initialise(void)
{
}

void SB_ShipGun_init(int obj);

/* 8b "li r3, N; blr" returners. */
int SB_CannonBall_getExtraSize(void) { return SB_CANNONBALL_EXTRA_SIZE; }
int SB_CannonBall_getObjectTypeId(void) { return 0x0; }

void SB_CannonBall_free(int obj)
{
    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (((SBCannonBallState*)state)->modelLight != 0)
    {
        ModelLightStruct_free(((SBCannonBallState*)state)->modelLight);
        *(undefined4*)&((SBCannonBallState*)state)->modelLight = 0;
    }
}

int SB_FireBall_getExtraSize(void);


/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E58B0;

void SB_CannonBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E58B0);
}

void SB_FireBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

extern f32 lbl_803E58BC;
extern f64 lbl_803E58C0;
extern void Obj_FreeObject(int* obj);
extern void objfx_spawnFlaggedTrailBurst(int* obj, f32 f, int a, int b, int c, int d);

void SB_CannonBall_update(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    if ((((SBCannonBallState*)state)->flags & SB_CANNONBALL_INITIAL_BURST_FLAG) != 0)
    {
        (*gPartfxInterface)->spawnObject(obj, SB_CANNONBALL_BURST_PARTICLE_ID,
                                         NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, SB_CANNONBALL_BURST_PARTICLE_ID,
                                         NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, SB_CANNONBALL_BURST_PARTICLE_ID,
                                         NULL, 1, -1, NULL);
        ((SBCannonBallState*)state)->flags = (s8)(
            ((SBCannonBallState*)state)->flags & ~SB_CANNONBALL_INITIAL_BURST_FLAG);
    }
    else
    {
        objfx_spawnFlaggedTrailBurst(obj, lbl_803E58BC, SB_CANNONBALL_SETUP_SIZE, SB_CANNONBALL_SETUP_MODEL_ID,
                                     SB_CANNONBALL_SETUP_PARAM, 0);
        objfx_spawnFlaggedTrailBurst(obj, lbl_803E58BC, SB_CANNONBALL_SETUP_SIZE, SB_CANNONBALL_SETUP_MODEL_ID,
                                     SB_CANNONBALL_SETUP_PARAM, 0);
    }
    (*gPartfxInterface)->spawnObject(obj, SB_CANNONBALL_TRAIL_PARTICLE_ID,
                                     NULL, 1, -1, NULL);
    ((GameObject*)obj)->anim.rotY += SB_CANNONBALL_ROTATION_STEP;
    if ((((SBCannonBallState*)state)->flags & SB_CANNONBALL_TRAJECTORY_INITIALIZED_FLAG) == 0)
    {
        *(f32*)state = ((GameObject*)obj)->anim.velocityX;
        ((SBCannonBallState*)state)->velocityY = ((GameObject*)obj)->anim.velocityY;
        ((SBCannonBallState*)state)->velocityZ = ((GameObject*)obj)->anim.velocityZ;
        ((SBCannonBallState*)state)->flags = (s8)(
            ((SBCannonBallState*)state)->flags | SB_CANNONBALL_TRAJECTORY_INITIALIZED_FLAG);
        ((SBCannonBallState*)state)->posX = ((GameObject*)obj)->anim.localPosX;
        ((SBCannonBallState*)state)->posY = ((GameObject*)obj)->anim.localPosY;
        ((SBCannonBallState*)state)->posZ = ((GameObject*)obj)->anim.localPosZ;
    }
    {
        f64 scale = lbl_803E58C0;
        ((SBCannonBallState*)state)->posX = (f32)(
            scale * (f64)(*(f32*)state * timeDelta) + (f64)((SBCannonBallState*)state)->posX);
        ((SBCannonBallState*)state)->posY = (f32)(
            scale * (f64)(((SBCannonBallState*)state)->velocityY * timeDelta) + (f64)((SBCannonBallState*)state)->posY);
        ((SBCannonBallState*)state)->posZ = (f32)(
            scale * (f64)(((SBCannonBallState*)state)->velocityZ * timeDelta) + (f64)((SBCannonBallState*)state)->posZ);
    }
    ((GameObject*)obj)->anim.localPosX = ((SBCannonBallState*)state)->posX;
    ((GameObject*)obj)->anim.localPosY = ((SBCannonBallState*)state)->posY;
    ((GameObject*)obj)->anim.localPosZ = ((SBCannonBallState*)state)->posZ;
    ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - (int)framesThisStep;
    if (((GameObject*)obj)->unkF4 < 0)
    {
        Obj_FreeObject(obj);
    }
    if (((SBCannonBallState*)state)->unk18 > SB_CANNONBALL_HITBOX_ENABLE_DELAY)
    {
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->hitVolumePriority =
            SB_CANNONBALL_HITBOX_TYPE;
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->hitVolumeId = SB_CANNONBALL_HITBOX_PRIORITY;
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->objectHitMask = SB_CANNONBALL_HITBOX_SIZE;
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->skeletonHitMask = SB_CANNONBALL_HITBOX_SIZE;
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags |= SB_CANNONBALL_SOLID_HITBOX_FLAG;
    }
    else
    {
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~SB_CANNONBALL_SOLID_HITBOX_FLAG;
    }
    ((SBCannonBallState*)state)->unk18 += framesThisStep;
}

extern f32 lbl_803E58B4;
extern f32 lbl_803E58B8;

void SB_CannonBall_hitDetect(int* obj)
{
    extern int Sfx_PlayFromObject();
    int* state = ((GameObject*)obj)->extra;
    f32 t = ((SBCannonBallState*)state)->impactCooldown;
    f32 zero = lbl_803E58B4;

    if (t > zero)
    {
        ((SBCannonBallState*)state)->impactCooldown = t - timeDelta;
        if (((SBCannonBallState*)state)->impactCooldown <= zero)
        {
            Obj_FreeObject(obj);
        }
        return;
    }

    {
        int* side = *(int**)&((GameObject*)obj)->anim.hitReactState;
        int* target = *(int**)&((ObjHitsPriorityState*)side)->lastHitObject;
        s16 type;
        if (target == NULL) return;
        type = *(s16*)((char*)target + 0x46);
        if (type == SB_CLOUDBALL_ALIAS_OBJECT_TYPE) return;
        if (type == SB_CANNONBALL_ALIAS_OBJECT_TYPE) return;
    }

    if (zero != t) return;

    Sfx_PlayFromObject(obj, SB_CANNONBALL_IMPACT_SFX);
    {
        int* p = *(int**)&((GameObject*)obj)->anim.hitReactState;
        ((ObjHitsPriorityState*)p)->flags = (s16)(((ObjHitsPriorityState*)p)->flags & ~SB_CANNONBALL_SOLID_HITBOX_FLAG);
    }
    ((SBCannonBallState*)state)->impactCooldown = lbl_803E58B8;
    ((GameObject*)obj)->anim.alpha = SB_CANNONBALL_IMPACT_VISUAL_TIMER;

    {
        int i;
        for (i = SB_CANNONBALL_SMOKE_PARTICLE_COUNT; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(
                obj, SB_CANNONBALL_IMPACT_SMOKE_PARTICLE_ID, NULL, 1, -1, NULL);
        }
    }
    {
        int i;
        for (i = SB_CANNONBALL_SPARK_PARTICLE_COUNT; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject(
                obj, SB_CANNONBALL_IMPACT_SPARK_PARTICLE_ID, NULL, 1, -1, NULL);
        }
    }
}

extern u8* objCreateLight(int* obj, int v);
extern void modelLightStruct_setLightKind(u8* p, int v);
extern void modelLightStruct_setDiffuseColor(u8* p, int a, int b, int c, int d);
extern void lightSetFieldBC_8001db14(u8* p, int v);
extern void modelLightStruct_setDistanceAttenuation(u8* p, f32 a, f32 b);
extern f32 lbl_803E58C8;
extern f32 lbl_803E58CC;
extern f32 lbl_803E58D0;

void SB_CannonBall_init(int* obj)
{
    extern int Sfx_PlayFromObject();
    int* state = ((GameObject*)obj)->extra;
    if (*(u8**)&((SBCannonBallState*)state)->modelLight == NULL)
    {
        *(u8**)&((SBCannonBallState*)state)->modelLight = objCreateLight(obj, SB_CANNONBALL_LIGHT_KIND);
        if (*(u8**)&((SBCannonBallState*)state)->modelLight != NULL)
        {
            modelLightStruct_setLightKind(*(u8**)&((SBCannonBallState*)state)->modelLight, SB_CANNONBALL_LIGHT_FIELD50);
            modelLightStruct_setDiffuseColor(*(u8**)&((SBCannonBallState*)state)->modelLight, SB_CANNONBALL_LIGHT_RED,
                                             SB_CANNONBALL_LIGHT_GREEN, SB_CANNONBALL_LIGHT_BLUE,
                                             SB_CANNONBALL_LIGHT_ALPHA);
            lightSetFieldBC_8001db14(*(u8**)&((SBCannonBallState*)state)->modelLight, SB_CANNONBALL_LIGHT_FIELD_BC);
            modelLightStruct_setDistanceAttenuation(*(u8**)&((SBCannonBallState*)state)->modelLight, lbl_803E58C8,
                                                    lbl_803E58CC);
        }
    }
    {
        int* p = *(int**)&((GameObject*)obj)->anim.hitReactState;
        ((ObjHitsPriorityState*)p)->flags = (s16)(((ObjHitsPriorityState*)p)->flags & ~SB_CANNONBALL_SOLID_HITBOX_FLAG);
    }
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E58D0;
    ((SBCannonBallState*)state)->flags = (s8)(((SBCannonBallState*)state)->flags | SB_CANNONBALL_INITIAL_BURST_FLAG);
    Sfx_PlayFromObject(obj, SB_CANNONBALL_LAUNCH_SFX);
    Sfx_PlayFromObject(obj, SB_CANNONBALL_LOOP_SFX);
}
