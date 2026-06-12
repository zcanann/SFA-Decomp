/* DLL 0x01EE — sbcannonball / SB_Galleon / SB_Propeller / SB_ShipHead group. TU: 0x801E341C–0x801E34C0. */
#include "main/game_object.h"
#include "main/dll/sbshipheadstate_struct.h"
#include "main/dll/sbpropellerstate_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/objseq.h"

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

extern EffectInterface** gPartfxInterface;

extern f32 timeDelta;

extern u8 framesThisStep;

extern void objRenderFn_8003b8f4(f32);

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* SB_Propeller_hitDetect: guard on 0x46 == 0x69c, copy halfword from sda21 ptr. */

/* SB_ShipGun_free: expgfx interface freeObject callback. */

/* SB_Galleon_setScale: state machine; advance counter, optionally play sfx. */

/* SB_Galleon_hitDetect: per-step expgfx spawn loop. */

/* SB_Galleon_free: textureFree manager textures, ObjGroup_RemoveObject, kill music, set bit. */

/* SB_ShipHead_init: add to group, alloc msg queue, set state + bias positions. */

/* SB_ShipGun_render: conditional render with multiple flag checks. */

/* SB_Galleon_modelMtxFn: returns -2 / -1 / state byte depending on flags. */

/* SB_Galleon_func0E: state byte == 1 -> compute from 0x7c; else return 0x640. */

#include "ghidra_import.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/TREX/TREX_levelcontrol.h"
#include "main/objhits_types.h"

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

extern f32 lbl_803E58B0;
extern f32 lbl_803E58BC;
extern f64 lbl_803E58C0;
extern void Obj_FreeObject(int* obj);
extern void objfx_spawnFlaggedTrailBurst(int* obj, f32 f, int a, int b, int c, int d);
extern f32 lbl_803E58B4;
extern f32 lbl_803E58B8;
extern u8* objCreateLight(int* obj, int v);
extern void modelLightStruct_setLightKind(u8* p, int v);
extern void modelLightStruct_setDiffuseColor(u8* p, int a, int b, int c, int d);
extern void lightSetFieldBC_8001db14(u8* p, int v);
extern void modelLightStruct_setDistanceAttenuation(u8* p, f32 a, f32 b);
extern f32 lbl_803E58C8;
extern f32 lbl_803E58CC;
extern f32 lbl_803E58D0;

void SB_CannonBall_release(void)
{
}

void SB_CannonBall_initialise(void)
{
}

void SB_ShipGun_init(int obj);

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

void SB_CannonBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E58B0);
}

void SB_FireBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

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
