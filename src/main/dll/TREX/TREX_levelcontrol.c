#include "ghidra_import.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
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


extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068fc();
extern undefined4 FUN_80006920();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_8001771c();
extern uint FUN_80017730();
extern undefined8 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a28();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017b00();
extern void ModelLightStruct_free(void* effect);
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8008112c();
extern uint FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();

extern undefined4 DAT_803dc070;
extern f32 lbl_803E6520;
extern f32 lbl_803E6524;
extern f32 lbl_803E6528;
extern f32 lbl_803E652C;
extern f32 lbl_803E6530;
extern f32 lbl_803E6534;
extern f32 lbl_803E6538;
extern f32 lbl_803E653C;
extern f32 lbl_803E6540;
extern f32 lbl_803E6544;

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
extern u8* Obj_GetPlayerObject(void);
extern int ObjList_GetObjects(int* outIndex, int* outCount);
extern void spawnExplosion(double scale, int obj, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern void Obj_SetModelColorFadeRecursive(int obj, int p2, int p3, int p4, int p5, int p6);
extern int Sfx_PlayFromObject();
extern void Sfx_StopObjectChannel();
extern s16 getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32);
extern u8 Obj_IsLoadingLocked(void);
extern void Obj_GetWorldPosition(int obj, float* x, float* y, float* z);
extern void vecRotateZXY(void* a, void* b);
extern void* Obj_AllocObjectSetup(int size, int objType);
extern u16* Obj_SetupObject(void* setup, int p2, int p3, int p4, int p5);
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 mag);
extern f32 Vec_distance(float* a, float* b);
extern u8 framesThisStep;
extern EffectInterface** gPartfxInterface;
extern f32 lbl_803E5888;
extern f32 lbl_803E588C;
extern f32 lbl_803E5890;
extern f32 lbl_803E5894;
extern f32 lbl_803E5898;
extern f32 lbl_803E589C;
extern f32 lbl_803E58A0;
extern f32 lbl_803E58A4;
extern f32 lbl_803E58A8;
extern f32 lbl_803E58AC;

void SB_ShipGun_update(int obj)
{
    char phase;
    float fa;
    u8* player;
    int ref;
    int* state;
    int ref2;
    int hitKind;
    uint randDelay;
    u16* spawned;
    int placement;
    float aimZv[3];
    float aimY;
    float aimX;
    float aimZ;
    ushort rotArgs[4];
    float offsetZ;
    float offsetY;
    float offsetX;
    float posX;
    float posY;
    float posZ;
    int listStart;
    int listCount;
    f32 fdx;
    f32 fdy;
    f32 fdz;
    f32 dist;
    int i;

    player = Obj_GetPlayerObject();
    state = ((GameObject*)obj)->extra;
    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    if (*(short*)(*(int*)&((GameObject*)obj)->anim.parent + 0x46) == SB_SHIPGUN_WM_GALLEON_ALIAS_OBJECT_TYPE)
    {
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
        *(undefined*)((int)state + 0xd) = 0;
    }
    else
    {
        if (*(uint*)state == 0)
        {
            ref = ObjList_GetObjects(&listStart, &listCount);
            for (i = listStart; i < listCount; i = i + 1)
            {
                ref2 = *(int*)(ref + i * 4);
                if (*(short*)(ref2 + 0x46) == SB_SHIPGUN_CLOUDRUNNER_ALIAS_OBJECT_TYPE)
                {
                    *state = ref2;
                    i = listCount;
                }
            }
        }
        ref = *(int*)&((GameObject*)obj)->anim.parent;
        if (((void*)ref != NULL) &&
            (((GameObject*)ref)->anim.seqId == SB_SHIPGUN_GALLEON_ALIAS_OBJECT_TYPE))
        {
            ref2 = (*(code*)(**(int**)&((GameObject*)ref)->anim.dll + 0x24))(ref);
        }
        else
        {
            ref2 = 0;
            *(undefined*)((int)state + 10) = 4;
        }
        *(undefined*)((int)state + 0xd) = 1;
        phase = *(char*)((int)state + 10);
        switch (phase)
        {
        case 0:
            if (((void*)ref != NULL) &&
                (ref = (*(code*)(**(int**)&((GameObject*)ref)->anim.dll + 0x28))(ref), ref == 0))
            {
                if (*(char*)(placement + 0x19) == '\0')
                {
                    *(undefined*)((int)state + 10) = 2;
                    *(undefined2*)(state + 2) = SB_SHIPGUN_WAKE_DELAY;
                }
                else
                {
                    *(undefined*)((int)state + 10) = 2;
                    *(undefined2*)(state + 2) = 0;
                }
            }
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
            break;
        case 2:
            {
                (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags |= 1;
                placement = (*(code*)(**(int**)&((GameObject*)ref)->anim.dll + 0x28))(ref);
                if ((placement == 0) &&
                    (hitKind = ObjHits_GetPriorityHit(obj, 0, 0, 0), hitKind != 0))
                {
                    Obj_SetModelColorFadeRecursive(obj, SB_SHIPGUN_HIT_REACT_TYPE, SB_SHIPGUN_HIT_REACT_POWER, 0, 0, 1);
                    Sfx_PlayFromObject(obj, SB_SHIPGUN_HIT_ANIM_A);
                    *(s8*)((int)state + 0xb) += 1;
                    if (*(char*)((int)state + 0xb) == SB_SHIPGUN_FIRST_DAMAGE_HIT_COUNT)
                    {
                        *(s8*)(state + 3) -= 1;
                        *(undefined*)((int)state + 10) = 3;
                        if ((void*)ref != NULL)
                        {
                            (*(code*)(**(int**)&((GameObject*)ref)->anim.dll + 0x20))(ref);
                        }
                    }
                    else if (*(char*)((int)state + 0xb) == SB_SHIPGUN_SECOND_DAMAGE_HIT_COUNT)
                    {
                        Sfx_PlayFromObject(obj, SB_SHIPGUN_HIT_ANIM_B);
                        *(s8*)(state + 3) -= 1;
                        *(undefined*)((int)state + 10) = 3;
                        if ((void*)ref != NULL)
                        {
                            (*(code*)(**(int**)&((GameObject*)ref)->anim.dll + 0x20))(ref);
                        }
                    }
                }
                if (((void*)ref != NULL) && (placement != 0))
                {
                    *(undefined*)((int)state + 10) = 3;
                }
                fdx = *(float*)(player + 0x18) - ((GameObject*)obj)->anim.worldPosX;
                fdz = *(float*)(player + 0x20) - ((GameObject*)obj)->anim.worldPosZ;
                *(short*)(state + 1) = (short)
                (((uint)(u16)
                getAngle(-fdz, fdx) & 0xffff
                )
                <<
                1
                )
                ;
                fdy = *(float*)(player + 0x1c) - ((GameObject*)obj)->anim.worldPosY;
                dist = sqrtf(fdx * fdx + fdz * fdz);
                {
                    extern int getAngle(f32 dx, f32 dz);
                    *(short*)((int)state + 6) = (s16)getAngle(-fdy, dist);
                }
                if (*(short*)((int)state + 6) > 8000)
                {
                    *(short*)((int)state + 6) = 8000;
                }
                else if (*(short*)((int)state + 6) < -8000)
                {
                    *(short*)((int)state + 6) = -8000;
                }
                *(ushort*)(state + 2) = *(short*)(state + 2) - (ushort)framesThisStep;
                if ((*(short*)(state + 2) < 0) && (Obj_IsLoadingLocked() != 0))
                {
                    Obj_GetWorldPosition(obj, &posX, &posY, &posZ);
                    aimX = lbl_803E588C;
                    aimY = lbl_803E588C;
                    aimZv[0] = lbl_803E588C;
                    aimZ = lbl_803E5888;
                    rotArgs[0] = *(ushort*)(state + 1);
                    rotArgs[1] = 0;
                    rotArgs[2] = 0;
                    offsetX = lbl_803E5890;
                    offsetY = lbl_803E5894;
                    offsetZ = lbl_803E588C;
                    vecRotateZXY(rotArgs, &offsetX);
                    placement = (int)Obj_AllocObjectSetup(SB_SHIPGUN_CANNONBALL_ALLOC_SIZE,
                                                       SB_CANNONBALL_ALIAS_OBJECT_TYPE);
                    ((SBShipGunPlacement*)placement)->unk8 = posX;
                    ((SBShipGunPlacement*)placement)->unkC = posY;
                    ((SBShipGunPlacement*)placement)->unk10 = posZ;
                    *(undefined*)(placement + 4) = SB_SHIPGUN_CANNONBALL_MODEL_FIELD;
                    *(undefined*)(placement + 5) = SB_SHIPGUN_CANNONBALL_FLAGS_FIELD;
                    *(undefined*)(placement + 6) = SB_SHIPGUN_CANNONBALL_BYTE_FF;
                    *(undefined*)(placement + 7) = SB_SHIPGUN_CANNONBALL_BYTE_FF;
                    spawned = Obj_SetupObject((void*)placement, 5, 0xffffffff, 0xffffffff, 0);
                    placement = *state;
                    fdx = ((SBShipGunPlacement*)placement)->unk18 - ((GameObject*)obj)->anim.worldPosX;
                    fdy = ((SBShipGunPlacement*)placement)->unk1C - (((GameObject*)obj)->anim.worldPosY - lbl_803E5898);
                    fdz = ((SBShipGunPlacement*)placement)->unk20 - ((GameObject*)obj)->anim.worldPosZ;
                    dist = sqrtf(fdz * fdz + (fdx * fdx + fdy * fdy));
                    posX = lbl_803E589C / dist;
                    *(float*)(spawned + 0x12) = fdx * posX;
                    *(float*)(spawned + 0x14) = fdy * posX;
                    *(float*)(spawned + 0x16) = fdz * posX;
                    fa = lbl_803E58A0;
                    *(float*)(spawned + 6) = fa * *(float*)(spawned + 0x12) + *(float*)(spawned + 6);
                    *(float*)(spawned + 8) = fa * *(float*)(spawned + 0x14) + *(float*)(spawned + 8);
                    *(float*)(spawned + 10) = fa * *(float*)(spawned + 0x16) + *(float*)(spawned + 10);
                    *spawned = getAngle(*(float*)(spawned + 0x12), *(float*)(spawned + 0x16));
                    *(undefined4*)(spawned + 0x7a) = SB_SHIPGUN_CANNONBALL_LIFETIME;
                    *(int*)(spawned + 0x7c) = *state;
                    Camera_EnableViewYOffset();
                    CameraShake_SetAllMagnitudes(lbl_803E58A4);
                    Sfx_PlayFromObject(obj, SB_SHIPGUN_FIRE_ANIM);
                    *(u8*)((int)state + 0xe) += 1;
                    if (*(u8*)((int)state + 0xe) == SB_SHIPGUN_VOLLEY_SIZE)
                    {
                        if (ref2 >= SB_SHIPGUN_FAST_FIRE_GALLEON_PHASE)
                        {
                            randDelay = randomGetRange(0, SB_SHIPGUN_FIRE_DELAY_VARIANCE);
                            *(short*)(state + 2) = (short)randDelay + SB_SHIPGUN_FAST_FIRE_DELAY;
                        }
                        else
                        {
                            randDelay = randomGetRange(0, SB_SHIPGUN_FIRE_DELAY_VARIANCE);
                            *(short*)(state + 2) = (short)randDelay + SB_SHIPGUN_SLOW_FIRE_DELAY;
                        }
                        *(undefined*)((int)state + 0xe) = 0;
                    }
                    else if (ref2 >= SB_SHIPGUN_FAST_FIRE_GALLEON_PHASE)
                    {
                        *(undefined2*)(state + 2) = SB_SHIPGUN_FAST_FIRE_DELAY;
                    }
                    else
                    {
                        *(undefined2*)(state + 2) = SB_SHIPGUN_SLOW_FIRE_DELAY;
                    }
                }
            }
            break;
        case 3:
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
            if (*(char*)(state + 3) == '\0')
            {
                spawnExplosion((double)lbl_803E5890, obj, 1, 1, 1, 0, 1, 1, 0);
                *(undefined*)((int)state + 10) = 4;
            }
            else
            {
                *(undefined*)((int)state + 10) = 5;
            }
            break;
        case 4:
            {
                aimZ = lbl_803E58A8;
                rotArgs[3] = SB_SHIPGUN_SMOKE_PARTICLE_FLAGS;
                ObjPath_GetPointWorldPosition(obj, 0, &aimX, &aimY, aimZv, 0);
                aimX = aimX - ((GameObject*)obj)->anim.worldPosX;
                aimY = aimY - ((GameObject*)obj)->anim.worldPosY;
                aimZv[0] = aimZv[0] - ((GameObject*)obj)->anim.worldPosZ;
                for (placement = 0; placement < (int)(uint)framesThisStep; placement = placement + 1)
                {
                    (*gPartfxInterface)->spawnObject(
                        (void*)obj, SB_SHIPGUN_SMOKE_PARTICLE_ID, rotArgs,
                        SB_SHIPGUN_SMOKE_PARTICLE_PARAM, -1, NULL);
                }
            }
            break;
        case 5:
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
            if (((void*)ref != NULL) &&
                (ref = (*(code*)(**(int**)&((GameObject*)ref)->anim.dll + 0x28))(ref), ref == 0))
            {
                if (*(char*)(placement + 0x19) == '\0')
                {
                    if (SB_SHIPGUN_FAST_FIRE_GALLEON_PHASE <= ref2)
                    {
                        *(undefined*)((int)state + 10) = 2;
                        *(undefined2*)(state + 2) = SB_SHIPGUN_WAKE_DELAY;
                    }
                }
                else if (SB_SHIPGUN_FAST_FIRE_GALLEON_PHASE <= ref2)
                {
                    *(undefined*)((int)state + 10) = 2;
                    *(undefined2*)(state + 2) = 0;
                }
            }
            aimZ = lbl_803E58A8;
            rotArgs[3] = SB_SHIPGUN_SMOKE_PARTICLE_FLAGS;
            ObjPath_GetPointWorldPosition(obj, 0, &aimX, &aimY, aimZv, 0);
            aimX = aimX - ((GameObject*)obj)->anim.worldPosX;
            aimY = aimY - ((GameObject*)obj)->anim.worldPosY;
            aimZv[0] = aimZv[0] - ((GameObject*)obj)->anim.worldPosZ;
            for (placement = 0; placement < (int)(uint)framesThisStep; placement = placement + 1)
            {
                (*gPartfxInterface)->spawnObject(
                    (void*)obj, SB_SHIPGUN_SMOKE_PARTICLE_ID, rotArgs,
                    SB_SHIPGUN_SMOKE_PARTICLE_PARAM, -1, NULL);
            }
            break;
        }
        if (*(char*)(state + 3) == '\0')
        {
            dist = Vec_distance((float*)(player + 0x18), (float*)(obj + 0x18));
            if (lbl_803E58AC <= dist)
            {
                Sfx_StopObjectChannel(obj, SB_SHIPGUN_RANGE_FAR_ANIM);
            }
            else
            {
                Sfx_PlayFromObject(obj, SB_SHIPGUN_RANGE_NEAR_ANIM);
            }
        }
    }
    return;
}


/* Trivial 4b 0-arg blr leaves. */
void SB_CannonBall_release(void)
{
}

void SB_CannonBall_initialise(void)
{
}

void SB_ShipGun_init(int obj)
{
    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    ((SBShipGunState*)state)->unkD = 0;
    ((SBShipGunState*)state)->unkC = SB_SHIPGUN_START_HEALTH;
    ((SBShipGunState*)state)->unkE = 0;
}

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

int SB_FireBall_getExtraSize(void) { return SB_FIREBALL_EXTRA_SIZE; }
int SB_FireBall_getObjectTypeId(void) { return 0x0; }

void SB_FireBall_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E58B0;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E58D8;

void SB_CannonBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E58B0);
}

void SB_FireBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E58D8);
}

extern f32 timeDelta;
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
