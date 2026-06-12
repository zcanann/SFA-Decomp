#include "main/game_object.h"
#include "main/dll/sbshipheadstate_struct.h"
#include "main/dll/sbpropellerstate_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/objseq.h"
#include "ghidra_import.h"
#include "main/effect_interfaces.h"
#include "main/dll/TREX/TREX_levelcontrol.h"
#include "main/objhits_types.h"

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

extern u32 randomGetRange(int min, int max);
extern int ObjHits_GetPriorityHit();

extern EffectInterface** gPartfxInterface;

extern int ObjList_GetObjects(int* start, int* end);

extern void Obj_SetModelColorFadeRecursive(int obj, int a, int b, int c, int d, int e);
extern u8 framesThisStep;

extern void Sfx_StopObjectChannel(int obj, int ch);
extern u8 Obj_IsLoadingLocked(void);
extern void Obj_GetWorldPosition(int obj, f32* x, f32* y, f32* z);
extern f32 sqrtf(f32);

extern u32 gSbGalleon;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E57FC;
extern f32 lbl_803E5888;
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

int SB_ShipGun_getExtraSize(void) { return 0x10; }

void SB_ShipGun_free(int param_1)
{
    (*gExpgfxInterface)->freeSource2((u32)param_1);
}

void SB_ShipGun_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    void* o30 = *(void**)&((GameObject*)obj)->anim.parent;
    s8* p = ((GameObject*)obj)->extra;
    s32 v;
    if (o30 != NULL)
    {
        if (((GameObject*)o30)->anim.seqId == 0x139) return;
    }
    v = visible;
    if (v != 0 && p[0xc] != 0 && ((u8*)p)[0xd] != 0)
    {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E5888);
    }
}

/* SB_Galleon_modelMtxFn: returns -2 / -1 / state byte depending on flags. */

/* SB_Galleon_func0E: state byte == 1 -> compute from 0x7c; else return 0x640. */

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

void SB_ShipGun_update(int obj)
{
    extern f32 Vec_distance(float* a, float* b);
    extern u16* Obj_SetupObject(void* setup, int p2, int p3, int p4, int p5);
    extern void* Obj_AllocObjectSetup(int size, int objType);
    extern int Sfx_PlayFromObject();
    extern void spawnExplosion(double scale, int obj, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
    extern u8* Obj_GetPlayerObject(void);
    extern undefined4 ObjPath_GetPointWorldPosition();
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

void SB_CannonBall_release(void);

void SB_ShipGun_init(int obj)
{
    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    ((SBShipGunState*)state)->unkD = 0;
    ((SBShipGunState*)state)->unkC = SB_SHIPGUN_START_HEALTH;
    ((SBShipGunState*)state)->unkE = 0;
}

int SB_CannonBall_getExtraSize(void);
