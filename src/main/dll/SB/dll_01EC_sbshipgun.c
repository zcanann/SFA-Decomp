/*
 * SB_ShipGun (DLL 0x1EC) - one of the two deck cannons on General Scales'
 * galleon in the ShipBattle prologue (SB = the retail "ShipBattle" map).
 * While the player chases the galleon on the Cloudrunner the gun tracks the
 * bird, fires aimed cannonballs (SB_CannonBall) in volleys, takes damage in
 * two stages, then runs an explosion + smoke death sequence (the wreck is
 * then drawn by the SB_ShipGunBroke prop). Both guns are shot out, then the
 * propellers, then both guns again, to bring the galleon down.
 *
 * Lifecycle is a small state machine in state->phase (SBShipGunState +0xA):
 *   0  idle, waiting on the parent Galleon's "wake" condition
 *   2  active: aim at the Cloudrunner, fire timed cannonball volleys, react
 *      to ObjHits damage (two damage thresholds knock the gun toward death)
 *   3  death trigger: spawn explosion (or skip straight to smoke)
 *   4  exploded: emit smoke from the path point each frame
 *   5  smoldering: like 4 but can re-arm if the Galleon re-enters its
 *      fast-fire phase
 * The gun caches the ridden Cloudrunner object in state[0] and reads its
 * parent Galleon's phase through the Galleon DLL's interface vtable.
 */
#include "main/game_object.h"
#include "main/dll/sbshipheadstate_struct.h"
#include "main/dll/sbpropellerstate_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/TREX/TREX_levelcontrol.h"
#include "main/dll/DB/DBstealerworm.h"

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

/* SBShipGunState. Most of update() reaches the timing/aim fields through
   raw int* offsets (state is int*); the layout is:
     +0x03 s8  livesRemaining  +0x04 s16 yawAngle    +0x06 s16 pitchAngle
     +0x08 s16 fireTimer       +0x0A u8  phase        +0x0B s8  hitCount
     +0x0C u8  health          +0x0D u8  active       +0x0E u8  volleyCount
   state[0] (+0x00) caches the CloudRunner object pointer. */
typedef struct SBShipGunState
{
    u8 pad0[0x3 - 0x0];
    s8 livesRemaining; /* 0x03: damage stages left before death */
    u8 pad4[0xC - 0x4];
    u8 health;         /* 0x0C: hit-points within the current stage */
    u8 active;         /* 0x0D: cleared while the WM-galleon alias is parent */
    u8 volleyCount;    /* 0x0E: shots fired in the current volley */
    u8 padF[0x10 - 0xF];
} SBShipGunState;

STATIC_ASSERT(offsetof(SBShipGunState, livesRemaining) == 0x3);
STATIC_ASSERT(offsetof(SBShipGunState, health) == 0xC);
STATIC_ASSERT(offsetof(SBShipGunState, active) == 0xD);
STATIC_ASSERT(offsetof(SBShipGunState, volleyCount) == 0xE);
STATIC_ASSERT(sizeof(SBShipGunState) == 0x10);

extern u32 randomGetRange(int min, int max);
extern int ObjHits_GetPriorityHit();
extern u8 framesThisStep;
extern u8 Obj_IsLoadingLocked(void);
extern void Obj_GetWorldPosition(int obj, f32* x, f32* y, f32* z);
extern f32 sqrtf(f32);
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5888;
extern int ObjList_GetObjects(int* outIndex, int* outCount);
extern void Obj_SetModelColorFadeRecursive(int obj, int p2, int p3, int p4, int p5, int p6);
extern void Sfx_StopObjectChannel(int obj, int ch);
extern int getAngle(f32 dx, f32 dz);
extern void vecRotateZXY(void* rot, void* vec);
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 mag);
extern const f32 lbl_803E588C;
extern f32 lbl_803E5890;
extern f32 lbl_803E5894;
extern f32 lbl_803E5898;
extern f32 lbl_803E589C;
extern f32 lbl_803E58A0;
extern f32 lbl_803E58A4;
extern f32 lbl_803E58A8;
extern f32 lbl_803E58AC;

int SB_ShipGun_getExtraSize(void) { return 0x10; }

void SB_ShipGun_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void SB_ShipGun_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    GameObject* parent;
    s8* state;
    s32 vis;
    state = ((GameObject*)obj)->extra;
    parent = ((GameObject*)obj)->anim.parent;
    if (parent != NULL)
    {
        if (parent->anim.seqId == SB_SHIPGUN_WM_GALLEON_ALIAS_OBJECT_TYPE) return;
    }
    vis = visible;
    if (vis == 0 || state[0xc] == 0 || ((SBShipGunState*)state)->active == 0) return;
    ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E5888);
}

/* The cannonball setup block (SBShipGunPlacement) doubles as the spawn-
   position scratch the gun writes before Obj_SetupObject, then as the
   live CloudRunner placement the gun reads its target world position from
   (targetX/Y/Z). */
typedef struct SBShipGunPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 modelField;  /* 0x04 */
    u8 flagsField;  /* 0x05 */
    u8 byte6;       /* 0x06 */
    u8 byte7;       /* 0x07 */
    f32 spawnX; /* 0x08: cannonball muzzle world position */
    f32 spawnY;
    f32 spawnZ;
    u8 pad14[0x18 - 0x14];
    f32 targetX; /* 0x18: target (CloudRunner) world position */
    f32 targetY;
    f32 targetZ;
    u8 pad24[0x28 - 0x24];
} SBShipGunPlacement;

STATIC_ASSERT(offsetof(SBShipGunPlacement, modelField) == 0x4);
STATIC_ASSERT(offsetof(SBShipGunPlacement, spawnX) == 0x8);
STATIC_ASSERT(offsetof(SBShipGunPlacement, targetX) == 0x18);
STATIC_ASSERT(sizeof(SBShipGunPlacement) == 0x28);

/* The parent Galleon's DLL exposes an interface vtable (anim.dll -> table);
   the ship gun reads its stage and "wake"/death conditions through the typed
   SBGalleonVtbl (see DBstealerworm.h). The gun's "wake condition" is the
   galleon's phase slot, and "on gun destroyed" is the onPartDestroyed slot. */

/* state->phase machine (SBShipGunState +0xA) */
enum
{
    SB_SHIPGUN_PHASE_IDLE = 0,
    SB_SHIPGUN_PHASE_ACTIVE = 2,
    SB_SHIPGUN_PHASE_DEATH_TRIGGER = 3,
    SB_SHIPGUN_PHASE_EXPLODED = 4,
    SB_SHIPGUN_PHASE_SMOLDERING = 5
};

/* placement +0x19: nonzero skips the initial wake delay */
#define SB_SHIPGUN_PLACEMENT_NO_WAKE_DELAY 0x19
/* elevation (pitch) aim angle clamp, in binary-angle units */
#define SB_SHIPGUN_MAX_PITCH 8000

void SB_ShipGun_update(int obj)
{
    extern f32 Vec_distance(float* a, float* b);
    extern u16* Obj_SetupObject(void* setup, int p2, int p3, int p4, int p5);
    extern void* Obj_AllocObjectSetup(int size, int objType);
    extern int Sfx_PlayFromObject();
    extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
    extern GameObject* Obj_GetPlayerObject(void);
    extern u32 ObjPath_GetPointWorldPosition();
    char phase;
    float boost;
    GameObject* player;
    int galleon;
    int* state;
    int galleonStage;
    int hit;
    uint randDelay;
    u16* spawned;
    int placement;
    struct
    {
        s16 rot[3];
        u16 flags;
        f32 a;
        f32 b;
        f32 c;
        f32 d;
    } stk;
    struct
    {
        f32 x;
        f32 y;
        f32 z;
    } offset;
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
    placement = (int)((GameObject*)obj)->anim.placementData;
    if (((GameObject*)((GameObject*)obj)->anim.parent)->anim.seqId == SB_SHIPGUN_WM_GALLEON_ALIAS_OBJECT_TYPE)
    {
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
        ((SBShipGunState*)state)->active = 0;
    }
    else
    {
        if (*(uint*)state == 0)
        {
            /* find and cache the CloudRunner object (galleon reused as the
               object-list base here, before it holds the parent Galleon). */
            galleon = ObjList_GetObjects(&listStart, &listCount);
            for (i = listStart; i < listCount; i = i + 1)
            {
                hit = *(int*)(galleon + i * 4);
                if (((GameObject*)hit)->anim.seqId == SB_SHIPGUN_CLOUDRUNNER_ALIAS_OBJECT_TYPE)
                {
                    *state = hit;
                    i = listCount;
                }
            }
        }
        galleon = (int)((GameObject*)obj)->anim.parent;
        if (((void*)galleon != NULL) &&
            (((GameObject*)galleon)->anim.seqId == SB_SHIPGUN_GALLEON_ALIAS_OBJECT_TYPE))
        {
            galleonStage = SB_GALLEON_VTBL(galleon)->getStage(galleon);
        }
        else
        {
            galleonStage = 0;
            *(u8*)((int)state + 10) = SB_SHIPGUN_PHASE_EXPLODED;
        }
        ((SBShipGunState*)state)->active = 1;
        phase = *(char*)((int)state + 10);
        switch (phase)
        {
        case SB_SHIPGUN_PHASE_IDLE:
            if (((void*)galleon != NULL) &&
                (galleon = SB_GALLEON_VTBL(galleon)->getPhase(galleon), galleon == 0))
            {
                if (*(char*)(placement + SB_SHIPGUN_PLACEMENT_NO_WAKE_DELAY) == '\0')
                {
                    *(u8*)((int)state + 10) = SB_SHIPGUN_PHASE_ACTIVE;
                    *(u16*)(state + 2) = SB_SHIPGUN_WAKE_DELAY;
                }
                else
                {
                    *(u8*)((int)state + 10) = SB_SHIPGUN_PHASE_ACTIVE;
                    *(u16*)(state + 2) = 0;
                }
            }
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
            break;
        case SB_SHIPGUN_PHASE_ACTIVE:
            {
                ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags |= 1;
                placement = SB_GALLEON_VTBL(galleon)->getPhase(galleon);
                if ((placement == 0) &&
                    (hit = ObjHits_GetPriorityHit(obj, 0, 0, 0), hit != 0))
                {
                    Obj_SetModelColorFadeRecursive(obj, SB_SHIPGUN_HIT_REACT_TYPE, SB_SHIPGUN_HIT_REACT_POWER, 0, 0, 1);
                    Sfx_PlayFromObject(obj, SB_SHIPGUN_HIT_ANIM_A);
                    *(s8*)((int)state + 0xb) += 1;
                    if (*(char*)((int)state + 0xb) == SB_SHIPGUN_FIRST_DAMAGE_HIT_COUNT)
                    {
                        *(s8*)(state + 3) -= 1;
                        *(u8*)((int)state + 10) = SB_SHIPGUN_PHASE_DEATH_TRIGGER;
                        if ((void*)galleon != NULL)
                        {
                            SB_GALLEON_VTBL(galleon)->onPartDestroyed(galleon);
                        }
                    }
                    else if (*(char*)((int)state + 0xb) == SB_SHIPGUN_SECOND_DAMAGE_HIT_COUNT)
                    {
                        Sfx_PlayFromObject(obj, SB_SHIPGUN_HIT_ANIM_B);
                        *(s8*)(state + 3) -= 1;
                        *(u8*)((int)state + 10) = SB_SHIPGUN_PHASE_DEATH_TRIGGER;
                        if ((void*)galleon != NULL)
                        {
                            SB_GALLEON_VTBL(galleon)->onPartDestroyed(galleon);
                        }
                    }
                }
                if (((void*)galleon != NULL) && (placement != 0))
                {
                    *(u8*)((int)state + 10) = SB_SHIPGUN_PHASE_DEATH_TRIGGER;
                }
                fdx = player->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
                fdz = player->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
                *(short*)(state + 1) = (short)
                (((uint)(u16)
                getAngle(-fdz, fdx) & 0xffff
                )
                <<
                1
                )
                ;
                fdy = player->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
                dist = sqrtf(fdx * fdx + fdz * fdz);
                {
                    extern int getAngle(f32 dx, f32 dz);
                    *(short*)((int)state + 6) = (s16)getAngle(-fdy, dist);
                }
                if (*(short*)((int)state + 6) > SB_SHIPGUN_MAX_PITCH)
                {
                    *(short*)((int)state + 6) = SB_SHIPGUN_MAX_PITCH;
                }
                else if (*(short*)((int)state + 6) < -SB_SHIPGUN_MAX_PITCH)
                {
                    *(short*)((int)state + 6) = -SB_SHIPGUN_MAX_PITCH;
                }
                *(s16*)(state + 2) -= framesThisStep;
                if ((*(short*)(state + 2) < 0) && (Obj_IsLoadingLocked() != 0))
                {
                    Obj_GetWorldPosition(obj, &posX, &posY, &posZ);
                    stk.b = lbl_803E588C;
                    stk.c = lbl_803E588C;
                    stk.d = lbl_803E588C;
                    stk.a = lbl_803E5888;
                    stk.rot[0] = *(s16*)(state + 1);
                    stk.rot[1] = 0;
                    stk.rot[2] = 0;
                    offset.x = lbl_803E5890;
                    offset.y = lbl_803E5894;
                    offset.z = lbl_803E588C;
                    vecRotateZXY(stk.rot, &offset.x);
                    placement = (int)Obj_AllocObjectSetup(SB_SHIPGUN_CANNONBALL_ALLOC_SIZE,
                                                       SB_CANNONBALL_ALIAS_OBJECT_TYPE);
                    ((SBShipGunPlacement*)placement)->spawnX = posX;
                    ((SBShipGunPlacement*)placement)->spawnY = posY;
                    ((SBShipGunPlacement*)placement)->spawnZ = posZ;
                    ((SBShipGunPlacement*)placement)->modelField = SB_SHIPGUN_CANNONBALL_MODEL_FIELD;
                    ((SBShipGunPlacement*)placement)->flagsField = SB_SHIPGUN_CANNONBALL_FLAGS_FIELD;
                    ((SBShipGunPlacement*)placement)->byte6 = SB_SHIPGUN_CANNONBALL_BYTE_FF;
                    ((SBShipGunPlacement*)placement)->byte7 = SB_SHIPGUN_CANNONBALL_BYTE_FF;
                    spawned = Obj_SetupObject((void*)placement, 5, 0xffffffff, 0xffffffff, 0);
                    placement = *state;
                    fdx = ((SBShipGunPlacement*)placement)->targetX - ((GameObject*)obj)->anim.worldPosX;
                    fdy = ((SBShipGunPlacement*)placement)->targetY - (((GameObject*)obj)->anim.worldPosY - lbl_803E5898);
                    fdz = ((SBShipGunPlacement*)placement)->targetZ - ((GameObject*)obj)->anim.worldPosZ;
                    posX = sqrtf(fdz * fdz + (fdx * fdx + fdy * fdy));
                    posX = lbl_803E589C / posX;
                    *(float*)(spawned + 0x12) = fdx * posX;
                    *(float*)(spawned + 0x14) = fdy * posX;
                    *(float*)(spawned + 0x16) = fdz * posX;
                    boost = lbl_803E58A0;
                    *(float*)(spawned + 6) = boost * *(float*)(spawned + 0x12) + *(float*)(spawned + 6);
                    *(float*)(spawned + 8) = boost * *(float*)(spawned + 0x14) + *(float*)(spawned + 8);
                    *(float*)(spawned + 10) = boost * *(float*)(spawned + 0x16) + *(float*)(spawned + 10);
                    *(s16*)spawned = getAngle(*(float*)(spawned + 0x12), *(float*)(spawned + 0x16));
                    *(u32*)(spawned + 0x7a) = SB_SHIPGUN_CANNONBALL_LIFETIME;
                    *(int*)(spawned + 0x7c) = *state;
                    Camera_EnableViewYOffset();
                    CameraShake_SetAllMagnitudes(lbl_803E58A4);
                    Sfx_PlayFromObject(obj, SB_SHIPGUN_FIRE_ANIM);
                    ((SBShipGunState*)state)->volleyCount += 1;
                    if (((SBShipGunState*)state)->volleyCount == SB_SHIPGUN_VOLLEY_SIZE)
                    {
                        if (galleonStage >= SB_SHIPGUN_FAST_FIRE_GALLEON_STAGE)
                        {
                            randDelay = randomGetRange(0, SB_SHIPGUN_FIRE_DELAY_VARIANCE);
                            *(short*)(state + 2) = randDelay + SB_SHIPGUN_FAST_FIRE_DELAY;
                        }
                        else
                        {
                            randDelay = randomGetRange(0, SB_SHIPGUN_FIRE_DELAY_VARIANCE);
                            *(short*)(state + 2) = randDelay + SB_SHIPGUN_SLOW_FIRE_DELAY;
                        }
                        ((SBShipGunState*)state)->volleyCount = 0;
                    }
                    else if (galleonStage >= SB_SHIPGUN_FAST_FIRE_GALLEON_STAGE)
                    {
                        *(u16*)(state + 2) = SB_SHIPGUN_FAST_FIRE_DELAY;
                    }
                    else
                    {
                        *(u16*)(state + 2) = SB_SHIPGUN_SLOW_FIRE_DELAY;
                    }
                }
            }
            break;
        case SB_SHIPGUN_PHASE_DEATH_TRIGGER:
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
            if (*(char*)(state + 3) == '\0')
            {
                spawnExplosion(obj, lbl_803E5890, 1, 1, 1, 0, 1, 1, 0);
                *(u8*)((int)state + 10) = SB_SHIPGUN_PHASE_EXPLODED;
            }
            else
            {
                *(u8*)((int)state + 10) = SB_SHIPGUN_PHASE_SMOLDERING;
            }
            break;
        case SB_SHIPGUN_PHASE_EXPLODED:
            {
                stk.a = lbl_803E58A8;
                stk.flags = SB_SHIPGUN_SMOKE_PARTICLE_FLAGS;
                ObjPath_GetPointWorldPosition(obj, 0, &stk.b, &stk.c, &stk.d, 0);
                stk.b = stk.b - ((GameObject*)obj)->anim.worldPosX;
                stk.c = stk.c - ((GameObject*)obj)->anim.worldPosY;
                stk.d = stk.d - ((GameObject*)obj)->anim.worldPosZ;
                for (placement = 0; placement < (int)(uint)framesThisStep; placement = placement + 1)
                {
                    (*gPartfxInterface)->spawnObject(
                        (void*)obj, SB_SHIPGUN_SMOKE_PARTICLE_ID, stk.rot,
                        SB_SHIPGUN_SMOKE_PARTICLE_PARAM, -1, NULL);
                }
            }
            break;
        case SB_SHIPGUN_PHASE_SMOLDERING:
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
            if (((void*)galleon != NULL) &&
                (galleon = SB_GALLEON_VTBL(galleon)->getPhase(galleon), galleon == 0))
            {
                if (*(char*)(placement + SB_SHIPGUN_PLACEMENT_NO_WAKE_DELAY) == '\0')
                {
                    if (SB_SHIPGUN_FAST_FIRE_GALLEON_STAGE <= galleonStage)
                    {
                        *(u8*)((int)state + 10) = SB_SHIPGUN_PHASE_ACTIVE;
                        *(u16*)(state + 2) = SB_SHIPGUN_WAKE_DELAY;
                    }
                }
                else if (SB_SHIPGUN_FAST_FIRE_GALLEON_STAGE <= galleonStage)
                {
                    *(u8*)((int)state + 10) = SB_SHIPGUN_PHASE_ACTIVE;
                    *(u16*)(state + 2) = 0;
                }
            }
            stk.a = lbl_803E58A8;
            stk.flags = SB_SHIPGUN_SMOKE_PARTICLE_FLAGS;
            ObjPath_GetPointWorldPosition(obj, 0, &stk.b, &stk.c, &stk.d, 0);
            stk.b = stk.b - ((GameObject*)obj)->anim.worldPosX;
            stk.c = stk.c - ((GameObject*)obj)->anim.worldPosY;
            stk.d = stk.d - ((GameObject*)obj)->anim.worldPosZ;
            for (placement = 0; placement < (int)(uint)framesThisStep; placement = placement + 1)
            {
                (*gPartfxInterface)->spawnObject(
                    (void*)obj, SB_SHIPGUN_SMOKE_PARTICLE_ID, stk.rot,
                    SB_SHIPGUN_SMOKE_PARTICLE_PARAM, -1, NULL);
            }
            break;
        }
        if (*(char*)(state + 3) == '\0')
        {
            dist = Vec_distance(&player->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
            if (dist < lbl_803E58AC)
            {
                Sfx_PlayFromObject(obj, SB_SHIPGUN_RANGE_NEAR_ANIM);
            }
            else
            {
                Sfx_StopObjectChannel(obj, SB_SHIPGUN_RANGE_FAR_ANIM);
            }
        }
    }
    return;
}

void SB_ShipGun_init(GameObject* obj)
{
    SBShipGunState* state;

    state = obj->extra;
    state->active = 0;
    state->health = SB_SHIPGUN_START_HEALTH;
    state->volleyCount = 0;
}
