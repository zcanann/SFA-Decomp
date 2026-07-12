/*
 * arwarwing (DLL 0x29A) - the player's Arwing in the on-rails flight
 * sections. This is the core object of the section; the singleton instance
 * is published through the gArwing global (getArwing) so the pickups,
 * squadron and level-controller TUs can find it.
 *
 * Per-object extra state is ArwingState (arwing_state.h, 0x498 bytes). The
 * update loop reads the controller, integrates flight physics toward stick-
 * driven velocity / rotation targets, runs the laser and bomb weapons, the
 * barrel-roll / wing-flex model rigging, the engine sound and the camera
 * push, then applies path and object damage. A small "mode" state machine
 * covers normal flight, barrel roll, death (4), explode (5) and warp-out
 * (6). arwarwing_init wires up the path-control block and per-course flight
 * tuning (keyed by mapEventSlot); arwarwing_initAttachments locates and
 * links the gun / bomb / engine child models and the wing light before the
 * Arwing becomes active (flags477 bit 1).
 *
 * arwarwing_SeqFn handles object-sequence events: course warps, spawning
 * lasers / bombs / boss objects, aim-snapshot capture for the hit-detect
 * pass, score registration and the per-course map-event setup.
 *
 * Most functions take the extra pointer as a raw int ("state") and cast at
 * each use - that spelling reproduces the retail register colouring; see the
 * CLAUDE.md matching notes. Several attachment / weapon / physics helpers
 * (updateThrusters, readControls, updateFlightPhysics, updateBombFire,
 * clampToFlightBounds, spawnBomb) are defined in a sibling TU.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/headdisplay.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/objlib.h"
#include "main/audio/sfx_ids.h"
#include "main/gamebit_ids.h"

#include "main/dll/ARW/arwing_state.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/dll/ARW/dll_029C_arwarwingbo.h"
#include "main/dll/ARW/dll_029D_arwarwinggu.h"
#include "main/dll/dll_029B_arwingandrossstuff.h"
#include "main/dll/ARW/dll_029F_arwbombcoll.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"

typedef struct ArwarwingState
{
    u8 pad0[0x47C - 0x0];
    u16 bonusScore; /* 0x47C: bonus score, +200 per pickup, capped at 9999 */
    u8 pad47E[0x498 - 0x47E];
} ArwarwingState;

typedef struct ArwInitCfgAB
{
    int a;
    int b;
} ArwInitCfgAB;

typedef struct ArwArwingProjectileSetup
{
    s16 objectId;
    u8 pad02[2];
    u8 field04;
    u8 field05;
    u8 pad06[2];
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad14[4];
    u8 rotX;
    u8 rotY;
    u8 rotZ;
} ArwArwingProjectileSetup;

STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, field04) == 0x04);
STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, field05) == 0x05);
STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, posX) == 0x08);
STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, posY) == 0x0c);
STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, posZ) == 0x10);
STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, rotX) == 0x18);
STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, rotY) == 0x19);
STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, rotZ) == 0x1a);

typedef struct ArwArwingVec3
{
    f32 x;
    f32 y;
    f32 z;
} ArwArwingVec3;

STATIC_ASSERT(offsetof(ArwArwingVec3, x) == 0x0);
STATIC_ASSERT(offsetof(ArwArwingVec3, y) == 0x4);
STATIC_ASSERT(offsetof(ArwArwingVec3, z) == 0x8);

#define ARWARWING_OBJGROUP 0x26

#define ARWARWING_OBJFLAG_PARENT_SLACK 0x1000

#define ARWARWING_CHILD_OBJ_LASERSHOT 0x604
#define ARWARWING_CHILD_OBJ_THRUSTER  0x6de
#define ARWARWING_CHILD_OBJ_BOMB      0x608

/* Damage partfx emitted in arwarwing_emitDamageEffects, keyed on health. */
#define ARWARWING_PARTFX_DAMAGE   0x7d0 /* health <= 4, every other frame */
#define ARWARWING_PARTFX_CRITICAL 0x7d1 /* health <= 2 (critical) */

/* cross-map destination: Krazoa shrine (0xb) map-event advanced (act 5)
   before warping out at end of the Arwing course; see setObjGroupStatus(0xb,..) */
#define ARWARWING_MAPEVENT_SHRINE 0xb

/* ArwingState.flags477 bits */
#define ARWING_FLAG_ACTIVE     0x1 /* Arwing is active / engaged */
#define ARWING_FLAG_ROLL_LEFT  0x2 /* barrel-rolling left */
#define ARWING_FLAG_ROLL_RIGHT 0x4 /* barrel-rolling right */
#define ARWING_FLAG_ROLLING    0x6 /* ROLL_LEFT | ROLL_RIGHT */

/* ArwingState.mode - the flight state machine. Mode 0 is normal flight
   (never compared against a literal); the others are explicit. */
enum
{
    ARWING_MODE_BARRELROLL = 1,
    ARWING_MODE_DEAD = 4,
    ARWING_MODE_EXPLODE = 5,
    ARWING_MODE_WARPOUT = 6
};

GameObject* getArwing(void)
{
    return (GameObject*)gArwing;
}

int arwarwing_getExtraSize(void)
{
    return 0x498;
}

int arwarwing_getObjectTypeId(void)
{
    return 0;
}

#pragma scheduling off
void arwarwing_free(GameObject* obj)
{
    ArwingState* state = (obj)->extra;

    ObjGroup_RemoveObject((int)obj, ARWARWING_OBJGROUP);
    gArwing = 0;
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
    }
}
#pragma scheduling reset

void arwarwing_release(void)
{
}

void arwarwing_initialise(void)
{
}

#pragma peephole off
#pragma scheduling off
void arwarwing_render(GameObject* obj, int p2, int p3, int p4, int p5)
{
    ArwingState* state = (obj)->extra;
    int dx, dy;

    if (state->hitShake != 0)
    {
        dx = (int)(lbl_803E6FF4 * mathSinf(lbl_803E6EFC * (f32) * (u16*)&state->shakePitch / lbl_803E6F00));
        dy = (int)(lbl_803E6F5C * mathSinf(lbl_803E6EFC * (f32) * (u16*)&state->shakeYaw / lbl_803E6F00));
        (obj)->anim.rotY = (s16)((obj)->anim.rotY + dx);
        (obj)->anim.rotZ = (s16)((obj)->anim.rotZ + dy);
    }
    objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E6ED0);
    if (state->hitShake != 0)
    {
        (obj)->anim.rotY = (s16)((obj)->anim.rotY - dx);
        (obj)->anim.rotZ = (s16)((obj)->anim.rotZ - dy);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwing_hitDetect(GameObject* obj)
{
    ArwingState* state = (obj)->extra;
    f32 pos[3];
    f32 mtx[16];

    if (((obj)->objectFlags & ARWARWING_OBJFLAG_PARENT_SLACK) != 0 && state->aimSnapshotValid != 0)
    {
        Obj_BuildWorldTransformMatrix(obj, mtx, 0);
        PSMTXMultVec(mtx, &state->aimOffsetX, pos);
        pos[0] += playerMapOffsetX;
        pos[2] += playerMapOffsetZ;
        {
            f32 posY = *(volatile f32*)&pos[1];
            fn_8008020C((s16)(0x8000 - (obj)->anim.rotX + state->aimYaw), (s16)((obj)->anim.rotY + state->aimPitch),
                        (s16)((obj)->anim.rotZ + state->aimRoll), pos[0], posY, pos[2], lbl_803E6FF8);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

void arwarwing_setFlightHalfWidth(GameObject* arwing, f32 width)
{
    (*(ArwingState**)&arwing->extra)->flightHalfWidth = width;
}

int arwarwing_getRotY(GameObject* arwing)
{
    return (s16)(*(ArwingState**)&arwing->extra)->rotYCur;
}

#pragma scheduling off
void arwarwing_setRotY(GameObject* arwing, int rotY)
{
    (*(ArwingState**)&arwing->extra)->rotYCur = (s16)rotY;
}
#pragma scheduling reset

void arwarwing_getVelocity(Vec3f* out, GameObject* arwing)
{
    *out = *(Vec3f*)&(*(ArwingState**)&arwing->extra)->velX;
}

void arwarwing_setVelocity(GameObject* arwing, int velocity)
{
    ArwingState* state = arwing->extra;
    state->velX = ((ArwArwingVec3*)velocity)->x;
    state->velY = ((ArwArwingVec3*)velocity)->y;
    state->velZ = ((ArwArwingVec3*)velocity)->z;
}

void arwarwing_addVelocity(GameObject* arwing, const Vec3f* velocity)
{
    int v = (int)&((ArwingState*)arwing->extra)->velX;
    PSVECAdd(v, (int)velocity, v);
}

#pragma scheduling off
void arwarwing_clearActiveBomb(GameObject* arwing)
{
    (*(ArwingState**)&arwing->extra)->activeBombObj = 0;
}
#pragma scheduling reset

int arwarwing_getRequiredRingCount(GameObject* arwing)
{
    return (*(ArwingState**)&arwing->extra)->requiredRings;
}

int arwarwing_getCollectedRingCount(GameObject* arwing)
{
    return (*(ArwingState**)&arwing->extra)->collectedRings;
}

#pragma scheduling off
#pragma peephole off
void arwarwing_addScore(GameObject* arwing, u8 amount)
{
    ArwingState* state = arwing->extra;
    int clamped;
    state->score += amount;
    clamped = state->score;
    if ((u32)clamped > 0x270f)
    {
        clamped = 0x270f;
    }
    state->score = clamped;
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
int arwarwing_getScore(GameObject* arwing)
{
    ArwingState* state = arwing->extra;
    int clamped = state->score;
    if ((u32)clamped > 0x270f)
    {
        clamped = 0x270f;
    }
    state->score = clamped;
    return state->score;
}
#pragma peephole reset

int arwarwing_getBombCount(GameObject* arwing)
{
    return (*(ArwingState**)&arwing->extra)->bombCount;
}

int arwarwing_getMaxHealth(GameObject* arwing)
{
    return *(s8*)&(*(ArwingState**)&arwing->extra)->maxHealth;
}

int arwarwing_getHealth(GameObject* arwing)
{
    return *(s8*)&(*(ArwingState**)&arwing->extra)->health;
}

int arwarwing_incrementPickup6DACount(GameObject* arwing)
{
    return ((*(ArwingState**)&arwing->extra)->pickup6DACount)++;
}

int arwarwing_incrementPickup6DBCount(GameObject* arwing)
{
    return ((*(ArwingState**)&arwing->extra)->pickup6DBCount)++;
}

int arwarwing_incrementPickup6D9Count(GameObject* arwing)
{
    return ((*(ArwingState**)&arwing->extra)->pickup6D9Count)++;
}

int arwarwing_incrementPickup6D8Count(GameObject* arwing)
{
    return ((*(ArwingState**)&arwing->extra)->pickup6D8Count)++;
}

#pragma peephole off
int arwarwing_incrementCollectedRingCount(GameObject* arwing)
{
    ArwingState* state = arwing->extra;
    int clamped;
    if (state->collectedRings == 9)
    {
        state->score += 0x64;
        clamped = state->score;
        if ((u32)clamped > 0x270f)
        {
            clamped = 0x270f;
        }
        state->score = clamped;
    }
    return (state->collectedRings)++;
}
#pragma peephole reset

#pragma peephole off
void arwarwing_addMaxHealth(GameObject* arwing, int amount)
{
    ArwingState* state = arwing->extra;
    *(s8*)&state->maxHealth = state->maxHealth + amount;
}
#pragma peephole reset

#pragma peephole off
void arwarwing_addHealth(GameObject* arwing, int amount)
{
    ArwingState* state = arwing->extra;
    int clamped;

    *(s8*)&state->health = state->health + amount;
    if (*(s8*)&state->health < 0)
    {
        clamped = 0;
    }
    else
    {
        clamped = (*(s8*)&state->health > *(s8*)&state->maxHealth) ? *(s8*)&state->maxHealth : *(s8*)&state->health;
    }
    *(s8*)&state->health = clamped;
    if (*(s8*)&state->health > 3)
    {
        Sfx_StopObjectChannel((u32)arwing, 4);
    }
}
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwing_emitDamageEffects(int obj, int state)
{
    ArwingState* arwing = (ArwingState*)state;
    u8 flag;
    struct
    {
        u8 pad[6];
        s16 type;
        f32 a;
        f32 b;
        f32 c;
        f32 d;
    } emit;
    flag = 0;
    if ((s8)arwing->health <= 4)
    {
        if (arwing->damageEffectCounter++ % 2 != 0)
        {
            emit.a = lbl_803E6F08;
            emit.b = lbl_803E6F0C;
            emit.c = lbl_803E6F10;
            emit.d = lbl_803E6F14;
            if ((s8)arwing->health <= 2)
                emit.type = 0x61a8;
            else
                emit.type = -0x63c0;
            (*gPartfxInterface)->spawnObject((void*)obj, ARWARWING_PARTFX_DAMAGE, &emit.pad, 4, -1, &flag);
        }
    }
    if ((s8)arwing->health <= 2)
    {
        emit.a = lbl_803E6F18;
        emit.type = 0xc0a;
        emit.b = lbl_803E6ECC;
        emit.c = lbl_803E6F1C;
        emit.d = lbl_803E6F20;
        (*gPartfxInterface)->spawnObject((void*)obj, ARWARWING_PARTFX_CRITICAL, &emit.pad, 4, -1, &flag);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void arwarwing_warpByCourse(GameObject* obj)
{
    switch (obj->anim.mapEventSlot)
    {
    case 0x3a:
        if ((u32)mainGetBit(GAMEBIT_ITEM_Spirit5_Got) != 0)
        {
            mainSetBits(GAMEBIT_WM_ObjGroups, 0);
            (*gMapEventInterface)->setMapAct(ARWARWING_MAPEVENT_SHRINE, 5);
            (*gMapEventInterface)->setObjGroupStatus(ARWARWING_MAPEVENT_SHRINE, 0xa, 1);
            (*gMapEventInterface)->setObjGroupStatus(ARWARWING_MAPEVENT_SHRINE, 0xb, 1);
            warpToMap(0x22, 0);
        }
        else
        {
            warpToMap(0x6c, 0);
        }
        break;
    case 0x3b:
        warpToMap(0x77, 0);
        break;
    case 0x3d:
        warpToMap(0x78, 0);
        break;
    case 0x3c:
        warpToMap(0x63, 0);
        break;
    case 0x3e:
        warpToMap(0x79, 0);
        break;
    }
}
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void arwarwing_updateWeaponFire(GameObject* obj, int state)
{
    int fire;
    arwarwing_updateThrusters(obj, state);
    {
        f32 t = ((ArwingState*)state)->fireCooldown;
        f32 zero = lbl_803E6ECC;
        if (t > zero)
        {
            ((ArwingState*)state)->fireCooldown = t - timeDelta;
            if (((ArwingState*)state)->fireCooldown < zero)
                ((ArwingState*)state)->fireCooldown = zero;
            else
                return;
        }
    }
    fire = 0;
    if (((ArwingState*)state)->inputFlags2 & 0x100)
    {
        ((ArwingState*)state)->fireTimer -= timeDelta;
        if (((ArwingState*)state)->fireTimer <= lbl_803E6ECC)
            fire = 1;
    }
    if ((((ArwingState*)state)->inputFlags & 0x100) == 0 && fire == 0)
        return;
    ((ArwingState*)state)->fireTimer = gArwingFireTimerReset;
    if ((s8)((ArwingState*)state)->laserLevel == 2)
    {
        arwarwing_spawnLaserShot(obj, state, 0, 2, 1);
        arwarwing_spawnLaserShot(obj, state, 1, 2, 0);
    }
    else if ((s8)((ArwingState*)state)->laserLevel == 1)
    {
        arwarwing_spawnLaserShot(obj, state, 0, 1, 1);
        arwarwing_spawnLaserShot(obj, state, 1, 1, 0);
    }
    else
    {
        arwarwing_spawnLaserShot(obj, state, ((ArwingState*)state)->laserSide, 0, 1);
        ((ArwingState*)state)->laserSide = (((ArwingState*)state)->laserSide ^ 1) & 0xff;
    }
    ((ArwingState*)state)->fireCooldown = (f32)(u32)((ArwingState*)state)->fireDelay;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwing_update(GameObject* obj)
{
    int state = *(int*)&(obj)->extra;
    s16 camRot[3];
    f32 camPos[2];
    u8 mode;
    s16 wingRot;
    f32 timer;
    f32 throttle;
    int vv;

    if ((((ArwingState*)state)->flags477 & ARWING_FLAG_ACTIVE) == 0)
    {
        arwarwing_initAttachments(obj, state);
        return;
    }
    mode = ((ArwingState*)state)->mode;
    if (mode == ARWING_MODE_EXPLODE)
    {
        timer = ((ArwingState*)state)->modeTimer - timeDelta;
        ((ArwingState*)state)->modeTimer = timer;
        if (timer <= lbl_803E6ECC)
        {
            ((ArwingState*)state)->mode = ARWING_MODE_WARPOUT;
            (*gScreenTransitionInterface)->start(0x14, 1);
            ((ArwingState*)state)->modeTimer = lbl_803E6F34;
        }
        return;
    }
    if (mode == ARWING_MODE_WARPOUT)
    {
        timer = ((ArwingState*)state)->modeTimer - timeDelta;
        ((ArwingState*)state)->modeTimer = timer;
        if (timer <= lbl_803E6ECC)
        {
            if ((obj)->anim.mapEventSlot == 0x26)
            {
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x26), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                warpToMap(0x32, 0);
            }
            else
            {
                warpToMap(0x60, 0);
            }
        }
        return;
    }
    if (mode == ARWING_MODE_DEAD)
    {
        timer = ((ArwingState*)state)->modeTimer - timeDelta;
        ((ArwingState*)state)->modeTimer = timer;
        if (timer <= lbl_803E6ECC)
        {
            ((ArwingState*)state)->mode = ARWING_MODE_EXPLODE;
            ((ArwingState*)state)->modeTimer = gArwingExplodeModeTime;
            (obj)->anim.flags = (s16)((obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
            spawnExplosion((int)obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
        }
        ((ArwingState*)state)->rotZCur = (int)(lbl_803E6F6C * timeDelta + (f32)((ArwingState*)state)->rotZCur);
        (obj)->anim.rotZ = (s16)((ArwingState*)state)->rotZCur;
        ((ArwingState*)state)->velY = ((ArwingState*)state)->velY - lbl_803E6EF8 * timeDelta;
        objMove((int)obj, ((ArwingState*)state)->velX * timeDelta, ((ArwingState*)state)->velY * timeDelta,
                ((ArwingState*)state)->velZ * timeDelta);
        arwarwing_clampToFlightBounds(obj, state);
        ((GameObject*)((ArwingState*)state)->thrusterL)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ((GameObject*)((ArwingState*)state)->thrusterR)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        arwarwing_readControls(obj, state);
        if (((obj)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
        {
            *(s16*)&((ArwingState*)state)->inputFlags2 = 0;
            *(s16*)&((ArwingState*)state)->inputFlags = 0;
            ((GameObject*)((ArwingState*)state)->thrusterL)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ((GameObject*)((ArwingState*)state)->thrusterR)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
        else
        {
            ((GameObject*)((ArwingState*)state)->thrusterL)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            throttle = lbl_803E6FFC * timeDelta + (f32)(u32)((GameObject*)((ArwingState*)state)->thrusterL)->anim.alpha;
            if (throttle > lbl_803E7000)
                throttle = lbl_803E7000;
            ((GameObject*)((ArwingState*)state)->thrusterL)->anim.alpha = throttle;
            ((GameObject*)((ArwingState*)state)->thrusterR)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ((GameObject*)((ArwingState*)state)->thrusterR)->anim.alpha = throttle;
        }
        ((ArwingState*)state)->velTargetX = -((ArwingState*)state)->stickX * ((ArwingState*)state)->maxSpeedX;
        ((ArwingState*)state)->velTargetY = -((ArwingState*)state)->stickY * ((ArwingState*)state)->maxSpeedY;
        ((ArwingState*)state)->velTargetZ = ((ArwingState*)state)->maxSpeedZ * ((ArwingState*)state)->speedScaleZ;
        ((ArwingState*)state)->rotXTarget = (int)(-((ArwingState*)state)->stickX * ((ArwingState*)state)->rotXRange);
        ((ArwingState*)state)->rotYTarget = (int)(((ArwingState*)state)->stickY * ((ArwingState*)state)->rotYRange);
        ((ArwingState*)state)->rotZTarget = (int)(((ArwingState*)state)->stickX * ((ArwingState*)state)->rotZRange);
        ((ArwingState*)state)->rotZTrimTarget =
            (int)(((ArwingState*)state)->rotZTrimRange *
                  (((ArwingState*)state)->lTriggerTrim + ((ArwingState*)state)->rTriggerTrim));
        arwarwing_updateFlightPhysics(obj, state);
        arwarwing_updateWeaponFire(obj, state);
        arwarwing_updateBombFire(obj, state);

        *(s16*)(((ArwingState*)state)->wingVec[0] + 0) =
            (s16)((f32)(-((ArwingState*)state)->rotZCur) * ((ArwingState*)state)->wingFlexScale);
        *(s16*)(((ArwingState*)state)->wingVec[0] + 4) =
            (s16)((f32)((ArwingState*)state)->rotZCur * ((ArwingState*)state)->wingFlexScale);
        *(s16*)(((ArwingState*)state)->wingVec[1] + 0) =
            (s16)((f32)(-((ArwingState*)state)->rotZCur) * ((ArwingState*)state)->wingFlexScale);
        *(s16*)(((ArwingState*)state)->wingVec[1] + 4) =
            (s16)((f32)((ArwingState*)state)->rotZCur * ((ArwingState*)state)->wingFlexScale);
        wingRot = (s16)((f32)((ArwingState*)state)->rotZCur * ((ArwingState*)state)->wingFlexScale);
        *(s16*)(((ArwingState*)state)->wingVec[2] + 4) = wingRot;
        *(s16*)(((ArwingState*)state)->wingVec[2] + 0) = wingRot;
        wingRot = (s16)((f32)((ArwingState*)state)->rotZCur * ((ArwingState*)state)->wingFlexScale);
        *(s16*)(((ArwingState*)state)->wingVec[3] + 4) = wingRot;
        *(s16*)(((ArwingState*)state)->wingVec[3] + 0) = wingRot;

        wingRot = (s16)((f32)(-((ArwingState*)state)->rotYCur) * ((ArwingState*)state)->wingFlexScale +
                        (f32) * (s16*)(((ArwingState*)state)->wingVec[0] + 0));
        *(s16*)(((ArwingState*)state)->wingVec[0] + 0) = wingRot;
        wingRot = (s16)((f32)((ArwingState*)state)->rotYCur * ((ArwingState*)state)->wingFlexScale +
                        (f32) * (s16*)(((ArwingState*)state)->wingVec[0] + 4));
        *(s16*)(((ArwingState*)state)->wingVec[0] + 4) = wingRot;
        wingRot = (s16)((f32)(-((ArwingState*)state)->rotYCur) * ((ArwingState*)state)->wingFlexScale +
                        (f32) * (s16*)(((ArwingState*)state)->wingVec[1] + 0));
        *(s16*)(((ArwingState*)state)->wingVec[1] + 0) = wingRot;
        wingRot = (s16)((f32)((ArwingState*)state)->rotYCur * ((ArwingState*)state)->wingFlexScale +
                        (f32) * (s16*)(((ArwingState*)state)->wingVec[1] + 4));
        *(s16*)(((ArwingState*)state)->wingVec[1] + 4) = wingRot;
        wingRot = (s16)((f32)(-((ArwingState*)state)->rotYCur) * ((ArwingState*)state)->wingFlexScale +
                        (f32) * (s16*)(((ArwingState*)state)->wingVec[2] + 0));
        *(s16*)(((ArwingState*)state)->wingVec[2] + 0) = wingRot;
        wingRot = (s16)((f32)(-((ArwingState*)state)->rotYCur) * ((ArwingState*)state)->wingFlexScale +
                        (f32) * (s16*)(((ArwingState*)state)->wingVec[2] + 4));
        *(s16*)(((ArwingState*)state)->wingVec[2] + 4) = wingRot;
        wingRot = (s16)((f32)(-((ArwingState*)state)->rotYCur) * ((ArwingState*)state)->wingFlexScale +
                        (f32) * (s16*)(((ArwingState*)state)->wingVec[3] + 0));
        *(s16*)(((ArwingState*)state)->wingVec[3] + 0) = wingRot;
        wingRot = (s16)((f32)(-((ArwingState*)state)->rotYCur) * ((ArwingState*)state)->wingFlexScale +
                        (f32) * (s16*)((vv = ((ArwingState*)state)->wingVec[3]) + 4));
        *(s16*)(vv + 4) = wingRot;
    }

    arwarwing_updateRollAndEngine((int)obj, state);
    (*gCameraInterface)->releaseAction((void*)(state + 0x2c), 0xc);
    camRot[0] = (obj)->anim.rotX;
    camRot[1] = (obj)->anim.rotY;
    camRot[2] = (s16)((ArwingState*)state)->rotZCur;
    (*gCameraInterface)->releaseAction(camRot, 6);
    camPos[0] = ((ArwingState*)state)->maxSpeedZ;
    camPos[1] = ((ArwingState*)state)->velZ;
    (*gCameraInterface)->releaseAction(camPos, 8);
    arwarwing_handlePathDamage(obj, state);
    arwarwing_handleObjectDamage(obj, state);
    arwarwing_emitDamageEffects((int)obj, state);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwing_spawnLaserShot(GameObject* obj, int state, int side, int level, int linkEffect)
{
    f32 pz, py, px;
    int proj;
    if (Obj_IsLoadingLocked() == 0)
        return;
    if (side == 0)
    {
        ObjPath_GetPointWorldPosition(obj, 3, &px, &py, &pz, 0);
        arwarwinggu_setActiveVisible(((ArwingState*)state)->gunObjL, 1, level == 2);
    }
    else
    {
        ObjPath_GetPointWorldPosition(obj, 4, &px, &py, &pz, 0);
        arwarwinggu_setActiveVisible(((ArwingState*)state)->gunObjR, 1, level == 2);
    }
    {
        ArwArwingProjectileSetup* setup =
            (ArwArwingProjectileSetup*)Obj_AllocObjectSetup(0x20, ARWARWING_CHILD_OBJ_LASERSHOT);
        setup->posX = px;
        setup->posY = py;
        setup->posZ = pz;
        setup->rotZ = (obj)->anim.rotX >> 8;
        setup->rotY = (obj)->anim.rotY >> 8;
        setup->rotX = 0;
        setup->field04 = 1;
        setup->field05 = 1;
        proj = ((int (*)(int, void*))loadObjectAtObject)((int)obj, setup);
    }
    if ((void*)proj == NULL)
        return;
    if (level == 0)
    {
        Sfx_PlayFromObject(proj, SFXTRIG_ar_brakes16);
    }
    else if (level == 1)
    {
        Sfx_PlayFromObject(proj, SFXTRIG_ar_englp16);
    }
    else
    {
        Sfx_PlayFromObject(proj, SFXTRIG_ar_deflect16);
        Obj_SetActiveModelIndex((GameObject*)proj, 1);
    }
    if ((u8)linkEffect != 0)
        arwprojectile_createLinkedEffect((GameObject*)(proj), 1);
    arwprojectile_setLifetime((GameObject*)(proj), ((ArwingState*)state)->projLifetime);
    arwprojectile_placeForward((GameObject*)(proj), ((ArwingState*)state)->projSpeed);
}
#pragma scheduling reset
#pragma peephole reset

void arwarwing_addBomb(int arwing)
{
    ArwingState* state = ((GameObject*)arwing)->extra;
    if (state->bombCount < state->maxBombCount)
    {
        (state->bombCount)++;
    }
}

void arwarwing_upgradeLaserLevel(int arwing)
{
    ArwingState* state = ((GameObject*)arwing)->extra;
    if ((s8)state->laserLevel < 2)
    {
        (state->laserLevel)++;
    }
}

#pragma scheduling off
int arwarwing_isExplodingOrWarping(int arwing)
{
    int result = 0;
    u32 v = (*(ArwingState**)&((GameObject*)arwing)->extra)->mode;
    if (v == ARWING_MODE_EXPLODE || v == ARWING_MODE_WARPOUT)
    {
        result = 1;
    }
    return result;
}
#pragma scheduling reset

int arwarwing_isBarrelRolling(int arwing)
{
    return (*(ArwingState**)&((GameObject*)arwing)->extra)->mode == ARWING_MODE_BARRELROLL;
}

int arwarwing_isDead(int arwing)
{
    return (*(ArwingState**)&((GameObject*)arwing)->extra)->mode == ARWING_MODE_DEAD;
}

#pragma peephole off
#pragma scheduling off
void arwarwing_updateRollAndEngine(int obj, int state)
{
    int vec;
    f32 vol;
    f64 sum;

    vec = objModelGetVecFn_800395d8(((ArwingState*)state)->escortObj, 0x14);

    if (((ArwingState*)state)->mode < ARWING_MODE_DEAD && mainGetBit(GAMEBIT_ArwingRelated09D6) == 0 &&
        mainGetBit(GAMEBIT_ARWING_FLIGHT_RINGS_PASSED) == 0)
    {
        sum = lbl_803E6F48 + fn_802945E0(((ArwingState*)state)->velZ / ((ArwingState*)state)->maxSpeedZ);
        vol = (f32)(sum * lbl_803E6F50);
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_ar_boost16);
        Sfx_SetObjectChannelVolume(obj, 0x40, 0xfe, vol);
    }

    arwarwinggu_setTextureFrame(((ArwingState*)state)->escortObj, ((ArwingState*)state)->enginePitch);

    if (((ArwingState*)state)->rollCooldown <= lbl_803E6ECC)
    {
        if ((((ArwingState*)state)->flags477 & ARWING_FLAG_ROLL_LEFT) == 0)
        {
            if ((((ArwingState*)state)->inputFlags & 0x800) != 0)
            {
                ((ArwingState*)state)->flags477 &= ~ARWING_FLAG_ROLL_RIGHT;
                ((ArwingState*)state)->flags477 |= ARWING_FLAG_ROLL_LEFT;
                ((ArwingState*)state)->wingFlexTarget = lbl_803E6F58;
                Sfx_PlayFromObjectLimited(obj, SFXTRIG_ar_barrel16_2b6, 3);
            }
        }
        else
        {
            ((ArwingState*)state)->speedScaleZ = ((ArwingState*)state)->speedScaleRollL;
            ((ArwingState*)state)->accelZ = ((ArwingState*)state)->accelZRollL;
            if ((((ArwingState*)state)->inputFlagsPrev & 0x800) != 0)
            {
                ((ArwingState*)state)->flags477 &= ~ARWING_FLAG_ROLL_LEFT;
                ((ArwingState*)state)->wingFlexTarget = lbl_803E6F5C;
            }
        }
        if ((((ArwingState*)state)->flags477 & ARWING_FLAG_ROLL_RIGHT) == 0)
        {
            if ((((ArwingState*)state)->inputFlags & 0x400) != 0)
            {
                ((ArwingState*)state)->flags477 &= ~ARWING_FLAG_ROLL_LEFT;
                ((ArwingState*)state)->flags477 |= ARWING_FLAG_ROLL_RIGHT;
                ((ArwingState*)state)->wingFlexTarget = lbl_803E6F60;
                Sfx_PlayFromObjectLimited(obj, SFXTRIG_ar_bblast16, 3);
            }
        }
        else
        {
            ((ArwingState*)state)->speedScaleZ = ((ArwingState*)state)->speedScaleRollR;
            ((ArwingState*)state)->accelZ = ((ArwingState*)state)->accelZRollR;
            if ((((ArwingState*)state)->inputFlagsPrev & 0x400) != 0)
            {
                ((ArwingState*)state)->flags477 &= ~ARWING_FLAG_ROLL_RIGHT;
                ((ArwingState*)state)->wingFlexTarget = lbl_803E6F5C;
            }
        }
    }
    else
    {
        if ((((ArwingState*)state)->inputFlags & 0xc00) != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_generic_pickup);
        }
        ((ArwingState*)state)->rollCooldown -= timeDelta;
        if (((ArwingState*)state)->rollCooldown <= lbl_803E6ECC)
        {
            ((ArwingState*)state)->wingFlexTarget = lbl_803E6F5C;
        }
    }

    if ((((ArwingState*)state)->flags477 & ARWING_FLAG_ROLLING) == 0)
    {
        ((ArwingState*)state)->speedScaleZ = lbl_803E6ED0;
        ((ArwingState*)state)->accelZ = ((ArwingState*)state)->accelZNeutral;
        if (((ArwingState*)state)->rollRegenDelay <= lbl_803E6ECC)
        {
            ((ArwingState*)state)->rollEnergy = lbl_803E6F64 * timeDelta + ((ArwingState*)state)->rollEnergy;
        }
        else
        {
            ((ArwingState*)state)->rollRegenDelay -= timeDelta;
        }
    }
    else
    {
        ((ArwingState*)state)->rollEnergy -= timeDelta;
        ((ArwingState*)state)->rollRegenDelay = lbl_803E6F38;
    }

    ((ArwingState*)state)->rollEnergy =
        ((ArwingState*)state)
                ->rollEnergy<lbl_803E6ECC ? lbl_803E6ECC : ((ArwingState*)state)->rollEnergy>((ArwingState*)state)
                ->rollEnergyMax
            ? ((ArwingState*)state)->rollEnergyMax
            : ((ArwingState*)state)->rollEnergy;

    {
        f32 zero;
        if (((ArwingState*)state)->rollEnergy <= (zero = lbl_803E6ECC))
        {
            ((ArwingState*)state)->flags477 &= ~ARWING_FLAG_ROLLING;
            ((ArwingState*)state)->rollCooldown = ((ArwingState*)state)->rollCooldownInit;
            ((ArwingState*)state)->rollEnergy = ((ArwingState*)state)->rollEnergyMax;
            ((ArwingState*)state)->wingFlexTarget = lbl_803E6F68;
            ((ArwingState*)state)->rollRegenDelay = zero;
        }
    }

    if ((u32)vec != 0)
    {
        s16 flex;
        ((ArwingState*)state)->wingFlexCur +=
            lbl_803E6EF8 * (((ArwingState*)state)->wingFlexTarget - ((ArwingState*)state)->wingFlexCur);
        flex = (s16)((ArwingState*)state)->wingFlexCur;
        *(s16*)(vec + 0xa) = flex;
        *(s16*)(vec + 0x8) = flex;
        *(s16*)(vec + 0x6) = flex;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void arwarwing_clearAimSnapshot(GameObject* obj)
{
    (*(ArwingState**)&obj->extra)->aimSnapshotValid = 0;
}
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void arwarwing_initAttachments(GameObject* obj, int state)
{
    int found;
    int mev;
    f32 radius;
    f32 c6F7C;
    f32 c6F78;
    f32 c6F74;
    f32 c6FB0;
    f32 c6F5C;
    f32 c6EF0;

    radius = gArwingEscortSearchRadius;
    mev = (int)(*gMapEventInterface)->getCurCharacterState();

    if (((ArwingState*)state)->escortObj == NULL)
    {
        ((ArwingState*)state)->escortObj = ObjList_FindNearestObjectByDefNo(obj, 0x606, &radius);
        if (((ArwingState*)state)->escortObj != NULL)
        {
            ObjLink_AttachChild((int)obj, (int)((ArwingState*)state)->escortObj, 0);
        }
    }

    if (((ArwingState*)state)->fullLoadout != 0)
    {
        if (((ArwingState*)state)->bombObj == NULL)
        {
            ((ArwingState*)state)->bombObj = ObjList_FindNearestObjectByDefNo(obj, 0x611, &radius);
            if (((ArwingState*)state)->bombObj != NULL)
            {
                ObjLink_AttachChild((int)obj, (int)((ArwingState*)state)->bombObj, 0);
            }
        }
        if (((ArwingState*)state)->gunObjL == NULL)
        {
            ((ArwingState*)state)->gunObjL = ObjList_FindNearestObjectByDefNo(obj, 0x610, &radius);
            if (((ArwingState*)state)->gunObjL != NULL)
            {
                ObjLink_AttachChild((int)obj, (int)((ArwingState*)state)->gunObjL, 0);
            }
        }
        if (((ArwingState*)state)->gunObjR == NULL)
        {
            ((ArwingState*)state)->gunObjR = ObjList_FindNearestObjectByDefNo(obj, 0x615, &radius);
            if (((ArwingState*)state)->gunObjR != NULL)
            {
                ObjLink_AttachChild((int)obj, (int)((ArwingState*)state)->gunObjR, 0);
            }
        }
    }

    if (*(void**)&((ArwingState*)state)->thrusterL == 0 && *(void**)&((ArwingState*)state)->thrusterR == 0)
    {
        ArwArwingProjectileSetup* setup;
        setup = (ArwArwingProjectileSetup*)Obj_AllocObjectSetup(0x20, ARWARWING_CHILD_OBJ_THRUSTER);
        setup->field04 = 1;
        setup->field05 = 1;
        ((ArwingState*)state)->thrusterL = ((int (*)(int, int))loadObjectAtObject)((int)obj, (int)setup);
        setup = (ArwArwingProjectileSetup*)Obj_AllocObjectSetup(0x20, ARWARWING_CHILD_OBJ_THRUSTER);
        setup->field04 = 1;
        setup->field05 = 1;
        ((ArwingState*)state)->thrusterR = ((int (*)(int, int))loadObjectAtObject)((int)obj, (int)setup);
    }

    found = 0;
    if (((ArwingState*)state)->fullLoadout != 0)
    {
        if (((ArwingState*)state)->light == 0)
        {
            *(int*)&((ArwingState*)state)->light = (int)objCreateLight(obj, 1);
            if (((ArwingState*)state)->light != 0)
            {
                modelLightStruct_setLightKind(((ArwingState*)state)->light, MODEL_LIGHT_KIND_POINT);
                modelLightStruct_setPosition(((ArwingState*)state)->light, lbl_803E6ECC, lbl_803E6FC4, lbl_803E6FC8);
                lightSetFieldBC_8001db14(((ArwingState*)state)->light, 1);
                modelLightStruct_setDiffuseColor(((ArwingState*)state)->light, 0x28, 0x7d, 0xff, 0);
                modelLightStruct_setDistanceAttenuation(((ArwingState*)state)->light, lbl_803E6FCC, lbl_803E6FD0);
                modelLightStruct_startColorFade(((ArwingState*)state)->light, 1, 1);
                modelLightStruct_setDiffuseTargetColor(((ArwingState*)state)->light, 0x14, 0x64, 0xc8, 0);
            }
        }
        if (((ArwingState*)state)->escortObj != NULL && ((ArwingState*)state)->bombObj != NULL &&
            ((ArwingState*)state)->gunObjL != NULL && ((ArwingState*)state)->gunObjR != NULL)
        {
            found = 1;
        }
    }
    else
    {
        if (((ArwingState*)state)->escortObj != NULL)
        {
            found = 1;
        }
    }

    if (found != 0)
    {
        (*gCameraInterface)->setFocus((void*)obj, 0);
        ((ArwingState*)state)->flags477 |= ARWING_FLAG_ACTIVE;
        ((ArwingState*)state)->maxSpeedX = lbl_803E6F70;
        ((ArwingState*)state)->accelX = (c6F74 = lbl_803E6F74);
        ((ArwingState*)state)->maxSpeedY = (c6F78 = lbl_803E6F78);
        ((ArwingState*)state)->accelY = (c6F7C = lbl_803E6F7C);
        ((ArwingState*)state)->maxSpeedZ = c6F78;
        ((ArwingState*)state)->accelZ = c6F7C;
        ((ArwingState*)state)->maxAccelZ = lbl_803E6F80;
        ((ArwingState*)state)->minAccelZ = lbl_803E6F84;
        ((ArwingState*)state)->speedScaleZ = lbl_803E6ED0;
        ((ArwingState*)state)->rotXRange = lbl_803E6F88;
        ((ArwingState*)state)->rotXGain = c6F74;
        ((ArwingState*)state)->rotYRange = lbl_803E6F8C;
        ((ArwingState*)state)->rotYGain = c6F7C;
        ((ArwingState*)state)->rotZRange = lbl_803E6F90;
        ((ArwingState*)state)->rotZGain = lbl_803E6F94;
        ((ArwingState*)state)->rotZTrimRange = lbl_803E6F98;
        ((ArwingState*)state)->rotZTrimGain = lbl_803E6F9C;
        ((ArwingState*)state)->rotZBlendThreshold = lbl_803E6FA0;
        ((ArwingState*)state)->rotZBlendRate = lbl_803E6FA4;
        ((ArwingState*)state)->barrelRollSpeed = lbl_803E6FA8;
        ((ArwingState*)state)->unk3FA = 0x19;
        ((ArwingState*)state)->barrelRollDecelRange = lbl_803E6FAC;
        ((ArwingState*)state)->rootMotionScale = (c6FB0 = lbl_803E6FB0);
        (obj)->anim.rootMotionScale = c6FB0;
        ((ArwingState*)state)->barrelRollMaxSpeedScale = lbl_803E6FB4;
        ((ArwingState*)state)->barrelRollAccelScale = lbl_803E6FB8;
        ((ArwingState*)state)->speedScaleRollL = lbl_803E6FBC;
        ((ArwingState*)state)->speedScaleRollR = lbl_803E6F64;
        ((ArwingState*)state)->accelZRollL = lbl_803E6FD4;
        ((ArwingState*)state)->accelZRollR = c6F74;
        ((ArwingState*)state)->accelZNeutral = lbl_803E6FD8;
        ((ArwingState*)state)->rollCooldownInit = lbl_803E6FDC;
        ((ArwingState*)state)->rollEnergyMax = lbl_803E6FE0;
        ((ArwingState*)state)->altRollEnergyMax = lbl_803E6F2C;
        ((ArwingState*)state)->rollEnergy = ((ArwingState*)state)->rollEnergyMax;
        ((ArwingState*)state)->altRollEnergy = ((ArwingState*)state)->altRollEnergyMax;
        ((ArwingState*)state)->wingFlexCur = (c6F5C = lbl_803E6F5C);
        ((ArwingState*)state)->wingFlexTarget = c6F5C;
        if ((obj)->anim.mapEventSlot == 0x26)
        {
            ((ArwingState*)state)->velZ = lbl_803E6ECC;
        }
        else
        {
            ((ArwingState*)state)->velZ = c6F78;
        }
        *(s16*)&((ArwingState*)state)->projLifetime = 0x28;
        ((ArwingState*)state)->projSpeed = lbl_803E6FE0;
        *(s16*)&((ArwingState*)state)->fireDelay = 0x6;
        ((ArwingState*)state)->bombProjectileParam = 0x5a;
        ((ArwingState*)state)->bombProjectileLifetime = lbl_803E6F34;
        ((ArwingState*)state)->bombFireDelay = 0xc;
        ((ArwingState*)state)->maxBombCount = 0x3;
        ((ArwingState*)state)->wingVec[0] = objModelGetVecFn_800395d8(obj, 0);
        ((ArwingState*)state)->wingVec[1] = objModelGetVecFn_800395d8(obj, 1);
        ((ArwingState*)state)->wingVec[2] = objModelGetVecFn_800395d8(obj, 2);
        ((ArwingState*)state)->wingVec[3] = objModelGetVecFn_800395d8(obj, 3);
        ((ArwingState*)state)->wingFlexScale = lbl_803E6F64;
        *(s16*)&((ArwingState*)state)->enginePitch = 0xaf;
        ((ArwingState*)state)->maxHealth = *(u8*)(mev + 0x1);
        ((ArwingState*)state)->health = ((ArwingState*)state)->maxHealth;
        ((ArwingState*)state)->bobSpeedThreshold = lbl_803E6EF8;
        ((ArwingState*)state)->bobRotZRate = (c6EF0 = lbl_803E6EF0);
        ((ArwingState*)state)->bobRotZAmp = lbl_803E6FE4;
        ((ArwingState*)state)->bobXRate = lbl_803E6EF4;
        ((ArwingState*)state)->bobXAmp = lbl_803E6FD4;
        ((ArwingState*)state)->bobYRate = lbl_803E6FE8;
        ((ArwingState*)state)->bobYAmp = lbl_803E6F80;
        ((ArwingState*)state)->bobBlendRate = lbl_803E6FA4;
        ((ArwingState*)state)->homeX = (obj)->anim.localPosX;
        ((ArwingState*)state)->homeY = (obj)->anim.localPosY;
        ((ArwingState*)state)->homeZ = (obj)->anim.localPosZ;
        ((ArwingState*)state)->flightHalfWidth = lbl_803E6FEC;
        ((ArwingState*)state)->flightUpperHeight = lbl_803E6FF0;
        ((ArwingState*)state)->flightLowerHeight = c6EF0;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void arwarwing_resetFlightState(GameObject* obj)
{
    ArwingState* state = obj->extra;
    f32 v7c;
    f32 v74;
    f32 v78;

    state->maxSpeedX = lbl_803E6F70;
    state->accelX = v74 = lbl_803E6F74;
    state->maxSpeedY = v78 = lbl_803E6F78;
    state->accelY = v7c = lbl_803E6F7C;
    state->maxSpeedZ = v78;
    state->accelZ = v7c;
    state->maxAccelZ = lbl_803E6F80;
    state->minAccelZ = lbl_803E6F84;
    state->speedScaleZ = lbl_803E6ED0;
    state->rotXRange = lbl_803E6F88;
    state->rotXGain = v74;
    state->rotYRange = lbl_803E6F8C;
    state->rotYGain = v7c;
    state->rotZRange = lbl_803E6F90;
    state->rotZGain = lbl_803E6F94;
    state->rotZTrimRange = lbl_803E6F98;
    state->rotZTrimGain = lbl_803E6F9C;
    state->rotZBlendThreshold = lbl_803E6FA0;
    state->rotZBlendRate = lbl_803E6FA4;
    state->barrelRollSpeed = lbl_803E6FA8;
    state->unk3FA = 0x19;
    state->barrelRollDecelRange = lbl_803E6FAC;
    state->rootMotionScale = lbl_803E6FB0;
    state->barrelRollMaxSpeedScale = lbl_803E6FB4;
    state->barrelRollAccelScale = lbl_803E6FB8;
    state->speedScaleRollL = lbl_803E6FBC;
    state->speedScaleRollR = lbl_803E6F64;
    state->rollEnergy = state->rollEnergyMax;
    state->altRollEnergy = state->altRollEnergyMax;
    state->wingFlexTarget = state->wingFlexCur = lbl_803E6F5C;
    state->velZ = state->velY = state->velX = lbl_803E6ECC;
    state->laserLevel = 0;
    obj->anim.localPosX = state->homeX;
    obj->anim.localPosY = state->homeY;
    obj->anim.localPosZ = state->homeZ;
    state->rotYCur = 0;
    state->rotZCur = 0;
    obj->anim.rotX = 0;
    obj->anim.rotY = 0;
    obj->anim.rotZ = 0;
    arwarwingbo_setActiveVisible(state->bombObj, 0, 0);
}
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void arwarwing_handlePathDamage(GameObject* obj, int state)
{
    u8* pathBlock = ((ArwingState*)state)->pathBlock;
    int dmg;

    (*gPathControlInterface)->update((void*)obj, pathBlock, timeDelta);
    (*gPathControlInterface)->apply((void*)obj, pathBlock);
    (*gPathControlInterface)->advance((void*)obj, pathBlock, timeDelta);

    if (((ArwingState*)state)->hitShake == 0 || ((ArwingState*)state)->mode == ARWING_MODE_DEAD)
    {
        dmg = (s8)pathBlock[0x260];
        if (dmg == 0)
            return;
        if (((ArwingState*)state)->mode == ARWING_MODE_DEAD)
        {
            ((ArwingState*)state)->mode = ARWING_MODE_EXPLODE;
            ((ArwingState*)state)->modeTimer = gArwingExplodeModeTime;
            (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            spawnExplosion((int)obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
            return;
        }
        if ((dmg & 1) && (s8)pathBlock[0xb8] == 8)
            ((ArwingState*)state)->health = 0;
        else
            ((ArwingState*)state)->health--;
        doRumble(lbl_803E6F2C);
        if ((s8)((ArwingState*)state)->health <= 0)
        {
            arwarwingbo_setActiveVisible(((ArwingState*)state)->bombObj, 0, 0);
            if ((obj)->anim.mapEventSlot == 0x26)
                mainSetBits(GAMEBIT_ArwingRelated0E74, 1);
            else
                ((ArwingState*)state)->mode = ARWING_MODE_DEAD;
            ((ArwingState*)state)->modeTimer = lbl_803E6F30;
            Sfx_PlayFromObject((int)obj, SFXTRIG_barrelblow11);
            Music_Trigger(MUSICTRIG_dark_ice_boss_1, 1);
        }
        else if ((s8)((ArwingState*)(obj)->extra)->health <= 3)
        {
            Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_bomb_pickup);
        }
        Sfx_PlayFromObject((int)obj, SFXTRIG_wmap_select);
        ((Arw339Flags*)&((ArwingState*)state)->flags339)->scoreFlag = 1;
        Obj_SetModelColorFadeRecursive((int)obj, 0x4b, 0xc8, 0, 0, 1);
        ((ArwingState*)state)->damageFlashTimer = lbl_803E6F34;
        ((ArwingState*)state)->hitShake = 1;
        ((ArwingState*)state)->shakeYaw = 0;
        ((ArwingState*)state)->shakePitch = 0;
        ((ArwingState*)state)->knockVelX = *(f32*)(pathBlock + 0x1a0);
        ((ArwingState*)state)->knockVelZ = *(f32*)(pathBlock + 0x1a4);
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(lbl_803E6F38);
    }
    else
    {
        ((ArwingState*)state)->shakeYaw = lbl_803E6F3C * timeDelta + (f32) * (u16*)&((ArwingState*)state)->shakeYaw;
        ((ArwingState*)state)->shakePitch = lbl_803E6F40 * timeDelta + (f32) * (u16*)&((ArwingState*)state)->shakePitch;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
#pragma opt_common_subs off
void arwarwing_handleObjectDamage(GameObject* obj, int state)
{
    int hitVol;
    int hitObj;

    if (objGetFlagsE5_2((u8*)obj) != 0)
        return;
    if (ObjHits_GetPriorityHit(obj, &hitObj, 0, (u32*)&hitVol) != 0 && hitVol != 0)
    {
        if (((ArwingState*)state)->mode == ARWING_MODE_DEAD)
        {
            ((ArwingState*)state)->mode = ARWING_MODE_EXPLODE;
            ((ArwingState*)state)->modeTimer = gArwingExplodeModeTime;
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
            spawnExplosion((int)obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
        }
        else
        {
            if (((GameObject*)hitObj)->anim.seqId == 0x6ae && ((ArwingState*)state)->mode == ARWING_MODE_BARRELROLL)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_ar_blaunch16);
                return;
            }
            doRumble(lbl_803E6F2C);
            *(s8*)&((ArwingState*)state)->health = *(s8*)&((ArwingState*)state)->health - hitVol;
            Sfx_PlayFromObject((int)obj, SFXTRIG_wmap_select_2ac);
            ((Arw339Flags*)(state + 0x339))->scoreFlag = 1;
            Obj_SetModelColorFadeRecursive((int)obj, 0x4b, 0xc8, 0, 0, 1);
            ((ArwingState*)state)->damageFlashTimer = lbl_803E6F34;
            ((ArwingState*)state)->hitShake = 1;
            ((ArwingState*)state)->shakeYaw = 0;
            ((ArwingState*)state)->shakePitch = 0;
            {
                f32 knock = lbl_803E6ECC;
                ((ArwingState*)state)->knockVelX = knock;
                ((ArwingState*)state)->knockVelZ = knock;
            }
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E6F2C);
        }
    }
    if (((ArwingState*)state)->mode != ARWING_MODE_DEAD && ((ArwingState*)state)->mode != ARWING_MODE_EXPLODE &&
        ((ArwingState*)state)->mode != ARWING_MODE_WARPOUT && (s8)((ArwingState*)state)->health <= 0)
    {
        arwarwingbo_setActiveVisible(((ArwingState*)state)->bombObj, 0, 0);
        if (obj->anim.mapEventSlot == 0x26)
            mainSetBits(GAMEBIT_ArwingRelated0E74, 1);
        ((ArwingState*)state)->mode = ARWING_MODE_DEAD;
        ((ArwingState*)state)->modeTimer = lbl_803E6F30;
        Sfx_PlayFromObject((int)obj, SFXTRIG_barrelblow11);
        Music_Trigger(MUSICTRIG_dark_ice_boss_1, 1);
        unlockLevel(0, 0, 1);
        loadMapAndParent(0x29);
        lockLevel(mapGetDirIdx(0x29), 0);
    }
    else if ((s8)((ArwingState*)obj->extra)->health <= 3)
    {
        Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_bomb_pickup);
    }
}
#pragma opt_common_subs reset
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int arwarwing_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    int state = *(int*)&obj->extra;

    Camera_GetCurrentViewSlot();
    animUpdate->freeCallback = (ObjAnimSequenceFreeCallback)arwarwing_clearAimSnapshot;
    if ((((ArwingState*)state)->flags477 & ARWING_FLAG_ACTIVE) == 0)
    {
        arwarwing_initAttachments(obj, state);
        return 0;
    }
    arwarwing_updateRollAndEngine((int)obj, state);
    arwarwing_updateThrusters(obj, state);
    if (((ArwingState*)state)->bombObj != NULL)
        arwarwingbo_setActiveVisible(((ArwingState*)state)->bombObj, 0, 0);
    ((GameObject*)((ArwingState*)state)->thrusterL)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    ((GameObject*)((ArwingState*)state)->thrusterL)->anim.alpha = 0;
    ((GameObject*)((ArwingState*)state)->thrusterR)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    ((GameObject*)((ArwingState*)state)->thrusterR)->anim.alpha = 0;
    obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 8:
        {
            CameraViewSlot* cam = Camera_GetCurrentViewSlot();
            ((ArwingState*)state)->aimOffsetX = cam->x - obj->anim.localPosX;
            ((ArwingState*)state)->aimOffsetY = cam->y - obj->anim.localPosY;
            ((ArwingState*)state)->aimOffsetZ = cam->z - obj->anim.localPosZ;
            ((ArwingState*)state)->aimYaw = obj->anim.rotX - (u16)cam->yaw;
            if (((ArwingState*)state)->aimYaw > 32768)
                ((ArwingState*)state)->aimYaw = ((ArwingState*)state)->aimYaw - 65535;
            if (((ArwingState*)state)->aimYaw < -32768)
                ((ArwingState*)state)->aimYaw = ((ArwingState*)state)->aimYaw + 65535;
            ((ArwingState*)state)->aimPitch = obj->anim.rotY - (u16)cam->pitch;
            if (((ArwingState*)state)->aimPitch > 32768)
                ((ArwingState*)state)->aimPitch = ((ArwingState*)state)->aimPitch - 65535;
            if (((ArwingState*)state)->aimPitch < -32768)
                ((ArwingState*)state)->aimPitch = ((ArwingState*)state)->aimPitch + 65535;
            ((ArwingState*)state)->aimRoll = cam->roll - obj->anim.rotZ;
            ((ArwingState*)state)->aimSnapshotValid = 1;
            break;
        }
        case 9:
            ((ArwingState*)state)->aimSnapshotValid = 0;
            break;
        case 1:
            clearLoadedFileFlags_blocks1();
            warpToMap(0x60, 0);
            break;
        case 2:
            clearLoadedFileFlags_blocks1();
            arwarwing_warpByCourse(obj);
            break;
        case 0xa:
            if (Obj_IsLoadingLocked())
            {
                ArwArwingProjectileSetup* setup =
                    (ArwArwingProjectileSetup*)Obj_AllocObjectSetup(0x24, ARWARWING_CHILD_OBJ_BOMB);
                int loaded;
                setup->posX = obj->anim.localPosX;
                setup->posY = obj->anim.localPosY;
                setup->posZ = obj->anim.localPosZ;
                setup->field04 = 1;
                setup->field05 = 1;
                loaded = ((int (*)(void*, int))loadObjectAtObject)(obj, (int)setup);
                if ((void*)loaded != 0)
                    arwbombcoll_setLifetime((GameObject*)(loaded), 0x12c);
            }
            break;
        case 0xb:
            ((ArwingState*)state)->bombCount = 1;
            arwarwing_spawnBomb(obj, state, ((ArwingState*)state)->bombSide);
            ((ArwingState*)state)->bombSide ^= 1;
            break;
        case 0xc:
            arwarwing_spawnLaserShot(obj, state, 0, 1, 1);
            arwarwing_spawnLaserShot(obj, state, 1, 1, 0);
            break;
        case 4:
            unlockLevel(0, 0, 1);
            mapUnload(0, 0x80000000);
            setLoadedFileFlags_blocks1();
            break;
        case 5:
            if (((ArwingState*)state)->levelIndex == 0 && mainGetBit(GAMEBIT_ITEM_Spirit5_Got))
            {
                loadMapAndParent(0xb);
                lockLevel(mapGetDirIdx(0xb), 0);
            }
            else
            {
                loadMapAndParent(gArwingCourseMapIds[((ArwingState*)state)->levelIndex]);
                lockLevel(mapGetDirIdx(gArwingCourseMapIds[((ArwingState*)state)->levelIndex]), 0);
            }
            switch (obj->anim.mapEventSlot)
            {
            case 0x3a:
                break;
            case 0x3b:
                (*gMapEventInterface)->setObjGroupStatus(0x13, 0, 1);
                (*gMapEventInterface)->setObjGroupStatus(0x13, 0x16, 1);
                break;
            case 0x3d:
                mainSetBits(GAMEBIT_WC_ObjGroups, 0);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 0, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 1, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 5, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 0xa, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 0xb, 1);
                mainSetBits(GAMEBIT_WC_MagicCaveRelated0E05, 0);
                break;
            case 0x3c:
                mainSetBits(GAMEBIT_CF_ObjGroups, 0);
                mainSetBits(GAMEBIT_CD_ObjGroups, 0);
                mainSetBits(GAMEBIT_CF_ObjGroups2, 0);
                (*gMapEventInterface)->setObjGroupStatus(0xc, 0, 1);
                mainSetBits(GAMEBIT_CFRelated0D73, 0);
                break;
            case 0x3e:
                mainSetBits(GAMEBIT_DR_ObjGroups, 0);
                (*gMapEventInterface)->setObjGroupStatus(2, 0xf, 1);
                (*gMapEventInterface)->setObjGroupStatus(2, 0x10, 1);
                mainSetBits(GAMEBIT_DRArwingRelated0E7B, 0);
                mainSetBits(GAMEBIT_DR_FlewTo, 0);
                break;
            }
            break;
        case 6:
            unlockLevel(0, 0, 1);
            loadMapAndParent(0x29);
            lockLevel(mapGetDirIdx(0x29), 0);
            break;
        case 7:
            if (!((Arw339Flags*)(state + 0x339))->scoreFlag)
            {
                int s2 = *(int*)&obj->extra;
                int score47C;
                ((ArwarwingState*)s2)->bonusScore += 0xc8;
                score47C = ((ArwarwingState*)s2)->bonusScore;
                if ((u16)score47C > 0x270f)
                    score47C = 0x270f;
                ((ArwarwingState*)s2)->bonusScore = score47C;
            }
            registerNewScore((s8)((ArwingState*)state)->scoreSlot, ((ArwingState*)state)->score,
                             ((ArwingState*)state)->collectedRings, 2);
            break;
        case 0xd:
            gameTextFn_80125ba4(0x13);
            break;
        case 0xe:
            gameTextFn_80125ba4(0x14);
            break;
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void arwarwing_init(GameObject* obj)
{
    int state;
    u8* pathBlock;
    ArwInitCfg cfg;

    *(ArwInitCfgAB*)&cfg = *(ArwInitCfgAB*)&gArwingInitConfig;
    cfg.c = gArwingInitConfig.c;
    state = *(int*)&(obj)->extra;
    pathBlock = ((ArwingState*)state)->pathBlock;
    (obj)->animEventCallback = arwarwing_SeqFn;
    (*gPathControlInterface)->init(pathBlock, 4, 0x1040006, 1);
    (*gPathControlInterface)->setup(pathBlock, 3, gArwingPathSetupData, sArwingPathName, &cfg);
    (*gPathControlInterface)->attachObject((void*)obj, pathBlock);
    ObjGroup_AddObject((int)obj, ARWARWING_OBJGROUP);
    gArwing = (int)obj;
    ObjHits_SetTargetMask((int)obj, 1);
    ((ArwingState*)state)->fullLoadout = 1;
    switch ((obj)->anim.mapEventSlot - 0x26)
    {
    case 27:
    default:
        ((ArwingState*)state)->fullLoadout = 0;
        break;
    case 20:
        ((ArwingState*)state)->levelIndex = 0;
        ((ArwingState*)state)->requiredRings = 1;
        ((ArwingState*)state)->scoreSlot = 0;
        break;
    case 21:
        ((ArwingState*)state)->levelIndex = 1;
        ((ArwingState*)state)->requiredRings = 3;
        ((ArwingState*)state)->scoreSlot = 1;
        break;
    case 23:
        ((ArwingState*)state)->levelIndex = 2;
        ((ArwingState*)state)->requiredRings = 7;
        ((ArwingState*)state)->scoreSlot = 3;
        break;
    case 22:
        ((ArwingState*)state)->levelIndex = 3;
        ((ArwingState*)state)->requiredRings = 5;
        ((ArwingState*)state)->scoreSlot = 2;
        break;
    case 24:
        ((ArwingState*)state)->levelIndex = 4;
        ((ArwingState*)state)->requiredRings = 0xa;
        ((ArwingState*)state)->scoreSlot = 4;
        break;
    case 0:
        break;
    }
}
#pragma scheduling reset

int gArwingPathSetupData[30] = {
    0,           0,           0,           1103626240,  -1073741824, -1038090240, -1043857408, -1073741824,
    -1038090240, 0,           0,           1110179840,  1095761920,  0,           -1049624576, -1051721728,
    0,           -1049624576, 1102577664,  0,           -1041235968, -1044905984, 0,           -1041235968,
    1095761920,  1097859072,  -1044381696, -1051721728, 1097859072,  -1044381696,
};

int sArwingPathName[] = {
    1097859072, 1082130432, 1082130432, 1082130432, 1092616192,
    1092616192, 1092616192, 1092616192, 1084227584, 1084227584,
};
