/*
 * wcpushblock (cloud-ride variant, Walled City) - a path-spawned rideable
 * cloud/push block. WCPushBlock_SpawnFromPath only spawns while object
 * loading is locked: it rotates a base vector by the path's yaw/pitch/roll
 * (vecRotateZXY) to seed the block's velocity, allocates a 0x18-byte object
 * setup (id WCPUSHBLOCK_SPAWN_OBJECT_ID, group 1) at path point 4, and arms
 * a spawn idle timer and spawn sfx. WCPushBlock_UpdateCloudAction drives a
 * rotor/cloud platform through gCloudActionInterface (setRotorAngle +
 * moveRelative), easing a lift amount toward a push-roll-derived target and
 * converting the rotor angle into a sin/cos planar move.
 * WCPushBlock_UpdateRideTilt reads the rider's analog stick, integrates
 * pitch/roll toward scaled targets with wrap-around and per-axis clamps
 * (MAX_PITCH/MAX_ROLL), applies a damped yaw drift and advances the ride
 * animation move.
 *
 * This is a distinct DLL from the tile-grid wcpushblock (DLL 0x290); it
 * does not use the WCLevelContInterface controller protocol and keeps its
 * own externs (their signatures differ from dll_80220608_shared.h).
 */
#include "main/audio/sfx.h"
#include "main/game_object.h"

#define WCPUSHBLOCK_SPAWN_OBJECT_ID 0x119
#define WCPUSHBLOCK_SPAWN_SETUP_SIZE 0x18
#define WCPUSHBLOCK_SPAWN_PATH_POINT 4
#define WCPUSHBLOCK_SPAWN_SFX 0x127
#define WCPUSHBLOCK_SPAWN_IDLE_TIMER 0x5a

#define WCPUSHBLOCK_INPUT_SCALE 70
#define WCPUSHBLOCK_PITCH_INPUT_SCALE 0x1770
#define WCPUSHBLOCK_ROLL_INPUT_SCALE 0x2ee0
#define WCPUSHBLOCK_ANGLE_DAMP_SHIFT 5
#define WCPUSHBLOCK_MAX_PITCH 0x1f40
#define WCPUSHBLOCK_MAX_ROLL 0x32c8
#define WCPUSHBLOCK_RIDE_MOVE_ID 0xf

typedef struct WCPushBlockObjectSetup
{
    u8 pad0[4];
    u8 placementMode;
    u8 group;
    u8 linkA;
    u8 linkB;
    f32 x;
    f32 y;
    f32 z;
} WCPushBlockObjectSetup;

typedef struct WCPushBlockRotationWork
{
    s16 yaw;
    s16 pitch;
    s16 roll;
    s16 pad;
    f32 scale;
    f32 zeroX;
    f32 zeroY;
    f32 zeroZ;
} WCPushBlockRotationWork;

typedef struct WCPushBlockObject
{
    union
    {
        ObjAnimComponent anim;
        struct
        {
            s16 yaw;
            s16 pitch;
            s16 roll;
            u8 pad6[0x1e];
            f32 velocityX;
            f32 velocityY;
            f32 velocityZ;
            u8 pad30[0x70];
            s16 currentMove;
            u8 padA2[0xA4 - 0xA2];
            void* linkedObject;
            u8 padA8[0xB0 - 0xA8];
        };
    };
    u8 padB0[0xF4 - sizeof(ObjAnimComponent)];
    int actionState;
    void* spawnPath;
} WCPushBlockObject;

STATIC_ASSERT(offsetof(WCPushBlockObject, anim) == 0x00);
STATIC_ASSERT(offsetof(WCPushBlockObject, velocityX) == offsetof(ObjAnimComponent, velocityX));
STATIC_ASSERT(offsetof(WCPushBlockObject, currentMove) == offsetof(ObjAnimComponent, currentMove));
STATIC_ASSERT(offsetof(WCPushBlockObject, linkedObject) == offsetof(ObjAnimComponent, targetObj));
STATIC_ASSERT(offsetof(WCPushBlockObject, actionState) == offsetof(GameObject, unkF4));
STATIC_ASSERT(offsetof(WCPushBlockObject, spawnPath) == offsetof(GameObject, unkF8));

typedef struct WCPushBlockState
{
    u8 pad0[0x10];
    void* linkedPushBlock;
    u8 pad14[0x18];
    s16 cloudYawDrift;
    s16 pushRoll;
    u8 pad30[0x30];
    f32 liftAmount;
    u8 pad64;
    s8 rideState;
    u8 pad66[4];
    s16 rotorAngle;
    u8 pad6C[4];
    int stickX;
    int stickY;
    f32 bankAmount;
    f32 liftBase;
} WCPushBlockState;

typedef struct WCPushBlockCloudActionInterface
{
    u8 pad0[0x20];
    void (*setRotorAngle)(s16 angle);
    void (*pad24)(void);
    void (*moveRelative)(f32 x, f32 z);
} WCPushBlockCloudActionInterface;

extern u8 Obj_IsLoadingLocked(void);
extern void vecRotateZXY(void* angles, void* out);
extern WCPushBlockObjectSetup* Obj_AllocObjectSetup(int size, int objectId);
extern WCPushBlockObject* Obj_SetupObject(WCPushBlockObjectSetup* setup, int mode, int mapLayer,
                                          int linkId, void* parent);
extern void ObjPath_GetPointWorldPosition(s16* path, int pointIndex, f32* outX, f32* outY,
                                          f32* outZ, int useInputPosition);
extern f32 mathCosf(f32 x);
extern f32 mathSinf(f32 x);

extern WCPushBlockCloudActionInterface** gCloudActionInterface;
extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E5C70;
extern f32 lbl_803E5C74;
extern f32 lbl_803E5C78;
extern f32 lbl_803E5C7C;
extern f32 lbl_803E5C80;
extern f32 lbl_803E5C84;
extern f32 lbl_803E5C88;
extern f32 lbl_803E5C8C;
extern f32 lbl_803E5C90;
extern f32 lbl_803E5C94;
extern f32 lbl_803E5C98;
extern f32 lbl_803E5CA8;
extern f32 lbl_803E5CAC;

void WCPushBlock_SpawnFromPath(s16* path)
{
    WCPushBlockObjectSetup* setup;
    WCPushBlockObject* block;
    f32 outVec[3];
    WCPushBlockRotationWork rotation;

    if (Obj_IsLoadingLocked() == 0)
    {
        return;
    }

    Sfx_PlayFromObject(0, WCPUSHBLOCK_SPAWN_SFX);

    rotation.zeroX = lbl_803E5C70;
    rotation.zeroY = lbl_803E5C70;
    rotation.zeroZ = lbl_803E5C70;
    rotation.scale = lbl_803E5C74;
    rotation.yaw = path[0];
    rotation.pitch = path[1];
    rotation.roll = path[2];
    outVec[0] = lbl_803E5C70;
    outVec[1] = lbl_803E5C78;
    outVec[2] = lbl_803E5C7C;
    vecRotateZXY(&rotation, outVec);

    setup = Obj_AllocObjectSetup(WCPUSHBLOCK_SPAWN_SETUP_SIZE, WCPUSHBLOCK_SPAWN_OBJECT_ID);
    setup->linkA = 0xff;
    setup->linkB = 0xff;
    setup->placementMode = 2;
    setup->group = 1;
    ObjPath_GetPointWorldPosition(path, WCPUSHBLOCK_SPAWN_PATH_POINT, &setup->x, &setup->y,
                                  &setup->z, 0);

    block = Obj_SetupObject(setup, 5, -1, -1, NULL);
    if (block == NULL)
    {
        return;
    }

    rotation.zeroX = lbl_803E5C70;
    rotation.zeroY = lbl_803E5C70;
    rotation.zeroZ = lbl_803E5C70;
    rotation.scale = lbl_803E5C74;
    rotation.yaw = path[0];
    rotation.pitch = path[1];
    rotation.roll = 0;
    outVec[0] = lbl_803E5C70;
    outVec[1] = lbl_803E5C70;
    outVec[2] = lbl_803E5C80;
    vecRotateZXY(&rotation, outVec);

    block->velocityX = outVec[0];
    block->velocityY = outVec[1];
    block->velocityZ = outVec[2];
    block->actionState = WCPUSHBLOCK_SPAWN_IDLE_TIMER;
    block->spawnPath = path;
    block->roll = 0;
    block->pitch = 0;
    block->yaw = 0;
}

void WCPushBlock_UpdateCloudAction(int obj, WCPushBlockState* state)
{
    f32 angle;
    f32 rotorCos;
    f32 rotorSin;
    f32 targetLift;
    f32 baseLift;
    f32 moveX;
    f32 moveZ;
    f32 liftStep;

    (void)obj;

    (*gCloudActionInterface)->setRotorAngle(state->rotorAngle);

    angle = (lbl_803E5C84 * state->rotorAngle) / lbl_803E5C88;
    rotorCos = mathCosf(angle);
    angle = (lbl_803E5C84 * state->rotorAngle) / lbl_803E5C88;
    rotorSin = mathSinf(angle);

    if (state->linkedPushBlock != NULL)
    {
        targetLift = state->pushRoll / lbl_803E5C8C;
    }
    else
    {
        targetLift = lbl_803E5C70;
    }
    liftStep = (targetLift - state->liftAmount) * timeDelta;
    state->liftAmount += liftStep * lbl_803E5C90;

    baseLift = lbl_803E5C94;
    moveX = baseLift * rotorSin;
    moveZ = baseLift * -rotorCos;
    moveX += rotorCos * -state->liftAmount;
    moveZ += rotorSin * -state->liftAmount;

    state->bankAmount = state->liftAmount;
    state->liftBase = baseLift;

    moveZ = moveZ * timeDelta;
    moveX = moveX * timeDelta;
    moveZ = moveZ / lbl_803E5C98;
    moveX = moveX / lbl_803E5C98;
    (*gCloudActionInterface)->moveRelative(moveZ, moveX);
}

void WCPushBlock_UpdateRideTilt(WCPushBlockObject* obj, WCPushBlockState* state)
{
    int targetPitch;
    int targetRoll;
    int pitchDelta;
    int rollDelta;
    int pitch;
    int roll;

    targetPitch = (-state->stickY * WCPUSHBLOCK_PITCH_INPUT_SCALE) / WCPUSHBLOCK_INPUT_SCALE;
    targetRoll = (-state->stickX * WCPUSHBLOCK_ROLL_INPUT_SCALE) / WCPUSHBLOCK_INPUT_SCALE;

    {
        f32 t = (f32)(state->stickX << 3) / lbl_803E5C98;
        state->cloudYawDrift = (s16)(-(t * timeDelta - state->cloudYawDrift));
    }
    state->cloudYawDrift =
        (s16)(state->cloudYawDrift -
            ((state->cloudYawDrift * framesThisStep) >> WCPUSHBLOCK_ANGLE_DAMP_SHIFT));

    pitchDelta = targetPitch - (u16)obj->pitch;
    if (pitchDelta > 0x8000)
    {
        pitchDelta = (pitchDelta - 0x10000) + 1;
    }
    if (pitchDelta < -0x8000)
    {
        pitchDelta = (pitchDelta + 0x10000) - 1;
    }

    obj->pitch = (s16)(lbl_803E5CA8 * ((f32)pitchDelta * timeDelta) + (f32) * (s16*)(int)&obj->pitch);

    rollDelta = targetRoll - (u16)state->pushRoll;
    if (rollDelta > 0x8000)
    {
        rollDelta = (rollDelta - 0x10000) + 1;
    }
    if (rollDelta < -0x8000)
    {
        rollDelta = (rollDelta + 0x10000) - 1;
    }

    state->pushRoll =
        (s16)(lbl_803E5CA8 * ((f32)rollDelta * timeDelta) + (f32) * (s16*)(int)&state->pushRoll);

    pitch = obj->pitch;
    if (pitch < -WCPUSHBLOCK_MAX_PITCH)
    {
        pitch = -WCPUSHBLOCK_MAX_PITCH;
    }
    else if (pitch > WCPUSHBLOCK_MAX_PITCH)
    {
        pitch = WCPUSHBLOCK_MAX_PITCH;
    }
    obj->pitch = pitch;

    roll = state->pushRoll;
    if (roll < -WCPUSHBLOCK_MAX_ROLL)
    {
        roll = -WCPUSHBLOCK_MAX_ROLL;
    }
    else if (roll > WCPUSHBLOCK_MAX_ROLL)
    {
        roll = WCPUSHBLOCK_MAX_ROLL;
    }
    state->pushRoll = roll;

    obj->yaw = (s16)(state->cloudYawDrift + 0x4000);
    obj->roll = state->pushRoll;

    if (obj->currentMove != WCPUSHBLOCK_RIDE_MOVE_ID)
    {
        ObjAnim_SetCurrentMove((int)obj, WCPUSHBLOCK_RIDE_MOVE_ID, lbl_803E5C70, 0);
    }

    if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E5CAC,
                                                                     timeDelta, NULL) != 0)
    {
        state->rideState = 0;
    }

    obj->actionState = 1;
}
