#include "ghidra_import.h"
#include "main/dll/WC/WCpushblock.h"

#define WCPUSHBLOCK_SPAWN_OBJECT_ID 0x119
#define WCPUSHBLOCK_SPAWN_SETUP_SIZE 0x18
#define WCPUSHBLOCK_SPAWN_PATH_POINT 4
#define WCPUSHBLOCK_SPAWN_SFX 0x127
#define WCPUSHBLOCK_SPAWN_IDLE_TIMER 0x5a

#define WCPUSHBLOCK_INPUT_SCALE 70
#define WCPUSHBLOCK_PITCH_INPUT_SCALE 0x1770
#define WCPUSHBLOCK_ROLL_INPUT_SCALE 0x2ee0
#define WCPUSHBLOCK_YAW_DRIFT_SCALE 8
#define WCPUSHBLOCK_ANGLE_DAMP_SHIFT 5
#define WCPUSHBLOCK_MAX_PITCH 0x1f40
#define WCPUSHBLOCK_MAX_ROLL 0x32c8
#define WCPUSHBLOCK_RIDE_MOVE_ID 0xf

typedef struct WCPushBlockObjectSetup {
    u8 pad0[4];
    u8 placementMode;
    u8 group;
    u8 linkA;
    u8 linkB;
    f32 x;
    f32 y;
    f32 z;
} WCPushBlockObjectSetup;

typedef struct WCPushBlockRotationWork {
    s16 yaw;
    s16 pitch;
    s16 roll;
    s16 pad;
    f32 scale;
    f32 zeroX;
    f32 zeroY;
    f32 zeroZ;
} WCPushBlockRotationWork;

typedef struct WCPushBlockObject {
    s16 yaw;
    s16 pitch;
    s16 roll;
    u8 pad6[0x1e];
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    u8 pad30[0x70];
    s16 currentMove;
    u8 padA2[0x52];
    int actionState;
    void *spawnPath;
} WCPushBlockObject;

typedef struct WCPushBlockState {
    u8 pad0[0x10];
    void *linkedPushBlock;
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

typedef struct WCPushBlockCloudActionInterface {
    u8 pad0[0x20];
    void (*setRotorAngle)(s16 angle);
    void (*moveRelative)(f32 x, f32 z);
} WCPushBlockCloudActionInterface;

extern u8 Obj_IsLoadingLocked(void);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void mathFn_80021ac8(void *angles, void *out);
extern WCPushBlockObjectSetup *Obj_AllocObjectSetup(int size, int objectId);
extern WCPushBlockObject *Obj_SetupObject(WCPushBlockObjectSetup *setup, int mode, int mapLayer,
                                          int linkId, void *parent);
extern void ObjPath_GetPointWorldPosition(s16 *path, int pointIndex, f32 *outX, f32 *outY,
                                          f32 *outZ, int useInputPosition);
extern int ObjAnim_SetCurrentMove(int obj, int moveId, f32 moveProgress, int flags);
extern int ObjAnim_AdvanceCurrentMove();
extern f32 sin(f32 x);
extern f32 fn_80293E80(f32 x);

extern WCPushBlockCloudActionInterface **gCloudActionInterface;
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

typedef int (*ObjAnimAdvanceObjectFirstFn)(int obj, f32 moveStepScale, f32 deltaTime, void *events);

#pragma scheduling off
#pragma peephole off
void WCPushBlock_SpawnFromPath(s16 *path)
{
    WCPushBlockObjectSetup *setup;
    WCPushBlockObject *block;
    f32 outVec[3];
    WCPushBlockRotationWork rotation;

    if (Obj_IsLoadingLocked() == 0) {
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
    mathFn_80021ac8(&rotation, outVec);

    setup = Obj_AllocObjectSetup(WCPUSHBLOCK_SPAWN_SETUP_SIZE, WCPUSHBLOCK_SPAWN_OBJECT_ID);
    setup->linkA = 0xff;
    setup->linkB = 0xff;
    setup->placementMode = 2;
    setup->group = 1;
    ObjPath_GetPointWorldPosition(path, WCPUSHBLOCK_SPAWN_PATH_POINT, &setup->x, &setup->y,
                                  &setup->z, 0);

    block = Obj_SetupObject(setup, 5, -1, -1, NULL);
    if (block == NULL) {
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
    mathFn_80021ac8(&rotation, outVec);

    block->velocityX = outVec[0];
    block->velocityY = outVec[1];
    block->velocityZ = outVec[2];
    block->actionState = WCPUSHBLOCK_SPAWN_IDLE_TIMER;
    block->spawnPath = path;
    block->roll = 0;
    block->pitch = 0;
    block->yaw = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void WCPushBlock_UpdateCloudAction(int obj, WCPushBlockState *state)
{
    f32 angle;
    f32 angleSin;
    f32 angleCos;
    f32 targetLift;
    f32 baseLift;
    f32 moveX;
    f32 moveZ;

    (void)obj;

    (*gCloudActionInterface)->setRotorAngle(state->rotorAngle);

    angle = (lbl_803E5C84 * (f32)state->rotorAngle) / lbl_803E5C88;
    angleSin = sin(angle);
    angle = (lbl_803E5C84 * (f32)state->rotorAngle) / lbl_803E5C88;
    angleCos = fn_80293E80(angle);

    if (state->linkedPushBlock != NULL) {
        targetLift = (f32)state->pushRoll / lbl_803E5C8C;
    } else {
        targetLift = lbl_803E5C70;
    }
    state->liftAmount += (targetLift - state->liftAmount) * timeDelta * lbl_803E5C90;

    baseLift = lbl_803E5C94;
    moveZ = baseLift * -angleSin;
    moveX = angleCos * baseLift;
    moveX += angleSin * -state->liftAmount;
    moveZ += angleCos * -state->liftAmount;

    state->bankAmount = state->liftAmount;
    state->liftBase = baseLift;

    moveZ = (moveZ * timeDelta) / lbl_803E5C98;
    moveX = (moveX * timeDelta) / lbl_803E5C98;
    (*gCloudActionInterface)->moveRelative(moveZ, moveX);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void WCPushBlock_UpdateRideTilt(WCPushBlockObject *obj, WCPushBlockState *state)
{
    int targetPitch;
    int targetRoll;
    int pitchDelta;
    int rollDelta;
    int pitch;
    int roll;

    targetPitch = (-(s32)state->stickY * WCPUSHBLOCK_PITCH_INPUT_SCALE) / WCPUSHBLOCK_INPUT_SCALE;
    targetRoll = (-(s32)state->stickX * WCPUSHBLOCK_ROLL_INPUT_SCALE) / WCPUSHBLOCK_INPUT_SCALE;

    state->cloudYawDrift =
        (s16)((f32)state->cloudYawDrift -
              (((f32)(state->stickX << 3) / lbl_803E5C98) * timeDelta));
    state->cloudYawDrift =
        (s16)(state->cloudYawDrift -
              ((state->cloudYawDrift * framesThisStep) >> WCPUSHBLOCK_ANGLE_DAMP_SHIFT));

    pitchDelta = targetPitch - (u16)obj->pitch;
    if (pitchDelta > 0x8000) {
        pitchDelta -= 0xffff;
    }
    if (pitchDelta < -0x8000) {
        pitchDelta += 0xffff;
    }

    obj->pitch = (s16)((f32)obj->pitch + (lbl_803E5CA8 * ((f32)pitchDelta * timeDelta)));

    rollDelta = targetRoll - (u16)state->pushRoll;
    if (rollDelta > 0x8000) {
        rollDelta -= 0xffff;
    }
    if (rollDelta < -0x8000) {
        rollDelta += 0xffff;
    }

    state->pushRoll =
        (s16)((f32)state->pushRoll + (lbl_803E5CA8 * ((f32)rollDelta * timeDelta)));

    pitch = obj->pitch;
    if (pitch < -WCPUSHBLOCK_MAX_PITCH) {
        pitch = -WCPUSHBLOCK_MAX_PITCH;
    } else if (pitch > WCPUSHBLOCK_MAX_PITCH) {
        pitch = WCPUSHBLOCK_MAX_PITCH;
    }
    obj->pitch = (s16)pitch;

    roll = state->pushRoll;
    if (roll < -WCPUSHBLOCK_MAX_ROLL) {
        roll = -WCPUSHBLOCK_MAX_ROLL;
    } else if (roll > WCPUSHBLOCK_MAX_ROLL) {
        roll = WCPUSHBLOCK_MAX_ROLL;
    }
    state->pushRoll = (s16)roll;

    obj->yaw = (s16)(state->cloudYawDrift + 0x4000);
    obj->roll = state->pushRoll;

    if (obj->currentMove != WCPUSHBLOCK_RIDE_MOVE_ID) {
        ObjAnim_SetCurrentMove((int)obj, WCPUSHBLOCK_RIDE_MOVE_ID, lbl_803E5C70, 0);
    }

    if (((ObjAnimAdvanceObjectFirstFn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E5CAC,
                                                                  timeDelta, NULL) != 0) {
        state->rideState = 0;
    }

    obj->actionState = 1;
}
#pragma peephole reset
#pragma scheduling reset
