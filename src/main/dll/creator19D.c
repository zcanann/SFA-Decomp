#include "ghidra_import.h"
#include "main/dll/creator19D.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006814();
extern undefined4 FUN_80006824();
extern int FUN_80017a98();
extern undefined4 ObjMsg_SendToObject();
extern void ObjMsg_AllocQueue(void *obj,int capacity);
extern void *Obj_GetPlayerObject(void);
extern int ObjAnim_AdvanceCurrentMove(f32 moveStepScale,f32 deltaTime,int objAnim,void *events);
extern s16 getAngle(f32 deltaX,f32 deltaZ);
extern f32 Vec_xzDistance(f32 *a,f32 *b);
extern void fn_8011F6D4(int enable);
extern void fn_8011F6E0(u8 channel,u8 param,s16 value);
extern int padGetStickX(int controller);
extern u32 randomGetRange(int min,int max);
extern void *Resource_Acquire(int id,int count);
extern void *textureLoadAsset(int id);
extern f32 fn_80293E80(f32 x);
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern int FUN_80294d6c();

extern undefined4 DAT_803dc070;
extern f32 timeDelta;
extern void *lbl_803DDBB8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803de838;
extern f64 DOUBLE_803e5b98;
extern f32 lbl_803DC074;
extern f32 lbl_803E4EC0;
extern f32 lbl_803E4F08;
extern f32 lbl_803E4F0C;
extern f32 lbl_803E4F10;
extern f32 lbl_803E4F14;
extern f32 lbl_803E4F18;
extern f32 lbl_803E4F1C;
extern f32 lbl_803E4F20;
extern f32 lbl_803E4F24;
extern f32 lbl_803E4F28;
extern f32 lbl_803E4F2C;
extern f32 lbl_803E4F30;
extern f64 lbl_803E4F38;
extern f32 lbl_803E4F40;
extern f32 lbl_803E4F44;
extern f32 lbl_803E4F48;
extern f32 lbl_803E4F4C;
extern f32 lbl_803E5B58;
extern f32 lbl_803E5B5C;
extern f32 lbl_803E5B60;
extern f32 lbl_803E5B64;
extern f32 lbl_803E5B68;
extern f32 lbl_803E5B6C;
extern f32 lbl_803E5B78;
extern f32 lbl_803E5B7C;
extern f32 lbl_803E5B80;
extern f32 lbl_803E5B84;
extern f32 lbl_803E5B88;
extern f32 lbl_803E5B8C;
extern f32 lbl_803E5B90;

typedef struct DFSHLaserBeamConfig {
  u8 pad00[0x18];
  s8 yawByte;
  u8 proximityMode;
  s16 rangeAngle;
  u8 pad1C[0x1E - 0x1C];
  s16 disableGameBit;
} DFSHLaserBeamConfig;

typedef struct DFSHLaserBeamRuntime {
  void *beamTexture;
  f32 swayPhase;
  f32 swayVelocity;
  f32 swayAccel;
  f32 swayTarget;
  u8 pad14[0x18 - 0x14];
  s32 flags;
  f32 beamVolumeScale;
  s16 orbitAngleA;
  s16 orbitAngleB;
  s16 orbitAngleC;
  u8 beamActive;
  u8 beamLocked;
  s8 proximityHalfWidth;
  s8 hitCooldown;
  s16 hitStrength;
  s16 lockTimer;
  s16 cycleTimer;
  s16 warmupThreshold;
  u8 pad30[0x48 - 0x30];
  u8 modgfxAttached;
  u8 blastPhase;
  u8 proximityMode;
  u8 pad4B[0x4C - 0x4B];
} DFSHLaserBeamRuntime;

typedef struct DFSHLaserBeamObject {
  s16 yaw;
  s16 pitch;
  s16 roll;
  s16 flags06;
  u8 pad08[0x0C - 0x08];
  f32 posX;
  f32 posY;
  f32 posZ;
  f32 prevPosX;
  f32 prevPosY;
  f32 prevPosZ;
  u8 pad24[0x36 - 0x24];
  u8 alpha;
  u8 pad37[0x4C - 0x37];
  DFSHLaserBeamConfig *config;
  u8 pad50[0xB8 - 0x50];
  DFSHLaserBeamRuntime *runtime;
} DFSHLaserBeamObject;

#define DFSH_LASER_ORBIT_A(runtime) (*(s16 *)((u8 *)(runtime) + 0x1E))
#define DFSH_LASER_ORBIT_B(runtime) (*(s16 *)((u8 *)(runtime) + 0x20))
#define DFSH_LASER_ORBIT_C(runtime) (*(s16 *)((u8 *)(runtime) + 0x22))

/*
 * --INFO--
 *
 * Function: DFSH_LaserBeam_update
 * EN v1.0 Address: 0x801C3EB8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C446C
 * EN v1.1 Size: 1768b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DFSH_LaserBeam_update(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: DFSH_LaserBeam_free
 * EN v1.0 Address: 0x801C45A0
 * EN v1.0 Size: 188b
 *
 * Object setup: initializes the rotating DarkIce Mines shrine laser beam state.
 */
#pragma scheduling off
#pragma peephole off
void DFSH_LaserBeam_free(void *objArg,void *configArg)
{
  DFSHLaserBeamObject *obj;
  DFSHLaserBeamConfig *config;
  DFSHLaserBeamRuntime *runtime;
  int timer;

  obj = (DFSHLaserBeamObject *)objArg;
  config = (DFSHLaserBeamConfig *)configArg;
  runtime = obj->runtime;
  ObjMsg_AllocQueue(obj,2);
  obj->yaw = (s16)((s32)config->yawByte << 8);
  timer = randomGetRange(-0x50,0x50);
  *(s16 *)((u8 *)runtime + 0x2C) = (s16)(timer + 0x190);
  *(u8 *)((u8 *)runtime + 0x49) = 0;
  lbl_803DDBB8 = Resource_Acquire(0x81,1);
  runtime->beamVolumeScale = lbl_803E4EC0;
  *(u8 *)((u8 *)runtime + 0x4A) = config->proximityMode;
  *(s16 *)((u8 *)runtime + 0x2E) = 0x118;
  if (runtime->beamTexture == NULL) {
    runtime->beamTexture = textureLoadAsset(0x2E);
  }
}
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */
void DFSH_LaserBeam_release(void) {}
void DFSH_LaserBeam_initialise(void) {}

/*
 * --INFO--
 *
 * Function: fn_801C4664
 * EN v1.0 Address: 0x801C4664
 * EN v1.0 Size: 852b
 *
 * Advances the ambient laser-beam bob, aim, and player proximity alpha.
 */
#pragma scheduling off
#pragma peephole off
void fn_801C4664(void *objArg)
{
  DFSHLaserBeamObject *obj;
  DFSHLaserBeamConfig *config;
  DFSHLaserBeamRuntime *runtime;
  void *playerObj;
  f32 trigA;
  f32 trigB;
  s32 angleDelta;
  f32 distance;
  int animEvents;

  obj = (DFSHLaserBeamObject *)objArg;
  config = obj->config;
  runtime = obj->runtime;
  playerObj = Obj_GetPlayerObject();

  if ((obj->flags06 & 0x4000) != 0) {
    obj->yaw = 0;
    obj->posY = *(f32 *)((u8 *)config + 0xC);
    return;
  }

  DFSH_LASER_ORBIT_A(runtime) =
      (s16)(DFSH_LASER_ORBIT_A(runtime) + (int)(lbl_803E4F08 * timeDelta));
  DFSH_LASER_ORBIT_B(runtime) =
      (s16)(DFSH_LASER_ORBIT_B(runtime) + (int)(lbl_803E4F0C * timeDelta));
  DFSH_LASER_ORBIT_C(runtime) =
      (s16)(DFSH_LASER_ORBIT_C(runtime) + (int)(lbl_803E4F10 * timeDelta));

  obj->posY = lbl_803E4F14 +
              (*(f32 *)((u8 *)config + 0xC) +
               fn_80293E80((lbl_803E4F18 * (f32)DFSH_LASER_ORBIT_A(runtime)) /
                            lbl_803E4F1C));

  trigA = fn_80293E80((lbl_803E4F18 * (f32)DFSH_LASER_ORBIT_B(runtime)) /
                      lbl_803E4F1C);
  trigB = fn_80293E80((lbl_803E4F18 * (f32)DFSH_LASER_ORBIT_A(runtime)) /
                      lbl_803E4F1C);
  obj->roll = (s16)(int)(lbl_803E4F20 * (trigB + trigA));

  trigA = fn_80293E80((lbl_803E4F18 * (f32)DFSH_LASER_ORBIT_C(runtime)) /
                      lbl_803E4F1C);
  trigB = fn_80293E80((lbl_803E4F18 * (f32)DFSH_LASER_ORBIT_A(runtime)) /
                      lbl_803E4F1C);
  obj->pitch = (s16)(int)(lbl_803E4F20 * (trigB + trigA));

  ObjAnim_AdvanceCurrentMove(lbl_803E4F24,timeDelta,(int)obj,&animEvents);
  if (playerObj == NULL) {
    return;
  }

  angleDelta = (u16)getAngle(obj->prevPosX - *(f32 *)((u8 *)playerObj + 0x18),
                             obj->prevPosZ - *(f32 *)((u8 *)playerObj + 0x20)) -
               (u16)obj->yaw;
  if (angleDelta > 0x8000) {
    angleDelta -= 0xFFFF;
  }
  if (angleDelta < -0x8000) {
    angleDelta += 0xFFFF;
  }

  obj->yaw = (s16)(obj->yaw + (s16)(int)(((f32)angleDelta * timeDelta) / lbl_803E4F28));
  distance = Vec_xzDistance(&obj->prevPosX,(f32 *)((u8 *)playerObj + 0x18));
  if (distance <= lbl_803E4F2C) {
    obj->alpha = (u8)(int)(lbl_803E4F30 * (distance / lbl_803E4F2C));
  }
  else {
    obj->alpha = 0xFF;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_801C49B8
 * EN v1.0 Address: 0x801C49B8
 * EN v1.0 Size: 344b
 *
 * Drives the shrine sway controller used by MMSH shrine sequences.
 */
#pragma scheduling off
#pragma peephole off
int fn_801C49B8(void *objArg)
{
  DFSHLaserBeamObject *obj;
  DFSHLaserBeamRuntime *runtime;
  f32 stickAccel;
  f32 target;
  f32 zero;
  int swayValue;

  obj = (DFSHLaserBeamObject *)objArg;
  runtime = obj->runtime;
  if ((runtime->flags & 0x20) == 0) {
    fn_8011F6D4(1);
    runtime->flags |= 0x20;
    zero = lbl_803E4F40;
    runtime->swayPhase = zero;
    runtime->swayVelocity = zero;
    runtime->swayAccel = zero;
  }

  stickAccel = ((f32)(s8)padGetStickX(0) / lbl_803E4F44) * lbl_803E4F48;
  runtime->swayVelocity += stickAccel * timeDelta;

  target = runtime->swayTarget;
  if (target < lbl_803E4F40) {
    if (runtime->swayAccel > target) {
      runtime->swayAccel -= lbl_803E4F48 * timeDelta;
    }
  }
  else if (target > lbl_803E4F40) {
    if (runtime->swayAccel < target) {
      runtime->swayAccel += lbl_803E4F48 * timeDelta;
    }
  }

  runtime->swayPhase += timeDelta * (runtime->swayVelocity + runtime->swayAccel);
  swayValue = (int)(lbl_803E4F4C * runtime->swayPhase);
  fn_8011F6E0(0x60,0x39,(s16)swayValue);
  if ((swayValue > 0x39) || (swayValue < -0x39)) {
    return 1;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset
