#include "main/dll/CAM/camcannon.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camcannon_state.h"


extern f32 Curve_EvalLinear(f32 param_1, float *param_2, float *param_3);
extern f32 Curve_EvalHermite(f32 param_1, float *param_2, float *param_3);
extern undefined4 FUN_80017814();
extern f32 sqrtf(f32 x);

extern CamCannonState *lbl_803DD560;
extern f64 lbl_803E18A0;
extern f32 timeDelta;
extern f32 lbl_803E1888;
extern f32 lbl_803E188C;
extern f32 lbl_803E1890;
extern f32 lbl_803E1894;
extern f32 lbl_803E1898;
extern f32 lbl_803E18AC;
extern f32 lbl_803E18B0;
extern f32 lbl_803E18B4;
extern f32 lbl_803E18B8;

/*
 * --INFO--
 *
 * Function: fn_8010AEA8
 * EN v1.0 Address: 0x8010AEA8
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x8010B144
 * EN v1.1 Size: 912b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint fn_8010AEA8(CameraObject *camera, uint flagsIn)
{
  u8 flags;
  f32 d;
  f32 t;
  f32 q;

  lbl_803DD560->posXEnd = camera->anim.localPosX;
  lbl_803DD560->posYEnd = camera->anim.localPosY;
  lbl_803DD560->posZEnd = camera->anim.localPosZ;
  lbl_803DD560->rotXEnd = (f32)camera->anim.rotX;
  lbl_803DD560->rotYEnd = (f32)camera->anim.rotY;
  lbl_803DD560->rotZEnd = (f32)camera->anim.rotZ;
  lbl_803DD560->fovEnd = camera->fov;

  if (lbl_803E1888 != lbl_803DD560->duration) {
    t = lbl_803DD560->elapsed / lbl_803DD560->duration;
  } else {
    t = lbl_803E1888;
  }
  if (t > lbl_803E188C) {
    t = lbl_803E188C;
  }
  t = Curve_EvalHermite(t, lbl_803DD560->speedCurve, (f32 *)0x0);
  if (t < lbl_803E18AC) {
    t = lbl_803E18AC;
  }
  lbl_803DD560->elapsed = t * timeDelta + lbl_803DD560->elapsed;

  q = lbl_803E1888;
  if (q != lbl_803DD560->duration) {
    q = lbl_803DD560->elapsed / lbl_803DD560->duration;
  }
  if (q > lbl_803E188C) {
    q = lbl_803E188C;
  }
  camera->anim.localPosX = Curve_EvalLinear(q, &lbl_803DD560->posXStart, (f32 *)0x0);
  camera->anim.localPosY = Curve_EvalLinear(q, &lbl_803DD560->posYStart, (f32 *)0x0);
  camera->anim.localPosZ = Curve_EvalLinear(q, &lbl_803DD560->posZStart, (f32 *)0x0);
  camera->fov = Curve_EvalLinear(q, &lbl_803DD560->fovStart, (f32 *)0x0);

  d = lbl_803DD560->rotXStart - lbl_803DD560->rotXEnd;
  if ((d > lbl_803E1890) || (d < lbl_803E1894)) {
    if (lbl_803DD560->rotXStart < lbl_803E1888) {
      lbl_803DD560->rotXStart = lbl_803DD560->rotXStart + lbl_803E1898;
    }
    else if (lbl_803DD560->rotXEnd < lbl_803E1888) {
      lbl_803DD560->rotXEnd = lbl_803DD560->rotXEnd + lbl_803E1898;
    }
  }
  d = lbl_803DD560->rotYStart - lbl_803DD560->rotYEnd;
  if ((d > lbl_803E1890) || (d < lbl_803E1894)) {
    if (lbl_803DD560->rotYStart < lbl_803E1888) {
      lbl_803DD560->rotYStart = lbl_803DD560->rotYStart + lbl_803E1898;
    }
    else if (lbl_803DD560->rotYEnd < lbl_803E1888) {
      lbl_803DD560->rotYEnd = lbl_803DD560->rotYEnd + lbl_803E1898;
    }
  }
  d = lbl_803DD560->rotZStart - lbl_803DD560->rotZEnd;
  if ((d > lbl_803E1890) || (d < lbl_803E1894)) {
    if (lbl_803DD560->rotZStart < lbl_803E1888) {
      lbl_803DD560->rotZStart = lbl_803DD560->rotZStart + lbl_803E1898;
    }
    else if (lbl_803DD560->rotZEnd < lbl_803E1888) {
      lbl_803DD560->rotZEnd = lbl_803DD560->rotZEnd + lbl_803E1898;
    }
  }

  flags = flagsIn;
  if ((flags & 1) == 0) {
    camera->anim.rotX = (s16)(int)Curve_EvalLinear(q, &lbl_803DD560->rotXStart, (f32 *)0x0);
  }
  if ((flags & 2) == 0) {
    camera->anim.rotY = (s16)(int)Curve_EvalLinear(q, &lbl_803DD560->rotYStart, (f32 *)0x0);
  }
  if ((flags & 4) == 0) {
    camera->anim.rotZ = (s16)(int)Curve_EvalLinear(q, &lbl_803DD560->rotZStart, (f32 *)0x0);
  }
  return q >= lbl_803E188C;
}

/*
 * --INFO--
 *
 * Function: cameraModeTestStrengthFn_8010b238
 * EN v1.0 Address: 0x8010B218
 * EN v1.0 Size: 528b
 * EN v1.1 Address: 0x8010B4D4
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cameraModeTestStrengthFn_8010b238(f32 fovEnd, CameraObject *camera, f32 *posEnd,
                 s32 rotXEnd, s32 rotYEnd, s32 rotZEnd)
{
  f32 fVar1;
  f32 fVar2;
  f32 fVar3;

  lbl_803DD560->transitionComplete = 0;
  lbl_803DD560->posXStart = camera->anim.localPosX;
  lbl_803DD560->posYStart = camera->anim.localPosY;
  lbl_803DD560->posZStart = camera->anim.localPosZ;
  lbl_803DD560->rotXStart = (f32)(s32)camera->anim.rotX;
  lbl_803DD560->rotYStart = (f32)(s32)camera->anim.rotY;
  lbl_803DD560->rotZStart = (f32)(s32)camera->anim.rotZ;
  lbl_803DD560->fovStart = camera->fov;
  lbl_803DD560->posXEnd = posEnd[0];
  lbl_803DD560->posYEnd = posEnd[1];
  lbl_803DD560->posZEnd = posEnd[2];
  lbl_803DD560->rotXEnd = (f32)rotXEnd;
  lbl_803DD560->rotYEnd = (f32)rotYEnd;
  lbl_803DD560->rotZEnd = (f32)rotZEnd;
  lbl_803DD560->fovEnd = fovEnd;
  lbl_803DD560->elapsed = lbl_803E1888;
  fVar1 = lbl_803DD560->posXEnd - lbl_803DD560->posXStart;
  fVar2 = lbl_803DD560->posYEnd - lbl_803DD560->posYStart;
  fVar3 = lbl_803DD560->posZEnd - lbl_803DD560->posZStart;
  lbl_803DD560->duration = sqrtf(fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3);
  (*gCameraInterface)->initialise(lbl_803DD560->speedCurve, (f64)lbl_803DD560->duration,
                                  (f64)lbl_803E18B0, (f64)lbl_803E18B4,
                                  (f64)lbl_803E18B4, (f64)lbl_803E18B8);
}



/* Trivial 4b 0-arg blr leaves. */
void CameraModeTestStrength_copyToCurrent_nop(void) {}

/* fn_X(lbl); lbl = 0; */
extern void mm_free(u32);
void CameraModeTestStrength_free(void) { mm_free((u32)lbl_803DD560); lbl_803DD560 = 0; }
