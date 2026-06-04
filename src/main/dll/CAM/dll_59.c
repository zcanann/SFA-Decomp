#include "ghidra_import.h"
#include "main/dll/CAM/dll_59.h"

#define SFXsc_snort03 0x286

extern void *mmAlloc(int size, int heap, int flags);
extern void memset(void *ptr, int value, int size);
extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY,
                                           f32 *outZ, int model);
extern void curvesMove(void *curve);
extern int getAngle(f32 dx, f32 dz);
extern undefined camcontrol_getTargetPosition(int obj, s16 *target, f32 *outPos, s16 *outAngle);
extern void camcontrol_buildPathPoints(f32 baseX, f32 baseZ, f32 targetX, f32 targetY, f32 targetZ,
                                       f32 height, s16 angleRange, s16 angleLimit,
                                       int *outPointCount);
extern int Camera_GetCurrentViewSlot();
extern undefined4 FUN_8028688c();
extern f32 sqrtf(f32 value);
extern f32 fn_80293E80(f32 angle);
extern f32 sin(f32 angle);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Curve_EvalBSpline(void);
extern void Curve_BuildBSplineCoeffs(void);

extern int *gCameraInterface;
extern u8 *lbl_803DD538;
extern f32* lbl_803DD540;
extern f64 lbl_803E1750;
extern f32 lbl_803E1740;
extern f32 lbl_803E1744;
extern f32 lbl_803E1758;
extern f32 lbl_803E175C;
extern f32 lbl_803E1760;
extern f32 lbl_803E1764;
extern f32 lbl_803E1768;
extern f32 lbl_803E176C;
extern f32 lbl_803E1770;
extern f32 lbl_803E1774;
extern f32 lbl_803E1778;

#define gCamcontrolPathState lbl_803DD538

static f32 CameraModeStaffAnim_angleToRadians(int angle)
{
  return (lbl_803E1760 * (f32)angle) / lbl_803E1764;
}

/*
 * --INFO--
 *
 * Function: CameraModeStaffAnim_init
 * EN v1.0 Address: 0x8010747C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80107718
 * EN v1.1 Size: 1640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void CameraModeStaffAnim_init(int obj, undefined4 param_2, u8 *settings)
{
  int cameraObj;
  s16 *target;
  int iface;
  int view;
  f32 cosFacing;
  f32 sinFacing;
  f32 relAngleRad;
  f32 relCos;
  f32 relSin;
  int facingDelta;
  s16 approachAngle;
  s16 turnAmount;
  s16 absTurn;
  s16 pathAngle;
  s16 threshold;
  f32 pathRadius;
  f32 pathScale;
  f32 dx;
  f32 dz;
  f32 localPos[3];
  int pointCount;
  int i;
  int pointOffset;

  settings[3] = 1;
  target = *(s16 **)(obj + 0xa4);

  if (gCamcontrolPathState == NULL) {
    gCamcontrolPathState = mmAlloc(0x1c0, 0xf, 0);
  }
  memset(gCamcontrolPathState, 0, 0x1c0);

  iface = *gCameraInterface;
  view = (*(int (**)(int))(iface + 0x18))(iface);
  (*(void (**)(f32 *, f32 *, f32 *, int, f32 *))(**(int **)(view + 4) + 0x20))
      ((f32 *)(gCamcontrolPathState + 4), (f32 *)(gCamcontrolPathState + 8),
       (f32 *)(gCamcontrolPathState + 0xc), 0, (f32 *)(gCamcontrolPathState + 0x10));

  gCamcontrolPathState[0x1bc] = 0;
  *(int *)gCamcontrolPathState = *(int *)(obj + 0x30);

  cosFacing = fn_80293E80(CameraModeStaffAnim_angleToRadians(target[0]));
  sinFacing = sin(CameraModeStaffAnim_angleToRadians(target[0]));

  if (*(s16 **)gCamcontrolPathState != NULL) {
    facingDelta = target[0] - (*(s16 **)gCamcontrolPathState)[0];
  }
  else {
    facingDelta = target[0];
  }

  relAngleRad = CameraModeStaffAnim_angleToRadians(facingDelta);
  relCos = fn_80293E80(relAngleRad);
  relSin = sin(relAngleRad);

  approachAngle = target[0] - (u16)getAngle(*(f32 *)(obj + 0x18) - *(f32 *)(target + 0xc),
                                            *(f32 *)(obj + 0x20) - *(f32 *)(target + 0x10));
  if (approachAngle > 0x8000) {
    approachAngle = approachAngle - 0xffff;
  }
  if (approachAngle < -0x8000) {
    approachAngle = approachAngle + 0xffff;
  }
  if (approachAngle < 0) {
    approachAngle = -approachAngle;
  }

  threshold = (s16)(lbl_803E1768 * (f32)(*(s16 *)settings));
  if (approachAngle < threshold) {
    gCamcontrolPathState[0x1bc] = 1;
  }
  else {
    pathRadius = *(f32 *)(gCamcontrolPathState + 4) * *(f32 *)(gCamcontrolPathState + 4) -
                 *(f32 *)(gCamcontrolPathState + 0xc) * *(f32 *)(gCamcontrolPathState + 0xc);
    if (pathRadius < lbl_803E176C) {
      pathRadius = lbl_803E176C;
    }
    pathRadius = sqrtf(pathRadius);

    localPos[0] = (cosFacing * pathRadius) + *(f32 *)(target + 0xc);
    localPos[1] = *(f32 *)(gCamcontrolPathState + 0xc) +
                  (*(f32 *)(target + 0xe) + *(f32 *)(gCamcontrolPathState + 0x10));
    localPos[2] = (sinFacing * pathRadius) + *(f32 *)(target + 0x10);

    if (settings[3] != 0) {
      camcontrol_getTargetPosition(obj, target, localPos, 0);
    }

    Obj_TransformWorldPointToLocal(localPos[0], localPos[1], localPos[2], &localPos[0],
                                   &localPos[1], &localPos[2], *(int *)(obj + 0x30));

    for (pointCount = 0; pointCount < 3; pointCount++) {
      *(f32 *)(gCamcontrolPathState + (pointCount * 4) + 0x1c) = *(f32 *)(obj + 0xc);
      *(f32 *)(gCamcontrolPathState + (pointCount * 4) + 0x6c) = *(f32 *)(obj + 0x10);
      *(f32 *)(gCamcontrolPathState + (pointCount * 4) + 0xbc) = *(f32 *)(obj + 0x14);
    }

    dx = *(f32 *)(obj + 0xc) - localPos[0];
    dz = *(f32 *)(obj + 0x14) - localPos[2];
    pathRadius = lbl_803E1770 * sqrtf(dx * dx + dz * dz);
    turnAmount = getAngle(-relCos, -relSin) - (u16)getAngle(dx, dz);

    if (turnAmount > 0x8000) {
      turnAmount = turnAmount - 0xffff;
    }
    if (turnAmount < -0x8000) {
      turnAmount = turnAmount + 0xffff;
    }

    pathAngle = turnAmount;
    if (turnAmount < 0) {
      turnAmount = -turnAmount;
    }

    if (turnAmount > 0x4000) {
      absTurn = 0;
    }
    else {
      absTurn = 0x4000 - turnAmount;
    }

    if (pathAngle < 0) {
      pathAngle = -(absTurn << 1);
    }
    else {
      pathAngle = absTurn << 1;
    }

    if (absTurn != 0) {
      pathScale = pathRadius / fn_80293E80(CameraModeStaffAnim_angleToRadians(absTurn));
    }
    else {
      pathScale = lbl_803E1740;
    }

    *(f32 **)(gCamcontrolPathState + 0x1a4) = (f32 *)(gCamcontrolPathState + 0x1c);
    *(f32 **)(gCamcontrolPathState + 0x1a8) = (f32 *)(gCamcontrolPathState + 0x6c);
    *(f32 **)(gCamcontrolPathState + 0x1ac) = (f32 *)(gCamcontrolPathState + 0xbc);
    *(void **)(gCamcontrolPathState + 0x1b4) = Curve_EvalBSpline;
    *(void **)(gCamcontrolPathState + 0x1b8) = Curve_BuildBSplineCoeffs;

    camcontrol_buildPathPoints(localPos[0] - (relCos * pathScale),
                               localPos[2] - (relSin * pathScale),
                               *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14),
                               localPos[1], pathAngle, 0x1555, &pointCount);

    pointOffset = pointCount * 4;
    for (i = pointCount; i < pointCount + 3; i++) {
      *(f32 *)(gCamcontrolPathState + pointOffset + 0x1c) = localPos[0];
      *(f32 *)(gCamcontrolPathState + pointOffset + 0x6c) = localPos[1];
      *(f32 *)(gCamcontrolPathState + pointOffset + 0xbc) = localPos[2];
      pointOffset += 4;
    }

    *(int *)(gCamcontrolPathState + 0x1b0) = i;
    *(int *)(gCamcontrolPathState + 0x1a0) = 0;
    curvesMove(gCamcontrolPathState + 0x120);

    if (pathAngle < 0) {
      pathAngle = -pathAngle;
    }
    if ((pathAngle > 0x2000) && (settings[2] != 0)) {
      Sfx_PlayFromObject(0, SFXsc_snort03);
    }

    (*(void (**)(f32 *, f32, f32, f32, f32, f32))(*gCameraInterface + 0x34))
        ((f32 *)(gCamcontrolPathState + 0x10c), *(f32 *)(gCamcontrolPathState + 0x12c),
         lbl_803E1774, lbl_803E1770, lbl_803E1744, lbl_803E1778);

    *(f32 *)(gCamcontrolPathState + 0x14) = lbl_803E1758;
    *(f32 *)(gCamcontrolPathState + 0x18) = lbl_803E175C;
  }
}
#pragma peephole reset
#pragma scheduling reset

void CameraModeBike_copyToCurrent(f32 *param_1)
{
  lbl_803DD540[7] = param_1[0];
  lbl_803DD540[9] = param_1[1];
  lbl_803DD540[0xb] = param_1[2];
  lbl_803DD540[0xc] = param_1[3];
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeStaffAnim_release(void) {}
void CameraModeStaffAnim_initialise(void) {}

/* fn_X(lbl); lbl = 0; */
extern void mm_free(void *);
#pragma scheduling off
#pragma peephole off
void CameraModeBike_free(void) { mm_free(lbl_803DD540); lbl_803DD540 = 0; }
#pragma peephole reset
#pragma scheduling reset
