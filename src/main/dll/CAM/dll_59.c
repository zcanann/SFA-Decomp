#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/dll/CAM/camcontrol_path_state.h"
#include "main/dll/CAM/dll_59.h"
#include "main/mm.h"
#include "main/object_transform.h"

extern void memset(void *ptr, int value, int size);
extern void curvesMove(void *curve);
extern int getAngle(f32 dx, f32 dz);
extern undefined camcontrol_getTargetPosition(int obj, s16 *target, f32 *outPos, s16 *outAngle);
extern void camcontrol_buildPathPoints(f32 baseX, f32 baseZ, f32 targetX, f32 targetY, f32 targetZ,
                                       f32 height, s16 angleRange, s16 angleLimit,
                                       int *outPointCount);
extern int Camera_GetCurrentViewSlot();
extern undefined4 FUN_8028688c();
extern f32 sqrtf(f32 value);
extern f32 mathSinf(f32 angle);
extern f32 mathCosf(f32 angle);
extern void Curve_EvalBSpline(void);
extern void Curve_BuildBSplineCoeffs(void);

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
  f32 baseX;
  f32 baseZ;
  f32 dx;
  f32 dz;
  f32 localPos[3];
  int pointCount;
  int pointOffset;
  int i;

  settings[3] = 1;
  target = ((GameObject *)obj)->anim.targetObj;

  if (gCamcontrolPathState == NULL) {
    gCamcontrolPathState = mmAlloc(sizeof(CamcontrolPathState), 0xf, 0);
  }
  memset(gCamcontrolPathState, 0, sizeof(CamcontrolPathState));

  view = (int)(*gCameraInterface)->getDefaultHandlerEntry();
  (*(void (**)(f32 *, f32 *, f32 *, int, f32 *))(**(int **)(view + 4) + 0x20))
      (&gCamcontrolPathState->actionParamX, &gCamcontrolPathState->pad08,
       &gCamcontrolPathState->actionParamZ, 0, &gCamcontrolPathState->actionParamY);

  gCamcontrolPathState->active = 0;
  gCamcontrolPathState->localFrameObj = *(int *)&((GameObject *)obj)->anim.parent;

  cosFacing = mathSinf(CameraModeStaffAnim_angleToRadians(target[0]));
  sinFacing = mathCosf(CameraModeStaffAnim_angleToRadians(target[0]));

  if (gCamcontrolPathState->localFrameObj != 0) {
    facingDelta = target[0] - ((s16 *)gCamcontrolPathState->localFrameObj)[0];
  }
  else {
    facingDelta = target[0];
  }

  relAngleRad = CameraModeStaffAnim_angleToRadians(facingDelta);
  relCos = mathSinf(relAngleRad);
  relSin = mathCosf(relAngleRad);

  approachAngle = target[0] - (u16)getAngle(((GameObject *)obj)->anim.worldPosX - *(f32 *)(target + 0xc),
                                            ((GameObject *)obj)->anim.worldPosZ - *(f32 *)(target + 0x10));
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
    gCamcontrolPathState->active = 1;
  }
  else {
    pathRadius = gCamcontrolPathState->actionParamX * gCamcontrolPathState->actionParamX -
                 gCamcontrolPathState->actionParamZ * gCamcontrolPathState->actionParamZ;
    if (pathRadius < lbl_803E176C) {
      pathRadius = lbl_803E176C;
    }
    pathRadius = sqrtf(pathRadius);

    localPos[0] = (cosFacing * pathRadius) + *(f32 *)(target + 0xc);
    localPos[1] = gCamcontrolPathState->actionParamZ +
                  (*(f32 *)(target + 0xe) + gCamcontrolPathState->actionParamY);
    localPos[2] = (sinFacing * pathRadius) + *(f32 *)(target + 0x10);

    if (settings[3] != 0) {
      camcontrol_getTargetPosition(obj, target, localPos, 0);
    }

    Obj_TransformWorldPointToLocal(localPos[0], localPos[1], localPos[2], &localPos[0],
                                   &localPos[1], &localPos[2], *(int *)&((GameObject *)obj)->anim.parent);

    for (pointCount = 0; pointCount < 3; pointCount++) {
      gCamcontrolPathState->pointsX[pointCount] = ((GameObject *)obj)->anim.localPosX;
      gCamcontrolPathState->pointsY[pointCount] = ((GameObject *)obj)->anim.localPosY;
      gCamcontrolPathState->pointsZ[pointCount] = ((GameObject *)obj)->anim.localPosZ;
    }

    dx = ((GameObject *)obj)->anim.localPosX - localPos[0];
    dz = ((GameObject *)obj)->anim.localPosZ - localPos[2];
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
      pathScale = pathRadius / mathSinf(CameraModeStaffAnim_angleToRadians(absTurn));
    }
    else {
      pathScale = lbl_803E1740;
    }

    baseX = localPos[0] - (relCos * pathScale);
    baseZ = localPos[2] - (relSin * pathScale);
    gCamcontrolPathState->pointsXPtr = gCamcontrolPathState->pointsX;
    gCamcontrolPathState->pointsYPtr = gCamcontrolPathState->pointsY;
    gCamcontrolPathState->pointsZPtr = gCamcontrolPathState->pointsZ;
    gCamcontrolPathState->evalCallback = Curve_EvalBSpline;
    gCamcontrolPathState->buildCallback = Curve_BuildBSplineCoeffs;

    camcontrol_buildPathPoints(baseX, baseZ,
                               ((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY, ((GameObject *)obj)->anim.localPosZ,
                               localPos[1], pathAngle, 0x1555, &pointCount);

    i = pointCount;
    pointOffset = pointCount * 4;
    for (; i < pointCount + 3; i++) {
      *(f32 *)((u8 *)gCamcontrolPathState->pointsX + pointOffset) = localPos[0];
      *(f32 *)((u8 *)gCamcontrolPathState->pointsY + pointOffset) = localPos[1];
      *(f32 *)((u8 *)gCamcontrolPathState->pointsZ + pointOffset) = localPos[2];
      pointOffset += 4;
    }

    gCamcontrolPathState->pointCount = i;
    gCamcontrolPathState->curveCursor = 0;
    curvesMove(gCamcontrolPathState->curveWork);

    if (pathAngle < 0) {
      pathAngle = -pathAngle;
    }
    if ((pathAngle > 0x2000) && (settings[2] != 0)) {
      Sfx_PlayFromObject(0, SFXsc_snort03);
    }

    (*gCameraInterface)->initialise(gCamcontrolPathState->initialiseCurve,
                                    *(f32 *)(gCamcontrolPathState->curveWork + 0xc),
                                    lbl_803E1774, lbl_803E1770, lbl_803E1744,
                                    lbl_803E1778);

    gCamcontrolPathState->curveMin = lbl_803E1758;
    gCamcontrolPathState->curveMax = lbl_803E175C;
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
void CameraModeBike_free(void) { mm_free(lbl_803DD540); lbl_803DD540 = 0; }
