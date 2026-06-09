#include "ghidra_import.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camcontrol_path_state.h"
#include "main/game_object.h"
#include "main/object_transform.h"

extern uint getAngle();
extern undefined4 doNothing_80103660();
extern char camcontrol_getTargetPosition();
extern char camcontrol_samplePathState();
extern undefined4 camcontrol_updatePathTargetAction();

extern f32 timeDelta;
extern f32 lbl_803E1740;
extern f32 lbl_803E1758;
extern f32 lbl_803E175C;

/*
 * --INFO--
 *
 * Function: camclimb_update
 * EN v1.0 Address: 0x801070FC
 * EN v1.0 Size: 896b
 * EN v1.1 Address: 0x80107398
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camclimb_update(CameraObject *cam)
{
  byte cVar2;
  uint uVar1;
  int defaultHandler;
  int yawDelta;
  GameObject *target;
  int pointIndex;
  float local_20 [4];
  float local_24;
  float local_28;
  float local_2c;
  undefined auStack_30 [4];
  float local_34;
  float local_38;

  if (lbl_803DD538->active != 0) {
    (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
  }
  else {
    if (lbl_803DD538->localFrameObj != *(int *)&cam->anim.parent) {
      for (pointIndex = 0; pointIndex < lbl_803DD538->pathCurve.count; pointIndex = pointIndex + 1) {
        Obj_TransformLocalPointToWorld(lbl_803DD538->pointsX[pointIndex],
                     lbl_803DD538->pointsY[pointIndex], lbl_803DD538->pointsZ[pointIndex],
                     &lbl_803DD538->pointsX[pointIndex], &lbl_803DD538->pointsY[pointIndex],
                     &lbl_803DD538->pointsZ[pointIndex], lbl_803DD538->localFrameObj);
      }
      for (pointIndex = 0; pointIndex < lbl_803DD538->pathCurve.count; pointIndex = pointIndex + 1) {
        Obj_TransformWorldPointToLocal(lbl_803DD538->pointsX[pointIndex],
                     lbl_803DD538->pointsY[pointIndex], lbl_803DD538->pointsZ[pointIndex],
                     &lbl_803DD538->pointsX[pointIndex], &lbl_803DD538->pointsY[pointIndex],
                     &lbl_803DD538->pointsZ[pointIndex], *(int *)&cam->anim.parent);
      }
      lbl_803DD538->localFrameObj = *(int *)&cam->anim.parent;
    }
    target = (GameObject *)cam->anim.targetObj;
    local_24 = cam->anim.localPosY;
    cVar2 = camcontrol_samplePathState(&local_28, &local_24, local_20, target, cam);
    cam->anim.localPosX = local_28;
    cam->anim.localPosZ = local_20[0];
    defaultHandler = (int)(*gCameraInterface)->getDefaultHandlerEntry();
    Obj_TransformLocalPointToWorld(cam->anim.localPosX, cam->anim.localPosY,
                 cam->anim.localPosZ, &cam->anim.worldPosX, &cam->anim.worldPosY,
                 &cam->anim.worldPosZ, *(int *)&cam->anim.parent);
    (*(code *)(**(int **)(defaultHandler + 4) + 0x1c))
              ((double)lbl_803E1758, (double)lbl_803E175C, cam, target);
    (*(code *)(**(int **)(defaultHandler + 4) + 0x24))(cam, 1, 3,
                                                 &lbl_803DD538->curveMin,
                                                 &lbl_803DD538->curveMax);
    if ((cam->anim.currentMove != 0) || (cam->unk142 != 0)) {
      lbl_803DD538->initialiseCurve[4] = lbl_803DD538->initialiseCurve[4] + timeDelta;
    }
    if (lbl_803DD538->initialiseCurve[4] > lbl_803E1740) {
      cVar2 = camcontrol_getTargetPosition(cam, target, &cam->anim.worldPosX, &cam->anim.rotY);
      if (cVar2 == 1) {
        doNothing_80103660(1);
      }
      cam->probePosX = cam->anim.worldPosX;
      cam->probePosY = cam->anim.worldPosY;
      cam->probePosZ = cam->anim.worldPosZ;
      cVar2 = 1;
    }
    (*gCameraInterface)->getRelativePosition(lbl_803E1740, (int)cam, &local_2c,
                                             (f32 *)auStack_30, &local_34, &local_38, 0);
    uVar1 = getAngle((double)local_2c, (double)local_34);
    yawDelta = 0x8000 - (uVar1 & 0xffff);
    yawDelta = yawDelta - (uint)(u16)cam->anim.rotX;
    if (0x8000 < yawDelta) {
      yawDelta = yawDelta + -0xffff;
    }
    if (yawDelta < -0x8000) {
      yawDelta = yawDelta + 0xffff;
    }
    cam->anim.rotX = (s16)(cam->anim.rotX + yawDelta);
    (*(code *)(**(int **)(defaultHandler + 4) + 0x18))
              ((double)target->anim.worldPosY, (double)local_38, cam);
    if (cVar2 != 0) {
      (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
    }
    camcontrol_updatePathTargetAction(cam, target);
    Obj_TransformWorldPointToLocal(cam->anim.worldPosX, cam->anim.worldPosY,
                 cam->anim.worldPosZ, &cam->anim.localPosX, &cam->anim.localPosY,
                 &cam->anim.localPosZ, *(int *)&cam->anim.parent);
  }
  return;
}
