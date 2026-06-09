#include "ghidra_import.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camcontrol_path_state.h"
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
#pragma scheduling off
#pragma peephole off
void camclimb_update(short *param_1)
{
  byte cVar2;
  uint uVar1;
  int defaultHandler;
  int yawDelta;
  short *psVar4;
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
    if (lbl_803DD538->localFrameObj != *(uint *)(param_1 + 0x18)) {
      for (pointIndex = 0; pointIndex < lbl_803DD538->pointCount; pointIndex = pointIndex + 1) {
        Obj_TransformLocalPointToWorld(lbl_803DD538->pointsX[pointIndex],
                     lbl_803DD538->pointsY[pointIndex], lbl_803DD538->pointsZ[pointIndex],
                     &lbl_803DD538->pointsX[pointIndex], &lbl_803DD538->pointsY[pointIndex],
                     &lbl_803DD538->pointsZ[pointIndex], lbl_803DD538->localFrameObj);
      }
      for (pointIndex = 0; pointIndex < lbl_803DD538->pointCount; pointIndex = pointIndex + 1) {
        Obj_TransformWorldPointToLocal(lbl_803DD538->pointsX[pointIndex],
                     lbl_803DD538->pointsY[pointIndex], lbl_803DD538->pointsZ[pointIndex],
                     &lbl_803DD538->pointsX[pointIndex], &lbl_803DD538->pointsY[pointIndex],
                     &lbl_803DD538->pointsZ[pointIndex], *(int *)(param_1 + 0x18));
      }
      lbl_803DD538->localFrameObj = *(int *)(param_1 + 0x18);
    }
    psVar4 = ((CameraObject *)param_1)->anim.targetObj;
    local_24 = *(float *)(param_1 + 8);
    cVar2 = camcontrol_samplePathState(&local_28, &local_24, local_20, psVar4, param_1);
    *(float *)(param_1 + 6) = local_28;
    *(float *)(param_1 + 10) = local_20[0];
    defaultHandler = (int)(*gCameraInterface)->getDefaultHandlerEntry();
    Obj_TransformLocalPointToWorld(*(float *)(param_1 + 6),*(float *)(param_1 + 8),
                 *(float *)(param_1 + 10),(float *)(param_1 + 0xc),(float *)(param_1 + 0xe),
                 (float *)(param_1 + 0x10),*(int *)(param_1 + 0x18));
    (*(code *)(**(int **)(defaultHandler + 4) + 0x1c))
              ((double)lbl_803E1758, (double)lbl_803E175C, param_1, psVar4);
    (*(code *)(**(int **)(defaultHandler + 4) + 0x24))(param_1, 1, 3,
                                                 &lbl_803DD538->curveMin,
                                                 &lbl_803DD538->curveMax);
    if ((param_1[0x50] != 0) || (((CameraObject *)param_1)->unk142 != 0)) {
      lbl_803DD538->initialiseCurve[4] = lbl_803DD538->initialiseCurve[4] + timeDelta;
    }
    if (lbl_803DD538->initialiseCurve[4] > lbl_803E1740) {
      cVar2 = camcontrol_getTargetPosition(param_1, psVar4, param_1 + 0xc, param_1 + 1);
      if (cVar2 == 1) {
        doNothing_80103660(1);
      }
      ((CameraObject *)param_1)->probePosX = *(float *)(param_1 + 0xc);
      ((CameraObject *)param_1)->probePosY = *(float *)(param_1 + 0xe);
      ((CameraObject *)param_1)->probePosZ = *(float *)(param_1 + 0x10);
      cVar2 = 1;
    }
    (*gCameraInterface)->getRelativePosition(lbl_803E1740, (int)param_1, &local_2c,
                                             (f32 *)auStack_30, &local_34, &local_38, 0);
    uVar1 = getAngle((double)local_2c, (double)local_34);
    yawDelta = 0x8000 - (uVar1 & 0xffff);
    yawDelta = yawDelta - (uint)*(ushort *)param_1;
    if (0x8000 < yawDelta) {
      yawDelta = yawDelta + -0xffff;
    }
    if (yawDelta < -0x8000) {
      yawDelta = yawDelta + 0xffff;
    }
    *param_1 = (short)(*param_1 + yawDelta);
    (*(code *)(**(int **)(defaultHandler + 4) + 0x18))
              ((double)*(float *)(psVar4 + 0xe), (double)local_38, param_1);
    if (cVar2 != 0) {
      (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
    }
    camcontrol_updatePathTargetAction(param_1, psVar4);
    Obj_TransformWorldPointToLocal(*(float *)(param_1 + 0xc),*(float *)(param_1 + 0xe),
                 *(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset
