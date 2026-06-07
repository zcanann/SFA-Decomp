#include "main/dll/CAM/camshipbattle.h"
#include "main/camera_object.h"
#include "main/pad.h"

extern undefined4 FUN_80017814();
extern int objFn_802962b4(int obj);
extern int objFn_80296700(int obj);

extern int *gCameraInterface;
extern u8 *lbl_803DD538;

#define gCamcontrolPathState lbl_803DD538

/*
 * --INFO--
 *
 * Function: camcontrol_updatePathTargetAction
 * EN v1.0 Address: 0x801071A8
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x80107214
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void camcontrol_updatePathTargetAction(int param_1,int param_2)
{
  short sVar1;
  u16 buttons;
  u8 *targetObj;
  struct {
    f32 x;
    f32 z;
    s16 y;
  } local_28;
  
  if (*(u32 *)(param_2 + 0xc0) == 0) {
    buttons = getButtonsJustPressed(0);
    targetObj = *(u8 **)(param_1 + 0x124);
    if (targetObj != NULL) {
      sVar1 = *(short *)(targetObj + 0x44);
      if (sVar1 == 0x1c) {
        goto checkActiveTarget;
      }
      if (sVar1 != 0x2a) {
        goto checkOverrideFlag;
      }
checkActiveTarget:
      if (*(short *)(param_2 + 0x44) != 1) {
        goto checkOverrideFlag;
      }
      if (objFn_80296700(param_2) != 0) {
        goto sendFollowAction;
      }
    }
checkOverrideFlag:
    if ((((CameraObject *)param_1)->unk141 & 2) != 0) {
sendFollowAction:
      (*(code *)(*gCameraInterface + 0x1c))(0x49,1,0,4,param_1 + 0x124,0x3c,0xff);
      goto done;
    }
    if ((((buttons & 0x10) != 0) && (*(short *)(param_2 + 0x44) == 1)) &&
        (objFn_802962b4(param_2) != 0)) {
      local_28.x = *(float *)(lbl_803DD538 + 4);
      local_28.z = *(float *)(lbl_803DD538 + 0xc);
      local_28.y = (s16)*(float *)(lbl_803DD538 + 0x10);
      (*(code *)(*gCameraInterface + 0x1c))(0x44,1,0,0xc,&local_28,0,0xff);
    }
  }
done:
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: camcontrol_releasePathState
 * EN v1.0 Address: 0x801072F0
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8010736C
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_releasePathState(void)
{
  FUN_80017814(gCamcontrolPathState);
  gCamcontrolPathState = 0;
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeStaffAnim_copyToCurrent_nop(void) {}
