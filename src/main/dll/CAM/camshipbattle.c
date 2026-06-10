#include "main/dll/CAM/camshipbattle.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camcontrol_path_state.h"
#include "main/game_object.h"
#include "main/pad.h"

extern undefined4 FUN_80017814();
extern int objFn_802962b4(int obj);
extern int objFn_80296700(int obj);

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
void camcontrol_updatePathTargetAction(CameraObject *camera,GameObject *target)
{
  short sVar1;
  u16 buttons;
  GameObject *targetObj;
  struct {
    f32 x;
    f32 z;
    s16 y;
  } local_28;
  
  if (*(u32 *)&target->pendingParentObj == 0) {
    buttons = getButtonsJustPressed(0);
    targetObj = (GameObject *)camera->unk124;
    if (targetObj != NULL) {
      sVar1 = targetObj->anim.classId;
      if (sVar1 == 0x1c) {
        goto checkActiveTarget;
      }
      if (sVar1 != 0x2a) {
        goto checkOverrideFlag;
      }
checkActiveTarget:
      if (target->anim.classId != 1) {
        goto checkOverrideFlag;
      }
      if (objFn_80296700((int)target) != 0) {
        goto sendFollowAction;
      }
    }
checkOverrideFlag:
    if ((camera->unk141 & 2) != 0) {
sendFollowAction:
      (*gCameraInterface)->setMode(0x49,1,0,4,&camera->unk124,0x3c,0xff);
      goto done;
    }
    if ((((buttons & 0x10) != 0) && (target->anim.classId == 1)) &&
        (objFn_802962b4((int)target) != 0)) {
      local_28.x = gCamcontrolPathState->actionParamX;
      local_28.z = gCamcontrolPathState->actionParamZ;
      local_28.y = (s16)gCamcontrolPathState->actionParamY;
      (*gCameraInterface)->setMode(0x44,1,0,0xc,&local_28,0,0xff);
    }
  }
done:
  return;
}

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
