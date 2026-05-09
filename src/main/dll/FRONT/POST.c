#include "ghidra_import.h"
#include "main/dll/FRONT/POST.h"
#include "main/objanim.h"
#include "main/objlib.h"

typedef struct PostMotionTarget {
  u8 pad0[0x5a];
  s16 yawA;
  u8 pad5c[2];
  s16 yawB;
  u8 pad60[2];
  u8 flags;
} PostMotionTarget;

typedef struct PostObject {
  u8 pad0[0x54];
  PostMotionTarget *motion;
} PostObject;

typedef struct PostObjAnimComponent {
  s16 yaw;
  u8 pad2[0x9e];
  s16 currentMove;
} PostObjAnimComponent;

typedef struct PostControl {
  u8 pad0[0x10];
  u8 primary[0xc];
  u8 secondary[0x5a0];
  s16 events[0x1e];
  int blocked;
  u8 pad5fc[0x10];
  s16 eventState;
  s16 yawLimit;
  u8 contactAnim;
  u8 flags;
} PostControl;

extern PostMotionTarget *seqFn_800394a0(void);
extern void fn_80038F1C(int a, int b);
extern s16 objMathFn_8003a380(double distance, PostObjAnimComponent *objAnim, PostObject *obj,
                       void *primary, void *secondary, s16 *events, int eventCount,
                       int eventState);
extern int fn_8003A8B4(PostObjAnimComponent *objAnim, PostMotionTarget *leadAnims,
                       u8 contactAnim, void *secondary);
extern f64 lbl_803E1C98;
extern f32 lbl_803E1C90;
extern f32 lbl_803E1CC4;
extern f32 lbl_803E1CD0;
extern f32 lbl_803E1CDC;
extern f32 lbl_803E1CE0;

/*
 * --INFO--
 *
 * Function: objAnimFn_80115650
 * EN v1.0 Address: 0x80115650
 * EN v1.0 Size: 908b
 * EN v1.1 Address: 0x801158EC
 * EN v1.1 Size: 916b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int objAnimFn_80115650(PostObjAnimComponent *objAnim, PostObject *obj, int *turning,
                PostControl *control, float *turnSpeed, s16 *moves)
{
  int yawDelta;
  PostMotionTarget *motion;
  s16 hitResult;
  int turnAmount;
  uint ret;
  double distance;
  void *secondary;

  motion = seqFn_800394a0();
  if (obj->motion != 0) {
    if ((obj->motion->flags & 2) != 0) {
      distance = (double)(lbl_803E1CDC * (float)(s32)obj->motion->yawB);
    } else if ((obj->motion->flags & 1) != 0) {
      distance = (double)(float)(s32)obj->motion->yawA;
    } else {
      distance = (double)lbl_803E1CD0;
    }
  } else {
    distance = (double)lbl_803E1CD0;
  }

  yawDelta = Obj_GetYawDeltaToObject((ushort *)objAnim,(int)obj,(float *)0);
  if ((control->flags & 0x10) != 0) {
    fn_80038F1C(0,1);
    yawDelta += -0x8000;
  }

  if ((control->flags & 8) != 0) {
    secondary = 0;
  } else {
    secondary = control->secondary;
  }

  hitResult = objMathFn_8003a380(distance,objAnim,obj,control->primary,secondary,control->events,8,
                          control->eventState);
  if ((control->flags & 8) == 0) {
    control->blocked = (uint)__cntlzw(fn_8003A8B4(objAnim,motion,control->contactAnim,
                                                  control->secondary)) >> 5;
  }
  control->blocked = 0;

  if (((control->flags & 2) != 0) && (hitResult != 0)) {
    *turning = 0;
    return 0;
  }

  if (control->blocked == 0) {
    if ((-(int)control->yawLimit < (int)yawDelta) &&
        ((int)yawDelta < (int)control->yawLimit)) {
      *turnSpeed = lbl_803E1CC4;
      *turning = 0;
      return (uint)__cntlzw((int)hitResult) >> 5;
    }
  }

  if ((*turning == 0) && (hitResult != 0)) {
    *turning = 1;
    *turnSpeed = lbl_803E1CC4;
    return 1;
  }

  if (*turning == 0) {
    return 1;
  }

  if ((0 < yawDelta) && (objAnim->currentMove != moves[1])) {
    ObjAnim_SetCurrentMove((double)lbl_803E1C90,(int)objAnim,moves[1],0);
    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)objAnim,0x1e);
  }
  if ((yawDelta < 0) && (objAnim->currentMove != moves[0])) {
    ObjAnim_SetCurrentMove((double)lbl_803E1C90,(int)objAnim,moves[0],0);
    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)objAnim,0x1e);
  }

  if (hitResult == 0) {
    turnAmount = (int)yawDelta;
    if (turnAmount > 0) {
      turnAmount = turnAmount / 0x14;
    } else {
      turnAmount = turnAmount / 0x14;
    }
    yawDelta = (s16)turnAmount;
  } else {
    turnAmount = (int)yawDelta;
    if (turnAmount > 0) {
      turnAmount = (turnAmount - 0x500) / 0x14;
    } else {
      turnAmount = (turnAmount + 0x500) / 0x14;
    }
    yawDelta = (s16)turnAmount;
  }

  objAnim->yaw += yawDelta;
  ret = (uint)(s16)yawDelta;
  if ((int)ret < 0) {
    ret = -ret;
  }
  *turnSpeed = (float)(s32)ret / lbl_803E1CE0;
  return 1;
}
#pragma peephole reset
#pragma scheduling reset

/* Trivial 4b 0-arg blr leaves. */
void dll_2E_release_nop(void) {}
void dll_2E_initialise_nop(void) {}
