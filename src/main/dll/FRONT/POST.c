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

extern PostMotionTarget *fn_800394A0(void);
extern void fn_80038F1C(int a, int b);
extern s16 fn_8003A380(double distance, PostObjAnimComponent *objAnim, PostObject *obj,
                       void *primary, void *secondary, s16 *events, int eventCount,
                       int eventState);
extern int fn_8003A8B4(PostObjAnimComponent *objAnim, PostMotionTarget *leadAnims,
                       u8 contactAnim, void *secondary);
extern uint countLeadingZeros(int value);

extern f64 lbl_803E1C98;
extern f32 lbl_803E1C90;
extern f32 lbl_803E1CC4;
extern f32 lbl_803E1CD0;
extern f32 lbl_803E1CDC;
extern f32 lbl_803E1CE0;

/*
 * --INFO--
 *
 * Function: fn_80115650
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
int fn_80115650(void *objAnimArg, void *objArg, int *turning, void *controlArg,
                float *turnSpeed, s16 *moves)
{
  PostObjAnimComponent *objAnim;
  PostObject *obj;
  PostControl *control;
  PostMotionTarget *motion;
  s16 yawDelta;
  s16 hitResult;
  int turnAmount;
  uint ret;
  double distance;
  void *secondary;

  objAnim = (PostObjAnimComponent *)objAnimArg;
  obj = (PostObject *)objArg;
  control = (PostControl *)controlArg;
  motion = fn_800394A0();
  if (obj->motion == 0) {
    distance = (double)lbl_803E1CD0;
  } else if ((obj->motion->flags & 2) != 0) {
    distance = (double)(lbl_803E1CDC *
                        (float)((double)(s32)obj->motion->yawB - lbl_803E1C98));
  } else if ((obj->motion->flags & 1) != 0) {
    distance = (double)(float)((double)(s32)obj->motion->yawA - lbl_803E1C98);
  } else {
    distance = (double)lbl_803E1CD0;
  }

  yawDelta = Obj_GetYawDeltaToObject((ushort *)objAnim,(int)obj,(float *)0);
  if ((control->flags & 0x10) != 0) {
    fn_80038F1C(0,1);
    yawDelta += -0x8000;
  }

  if ((control->flags & 8) == 0) {
    secondary = control->secondary;
  } else {
    secondary = 0;
  }

  hitResult = fn_8003A380(distance,objAnim,obj,control->primary,secondary,control->events,8,
                          control->eventState);
  if ((control->flags & 8) == 0) {
    control->blocked = countLeadingZeros(fn_8003A8B4(objAnim,motion,control->contactAnim,
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
      return countLeadingZeros((int)hitResult) >> 5;
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
    turnAmount = turnAmount / 0x14 + (turnAmount >> 0x1f);
    yawDelta = (s16)turnAmount - (s16)(turnAmount >> 0x1f);
  } else {
    turnAmount = (int)yawDelta;
    if (turnAmount > 0) {
      turnAmount = (turnAmount - 0x500) / 0x14 + ((turnAmount - 0x500) >> 0x1f);
    } else {
      turnAmount = (turnAmount + 0x500) / 0x14 + ((turnAmount + 0x500) >> 0x1f);
    }
    yawDelta = (s16)turnAmount - (s16)(turnAmount >> 0x1f);
  }

  objAnim->yaw += yawDelta;
  ret = (uint)yawDelta;
  if ((int)ret < 0) {
    ret = -ret;
  }
  *turnSpeed = (float)((double)(s32)ret - lbl_803E1C98) / lbl_803E1CE0;
  return 1;
}
#pragma peephole reset
#pragma scheduling reset

/* Trivial 4b 0-arg blr leaves. */
void fn_801159DC(void) {}
void fn_801159E0(void) {}
