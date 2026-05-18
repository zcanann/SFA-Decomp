#ifndef MAIN_DLL_FRONT_POST_H_
#define MAIN_DLL_FRONT_POST_H_

#include "ghidra_import.h"

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

int objAnimFn_80115650(PostObjAnimComponent *objAnim,PostObject *obj,int *turning,
                PostControl *control,float *turnSpeed,short *moves);
void dll_2E_release_nop(void);
void dll_2E_initialise_nop(void);

#endif /* MAIN_DLL_FRONT_POST_H_ */
