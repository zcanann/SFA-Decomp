#ifndef MAIN_CAMERA_H_
#define MAIN_CAMERA_H_

#include "global.h"

f32 *Camera_GetViewMatrix(void);
f32 *Camera_GetViewRotationMatrix(void);
void *Camera_GetCurrentViewSlot(void);
void Obj_RotateLocalOffsetByYaw(f32 *local, f32 *out, u8 yawIndex);

#endif /* MAIN_CAMERA_H_ */
