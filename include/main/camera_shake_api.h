#ifndef MAIN_CAMERA_SHAKE_API_H_
#define MAIN_CAMERA_SHAKE_API_H_

#include "types.h"

void CameraShake_SetAllMagnitudes(f32 magnitude);
void CameraShake_Start(f32 magnitude, f32 duration, f32 falloff);
void CameraShake_ApplyRadial(f32 x, f32 y, f32 z, f32 radius, f32 magnitude);

#endif /* MAIN_CAMERA_SHAKE_API_H_ */
