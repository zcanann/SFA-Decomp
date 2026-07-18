#ifndef MAIN_CAMERA_EXT_H_
#define MAIN_CAMERA_EXT_H_

#include "types.h"

void Obj_GetWorldPosition(u32 obj, f32* outX, f32* outY, f32* outZ);
void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, u32 obj);
void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, u32 obj);

#endif /* MAIN_CAMERA_EXT_H_ */
