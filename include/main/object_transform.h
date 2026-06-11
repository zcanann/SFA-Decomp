#ifndef MAIN_OBJECT_TRANSFORM_H_
#define MAIN_OBJECT_TRANSFORM_H_

#include "ghidra_import.h"

void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj);
void Obj_TransformWorldVectorToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ,
                                     u32 obj);
void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj);

#endif /* MAIN_OBJECT_TRANSFORM_H_ */
