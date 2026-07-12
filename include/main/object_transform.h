#ifndef MAIN_OBJECT_TRANSFORM_H_
#define MAIN_OBJECT_TRANSFORM_H_

#include "ghidra_import.h"

/* Rotation, uniform scale, and position block consumed by object-space transforms. */
typedef struct ObjLocalTransform
{
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 pad;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ObjLocalTransform;

void Obj_TransformLocalVectorToWorld(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ,
                                     u32 obj);
void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj);
void Obj_TransformWorldVectorToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ,
                                     u32 obj);
void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj);
void Obj_GetWorldPosition(u32 obj, f32 *outX, f32 *outY, f32 *outZ);
void objWorldToLocalPos(f32* out, ObjLocalTransform* transform, f32* in);

#endif /* MAIN_OBJECT_TRANSFORM_H_ */
