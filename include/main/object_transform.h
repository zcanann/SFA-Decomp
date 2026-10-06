#ifndef MAIN_OBJECT_TRANSFORM_H_
#define MAIN_OBJECT_TRANSFORM_H_

#include "types.h"
#include "main/vecmath.h"

typedef struct GameObject GameObject;

void Obj_TransformLocalVectorToWorld(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, GameObject* obj);
void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, GameObject* obj);
void Obj_TransformWorldVectorToLocal(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, GameObject* obj);
void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, GameObject* obj);
void Obj_GetWorldPosition(GameObject* obj, f32* outX, f32* outY, f32* outZ);
void Obj_TransformLocalPointByWorldMatrix(GameObject* obj, f32* src, f32* dst, u8 ignoreScale);
void Obj_TransformLocalVectorByWorldMatrix(GameObject* obj, f32* src, f32* dst);
void objWorldToLocalPos(f32* out, MatrixTransform* transform, f32* in);

#endif /* MAIN_OBJECT_TRANSFORM_H_ */
