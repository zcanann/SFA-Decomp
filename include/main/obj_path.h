#ifndef MAIN_OBJ_PATH_H_
#define MAIN_OBJ_PATH_H_

#include "main/game_object.h"

void ObjPath_GetPointWorldPositionArray(GameObject* obj, int pointIndex, int count, f32* positions);
void ObjPath_GetPointLocalPosition(GameObject* obj, int pointIndex, f32* outX, f32* outY, f32* outZ);
void ObjPath_GetPointLocalMtx(GameObject* obj, int pointIndex, f32* mtx);
u32 ObjPath_GetPointModelMtx(GameObject* obj, int pointIndex);
void ObjPath_GetPointWorldPosition(GameObject* obj, int pointIndex, f32* outX, f32* outY, f32* outZ,
                                   int useInputPosition);

#endif /* MAIN_OBJ_PATH_H_ */
