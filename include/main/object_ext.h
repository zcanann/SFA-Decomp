#ifndef MAIN_OBJECT_EXT_H_
#define MAIN_OBJECT_EXT_H_

#include "main/object_transform.h"

void Obj_InsertIntoUpdateList(u8* obj);
void Obj_ClearModelSlotIndex(u8* obj);
void Obj_SetModelSlotIndex(u8* obj, int slotIndex);
int objApplyVelocity(u8* obj);
void fn_8002B860(void* v);
void objWorldToLocalPos(f32* out, ObjLocalTransform* transform, f32* in);
void fn_8002A5DC(u8* obj);

#endif /* MAIN_OBJECT_EXT_H_ */
