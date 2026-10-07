#ifndef SYS_OBJECTS_LIFECYCLE_H_
#define SYS_OBJECTS_LIFECYCLE_H_

#include "game/objects/object.h"
#include "game/objects/object_setup.h"

void* getTablesBinEntry(int i);
ObjDef* loadObjectFile(int id);
int objGetTotalDataSize(void* tmpl, ObjDef* def, s16* data, int flags);
void Obj_UpdateModelBlendStates(void);
void Obj_UpdateObject(GameObject* obj);
void Obj_FreeObject(GameObject* obj);
void Obj_InsertIntoUpdateList(GameObject* obj);
void Obj_ClearModelSlotIndex(GameObject* obj);
void Obj_SetModelSlotIndex(GameObject* obj, int slotIndex);
int objApplyVelocity(GameObject* obj);
void Obj_RegisterEffectBox(GameObject* obj);
void Obj_UnregisterEffectBox(GameObject* obj);
void Obj_UpdateRollingRotation(GameObject* obj);
ObjPlacement* Obj_AllocObjectSetup(int size, int type);
GameObject* loadObjectAtObject(GameObject* source, ObjPlacement* setup);
GameObject* objSetupObject(ObjPlacement* setup, int flags, int mapLayer, int objIndex, void* parent);
GameObject* getTrickyObject(void);
void mapSetupPlayer(void);

int objGetFlagsE5_2(u8* obj);

#endif /* SYS_OBJECTS_LIFECYCLE_H_ */
