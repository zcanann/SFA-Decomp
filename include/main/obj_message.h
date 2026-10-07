#ifndef MAIN_OBJ_MESSAGE_H_
#define MAIN_OBJ_MESSAGE_H_

#include "game/objects/object.h"

extern char sObjMsgOverflowInObjectWarning[];

/* param carries either a pointer or a message-specific integer cast to void*.
 * Integer consumers must explicitly decode it; pointer consumers retain it. */

int ObjMsg_Peek(GameObject* obj, u32* outMessage, GameObject** outSender, void** outParam);
int ObjMsg_Pop(GameObject* obj, u32* outMessage, GameObject** outSender, void** outParam);
void ObjMsg_SendToNearbyObjects(int targetId, f32 radius, u32 flags, GameObject* sender, u32 message, void* param);
void ObjMsg_SendToObjects(int targetId, u32 flags, GameObject* sender, u32 message, void* param);
u32 ObjMsg_SendToObject(GameObject* obj, u32 message, GameObject* sender, void* param);
void ObjMsg_AllocQueue(GameObject* obj, int capacity);

#endif /* MAIN_OBJ_MESSAGE_H_ */
