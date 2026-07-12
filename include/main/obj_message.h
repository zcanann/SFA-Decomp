#ifndef MAIN_OBJ_MESSAGE_H_
#define MAIN_OBJ_MESSAGE_H_

#include "global.h"

extern char sObjMsgOverflowInObjectWarning[];

u32 ObjMsg_Peek(void* obj, u32* outMessage, u32* outSender, u32* outParam);
int ObjMsg_Pop(void* obj, u32* outMessage, u32* outSender, u32* outParam);
void ObjMsg_SendToNearbyObjects(int targetId, f32 radius, u32 flags, void* sender, u32 message, u32 param);
void ObjMsg_SendToObjects(int targetId, u32 flags, void* sender, u32 message, u32 param);
u32 ObjMsg_SendToObject(void* obj, u32 message, void* sender, u32 param);
void ObjMsg_AllocQueue(void* obj, int capacity);

#endif /* MAIN_OBJ_MESSAGE_H_ */
