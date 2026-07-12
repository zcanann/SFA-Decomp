#ifndef MAIN_OBJLIB_H_
#define MAIN_OBJLIB_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/obj_group.h"
#include "main/obj_link.h"
#include "main/obj_list.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/obj_trigger.h"

typedef struct ObjAnimBank ObjAnimBank;
typedef void (*ObjContactCallback)(int objA, int objB);

extern char sObjAddObjectTypeReachedMaxTypes[];
int Obj_IsObjectAlive(int obj);
void ObjContact_DispatchCallbacks(int objA, int objB);
void ObjContact_RemoveObjectCallbacks(int param_1);
int ObjContact_AddCallback(int obj, int otherObj, ObjContactCallback callback);
int Obj_GetYawDeltaToObject(GameObject* obj, int target, float* distanceOut);
u32 ObjHitRegion_FindContainingId(f32 x, f32 y, f32 z);
void fn_80038988(int param_1, int param_2, u32 param_3);
void FUN_80038bb0(char param_1, int param_2);

int ObjHits_PollPriorityHitWithCooldown();

#endif /* MAIN_OBJLIB_H_ */
