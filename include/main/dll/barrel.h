#ifndef MAIN_DLL_BARREL_H_
#define MAIN_DLL_BARREL_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

int grimble_stateHandlerA00(GameObject* obj, char* state, f32 arg);
int grimble_stateHandlerA01(GameObject* obj, char* state, f32 arg);
int grimble_stateHandlerA02(GameObject* obj, char* state, f32 arg);
void cannonclaw_release(void);

extern ObjectDescriptor gGrimbleObjDescriptor;
extern ObjectDescriptor gCannonClawObjDescriptor;

int grimble_getExtraSize(void);
int grimble_getObjectTypeId(void);
void grimble_free(GameObject* obj);
void grimble_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void grimble_hitDetect(int obj);
void grimble_update(GameObject* obj);
void grimble_init(int obj, int p2, int p3);
void grimble_release(void);
void grimble_initialise(void);

int cannonclaw_getExtraSize(void);
int cannonclaw_getObjectTypeId(void);
void cannonclaw_free(void);
void cannonclaw_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void cannonclaw_hitDetect(void);
void cannonclaw_update(u8* obj);
void cannonclaw_init(s16* dst, void* src);
void cannonclaw_initialise(void);

#endif /* MAIN_DLL_BARREL_H_ */
