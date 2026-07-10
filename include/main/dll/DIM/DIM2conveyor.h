#ifndef MAIN_DLL_DIM_DIM2CONVEYOR_H_
#define MAIN_DLL_DIM_DIM2CONVEYOR_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gDIMBridgeCogMaiObjDescriptor;
extern ObjectDescriptor12 gDIMDismountPointObjDescriptor;

void dimlavasmash_init(s16* obj, s8* def);

int dimbridgecogmai_getExtraSize(void);
int dimbridgecogmai_getObjectTypeId(void);
void dimbridgecogmai_free(int obj);
void dimbridgecogmai_render(GameObject* p1, int p2, int p3, int p4, int p5, s8 visible);
void dimbridgecogmai_hitDetect(void);
void dimbridgecogmai_update(int* obj);
void dimbridgecogmai_init(int* obj, int* def);
int dimbridgecogmai_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void dimbridgecogmai_initialise(void);

void DIMDismountPoint_func0B(GameObject* obj, int flag);
int DIMDismountPoint_setScale(GameObject* obj);
int DIMDismountPoint_getExtraSize(void);
void DIMDismountPoint_free(int obj);
void DIMDismountPoint_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void DIMDismountPoint_hitDetect(void);
void DIMDismountPoint_update(int* obj);
void DIMDismountPoint_init(u8* obj, u8* params);
void DIMDismountPoint_release(void);
void DIMDismountPoint_initialise(void);

#endif /* MAIN_DLL_DIM_DIM2CONVEYOR_H_ */
