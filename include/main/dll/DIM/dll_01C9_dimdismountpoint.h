#ifndef MAIN_DLL_DIM_DLL_01C9_DIMDISMOUNTPOINT_H_
#define MAIN_DLL_DIM_DLL_01C9_DIMDISMOUNTPOINT_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor12 gDIMDismountPointObjDescriptor;

void DIMDismountPoint_func0B(GameObject* obj, int flag);
int DIMDismountPoint_setScale(GameObject* obj);
int DIMDismountPoint_getExtraSize(void);
int DIMDismountPoint_getObjectTypeId(void);
void DIMDismountPoint_free(int obj);
void DIMDismountPoint_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void DIMDismountPoint_hitDetect(void);
void DIMDismountPoint_update(int* obj);
void DIMDismountPoint_init(u8* obj, u8* params);
void DIMDismountPoint_release(void);
void DIMDismountPoint_initialise(void);

#endif /* MAIN_DLL_DIM_DLL_01C9_DIMDISMOUNTPOINT_H_ */
