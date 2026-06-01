#ifndef MAIN_DLL_DIM_DIM2CONVEYOR_H_
#define MAIN_DLL_DIM_DIM2CONVEYOR_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gDIMBridgeCogMaiObjDescriptor;
extern ObjectDescriptor12 gDIMDismountPointObjDescriptor;

void dimlavasmash_init(s16 *obj,s8 *def);

int dimbridgecogmai_getExtraSize(void);
int dimbridgecogmai_getObjectTypeId(void);
void dimbridgecogmai_free(int obj);
void dimbridgecogmai_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dimbridgecogmai_hitDetect(void);
void dimbridgecogmai_update(int *obj);
void dimbridgecogmai_init(int *obj, int *def);
void dimbridgecogmai_initialise(void);

void dimdismountpoint_func11(int obj, int flag);
int dimdismountpoint_setScale(int obj);
int dimdismountpoint_getExtraSize(void);
void dimdismountpoint_free(int obj);
void dimdismountpoint_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void dimdismountpoint_hitDetect(void);
void dimdismountpoint_update(int *obj);
void dimdismountpoint_init(u8* obj, u8* params);
void dimdismountpoint_release(void);
void dimdismountpoint_initialise(void);

#endif /* MAIN_DLL_DIM_DIM2CONVEYOR_H_ */
