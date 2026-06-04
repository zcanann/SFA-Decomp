#ifndef MAIN_DLL_CAMPFIRE_H_
#define MAIN_DLL_CAMPFIRE_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

void kaldaChomFn_8016821c(int param_1,int *param_2);
void kaldaChomFn_80168374(int param_1,int param_2,char param_3);
void kaldachom_handleAnimEvents(int obj, int p2, int p3);
void kaldachom_updateCombat(int obj, int stateWithBaddieData, int state);
void kaldachom_func0B(void);
s16 kaldachom_setScale(int *obj);
int kaldachom_getExtraSize(void);
int kaldachom_getObjectTypeId(void);
void kaldachom_free(int param_1);
void kaldachom_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void kaldachom_hitDetect(void);
void kaldachom_update(int param_1);
void kaldachom_init(int obj, int data, int skip_alloc);
void kaldachom_release(void);
void kaldachom_initialise(void);

extern ObjectDescriptor12 gKaldaChomObjDescriptor;

#endif /* MAIN_DLL_CAMPFIRE_H_ */
