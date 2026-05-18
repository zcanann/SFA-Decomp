#ifndef MAIN_DLL_DB_DBROCKFALL_H_
#define MAIN_DLL_DB_DBROCKFALL_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

typedef struct FEseqobjectState {
  u8 state;
  u8 pad01;
  u8 promptState;
} FEseqobjectState;

void paymentkiosk_init(int param_1);
void paymentkiosk_release(void);
void paymentkiosk_initialise(void);
void FUN_801df45c(undefined2 *param_1);
uint FUN_801df69c(int param_1,undefined4 param_2,int param_3);
void FUN_801df784(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11);
void FUN_801df788(int param_1);
int FEseqobject_getExtraSize(void);
int FEseqobject_func08(void);
void FEseqobject_free(void);
void FEseqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void FEseqobject_hitDetect(void);
void FEseqobject_release(void);
void FEseqobject_initialise(void);
int FElevControl_getExtraSize(void);
int FElevControl_func08(void);
void FElevControl_free(void);
void FElevControl_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void FElevControl_hitDetect(void);
void FElevControl_update(void);
void FElevControl_init(int x);
void FElevControl_release(void);
void FElevControl_initialise(void);

extern ObjectDescriptor gFEseqobjectObjDescriptor;
extern ObjectDescriptor gFElevControlObjDescriptor;

#endif /* MAIN_DLL_DB_DBROCKFALL_H_ */
