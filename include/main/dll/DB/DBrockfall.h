#ifndef MAIN_DLL_DB_DBROCKFALL_H_
#define MAIN_DLL_DB_DBROCKFALL_H_

#include "ghidra_import.h"
#include "main/dll/paymentkiosk.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

typedef struct FEseqobjectState {
  u8 state;
  u8 pad01;
  u8 promptState;
} FEseqobjectState;

void paymentkiosk_init(int obj, PaymentKioskMapData *initData);
int FEseqobject_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void FEseqobject_init(int obj);
void FEseqobject_update(int obj);
int dll_144_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void dll_144_init(int obj);
void paymentkiosk_release(void);
void paymentkiosk_initialise(void);
void FUN_801df45c(u16 *param_1);
u32 FUN_801df69c(int param_1,u32 param_2,int param_3);
void FUN_801df784(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,int param_11);
void FUN_801df788(int param_1);
int FEseqobject_getExtraSize(void);
int FEseqobject_getObjectTypeId(void);
void FEseqobject_free(void);
void FEseqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void FEseqobject_hitDetect(void);
void FEseqobject_release(void);
void FEseqobject_initialise(void);
int FElevControl_getExtraSize(void);
int FElevControl_getObjectTypeId(void);
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
