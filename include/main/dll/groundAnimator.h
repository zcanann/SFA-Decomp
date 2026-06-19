#ifndef MAIN_DLL_GROUNDANIMATOR_H_
#define MAIN_DLL_GROUNDANIMATOR_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

struct GameObject;
struct WmColumnPlacement;

void dll_115_update(int obj);
void dll_115_init(short *obj,int mapData);
void dll_115_release_nop(void);
void dll_115_initialise_nop(void);
int wm_column_getExtraSize(void);
int wm_column_getObjectTypeId(void);
void wm_column_free(int obj);
void wm_column_render(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void wm_column_hitDetect(void);
void wm_column_update(int obj);
void wm_column_init(struct GameObject *obj, struct WmColumnPlacement *mapData);
void wm_column_release(void);
void wm_column_initialise(void);
extern ObjectDescriptor gWM_ColumnObjDescriptor;
extern ObjectDescriptor13 gAppleOnTreeObjDescriptor;
void appleontree_func0B(int obj,float *pos);
void FUN_8017db40(u32 param_1,int param_2);
void FUN_8017de58(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);
void FUN_8017e0f8(int obj);
void FUN_8017e12c(int param_1);
u32 FUN_8017e15c(double param_1,u16 *param_2,int param_3);
u32 FUN_8017e3c0(double param_1,u16 *param_2,int param_3);

#endif /* MAIN_DLL_GROUNDANIMATOR_H_ */
