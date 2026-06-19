#ifndef MAIN_DLL_DLL_19E_H_
#define MAIN_DLL_DLL_19E_H_

#include "ghidra_import.h"

void dfsh_objcreator_update(int obj);
void DFSH_LaserBeam_init(int *obj);
void FUN_801c4098(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801c40c0(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9);
void FUN_801c43b0(int param_1);
void dfsh_objcreator_release(void);
void dfsh_objcreator_initialise(void);
int DFSH_LaserBeam_getExtraSize(void);
int DFSH_LaserBeam_getObjectTypeId(void);
void DFSH_LaserBeam_render(void);
void DFSH_LaserBeam_hitDetect(void);

#endif /* MAIN_DLL_DLL_19E_H_ */
