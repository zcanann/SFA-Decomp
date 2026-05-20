#ifndef MAIN_DLL_MMP_MMP_BARREL_H_
#define MAIN_DLL_MMP_MMP_BARREL_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor14 gWaveAnimatorObjDescriptor;
extern ObjectDescriptor gAlphaAnimatorObjDescriptor;
extern ObjectDescriptor14 gGroundAnimatorObjDescriptor;

u8 waveanimator_modelMtxFn(int *obj);
void waveanimator_func0B(undefined2 *param_1,int param_2);
void waveanimator_setScale(int *obj, f32 fval);
void FUN_80192488(void);
void FUN_80192618(int param_1);
void FUN_80192640(int param_1);
void FUN_80192720(int param_1,int param_2,int param_3);
void FUN_80192790(int param_1);
void FUN_801927b8(void);
void FUN_80192ab4(int param_1);
void FUN_80192b28(int param_1);
void FUN_80192b50(int param_1,int param_2);
void FUN_80192c90(int param_1);
void FUN_80192cc0(int param_1);
void FUN_80192ce8(void);
uint FUN_80193378(int param_1);
double FUN_801933d8(int param_1,int param_2);
void FUN_80193544(undefined4 param_1,undefined4 param_2,int param_3);
void FUN_80193800(void);
void FUN_80193924(int param_1);
void FUN_8019394c(void);
void FUN_80193950(int param_1,int param_2);
void FUN_80193a50(undefined4 param_1,undefined4 param_2,char *param_3,int param_4);
void FUN_80193ba8(int param_1);

int waveanimator_getExtraSize(void);
int waveanimator_func08(void);
void waveanimator_free(void);
void waveanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void waveanimator_hitDetect(void);
void waveanimator_update(void);
void waveanimator_init(void);
void waveanimator_release(void);
void waveanimator_initialise(void);

int alphaanimator_getExtraSize(void);
int alphaanimator_func08(void);
void alphaanimator_free(void);
void alphaanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void alphaanimator_hitDetect(void);
void alphaanimator_update(void);
void alphaanimator_init(int *obj);
void alphaanimator_release(void);
void alphaanimator_initialise(void);

u8 groundanimator_modelMtxFn(int *obj);
void groundanimator_func0B(void);
void groundanimator_setScale(void);
int groundanimator_getExtraSize(void);
void groundanimator_free(void);
void groundanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void groundanimator_update(void);
void groundanimator_init(void);

#endif /* MAIN_DLL_MMP_MMP_BARREL_H_ */
