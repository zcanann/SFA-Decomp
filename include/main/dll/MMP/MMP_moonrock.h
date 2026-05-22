#ifndef MAIN_DLL_MMP_MMP_MOONROCK_H_
#define MAIN_DLL_MMP_MMP_MOONROCK_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gWaterFallSprayObjDescriptor;
extern ObjectDescriptor gLightningObjDescriptor;
extern ObjectDescriptor gSfxPlayerObjDescriptor;

void lightning_free(u8 *obj, int p2);
void lightning_render(u8 *obj);
void WaterFallSpray_free(u8 *obj);
void WaterFallSpray_init(u8 *obj, u8 *data);
void WaterFallSpray_render(void);
int WaterFallSpray_getExtraSize(void);
int WaterFallSpray_SeqFn(int *obj);
void sfxplayerObj_init(u8 *obj, u8 *data);
void sfxplayerObj_free(u8 *obj);
int sfxplayerObj_getExtraSize(void);

void FUN_80197960(int param_1);
void FUN_80197990(int param_1);
void FUN_80197c38(int param_1,int param_2);
void FUN_80197e14(int param_1);
void FUN_80197e54(int param_1);
void FUN_80197e84(void);
void FUN_80198230(int param_1,int param_2);
undefined4 FUN_80198348(uint param_1);
void FUN_8019836c(void);
void FUN_801983a0(uint param_1);
void FUN_80198634(int param_1);
void FUN_801986d4(uint param_1);
void FUN_80198d58(int param_1,int param_2);
void FUN_80198e08(void);

#endif /* MAIN_DLL_MMP_MMP_MOONROCK_H_ */
