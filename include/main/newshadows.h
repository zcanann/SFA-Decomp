#ifndef MAIN_NEWSHADOWS_H_
#define MAIN_NEWSHADOWS_H_

#include "ghidra_import.h"

void FUN_8006a1a4(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4);
void FUN_8006b6d4(ushort *param_1);
void FUN_8006b9ac(int param_1,int param_2);
void FUN_8006badc(void);
void FUN_8006c500(int param_1);
void newshadows_getShadowTextureTable4x8(int *tableOut,int *columnsOut,int *rowsOut);
void newshadows_getShadowTextureTable16(int *tableOut,int *countOut);
void FUN_8006c674(undefined4 *param_1);
void FUN_8006c680(undefined4 *param_1);
void newshadows_getShadowTexture(int *textureOut);
void FUN_8006c698(undefined4 *param_1);
void newshadows_getBlankShadowTexture(int *textureOut);
void FUN_8006c6b0(undefined4 *param_1);
void newshadows_getSoftShadowTexture(int *textureOut);
int FUN_8006c6c8(void);
void newshadows_getShadowRampTexture(int *textureOut);
int newshadows_getSmallShadowTexture(void);
void newshadows_getShadowDiskTexture(int *textureOut);
void FUN_8006c754(undefined4 *param_1);
void newshadows_getShadowNoiseTexture(int *textureOut);
void FUN_8006c76c(int param_1,undefined4 *param_2,undefined4 *param_3,int *param_4,int *param_5);
double newshadows_getShadowNoiseScale(void);
void FUN_8006c7f4(int param_1);
void FUN_8006c820(int param_1);
void newshadows_bindShadowRenderTexture(int textureSlot);
int newshadows_getShadowRenderTexture(void);
undefined4 FUN_8006c8c0(void);
int newshadows_getInverseShadowRampTexture(void);
int newshadows_getRadialFalloffTexture(void);
void newshadows_bindShadowCaptureTexture(int textureSlot);
void FUN_8006c924(void);
void FUN_8006c9ac(void);
void newshadows_updateFrameState(void);
void newshadows_getShadowNoiseScroll(float *xOffsetOut,float *yOffsetOut);
void FUN_8006cc4c(undefined *param_1);
void FUN_8006cca0(void);
void FUN_8006cccc(void);
void FUN_8006ce9c(double param_1,double param_2,double param_3,float *param_4,int param_5,
                 float *param_6,float *param_7);
void FUN_8006d19c(void);
void FUN_8006d764(void);
undefined2 FUN_8006eea0(uint param_1,undefined param_2);
void FUN_8006ef48(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7);

#endif /* MAIN_NEWSHADOWS_H_ */
