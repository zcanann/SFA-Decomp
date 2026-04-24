#ifndef MAIN_NEWSHADOWS_H_
#define MAIN_NEWSHADOWS_H_

#include "ghidra_import.h"

void FUN_8006a028(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4);
void newshadows_captureProjectedShadow(ushort *object);
void newshadows_sortQueuedShadowCasters(int queueBase,int casterCount);
void newshadows_renderQueuedShadowCasters(void);
void newshadows_queueShadowCaster(int object);
void newshadows_getShadowTextureTable4x8(int *tableOut,int *columnsOut,int *rowsOut);
void newshadows_getShadowTextureTable16(int *tableOut,int *countOut);
void FUN_8006af44(undefined4 *param_1);
void FUN_8006af50(undefined4 *param_1);
void newshadows_getShadowTexture(int *textureOut);
void FUN_8006af68(undefined4 *param_1);
void newshadows_getBlankShadowTexture(int *textureOut);
void newshadows_getShadowDirectionTexture(int *textureOut);
void newshadows_getSoftShadowTexture(int *textureOut);
int FUN_8006af98(void);
void newshadows_getShadowRampTexture(int *textureOut);
int newshadows_getSmallShadowTexture(void);
void newshadows_getShadowDiskTexture(int *textureOut);
void FUN_8006b024(undefined4 *param_1);
void newshadows_getShadowNoiseTexture(int *textureOut);
void FUN_8006b03c(int param_1,undefined4 *param_2,undefined4 *param_3,int *param_4,int *param_5);
double newshadows_getShadowNoiseScale(void);
void FUN_8006b0bc(int param_1);
void FUN_8006b0e8(int param_1);
void newshadows_bindShadowRenderTexture(int textureSlot);
int newshadows_getShadowRenderTexture(void);
undefined4 FUN_8006b188(void);
int newshadows_getInverseShadowRampTexture(void);
int newshadows_getRadialFalloffTexture(void);
void newshadows_bindShadowCaptureTexture(int textureSlot);
void newshadows_refreshShadowCaptureTexture(void);
void newshadows_flushShadowRenderTargets(void);
void newshadows_updateFrameState(void);
void newshadows_getShadowNoiseScroll(float *xOffsetOut,float *yOffsetOut);
void FUN_8006b4f8(undefined *param_1);
void newshadows_freeShadowDirectionTexture(void);
void newshadows_buildShadowDirectionTexture(void);
void FUN_8006b824(double param_1,double param_2,double param_3,float *param_4,int param_5,
                 float *param_6,float *param_7);
void FUN_8006bce4(void);
void FUN_8006c2d8(void);
undefined2 FUN_8006dc08(uint param_1,undefined param_2);
void FUN_8006dca8(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7);

#endif /* MAIN_NEWSHADOWS_H_ */
