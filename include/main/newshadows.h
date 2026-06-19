#ifndef MAIN_NEWSHADOWS_H_
#define MAIN_NEWSHADOWS_H_

#include "ghidra_import.h"

void FUN_8006a028(u32 param_1,u32 param_2,u32 param_3,u32 param_4);
void newshadows_captureProjectedShadow(u16 *object);
void newshadows_sortQueuedShadowCasters(int queueBase,int casterCount);
void newshadows_renderQueuedShadowCasters(void);
void newshadows_queueShadowCaster(int object);
void newshadows_getShadowTextureTable4x8(int *tableOut,int *columnsOut,int *rowsOut);
void newshadows_getShadowTextureTable16(int *tableOut,int *countOut);
void FUN_8006af44(u32 *param_1);
void FUN_8006af50(u32 *param_1);
void newshadows_getShadowTexture(int *textureOut);
void FUN_8006af68(u32 *param_1);
void newshadows_getBlankShadowTexture(int *textureOut);
void newshadows_getShadowDirectionTexture(int *textureOut);
void newshadows_getSoftShadowTexture(int *textureOut);
int FUN_8006af98(void);
void newshadows_getShadowRampTexture(int *textureOut);
int newshadows_getSmallShadowTexture(void);
void newshadows_getShadowDiskTexture(int *textureOut);
void FUN_8006b024(u32 *param_1);
void newshadows_getShadowNoiseTexture(int *textureOut);
void FUN_8006b03c(int param_1,u32 *param_2,u32 *param_3,int *param_4,int *param_5);
double newshadows_getShadowNoiseScale(void);
void FUN_8006b0bc(int param_1);
void FUN_8006b0e8(int param_1);
void newshadows_bindShadowRenderTexture(int textureSlot);
int newshadows_getShadowRenderTexture(void);
u32 FUN_8006b188(void);
int newshadows_getInverseShadowRampTexture(void);
int newshadows_getRadialFalloffTexture(void);
void newshadows_bindShadowCaptureTexture(int textureSlot);
void newshadows_refreshShadowCaptureTexture(void);
void newshadows_flushShadowRenderTargets(void);
void newshadows_updateFrameState(void);
void newshadows_getShadowNoiseScroll(float *xOffsetOut,float *yOffsetOut);
void FUN_8006b4f8(u8 *param_1);
void newshadows_freeShadowDirectionTexture(void);
void newshadows_buildShadowDirectionTexture(void);
void FUN_8006b824(double param_1,double param_2,double param_3,float *param_4,int param_5,
                 float *param_6,float *param_7);
void FUN_8006bce4(void);
void FUN_8006c2d8(void);
u16 FUN_8006dc08(u32 param_1,u8 param_2);
void FUN_8006dca8(u64 param_1,double param_2,u32 param_3,u32 param_4,
                 u32 param_5,int param_6,int param_7);

#endif /* MAIN_NEWSHADOWS_H_ */
