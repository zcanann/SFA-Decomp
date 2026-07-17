#ifndef MAIN_NEWSHADOWS_H_
#define MAIN_NEWSHADOWS_H_

#include "ghidra_import.h"

void FUN_8006a028(u32 param_1,u32 param_2,u32 param_3,u32 param_4);
void newshadows_renderQueuedShadowCasters(void);
void newshadows_queueShadowCaster(int object);
void FUN_8006af44(u32 *param_1);
void FUN_8006af50(u32 *param_1);
void FUN_8006af68(u32 *param_1);
int FUN_8006af98(void);
void FUN_8006b024(u32 *param_1);
void FUN_8006b03c(int param_1,u32 *param_2,u32 *param_3,int *param_4,int *param_5);
void FUN_8006b0bc(int param_1);
void FUN_8006b0e8(int param_1);
u32 FUN_8006b188(void);
void updateReflectionTextures(void);
void selectReflectionTexture(int id);
void FUN_8006b4f8(u8 *param_1);
void FUN_8006b824(double param_1,double param_2,double param_3,float *param_4,int param_5,
                 float *param_6,float *param_7);
void FUN_8006bce4(void);
void FUN_8006c2d8(void);
u16 FUN_8006dc08(u32 param_1,u8 param_2);
void FUN_8006dca8(u64 param_1,double param_2,u32 param_3,u32 param_4,
                 u32 param_5,int param_6,int param_7);


/* extern-cleanup: defining-file public prototypes */
void initFn_8006d020(void);
f32 fn_8006C670(void);
void drawReflectionTexture(void);
void maybeHudFn_8006c91c(void);
void fn_8006CB24(void);
void fn_8006CB50(void);

int getReflectionTexture1(void);
void getReflectionTexture2(u32* out);
void getTextureFn_8006c5e4(u32* out);
void fn_8006C5CC(u32* out);
void newshadows_getReflectionScrollOffsets(f32* outScrollX, f32* outScrollY);
u32 getTextureFn_8006c744(void);
void fn_8006C4F8(u32* out);
void fn_8006C534(u32* out);
void fn_8006C540(u32* out);
void fn_8006C5B8(u32* out);
void fn_8006C678(int id);
void fn_8006C6A4(int id);
void textureFn_8006c4e0(int* tableOut, int* countOut);

#endif /* MAIN_NEWSHADOWS_H_ */
