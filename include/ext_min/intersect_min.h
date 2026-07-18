#ifndef EXT_MIN_INTERSECT_MIN_H_
#define EXT_MIN_INTERSECT_MIN_H_

#include "types.h"

int renderWhirlpool(void* obj_a, void** obj_b, int param_3);

void setHudOpacity(u8 param_1);
void fn_8006FC00(int param_1);
void setupReflectionIndirectTev(u8 flag);
void drawViewFinderAperture(f32 sx, f32 sy, u8 a, u8 flag);
void doHeatEffect(u8 alpha);
void drawFn_80079e64(f32 s1, u8 mtxIdx, void* vec, f32 s2, u8 alpha0, u8 alpha1, f32 s3);
u32 objCallback_80074d04(int handle, void* model);
int modelCb_80073d04(u8* obj, int* objB);
int modelCb_80074518(void* obj_a, void** obj_b, int param_3);
int moonFxCb_80074110(u8* obj, int* objB, int slot);
#endif /* EXT_MIN_INTERSECT_MIN_H_ */
