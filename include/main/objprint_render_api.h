#ifndef MAIN_OBJPRINT_RENDER_API_H_
#define MAIN_OBJPRINT_RENDER_API_H_

#include "types.h"

typedef struct GameObject GameObject;
typedef struct ModelLightStruct ModelLightStruct;

extern ModelLightStruct* lbl_803DCC64;

void objRenderFuzz(int* obj);
void objRenderFn_800413d4(int* obj);
void fuzzRenderFn_800412dc(int* obj);
void renderResetFn_8003fc60(void);
void objRenderFn_80041018(GameObject* obj);
void objSetMtxFn_800412d4(u32 mtx);

#endif /* MAIN_OBJPRINT_RENDER_API_H_ */
