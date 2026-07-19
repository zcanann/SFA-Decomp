#ifndef MAIN_OBJPRINT_RENDER_API_H_
#define MAIN_OBJPRINT_RENDER_API_H_

#include "types.h"

typedef struct GameObject GameObject;
typedef struct ModelLightStruct ModelLightStruct;
typedef struct ObjModel ObjModel;

extern ModelLightStruct* lbl_803DCC64;

void objRender(int a, int b, int c, int d, GameObject* obj, int flag);
void objRenderFuzzFn_8003d6f8(void* obj);
void objRenderShadow(void* obj);
void objRenderFn_8003d980(u8* obj, int* model);
void objRenderFuzz(int* obj);
void objRenderFn_800413d4(int* obj);
void fuzzRenderFn_800412dc(int* obj);
void renderResetFn_8003fc60(void);
void set_shadowFlag_803dcc29(u8 enabled);
void objRenderFn_80041018(GameObject* obj);
void objSetOverrideColor(u8 red, u8 green, u8 blue);
void objRenderModel(GameObject* obj);
void objSetMtxFn_800412d4(u32 mtx);
void modelInitMtxs(int modelFile, int model);
void modelMtxFn_8003be38(u8* modelFile, int* model, f32* matrix, f32* matrix2);
int objRotateFn_8003bce8(f32* matrix, s16* outX, s16* outY, s16* outZ);
int modelRenderCb_8003c268(int obj, int* model, int renderOpIndex);
int shaderFuzzFn_8003cc1c(GameObject* obj, ObjModel* model, int renderOpIndex);

#define modelInitMtxsPtrLegacy(modelFile, model) \
    (((void (*)(u8*, int*))modelInitMtxs)((modelFile), (model)))
#define objRotateFn_8003bce8VoidLegacy(matrix, outX, outY, outZ) \
    (((void (*)(f32*, s16*, s16*, s16*))objRotateFn_8003bce8)( \
        (matrix), (outX), (outY), (outZ)))
#define modelRenderCb_8003c268Legacy \
    ((void (*)(void))modelRenderCb_8003c268)
#define shaderFuzzFn_8003cc1cLegacy \
    ((void (*)(void))shaderFuzzFn_8003cc1c)
#define objRenderModelPtrLegacy(obj) \
    (((void (*)(int*))objRenderModel)((obj)))
#define objRenderModelIntLegacy(obj) \
    (((void (*)(int))objRenderModel)((obj)))
#define objRenderModelWithBankTableLegacy(obj, bankTable) \
    (((void (*)(int*, int**))objRenderModel)((obj), (bankTable)))

#endif /* MAIN_OBJPRINT_RENDER_API_H_ */
