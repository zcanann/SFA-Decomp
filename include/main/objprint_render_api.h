#ifndef MAIN_OBJPRINT_RENDER_API_H_
#define MAIN_OBJPRINT_RENDER_API_H_

#include "types.h"

typedef struct GameObject GameObject;
typedef struct ModelLightStruct ModelLightStruct;
typedef struct ObjModel ObjModel;

extern ModelLightStruct* lbl_803DCC64;

void objRenderFuzz(int* obj);
void objRenderFn_800413d4(int* obj);
void fuzzRenderFn_800412dc(int* obj);
void renderResetFn_8003fc60(void);
void objRenderFn_80041018(GameObject* obj);
void objRenderModel(GameObject* obj);
void objSetMtxFn_800412d4(u32 mtx);
void modelInitMtxs(int modelFile, int model);
void modelMtxFn_8003be38(int modelFile, int model, int matrix, int matrix2);
int objRotateFn_8003bce8(f32* matrix, s16* outX, s16* outY, s16* outZ);
int modelRenderCb_8003c268(int obj, int* model, int renderOpIndex);
int shaderFuzzFn_8003cc1c(GameObject* obj, ObjModel* model, int renderOpIndex);

#define modelInitMtxsPtrLegacy(modelFile, model) \
    (((void (*)(u8*, int*))modelInitMtxs)((modelFile), (model)))
#define modelMtxFn_8003be38PtrLegacy(modelFile, model, matrix, matrix2) \
    (((void (*)(u8*, int*, f32*, f32*))modelMtxFn_8003be38)( \
        (modelFile), (model), (matrix), (matrix2)))
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
