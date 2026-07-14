#ifndef MAIN_MODEL_RUNTIME_API_H_
#define MAIN_MODEL_RUNTIME_API_H_

#include "types.h"

void ObjModel_ToggleVertexBuffer(u8* model);
void ObjModel_ToggleMatrixBuffer(u8* model);
void ObjModel_ApplyBlendChannels(u8* model);
void model_multMtxs(u8* model, f32* out);
void modelInitBoneMtxs(u8* model, u8* out);
void modelInitBoneMtxs2(u8* model, u8* out2, u8* out);
void ObjModel_UpdateAnimMatrices(u8* model, u8* blend, u8* obj, u8* dst);

#define ObjModel_ToggleVertexBufferIntLegacy(model) \
    (((void (*)(int*))ObjModel_ToggleVertexBuffer)((model)))
#define ObjModel_ToggleMatrixBufferIntLegacy(model) \
    (((void (*)(int*))ObjModel_ToggleMatrixBuffer)((model)))
#define ObjModel_ApplyBlendChannelsIntLegacy(model) \
    (((void (*)(int*))ObjModel_ApplyBlendChannels)((model)))
#define model_multMtxsIntLegacy(model, out) \
    (((void (*)(int*, f32*))model_multMtxs)((model), (out)))
#define modelInitBoneMtxsIntLegacy(model, out) \
    (((void (*)(int*, f32*))modelInitBoneMtxs)((model), (out)))
#define modelInitBoneMtxs2IntLegacy(model, out2, out) \
    (((void (*)(int*, f32*, f32*))modelInitBoneMtxs2)((model), (out2), (out)))
#define ObjModel_UpdateAnimMatricesIntLegacy(model, blend, obj, dst) \
    (((void (*)(int*, u8*, int*, f32*))ObjModel_UpdateAnimMatrices)( \
        (model), (blend), (obj), (dst)))

#endif /* MAIN_MODEL_RUNTIME_API_H_ */
