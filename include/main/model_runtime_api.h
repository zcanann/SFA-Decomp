#ifndef MAIN_MODEL_RUNTIME_API_H_
#define MAIN_MODEL_RUNTIME_API_H_

#include "types.h"

typedef struct ObjModel ObjModel;
typedef struct GameObject GameObject;
typedef struct ModelFileHeader ModelFileHeader;
typedef struct ModelVtxAnimJob ModelVtxAnimJob;

void ObjModel_ToggleVertexBuffer(ObjModel* model);
void ObjModel_ToggleMatrixBuffer(ObjModel* model);
void ObjModel_ApplyBlendChannels(ObjModel* model);
void model_multMtxs(ObjModel* model, f32* worldMtx);
void modelInitBoneMtxs(ObjModel* model, f32* outReordered);
void modelInitBoneMtxs2(ObjModel* model, f32* worldMtx, f32* outReordered);
void ObjModel_UpdateAnimMatrices(ObjModel* model, ModelFileHeader* blend, GameObject* obj, f32* dst);
void ObjModel_BlendVertexStream(u8* mtxs, ModelVtxAnimJob* job, u8* data, int* offsets, u8* out);
void ObjModel_BlendNormalStream(u8* mtxs, ModelVtxAnimJob* job, u8* data, u8** outputs, int quad);
void objUpdateHitSpheres(ObjModel* model, ModelFileHeader* file, GameObject* targetObj, u8* boneMtx,
                         GameObject* sourceObj);
void* modelFileGetDisplayList(u8* modelFile, int displayListIndex);

#endif /* MAIN_MODEL_RUNTIME_API_H_ */
