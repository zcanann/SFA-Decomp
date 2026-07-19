#ifndef MAIN_MODEL_RUNTIME_API_H_
#define MAIN_MODEL_RUNTIME_API_H_

#include "types.h"

typedef struct ObjModel ObjModel;
typedef struct GameObject GameObject;
typedef struct ModelFileHeader ModelFileHeader;

void ObjModel_ToggleVertexBuffer(ObjModel* model);
void ObjModel_ToggleMatrixBuffer(ObjModel* model);
void ObjModel_ApplyBlendChannels(ObjModel* model);
void model_multMtxs(u8* model, f32* out);
void modelInitBoneMtxs(ObjModel* model, f32* out);
void modelInitBoneMtxs2(ObjModel* model, f32* transform, f32* out);
void ObjModel_UpdateAnimMatrices(ObjModel* model, ModelFileHeader* blend, GameObject* obj, f32* dst);
void ObjModel_BlendVertexStream(u8* mtxs, u8* header, u8* data, int* offsets, u8* out);
void ObjModel_BlendNormalStream(u8* mtxs, u8* header, u8* data, u8** outputs, int quad);
void objUpdateHitSpheres(u8* hitState, u8* headerOwner, u8* previousObj, u8* boneMtx, u8* obj);
void* modelFileGetDisplayList(u8* modelFile, int displayListIndex);

#endif /* MAIN_MODEL_RUNTIME_API_H_ */
