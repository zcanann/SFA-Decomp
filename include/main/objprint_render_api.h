#ifndef MAIN_OBJPRINT_RENDER_API_H_
#define MAIN_OBJPRINT_RENDER_API_H_

#include "dolphin/mtx.h"
#include "types.h"

typedef struct GameObject GameObject;
typedef struct ModelLightStruct ModelLightStruct;
typedef struct ModelFileHeader ModelFileHeader;
typedef struct ObjModel ObjModel;

extern ModelLightStruct* gObjSelectedLights;

void objRender(int a, int b, int c, int d, GameObject* obj, int flag);
void objFuzzSetupGxState(void* obj);
void objRenderShadow(GameObject* obj);
void objRenderShadowIfVisible(GameObject* obj, int a, int b, int c, int d, int e);
void objRenderAttachment(GameObject* obj, int* model);
void objRenderFuzz(GameObject* obj);
void objRenderFuzzShadowShells(GameObject* obj);
void objRenderFuzzShells(GameObject* obj);
void objRenderInvalidateStateCache(void);
void objSetRenderingShadowPass(u8 enabled);
void objUpdateHitVolumeTransforms(GameObject* obj);
void objSetOverrideColor(u8 red, u8 green, u8 blue);
void objRenderModel(GameObject* obj);
void objSetCurrentMatrix(MtxPtr mtx);
void modelInitMtxs(ModelFileHeader* modelFile, ObjModel* model);
void modelBuildPosNrmMtxs(ModelFileHeader* modelFile, int* model, f32* matrix, f32* matrix2);
int objMatrixToRotation(f32* matrix, s16* outX, s16* outY, s16* outZ);
int objFuzzShellRenderCb(GameObject* obj, int* model, int renderOpIndex);
int objFuzzRenderCb(GameObject* obj, ObjModel* model, int renderOpIndex);

#endif /* MAIN_OBJPRINT_RENDER_API_H_ */
