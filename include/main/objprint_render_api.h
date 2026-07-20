#ifndef MAIN_OBJPRINT_RENDER_API_H_
#define MAIN_OBJPRINT_RENDER_API_H_

#include "types.h"

typedef struct GameObject GameObject;
typedef struct ModelLightStruct ModelLightStruct;
typedef struct ModelFileHeader ModelFileHeader;
typedef struct ObjModel ObjModel;

extern ModelLightStruct* lbl_803DCC64;

void objRender(int a, int b, int c, int d, GameObject* obj, int flag);
void objRenderFuzzFn_8003d6f8(void* obj);
void objRenderShadow(void* obj);
void objRenderShadowIfVisible(GameObject* obj, int a, int b, int c, int d, int e);
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
void modelInitMtxs(ModelFileHeader* modelFile, ObjModel* model);
void modelMtxFn_8003be38(u8* modelFile, int* model, f32* matrix, f32* matrix2);
int objRotateFn_8003bce8(f32* matrix, s16* outX, s16* outY, s16* outZ);
int modelRenderCb_8003c268(int obj, int* model, int renderOpIndex);
int shaderFuzzFn_8003cc1c(GameObject* obj, ObjModel* model, int renderOpIndex);

#endif /* MAIN_OBJPRINT_RENDER_API_H_ */
