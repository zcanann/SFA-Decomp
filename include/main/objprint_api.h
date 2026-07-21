#ifndef MAIN_OBJPRINT_API_H_
#define MAIN_OBJPRINT_API_H_

#include "global.h"
#include "main/game_object.h"

typedef struct ModelFileHeader ModelFileHeader;
typedef struct ObjModel ObjModel;

int* seqFn_800394a0(void);
void objPosFn_80039510(GameObject* obj, int key, f32* outPosition);
void fn_8003AAE0(GameObject* obj, int* keys, int count, int lo, int hi);
s16* objModelGetVecFn_800395d8(GameObject* obj, int target);
void fn_8003A168(GameObject* obj, void* state);
void fn_8003B608(s16 red, s16 green, s16 blue);
void fn_8003B5E0(int red, int green, int blue, int alpha);
void objSetModelMatrixOverride(f32* matrix);
int objGetAlphaCompareThreshold(void);
void objSetAlphaCompareThreshold(u8 alpha);
void modelCalcVtxGroupMtxs(ModelFileHeader* def, ObjModel* model);
void staffMtxFn_8003b620(int staff, GameObject* obj, int model, int a, int b, int c);
void objModelClearVecFn_8003aa40(GameObject* obj);
int fn_8003A8B4(GameObject* obj, int* keys, int count, u8* channels);
s16 objMathFn_8003a380(GameObject* obj, GameObject* target, f32* targetPos, u8* channels, s16* speeds,
                       f32 yOffset, int unused, int basePitch);
void objJointTracksSetAngles(u8* channelData, int count, s16 yaw, s16 pitch);
void fn_8003AC14(GameObject* obj, int* keys, int count);
void objFn_8003acfc(GameObject* obj, int* keys, int count, u8* channels);

#endif /* MAIN_OBJPRINT_API_H_ */
