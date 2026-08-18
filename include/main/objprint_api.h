#ifndef MAIN_OBJPRINT_API_H_
#define MAIN_OBJPRINT_API_H_

#include "global.h"
#include "game/objects/object.h"

typedef struct ModelFileHeader ModelFileHeader;
typedef struct ObjModel ObjModel;

int* objGetLookAtJointKeys(void);
void objGetJointWorldPosition(GameObject* obj, int key, f32* outPosition);
void characterClampJointVecs(GameObject* obj, int* keys, int count, int lo, int hi);
s16* objFindJointPoseVector(GameObject* obj, int key);
void characterHeadLookRelax(GameObject* obj, void* state);
void objSetColorFilter(s16 red, s16 green, s16 blue);
void objSetGlowColor(int red, int green, int blue, int alpha);
void objSetModelMatrixOverride(f32* matrix);
int objGetAlphaCompareThreshold(void);
void objSetAlphaCompareThreshold(u8 alpha);
void modelCalcVtxGroupMtxs(ModelFileHeader* def, ObjModel* model);
void staffUpdateSegmentTransforms(GameObject* staff, GameObject* obj, ObjModel* model, int a, int b, int c);
void objModelClearJointVectors(GameObject* obj);
int characterTrackJointList(GameObject* obj, int* keys, int count, u8* channels);
s16 objJointTracksAimAtTarget(GameObject* obj, GameObject* target, f32* targetPos, u8* channels, s16* speeds,
                              f32 yOffset, int unused, int basePitch);
void objJointTracksSetAngles(u8* channelData, int count, s16 yaw, s16 pitch);
void characterDecayJointVecs(GameObject* obj, int* keys, int count);
void objJointTracksCaptureCurrentAngles(GameObject* obj, int* keys, int count, u8* channels);

#endif /* MAIN_OBJPRINT_API_H_ */
