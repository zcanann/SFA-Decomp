#ifndef MAIN_DLL_DLL_00E2_STAFF_API_H_
#define MAIN_DLL_DLL_00E2_STAFF_API_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor23 gStaffObjDescriptor;
extern u32 lbl_80320978[];

void objSetAnimField48to0(GameObject* obj);
void quakeSpellFn_8016cee8(int* obj, int* obj2);
void staff_addHitReactValue(int* obj, s32 delta);
void staffDoGrowShrinkAnim(GameObject* obj, u8 grow, u8 alternateRate, int unused);
void staff_free(int* obj);
void staff_func0B(void);
void staff_func0E(void);
void staff_func0F(void);
void staff_func10(int* obj, s32 value);
int staff_getExtraSize(void);
void staff_getHitGeometryPoints(int* obj, f32* outA, f32* outB);
s16 staff_getHitReactValue(int* obj);
int staff_getObjectTypeId(void);
s32 staff_getSwipeTextureIndex(int* obj);
void staff_hitDetect(void);
void staff_hitDetectGeometry(int* obj);
void staff_init(int* obj);
void staff_initialise(void);
void staff_modelMtxFn(int* obj, int p4, int p5);
void staff_release(void);
void staff_render(void);
void staff_setScale(void);
void staff_setHitReactValue(int* obj, s32 value);
void staff_startSwipe(int* obj, s16 index, f32 arg2, f32 arg3);
void staff_update(int* obj);
void superQuakeFn_8016d9fc(f32* position);

#endif /* MAIN_DLL_DLL_00E2_STAFF_API_H_ */
