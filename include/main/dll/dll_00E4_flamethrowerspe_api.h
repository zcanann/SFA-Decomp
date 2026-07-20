#ifndef MAIN_DLL_DLL_00E4_FLAMETHROWERSPE_API_H_
#define MAIN_DLL_DLL_00E4_FLAMETHROWERSPE_API_H_

#include "types.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor13 gFlameThrowerSpeObjDescriptor;

void flamethrowerspe_free(void);
void flamethrowerspe_func0B(GameObject* obj);
int flamethrowerspe_getExtraSize(void);
int flamethrowerspe_getObjectTypeId(void);
void flamethrowerspe_hitDetect(void);
void flamethrowerspe_init(GameObject* obj, int* params);
void flamethrowerspe_initialise(void);
void flamethrowerspe_modelMtxFn(void);
void flamethrowerspe_release(void);
void flamethrowerspe_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void flamethrowerspe_setScale(GameObject* obj, s16 a, s16 b, f32 f1, f32 f2, f32 f3);
void flamethrowerspe_update(GameObject* obj);

#endif /* MAIN_DLL_DLL_00E4_FLAMETHROWERSPE_API_H_ */
