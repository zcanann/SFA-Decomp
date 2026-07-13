#ifndef MAIN_DLL_DLL_00D2_TUMBLEWEED_H_
#define MAIN_DLL_DLL_00D2_TUMBLEWEED_H_

#include "main/game_object.h"
#include "types.h"

void tumbleweed_updateRollingMotion(GameObject* obj, int state);
void tumbleweed_func0F(GameObject* obj, int value);
int tumbleweed_func0E(GameObject* obj);
void tumbleweed_render2(int* obj, int targetPos);
void tumbleweed_modelMtxFn(GameObject* obj);
void tumbleweed_func0B(GameObject* obj, float x, float y);
int tumbleweed_setScale(GameObject* obj);
int tumbleweed_getExtraSize(void);
void tumbleweed_free(int* obj);
void tumbleweed_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void tumbleweed_update(GameObject* obj);
void tumbleweed_updateStateMachine(GameObject* obj);
void tumbleweed_init(GameObject* obj, int defData);
void tumbleweed_updateEffects(GameObject* obj);
void tumbleweed_updateTargetedStateMachine(GameObject* obj);

#endif /* MAIN_DLL_DLL_00D2_TUMBLEWEED_H_ */
