#ifndef MAIN_DLL_WATERFALLCONTROL_H_
#define MAIN_DLL_WATERFALLCONTROL_H_

#include "ghidra_import.h"
#include "main/game_object.h"

void tumbleweed_updateRollingMotion(short* param_1, int param_2);
void FUN_80163e44(short* param_1, int param_2);
void tumbleweed_func0F(GameObject* obj, int value);
int tumbleweed_func0E(GameObject* obj);
void tumbleweed_func0B(GameObject* obj, float x, float y);
int tumbleweed_setScale(GameObject* obj);
int tumbleweed_getExtraSize(void);

#endif /* MAIN_DLL_WATERFALLCONTROL_H_ */
