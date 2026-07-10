#ifndef MAIN_DLL_TRICKY_SUBSTATES_H_
#define MAIN_DLL_TRICKY_SUBSTATES_H_

#include "main/game_object.h"
#include "ghidra_import.h"

void trickyDigTunnel(u8* obj, u8* state);
void trickyFn_80141fec(u8* obj, u8* state);
void trickyFn_80142524(u8* obj, u8* state);
int trickyFn_80142a14(int obj, int state);
int trickyFlameFn_80142b6c(u8* obj, u8* state);
int trickyFoodFn_80142d2c(GameObject* obj, int state);
int trickyFn_80142eb0(GameObject* obj, int state);
int trickyFn_801430e0(u8* obj, u8* state);
u32 trickyFn_80143210(GameObject* param_1, int* param_2);
u32 trickyFn_801432cc(GameObject* param_1, int* param_2);
u32 trickyFn_80143388(GameObject* param_1, int* param_2);
int trickyFn_801434b0(GameObject* param_1, int* param_2);
int trickyFoodFn_801437d4(GameObject* obj, int* state);
u32 trickyFn_80143b04(GameObject* param_1, int* param_2);
u32 trickyFn_80143b78(GameObject* param_1, int* param_2);
int trickyFn_80143c04(GameObject* obj, int state);
u32 fn_80143DD4(int param_1, int* param_2);
void objAnimFn_801441c0(u8* obj, u8* state);
void tricky_startRandomIdleMove(GameObject* param_1, int param_2);
int trickyFoodFn_8014460c(GameObject* param_1, int* param_2);

#endif /* MAIN_DLL_TRICKY_SUBSTATES_H_ */
