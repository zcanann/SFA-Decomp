#ifndef MAIN_DLL_DLL_00C9_ENEMY_H_
#define MAIN_DLL_DLL_00C9_ENEMY_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/objanim_update.h"

void objAnimFn_8014a9f0(short* obj, int state);
void FUN_8014ab58(u64 param_1, double param_2, double param_3, double param_4, double param_5, double param_6,
                  double param_7, u64 param_8, u16* param_9, int* param_10, u32 param_11, u32 param_12, u32 param_13,
                  u32 param_14, u32 param_15, u32 param_16);
void FUN_8014c0b4(double param_1, double param_2, u64 param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, int param_9, int param_10);
void FUN_8014c528(u16* param_1, int param_2);
void FUN_8014c690(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, u32 param_9, u32 param_10, int param_11);
void FUN_8014c694(u64 param_1, u64 param_2, u64 param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, int param_9);
void FUN_8014c78c(u32 param_1, u32 param_2, int param_3, int* param_4);
int enemy_SeqFn(int* node, int unused, ObjAnimUpdateState* animUpdate);
void fn_8014C66C(GameObject* obj, GameObject* target);
void fn_8014C5C0(GameObject* obj);
void fn_8014C63C(GameObject* obj);
u8 fn_8014C4D8(GameObject* obj);
void fn_8014C540(GameObject* obj, int* outIdx, f32* outA, f32* outB);
f32 enemy_getHealthFraction(GameObject* obj);
f32 sidekickToy_accelerateTowardTarget3D(GameObject* obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale,
                                         f32 maxVel, f32 drag);
f32 sidekickToy_accelerateTowardTargetXZ(GameObject* obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale,
                                         f32 maxVel, f32 drag);
int enemy_getExtraSize(void);
int enemy_getObjectTypeId(void);
void enemy_release(void);
void enemy_initialise(void);
void enemy_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void enemy_hitDetect(GameObject* obj);
void enemy_free(GameObject* obj, int flag);
void enemy_update(int obj);
void enemy_init(GameObject* obj, u8* setup, int flag);
u32 FUN_8014ca90(int param_1);
void FUN_8014caf4(int param_1, u32* param_2, float* param_3, float* param_4);
void FUN_8014cbbc(int param_1);
double FUN_8014cbcc(int param_1);
void FUN_8014cc7c(int param_1);
void FUN_8014ccac(int param_1, u32 param_2);
void FUN_8014ccb8(double param_1, double param_2, double param_3, int param_4, int param_5, float* param_6,
                  char param_7);
double FUN_8014cfac(double param_1, double param_2, double param_3, double param_4, double param_5, double param_6,
                    double param_7, int param_8);
double FUN_8014d2a4(double param_1, double param_2, double param_3, double param_4, double param_5, double param_6,
                    double param_7, int param_8);

#endif /* MAIN_DLL_DLL_00C9_ENEMY_H_ */
