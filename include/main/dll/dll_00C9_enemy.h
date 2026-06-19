#ifndef MAIN_DLL_SIDEKICKTOY_H_
#define MAIN_DLL_SIDEKICKTOY_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

void objAnimFn_8014a9f0(short *obj, int state);
void FUN_8014ab58(u64 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,double param_7,u64 param_8,u16 *param_9,int *param_10,
                 u32 param_11,u32 param_12,u32 param_13,u32 param_14,
                 u32 param_15,u32 param_16);
void FUN_8014c0b4(double param_1,double param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_8014c528(u16 *param_1,int param_2);
void FUN_8014c690(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,int param_11);
void FUN_8014c694(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_8014c78c(u32 param_1,u32 param_2,int param_3,int *param_4);
int enemy_animEventCallback(int *node, int unused, ObjAnimUpdateState *animUpdate);
f32 sidekickToy_accelerateTowardTarget3D(int obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale,
                                        f32 maxVel, f32 drag);
f32 sidekickToy_accelerateTowardTargetXZ(int obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale,
                                        f32 maxVel, f32 drag);
u32 FUN_8014ca90(int param_1);
void FUN_8014caf4(int param_1,u32 *param_2,float *param_3,float *param_4);
void FUN_8014cbbc(int param_1);
double FUN_8014cbcc(int param_1);
void FUN_8014cc7c(int param_1);
void FUN_8014ccac(int param_1,u32 param_2);
void FUN_8014ccb8(double param_1,double param_2,double param_3,int param_4,int param_5,
                 float *param_6,char param_7);
double FUN_8014cfac(double param_1,double param_2,double param_3,double param_4,double param_5,
                   double param_6,double param_7,int param_8);
double FUN_8014d2a4(double param_1,double param_2,double param_3,double param_4,double param_5,
                   double param_6,double param_7,int param_8);

#endif /* MAIN_DLL_SIDEKICKTOY_H_ */
