#ifndef MAIN_DLL_BARREL_H_
#define MAIN_DLL_BARREL_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

int fn_80161F0C(int obj, char *state, f32 arg);
undefined4
FUN_801620c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
bool FUN_8016228c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
undefined4
FUN_80162450(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
undefined4
FUN_801628c4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
undefined4
FUN_80162b78(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
void FUN_80162ec0(short *param_1);
void cannonclaw_release(int param_1);
void FUN_80163220(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80163308(int param_1);

extern ObjectDescriptor gGrimbleObjDescriptor;
extern ObjectDescriptor gCannonClawObjDescriptor;

int grimble_getExtraSize(void);
int grimble_getObjectTypeId(void);
void grimble_free(int obj);
void grimble_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void grimble_hitDetect(int obj);
void grimble_update(int obj);
void grimble_init(int obj, int p2, int p3);
void grimble_release(void);
void grimble_initialise(void);

int cannonclaw_getExtraSize(void);
int cannonclaw_getObjectTypeId(void);
void cannonclaw_free(void);
void cannonclaw_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void cannonclaw_hitDetect(void);
void cannonclaw_update(void);
void cannonclaw_init(void);
void cannonclaw_initialise(void);

#endif /* MAIN_DLL_BARREL_H_ */
