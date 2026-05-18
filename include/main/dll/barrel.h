#ifndef MAIN_DLL_BARREL_H_
#define MAIN_DLL_BARREL_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

undefined4
FUN_80161f0c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
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
void FUN_80163220(int param_1);
void FUN_80163308(int param_1);

extern ObjectDescriptor gGrimbleObjDescriptor;
extern ObjectDescriptor gCannonClawObjDescriptor;

int grimble_getExtraSize(void);
int grimble_func08(void);
void grimble_free(void);
void grimble_render(void);
void grimble_hitDetect(void);
void grimble_update(void);
void grimble_init(void);
void grimble_release(void);
void grimble_initialise(void);

int cannonclaw_getExtraSize(void);
int cannonclaw_func08(void);
void cannonclaw_free(void);
void cannonclaw_render(void);
void cannonclaw_hitDetect(void);
void cannonclaw_update(void);
void cannonclaw_init(void);
void cannonclaw_initialise(void);

#endif /* MAIN_DLL_BARREL_H_ */
