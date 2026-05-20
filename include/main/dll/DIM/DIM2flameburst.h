#ifndef MAIN_DLL_DIM_DIM2FLAMEBURST_H_
#define MAIN_DLL_DIM_DIM2FLAMEBURST_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gExplosionObjDescriptor;
extern ObjectDescriptor gDIMWoodDoor2ObjDescriptor;
extern ObjectDescriptor gDIMMagicBridgeObjDescriptor;

void FUN_801b3de4(undefined4 param_1,uint param_2);
bool FUN_801b3e28(int param_1);
void FUN_801b3ec0(int param_1);
void FUN_801b3ee4(int param_1);
void FUN_801b3f2c(int param_1);
void FUN_801b4020(undefined2 *param_1,int param_2);
void FUN_801b40f0(undefined8 param_1,double param_2,double param_3,double param_4);
void FUN_801b43a8(byte param_1,undefined *param_2);
void FUN_801b457c(int param_1);
void FUN_801b45ac(void);
void FUN_801b45b0(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined8 param_7,undefined8 param_8);
void FUN_801b4f60(void);
void FUN_801b55c0(void);
void FUN_801b5624(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_801b5628(int param_1);
void FUN_801b5650(uint param_1);
void FUN_801b57b4(undefined2 *param_1,int param_2);
void FUN_801b5844(void);
void FUN_801b5848(int param_1);
void FUN_801b5870(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9);
void FUN_801b5b00(undefined2 *param_1,int param_2);
void FUN_801b5b8c(void);
void FUN_801b5d00(int param_1,int param_2);
undefined4 FUN_801b5df0(int param_1,undefined4 param_2,int param_3);
void FUN_801b6108(int param_1);
void FUN_801b6130(int param_1);
void FUN_801b63c0(void);

int explosion_getExtraSize(void);
int explosion_func08(int obj);
void explosion_free(int obj);
void explosion_render(void);
void explosion_hitDetect(void);
void explosion_update(void);
void explosion_init(void);
void explosion_release(uint param_1);
void explosion_initialise(void);

int dimwooddoor2_getExtraSize(void);
int dimwooddoor2_func08(void);
void dimwooddoor2_free(void);
void dimwooddoor2_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dimwooddoor2_hitDetect(void);
void dimwooddoor2_update(void);
void dimwooddoor2_init(void);
void dimwooddoor2_release(void);
void dimwooddoor2_initialise(void);

int dimmagicbridge_getExtraSize(void);
int dimmagicbridge_func08(void);
void dimmagicbridge_free(void);
void dimmagicbridge_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dimmagicbridge_hitDetect(void);
void dimmagicbridge_update(void);
void dimmagicbridge_init(void);
void dimmagicbridge_release(void);
void dimmagicbridge_initialise(void);
int dll_1CE_getExtraSize(void);
int dll_1CE_func08(void);
void dll_1CE_free(void);
void dll_1CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_1CE_hitDetect(void);
void dll_1CE_init(u8* obj, u8* params);
void dll_1CE_release(void);
void dll_1CE_initialise(void);

#endif /* MAIN_DLL_DIM_DIM2FLAMEBURST_H_ */
