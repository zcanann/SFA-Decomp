#ifndef MAIN_DLL_DIM_DIM2FLAMEBURST_H_
#define MAIN_DLL_DIM_DIM2FLAMEBURST_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gExplosionObjDescriptor;
extern ObjectDescriptor gDIMWoodDoor2ObjDescriptor;
extern ObjectDescriptor gDIMMagicBridgeObjDescriptor;

void FUN_801b3de4(u32 param_1,u32 param_2);
bool FUN_801b3e28(int param_1);
void FUN_801b3ec0(int param_1);
void FUN_801b3ee4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801b3f2c(int param_1);
void FUN_801b4020(u16 *param_1,int param_2);
void FUN_801b40f0(u64 param_1,double param_2,double param_3,double param_4);
void FUN_801b43a8(u8 param_1,u8 *param_2);
void FUN_801b457c(int param_1);
void FUN_801b45ac(void);
void FUN_801b45b0(u64 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,u64 param_7,u64 param_8);
void FUN_801b4f60(void);
void FUN_801b55c0(void);
void FUN_801b5624(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_801b5628(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801b57b4(u16 *param_1,int param_2);
void FUN_801b5844(void);
void FUN_801b5848(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801b5870(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9);
void FUN_801b5b00(u16 *param_1,int param_2);
void FUN_801b5b8c(void);
void FUN_801b5d00(int param_1,int param_2);
u32 FUN_801b5df0(int param_1,u32 param_2,ObjAnimUpdateState *animUpdate);
void FUN_801b6108(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801b6130(int param_1);
void FUN_801b63c0(void);

int explosion_getExtraSize(void);
int explosion_getObjectTypeId(int obj);
void explosion_free(int obj);
void explosion_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void explosion_hitDetect(void);
void explosion_update(int obj);
void explosion_init(int obj, int p2);
void explosion_release(u32 param_1);
void explosion_initialise(void);

int dimwooddoor2_getExtraSize(void);
int dimwooddoor2_getObjectTypeId(void);
void dimwooddoor2_free(void);
void dimwooddoor2_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dimwooddoor2_hitDetect(void);
void dimwooddoor2_update(int* obj);
void dimwooddoor2_init(u8* obj, u8* params);
void dimwooddoor2_release(void);
void dimwooddoor2_initialise(void);

int dimmagicbridge_getExtraSize(void);
int dimmagicbridge_getObjectTypeId(void);
void dimmagicbridge_free(void);
void dimmagicbridge_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dimmagicbridge_hitDetect(void);
void dimmagicbridge_update(int obj);
void dimmagicbridge_init(u8* obj, u8* params);
int dimmagicbridge_flameSeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void dimmagicbridge_release(void);
void dimmagicbridge_initialise(void);
int dll_1CE_getExtraSize(void);
int dll_1CE_getObjectTypeId(void);
void dll_1CE_free(void);
void dll_1CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_1CE_hitDetect(void);
void dll_1CE_init(u8* obj, u8* params);
void dll_1CE_release(void);
void dll_1CE_initialise(void);

#endif /* MAIN_DLL_DIM_DIM2FLAMEBURST_H_ */
