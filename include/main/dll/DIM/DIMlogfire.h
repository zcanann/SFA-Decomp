#ifndef MAIN_DLL_DIM_DIMLOGFIRE_H_
#define MAIN_DLL_DIM_DIMLOGFIRE_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gAnimSharpclawObjDescriptor;
extern ObjectDescriptor14 gMoonSeedPlantingSpotObjDescriptor;
extern ObjectDescriptor gCCgasventObjDescriptor;
extern ObjectDescriptor gCCgasventControlObjDescriptor;
extern ObjectDescriptor gDIMLogFireObjDescriptor;

void FUN_801a8f88(void);
void FUN_801a92cc(uint param_1);
void FUN_801a93b0(int param_1);
undefined4
FUN_801a9408(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10);
void FUN_801a9614(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_801a9730(int param_1);
void FUN_801a9758(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_801a9ab4(int param_1,int param_2);
undefined4 FUN_801a9c3c(int param_1,int param_2);
void FUN_801a9d30(int param_1);
void FUN_801a9d54(void);
void FUN_801a9e5c(uint param_1);
void FUN_801aa378(short *param_1,int param_2);
void FUN_801aa37c(int param_1);
void FUN_801aa3a0(int param_1);
void FUN_801aa480(int param_1);
undefined4 FUN_801aa4a4(void);

int animsharpclaw_getExtraSize(void);
int animsharpclaw_func08(void);
void animsharpclaw_free(int obj);
void animsharpclaw_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void animsharpclaw_hitDetect(void);
void animsharpclaw_update(void);
void animsharpclaw_init(void);
void animsharpclaw_release(void);
void animsharpclaw_initialise(void);

int MoonSeedPlantingSpot_render2(void);
int MoonSeedPlantingSpot_modelMtxFn(void);
int MoonSeedPlantingSpot_func0B(void);
void MoonSeedPlantingSpot_setScale(void);
int MoonSeedPlantingSpot_getExtraSize(void);
int MoonSeedPlantingSpot_func08(void);
void MoonSeedPlantingSpot_free(int x);
int MoonSeedPlantingSpot_SeqFn(int obj);
void MoonSeedPlantingSpot_render(void);
void MoonSeedPlantingSpot_hitDetect(void);
void MoonSeedPlantingSpot_update(void);
void MoonSeedPlantingSpot_init(void);
void MoonSeedPlantingSpot_release(void);
void MoonSeedPlantingSpot_initialise(void);

int ccgasvent_getExtraSize(void);
void ccgasvent_free(int x);
void ccgasvent_render(void);
void ccgasvent_update(void);
void ccgasvent_init(int x);

int ccgasventcontrol_getExtraSize(void);
void ccgasventcontrol_free(int obj);
int CCGasVentControl_SeqFn(int obj);
void ccgasventcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void ccgasventcontrol_update(void);
void ccgasventcontrol_init(int obj, u8 *p);

int dimlogfire_getExtraSize(void);
int dimlogfire_func08(void);
void dimlogfire_free(void);
void dimlogfire_render(void);
void dimlogfire_update(short *param_1, int param_2);
void dimlogfire_init(void);

#endif /* MAIN_DLL_DIM_DIMLOGFIRE_H_ */
