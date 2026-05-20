#ifndef MAIN_DLL_DIM_DIMBOULDER_H_
#define MAIN_DLL_DIM_DIMBOULDER_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gIMIceMountainObjDescriptor;
extern ObjectDescriptor gCRrockfallObjDescriptor;
extern ObjectDescriptor gMagicLightObjDescriptor;
extern ObjectDescriptor gIMIcePillarObjDescriptor;

void FUN_801ac248(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_801ac24c(int param_1);
void FUN_801ac340(int param_1,undefined *param_2);
void FUN_801ac490(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
undefined4 FUN_801accf4(int param_1,undefined4 param_2,int param_3);
void FUN_801acd7c(int param_1);
void FUN_801acda4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_801ad248(int param_1);
double FUN_801ad24c(int param_1);
void FUN_801ad318(int param_1);
void FUN_801ad350(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_801ad97c(int param_1,int param_2);
void FUN_801ad980(void);
undefined4
FUN_801ad984(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9);
void FUN_801adb28(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_801adbec(int param_1);
void FUN_801adc20(undefined2 *param_1);
void FUN_801adc9c(undefined2 *param_1,int param_2);
void FUN_801adca0(undefined2 *param_1,undefined2 *param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,char param_7,int param_8,int param_9);
undefined4
FUN_801addec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,uint *param_13,undefined4 param_14,undefined4 param_15
            ,undefined4 param_16);

int imicemountain_getExtraSize(void);
int imicemountain_func08(void);
void imicemountain_free(void);
int IMIceMountain_SeqFn(void *obj, int arg2, u8 *arg3);
void imicemountain_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void imicemountain_hitDetect(void);
void imicemountain_update(void);
void imicemountain_init(void);

int crrockfall_getExtraSize(void);
int crrockfall_func08(void);
void crrockfall_free(void);
void crrockfall_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void crrockfall_hitDetect(void);
void crrockfall_update(void);
void crrockfall_init(void);
void crrockfall_release(void);
void crrockfall_initialise(void);

int magiclight_getExtraSize(int *obj);
int magiclight_func08(void);
void magiclight_free(int obj);
void magiclight_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void magiclight_hitDetect(void);
void magiclight_update(int obj);
void magiclight_init(void);
void magiclight_release(void);
void magiclight_initialise(void);

int dll_16C_getExtraSize(void);
int dll_16C_func08(void);
void dll_16C_free(int *obj);
void dll_16C_hitDetect(void *obj);
void dll_16C_init(void *obj, void *arg2);
void dll_16C_release(void);
void dll_16C_initialise(void);

int imicepillar_getExtraSize(void);
int imicepillar_func08(void);
void imicepillar_free(void);
void imicepillar_render(void);
void imicepillar_hitDetect(void);
void imicepillar_update(void);
void imicepillar_init(void);
void imicepillar_release(void);
void imicepillar_initialise(void);

#endif /* MAIN_DLL_DIM_DIMBOULDER_H_ */
