#ifndef MAIN_DLL_DIM_DIMLAVABALL_H_
#define MAIN_DLL_DIM_DIMLAVABALL_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gMMP_levelcontrolObjDescriptor;
extern ObjectDescriptor gMoonSeedBushObjDescriptor;
extern ObjectDescriptor gMMP_asteroid_reObjDescriptor;
extern ObjectDescriptor gMMP_moonrockObjDescriptor;
extern ObjectDescriptor gMMP_trenchFXObjDescriptor;
extern ObjectDescriptor gMMP_gyserventObjDescriptor;

void MMP_levelcontrol_update(int param_1,int param_2);
undefined4
FUN_801a68b8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
void FUN_801a6ab0(void);
void FUN_801a6ae8(int param_1);
void FUN_801a6b10(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_801a7648(int param_1);
void FUN_801a764c(undefined4 param_1,undefined4 param_2,int param_3);
void FUN_801a777c(int param_1);
void FUN_801a77a4(int param_1);
void FUN_801a7870(short *param_1,int param_2);
undefined4
FUN_801a7874(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,
            undefined4 param_10,int param_11);
void FUN_801a7a6c(int param_1);
void FUN_801a7a94(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);
void FUN_801a8164(int param_1);
int FUN_801a8168(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5,
                float *param_6,undefined4 *param_7);
void FUN_801a8284(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9);
void FUN_801a8454(int param_1);
void FUN_801a86b0(int param_1);
void FUN_801a8748(undefined4 param_1,undefined4 param_2,uint param_3);
void FUN_801a8ae8(double param_1,double param_2,double param_3,int param_4);
void FUN_801a8b20(int param_1,char param_2);
void FUN_801a8b64(int param_1);
void FUN_801a8bb0(void);
void FUN_801a8c14(void);
void FUN_801a8c18(int param_1,int param_2);
void FUN_801a8d70(void);

void MMP_levelcontrol_release(void);
void MMP_levelcontrol_initialise(void);

int MoonSeedBush_getExtraSize(void);
int MoonSeedBush_func08(void);
void MoonSeedBush_free(void);
void MoonSeedBush_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void MoonSeedBush_hitDetect(void);
void MoonSeedBush_update(void);
void MoonSeedBush_init(int obj, int data);
void MoonSeedBush_release(void);
void MoonSeedBush_initialise(void);

int mmp_asteroid_re_getExtraSize(void);
int mmp_asteroid_re_func08(void);
void mmp_asteroid_re_free(void);
void mmp_asteroid_re_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void mmp_asteroid_re_hitDetect(void);
void mmp_asteroid_re_update(void);
void mmp_asteroid_re_init(void);
void mmp_asteroid_re_release(void);
void mmp_asteroid_re_initialise(void);

int mmp_moonrock_getExtraSize(void);
int mmp_moonrock_func08(void);
void mmp_moonrock_free(int obj);
void mmp_moonrock_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void mmp_moonrock_hitDetect(void);
void mmp_moonrock_update(void);
void mmp_moonrock_init(void);
void mmp_moonrock_release(void);
void mmp_moonrock_initialise(void);

int mmp_trenchfx_getExtraSize(void);
int mmp_trenchfx_func08(void);
void mmp_trenchfx_free(int obj);
void mmp_trenchfx_render(void);
void mmp_trenchfx_hitDetect(void);
void mmp_trenchfx_update(void);
void mmp_trenchfx_init(int obj, int data);
void mmp_trenchfx_release(void);
void mmp_trenchfx_initialise(void);

int mmp_gyservent_getExtraSize(void);
int mmp_gyservent_func08(void);
void mmp_gyservent_free(void);
void mmp_gyservent_render(void);
void mmp_gyservent_hitDetect(void);
void mmp_gyservent_update(void);
void mmp_gyservent_init(int obj);
void mmp_gyservent_release(void);
void mmp_gyservent_initialise(void);

#endif /* MAIN_DLL_DIM_DIMLAVABALL_H_ */
