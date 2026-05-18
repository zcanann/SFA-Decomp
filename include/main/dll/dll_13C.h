#ifndef MAIN_DLL_DLL_13C_H_
#define MAIN_DLL_DLL_13C_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

typedef struct PollenFragmentConfig {
  s16 spawnSfxId;
  s16 field02;
  s16 field04;
  s16 effectObjectId;
  s16 field08;
  s16 field0A;
  f32 scale;
  s16 field10;
  u16 flags;
} PollenFragmentConfig;

void kaldachompspit_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,
                           undefined4 param_4,undefined4 param_5,char visible);
void kaldachompspit_init(uint param_1);
void FUN_80169d38(undefined8 param_1,undefined8 param_2,undefined8 param_3,double param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9);
int FUN_8016a534(double param_1,double param_2,float *param_3,float *param_4,char param_5);
void FUN_8016a6d4(void);
void FUN_8016a708(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9);
void FUN_8016aa90(uint param_1);
void FUN_8016aae4(void);
void FUN_8016ab18(int param_1);
void FUN_8016ab40(int param_1);
void FUN_8016aba8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);
void FUN_8016ae64(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9);
void pollenfragment_init(int obj,int config);
void FUN_8016b174(int param_1);
void FUN_8016b1dc(void);
void FUN_8016b228(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);
void FUN_8016b428(undefined8 param_1,undefined8 param_2,undefined8 param_3,double param_4,
                 double param_5,double param_6,undefined8 param_7,undefined8 param_8,ushort *param_9
                 );

extern ObjectDescriptor gKaldaChompSpitObjDescriptor;
extern ObjectDescriptor gPinPonSpikeObjDescriptor;
extern ObjectDescriptor gPollenObjDescriptor;
extern ObjectDescriptor gPollenFragmentObjDescriptor;
extern PollenFragmentConfig lbl_80320538;
extern PollenFragmentConfig lbl_8032054C;
extern PollenFragmentConfig lbl_80320560;
extern PollenFragmentConfig lbl_80320574;
extern PollenFragmentConfig lbl_80320588;
extern PollenFragmentConfig *lbl_8032059C[];

#endif /* MAIN_DLL_DLL_13C_H_ */
