#ifndef MAIN_DLL_GAMEPLAY_H_
#define MAIN_DLL_GAMEPLAY_H_

#include "ghidra_import.h"

undefined4 gameplay_isDebugOptionEnabled(uint param_1);
void gameplay_registerDebugOption(uint param_1);
uint gameplay_hasDebugOption(uint param_1);
void gameplay_resetPreviewColor(void);
u8 * gameplay_getPreviewSettings(void);
void gameplay_applyPreviewSettings(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                                   undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                   undefined8 param_7,undefined8 param_8);
undefined * FUN_800e82d8(void);
undefined4 FUN_800e82e0(int param_1);
undefined4 FUN_800e83c8(int param_1);
void FUN_800e842c(int param_1);
void FUN_800e8630(int param_1);
void FUN_800e8794(undefined2 param_1);
int FUN_800e87a0(void);
undefined4 * FUN_800e87a8(void);
int gameplay_loadPreviewSettings(undefined8 param_1,double param_2,undefined8 param_3,
                                 undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                 undefined8 param_7,undefined8 param_8);
void gameplay_applyPreviewSettingsForSlot(undefined8 param_1,double param_2,undefined8 param_3,
                                          undefined8 param_4,undefined8 param_5,
                                          undefined8 param_6,undefined8 param_7,
                                          undefined8 param_8,byte param_9);
void gameplay_capturePreviewSettings(void);
void gameplay_applyCurrentPreviewSettings(undefined8 param_1,double param_2,undefined8 param_3,
                                          undefined8 param_4,undefined8 param_5,
                                          undefined8 param_6,undefined8 param_7,
                                          undefined8 param_8);
void FUN_800e8b48(void);
void FUN_800e8b54(void);
uint FUN_800e8b6c(void);
undefined FUN_800e8b98(void);
int FUN_800e8ba4(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                byte param_9);
undefined * FUN_800e8d50(uint param_1,uint param_2);
int FUN_800e8d6c(uint param_1,byte param_2,uint param_3,undefined *param_4);
undefined1 * FUN_800e8f50(void);
void FUN_800e8f58(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_800e9298(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_800e95e8(undefined4 param_1,undefined4 param_2,int param_3);
void FUN_800e99f8(void);
int FUN_800e9b14(int param_1,uint param_2);
void FUN_800e9c00(uint param_1,int param_2);
void FUN_800e9c3c(uint param_1);
uint FUN_800e9ca4(uint param_1,uint param_2);
undefined FUN_800e9d1c(uint param_1);
void FUN_800e9da0(uint param_1,uint param_2);
void FUN_800e9e54(void);
double FUN_800e9e74(void);
void FUN_800e9e9c(void);
void FUN_800ea000(void);
void FUN_800ea034(void);
void FUN_800ea1cc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined param_11,int param_12);
void FUN_800ea3e8(void);
void FUN_800ea590(undefined4 *param_1,undefined2 param_2,uint param_3,undefined param_4);
void FUN_800ea698(void);
void FUN_800ea6c4(void);
void FUN_800ea7bc(int param_1);
ushort FUN_800ea83c(void);
void FUN_800ea858(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
undefined4
FUN_800ea8c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
undefined FUN_800ea9ac(void);
void FUN_800ea9b8(void);
void FUN_800eab50(void);
void FUN_800eac54(void);
void FUN_800eac94(void);
void FUN_800eacd8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_800eaeb8(int param_1);
void FUN_800eaf2c(int param_1,int param_2);
void FUN_800eaf90(int param_1);
int FUN_800eafb4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                uint param_9);
void FUN_800eb410(int param_1,int param_2);
void FUN_800eb464(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800eb4d0(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,undefined4 param_5,
                 int *param_6);
void FUN_800eb6f8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,uint param_12,
                 undefined4 param_13,undefined4 *param_14,undefined4 param_15,undefined4 param_16);
void FUN_800ec43c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ec4a8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ec514(undefined4 param_1,undefined param_2,undefined4 param_3,uint param_4);
void FUN_800eca00(int param_1,undefined2 param_2,int param_3,uint param_4);
void FUN_800eca64(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ecb04(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ecb7c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ecbf8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ecd94(int param_1,int param_2,int param_3,uint param_4);
void FUN_800ece08(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ece84(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ecef0(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ecf5c(int param_1,undefined2 param_2,int param_3,uint param_4);
void FUN_800ecfc0(int param_1,undefined2 param_2,int param_3,uint param_4);
void FUN_800ed024(short *param_1,int param_2,int param_3,uint param_4,undefined4 param_5,
                 uint *param_6);
void FUN_800ed228(int param_1,int param_2,int param_3,uint param_4);
void FUN_800ed28c(int param_1,undefined2 param_2,int param_3,uint param_4);
void FUN_800ed2f0(int param_1,undefined2 param_2,int param_3,uint param_4);
void FUN_800ed354(int param_1,undefined2 param_2,int param_3,uint param_4);
void FUN_800ed3b8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ed424(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ed490(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ed4fc(int param_1,undefined2 param_2,int param_3,uint param_4);
void FUN_800ed560(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ed5e4(int param_1,int param_2,int param_3,uint param_4);
void FUN_800ed68c(int param_1,int param_2,int param_3,uint param_4);
void FUN_800ed880(int param_1,undefined2 param_2,int param_3,uint param_4);
void FUN_800ed8e4(int param_1,undefined2 param_2,int param_3,uint param_4);
void FUN_800ed948(int param_1,undefined2 param_2,short *param_3,uint param_4);
void FUN_800ed9ac(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ee000(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);
void FUN_800ee10c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);

#endif /* MAIN_DLL_GAMEPLAY_H_ */
