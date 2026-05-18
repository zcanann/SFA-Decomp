#ifndef MAIN_DLL_CAM_DLL_5B_H_
#define MAIN_DLL_CAM_DLL_5B_H_

#include "ghidra_import.h"

void firstPersonDoControls(short *param_1);
void firstPersonEnter(void);
void CameraModeViewfinder_copyToCurrent(undefined2 *param_1);
void CameraModeViewfinder_free(int param_1);
void CameraModeViewfinder_update(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void CameraModeViewfinder_init(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 *param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void CameraModeViewfinder_release(void);
void CameraModeViewfinder_initialise(void);
void FUN_801089d8(void);
void CameraModeDebug_update(short *param_1);
void CameraModeDebug_init(void);
void CameraModeDebug_copyToCurrent_nop(void);
void CameraModeDebug_free(void);
void CameraModeDebug_release_nop(void);
void CameraModeDebug_initialise_nop(void);
void fn_80109B04(undefined8 param_1,double param_2,double param_3);
void FUN_80108e7c(void);
void CameraModeStatic_update(short *param_1);
void CameraModeStatic_init(void);
void CameraModeStatic_copyToCurrent_nop(void);
void CameraModeStatic_free(void);
void CameraModeStatic_release(void);
void CameraModeStatic_initialise(void);
void fn_8010A104(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void fn_8010A47C(undefined4 param_1,undefined4 param_2,uint param_3);

#endif /* MAIN_DLL_CAM_DLL_5B_H_ */
