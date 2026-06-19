#ifndef MAIN_DLL_CAM_DLL_5B_H_
#define MAIN_DLL_CAM_DLL_5B_H_

#include "ghidra_import.h"

void firstPersonDoControls(short *param_1);
int firstPersonEnter(u8 *cam, s16 *p2);
void CameraModeViewfinder_copyToCurrent(u16 *param_1);
void CameraModeViewfinder_free(int param_1);
void CameraModeViewfinder_update(s16 *param_1);
void CameraModeViewfinder_init(s16 *param_1, int param_2, int *param_3);
void CameraModeViewfinder_release(void);
void CameraModeViewfinder_initialise(void);
void FUN_801089d8(void);
void CameraModeDebug_update(short *param_1);
void CameraModeDebug_init(void);
void CameraModeDebug_copyToCurrent_nop(void);
void CameraModeDebug_free(void);
void CameraModeDebug_release_nop(void);
void CameraModeDebug_initialise_nop(void);
void *fn_80109B04(f32 x, f32 y, f32 z, int filter1, int filter2);
void FUN_80108e7c(void);
void CameraModeStatic_update(short *param_1);
void CameraModeStatic_init(u8 *cam, int p2, int *p3);
void CameraModeStatic_copyToCurrent_nop(void);
void CameraModeStatic_free(void);
void CameraModeStatic_release(void);
void CameraModeStatic_initialise(void);
void fn_8010A104(int *p1, int *p2, f32 x, f32 y, f32 z, int tag);
int fn_8010A47C(int curve, int *count, int tag);

#endif /* MAIN_DLL_CAM_DLL_5B_H_ */
