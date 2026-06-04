#ifndef MAIN_DLL_FIREFLYLANTERN_H_
#define MAIN_DLL_FIREFLYLANTERN_H_

#include "ghidra_import.h"

void fn_80154870(int obj, int *state);
void fn_80154C24(int obj, int state);
void fn_80154D0C(int obj, int state, u16 *outAngle, float *outDistance);
uint fn_80154FB4(f32 maxDistance, short *obj, int state, uint turnTime);

#endif /* MAIN_DLL_FIREFLYLANTERN_H_ */
