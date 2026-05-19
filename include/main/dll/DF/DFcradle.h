#ifndef MAIN_DLL_DF_DFCRADLE_H_
#define MAIN_DLL_DF_DFCRADLE_H_

#include "ghidra_import.h"

void dimbossfire_update(int param_1);
void dimbossfire_init(int obj, undefined4 param_2, int param_3);
void dimbossfire_release(void);
void dimbossfire_initialise(void);
int ccriverflow_getExtraSize(void);
void ccriverflow_free(int obj);
void ccriverflow_render(void);
void ccriverflow_update(int obj);
void ccriverflow_init(short *obj, int params);
void fn_801C0BF8(void *templateData, int angle, float *startNode, float *endNode, short *out);

#endif /* MAIN_DLL_DF_DFCRADLE_H_ */
