#ifndef MAIN_DLL_DF_ROPE_H_
#define MAIN_DLL_DF_ROPE_H_

#include "ghidra_import.h"

void dimbossgut2_updateTracking(ushort *param_1,int param_2);
void dimbossgut2_free(int param_9);
void dimbossgut2_render(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void dimbossgut2_update(ushort *param_1);
void DIMbossspit_updateBurst(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                             undefined8 param_4,undefined8 param_5,undefined8 param_6,
                             undefined8 param_7,undefined8 param_8,short *param_9);
void DIMbossspit_free(int param_1);
void DIMbossspit_render(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void DIMbossspit_update(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                        undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                        short *param_9);
void DIMbossspit_init(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                      undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                      int param_9);

#endif /* MAIN_DLL_DF_ROPE_H_ */
