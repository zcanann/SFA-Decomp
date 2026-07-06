#ifndef MAIN_DLL_DF_ROPE_H_
#define MAIN_DLL_DF_ROPE_H_

#include "ghidra_import.h"

void dimbossgut2_updateTracking(int obj, int state);
void DIM_BossGut2_free(int param_9);
void DIM_BossGut2_render(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void DIM_BossGut2_update(int obj);
void DIMbossspit_updateBurst(int obj);
void DIMbossspit_free(int param_1);
void DIMbossspit_render(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void DIMbossspit_update(int obj);
void DIMbossspit_init(int obj);
void dimbossfire_free(int obj);
void dimbossfire_render(int p1,int p2,int p3,int p4,int p5,s8 visible);

#endif /* MAIN_DLL_DF_ROPE_H_ */
