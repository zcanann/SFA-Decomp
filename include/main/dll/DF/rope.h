#ifndef MAIN_DLL_DF_ROPE_H_
#define MAIN_DLL_DF_ROPE_H_

#include "ghidra_import.h"
#include "main/game_object.h"

typedef struct Dimbossgut2State Dimbossgut2State;

void dimbossgut2_updateTracking(GameObject* obj, Dimbossgut2State* state);
void DIM_BossGut2_free(int param_9);
void DIM_BossGut2_render(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void DIM_BossGut2_update(GameObject* obj);
void DIMbossspit_updateBurst(GameObject* obj);
void DIMbossspit_free(int param_1);
void DIMbossspit_render(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void DIMbossspit_update(GameObject* obj);
void DIMbossspit_init(int obj);
void dimbossfire_free(GameObject* obj);
void dimbossfire_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

#endif /* MAIN_DLL_DF_ROPE_H_ */
