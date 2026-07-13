#ifndef MAIN_DLL_DF_DLL_022B_DFPTORCH_H_
#define MAIN_DLL_DF_DLL_022B_DFPTORCH_H_

#include "main/game_object.h"

int DFP_Torch_getExtraSize(void);
int DFP_Torch_getObjectTypeId(void);
void DFP_Torch_free(int obj);
void DFP_Torch_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void DFP_Torch_hitDetect(void);
void DFP_Torch_update(int obj);
void DFP_Torch_init(int obj, int def);
void DFP_Torch_release(void);
void DFP_Torch_initialise(void);

#endif /* MAIN_DLL_DF_DLL_022B_DFPTORCH_H_ */
