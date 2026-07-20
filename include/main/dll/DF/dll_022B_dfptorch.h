#ifndef MAIN_DLL_DF_DLL_022B_DFPTORCH_H_
#define MAIN_DLL_DF_DLL_022B_DFPTORCH_H_

#include "main/game_object.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/object_descriptor.h"

int DFP_Torch_getExtraSize(void);
int DFP_Torch_getObjectTypeId(void);
void DFP_Torch_free(GameObject* obj);
void DFP_Torch_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void DFP_Torch_hitDetect(void);
void DFP_Torch_update(GameObject* obj);
void DFP_Torch_init(GameObject* obj, DfpTorchPlacement* def);
void DFP_Torch_release(void);
void DFP_Torch_initialise(void);

extern ObjectDescriptor gDFP_TorchObjDescriptor;

#endif /* MAIN_DLL_DF_DLL_022B_DFPTORCH_H_ */
