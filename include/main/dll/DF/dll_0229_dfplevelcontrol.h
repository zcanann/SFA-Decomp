#ifndef MAIN_DLL_DF_DLL_0229_DFPLEVELCONTROL_H_
#define MAIN_DLL_DF_DLL_0229_DFPLEVELCONTROL_H_

#include "main/game_object.h"
extern u32 gDFP_LevelControlObjDescriptor[15];

int DFP_LevelControl_SeqFn(int obj);
void DFP_LevelControl_setScale(int unused, u8* out);
int DFP_LevelControl_getExtraSize(void);
int DFP_LevelControl_getObjectTypeId(void);
void DFP_LevelControl_free(int obj);
void DFP_LevelControl_render(void);
void DFP_LevelControl_hitDetect(void);
void DFP_LevelControl_update(GameObject* obj);
void DFP_LevelControl_init(GameObject* obj, int param2);
void DFP_LevelControl_release(void);
void DFP_LevelControl_initialise(void);

#endif /* MAIN_DLL_DF_DLL_0229_DFPLEVELCONTROL_H_ */
