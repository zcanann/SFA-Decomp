#ifndef MAIN_DLL_MAGICPLANT_EXT_H_
#define MAIN_DLL_MAGICPLANT_EXT_H_

#include "main/camera.h"

void vambat_updateIdle(GameObject* obj, int state);
void vambat_updateEngaged(GameObject* obj, int state);
void fn_8015355C(GameObject* obj, int state);

extern u8 gMagicPlantSeqEntryTable[8];

#endif /* MAIN_DLL_MAGICPLANT_EXT_H_ */
