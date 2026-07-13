#ifndef MAIN_DLL_NW_DLL_01A5_NWLEVCONTROL_H_
#define MAIN_DLL_NW_DLL_01A5_NWLEVCONTROL_H_

#include "main/game_object.h"
#include "types.h"

void nw_levcontrol_update(int obj);
void nw_levcontrol_init(int* obj);
int fn_801CFD68(u8* stateBytes);
int nw_levcontrol_getExtraSize(void);
void nw_levcontrol_free(GameObject* obj);

#endif /* MAIN_DLL_NW_DLL_01A5_NWLEVCONTROL_H_ */
