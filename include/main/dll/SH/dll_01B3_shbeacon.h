#ifndef MAIN_DLL_SH_DLL_01B3_SHBEACON_H_
#define MAIN_DLL_SH_DLL_01B3_SHBEACON_H_

#include "main/game_object.h"

int shbeacon_resetFadeTimerCallback(GameObject* obj);
int sh_beacon_getExtraSize(void);
void sh_beacon_free(GameObject* obj, int keepChild);
void sh_beacon_update(GameObject* obj);
void sh_beacon_init(GameObject* obj, int defData);

#endif /* MAIN_DLL_SH_DLL_01B3_SHBEACON_H_ */
