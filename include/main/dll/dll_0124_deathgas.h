#ifndef MAIN_DLL_DLL_0124_DEATHGAS_H_
#define MAIN_DLL_DLL_0124_DEATHGAS_H_

#include "main/game_object.h"

int DeathGas_getExtraSize(void);
void DeathGas_free(GameObject* obj);
void DeathGas_update(GameObject* obj);
void DeathGas_init(GameObject* obj);

#endif /* MAIN_DLL_DLL_0124_DEATHGAS_H_ */
