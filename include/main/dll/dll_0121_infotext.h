#ifndef MAIN_DLL_DLL_0121_INFOTEXT_H_
#define MAIN_DLL_DLL_0121_INFOTEXT_H_

#include "main/game_object.h"
#include "types.h"

int infotext_getExtraSize(void);
void infotext_update(int obj);
void infotext_init(GameObject* obj, s8* def);

#endif /* MAIN_DLL_DLL_0121_INFOTEXT_H_ */
