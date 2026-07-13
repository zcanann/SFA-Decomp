#ifndef MAIN_DLL_DLL_0129_CAMPFIRE_H_
#define MAIN_DLL_DLL_0129_CAMPFIRE_H_

#include "main/game_object.h"
#include "types.h"

int CampFire_getExtraSize(void);
int CampFire_getObjectTypeId(void);
void CampFire_free(GameObject* obj);
void CampFire_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void CampFire_update(int obj);
void CampFire_init(int obj, int def);

#endif /* MAIN_DLL_DLL_0129_CAMPFIRE_H_ */
