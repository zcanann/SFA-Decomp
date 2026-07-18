#ifndef MAIN_DLL_DIMMAGICBRIDGE_API_H_
#define MAIN_DLL_DIMMAGICBRIDGE_API_H_

#include "main/game_object.h"

int dimmagicbridge_getExtraSize(void);
void dimmagicbridge_update(GameObject* obj);
int dimmagicbridge_getObjectTypeId(void);
void dimmagicbridge_free(void);
void dimmagicbridge_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dimmagicbridge_hitDetect(void);
void dimmagicbridge_init(u8* obj, u8* params);
void dimmagicbridge_release(void);
void dimmagicbridge_initialise(void);

#endif /* MAIN_DLL_DIMMAGICBRIDGE_API_H_ */
