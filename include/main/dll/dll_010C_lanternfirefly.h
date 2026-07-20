#ifndef MAIN_DLL_DLL_010C_LANTERNFIREFLY_H_
#define MAIN_DLL_DLL_010C_LANTERNFIREFLY_H_

#include "main/game_object.h"
#include "main/dll/CF/lanternfirefly_state.h"

int LanternFireFly_getExtraSize(void);
int LanternFireFly_getObjectTypeId(void);
void LanternFireFly_free(u8* obj, int flag);
void LanternFireFly_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void LanternFireFly_hitDetect(void);
void LanternFireFly_update(GameObject* obj);
void LanternFireFly_init(GameObject* obj, int def);
void LanternFireFly_release(void);
void LanternFireFly_initialise(void);

#endif /* MAIN_DLL_DLL_010C_LANTERNFIREFLY_H_ */
