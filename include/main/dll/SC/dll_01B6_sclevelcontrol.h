#ifndef MAIN_DLL_SC_DLL_01B6_SCLEVELCONTROL_H_
#define MAIN_DLL_SC_DLL_01B6_SCLEVELCONTROL_H_

#include "main/game_object.h"
#include "main/objanim_update.h"
#include "types.h"

int sc_levelcontrol_processAnimEventsCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
u8 sc_levelcontrol_getAnimEventState(int* obj);
void sc_levelcontrol_applyAnimEventState(GameObject* obj, u8 scale);
int sc_levelcontrol_getExtraSize(void);
int sc_levelcontrol_getObjectTypeId(void);
void sc_levelcontrol_free(GameObject* obj);
void sc_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void sc_levelcontrol_hitDetect(void);
void sc_levelcontrol_update(GameObject* obj);
void sc_levelcontrol_init(GameObject* obj);
void sc_levelcontrol_release(void);
void sc_levelcontrol_initialise(void);

#endif /* MAIN_DLL_SC_DLL_01B6_SCLEVELCONTROL_H_ */
