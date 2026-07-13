#ifndef MAIN_DLL_DLL_01FE_PRESSURESWITCH_H_
#define MAIN_DLL_DLL_01FE_PRESSURESWITCH_H_

#include "main/game_object.h"
#include "main/objanim_update.h"

int PressureSwitch_getExtraSize(void);
int PressureSwitch_getObjectTypeId(void);
int PressureSwitch_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
void PressureSwitch_free(void);
void PressureSwitch_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void PressureSwitch_hitDetect(void);
void PressureSwitch_update(int obj);
void PressureSwitch_init(int* obj, u8* init);
void PressureSwitch_release(void);
void PressureSwitch_initialise(void);

#endif /* MAIN_DLL_DLL_01FE_PRESSURESWITCH_H_ */
