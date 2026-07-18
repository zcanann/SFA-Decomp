#ifndef MAIN_DLL_DLL_0109_UNK_H_
#define MAIN_DLL_DLL_0109_UNK_H_

#include "main/game_object.h"

typedef struct Dll109MapData Dll109MapData;

int dll_109_getExtraSize_ret_16(void);
int dll_109_getObjectTypeId(void);
void dll_109_free(int obj);
void dll_109_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void dll_109_hitDetect_nop(void);
void carryable_break_respawn_update(GameObject* obj);
void dll_109_init(GameObject* obj, Dll109MapData* p);
void dll_109_release_nop(void);
void dll_109_initialise_nop(void);

#endif /* MAIN_DLL_DLL_0109_UNK_H_ */
