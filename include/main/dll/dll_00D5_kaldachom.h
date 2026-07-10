#ifndef MAIN_DLL_CAMPFIRE_H_
#define MAIN_DLL_CAMPFIRE_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/dll/campfire_state.h"
#include "main/object_descriptor.h"

void kaldaChomFn_8016821c(GameObject* obj, KaldaChomControl* control);
void kaldaChomFn_80168374(GameObject* obj, int state, u8 useUpperMouthPoint);
void kaldachom_handleAnimEvents(GameObject* obj, int p2, int p3);
void kaldachom_updateCombat(GameObject* obj, int stateWithBaddieData, int state);
void kaldachom_func0B(void);
s16 kaldachom_setScale(int* obj);
int kaldachom_getExtraSize(void);
int kaldachom_getObjectTypeId(void);
void kaldachom_free(GameObject* param_1);
void kaldachom_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void kaldachom_hitDetect(void);
void kaldachom_update(GameObject* param_1);
void kaldachom_init(GameObject* obj, int data, int skip_alloc);
void kaldachom_release(void);
void kaldachom_initialise(void);

extern ObjectDescriptor12 gKaldaChomObjDescriptor;

#endif /* MAIN_DLL_CAMPFIRE_H_ */
