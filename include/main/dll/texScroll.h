#ifndef MAIN_DLL_TEXSCROLL_H_
#define MAIN_DLL_TEXSCROLL_H_

#include "main/game_object.h"
#include "ghidra_import.h"

u32 PressureSwitchFB_SeqFn(GameObject* obj, u32 param_2, int stateParam);
int PressureSwitchFB_getExtraSize(void);
void PressureSwitchFB_free(int obj);

#endif /* MAIN_DLL_TEXSCROLL_H_ */
