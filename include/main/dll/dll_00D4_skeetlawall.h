#ifndef MAIN_DLL_TREASURECHEST_H_
#define MAIN_DLL_TREASURECHEST_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

void FUN_8016702c(void);
void dll_D3_update(int* obj);
void dll_D3_init(GameObject* obj, int def, int flag);
void dll_D3_initialise(void);
extern ObjectDescriptor11WithPadding gSkeetlaWallObjDescriptor;

#endif /* MAIN_DLL_TREASURECHEST_H_ */
