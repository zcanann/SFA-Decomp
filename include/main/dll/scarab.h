#ifndef MAIN_DLL_SCARAB_H_
#define MAIN_DLL_SCARAB_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/object_descriptor.h"

void iceBaddie_update(GameObject* param_1, int param_2, int param_3);
void dll_CE_func0B(GameObject* obj, int v);
void IceBall_update(u16* param_1, int param_2);

extern ObjectDescriptor11WithPadding gChukChukObjDescriptor;
extern ObjectDescriptor gIceBallObjDescriptor;

#endif /* MAIN_DLL_SCARAB_H_ */
