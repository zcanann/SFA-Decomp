#ifndef MAIN_DLL_CF_CFGUARDIAN_H_
#define MAIN_DLL_CF_CFGUARDIAN_H_

#include "ghidra_import.h"
#include "main/game_object.h"

void fn_801845FC(u8 *obj, f32 *posOrHit, u8 mode, f32 *fallbackPos);
int Scarab_getExtraSize(void);
void Scarab_free(void);
void Scarab_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);

#endif /* MAIN_DLL_CF_CFGUARDIAN_H_ */
