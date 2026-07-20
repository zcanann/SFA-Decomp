#ifndef MAIN_DLL_MMP_DLL_0182_MMPMOONROCK_H_
#define MAIN_DLL_MMP_DLL_0182_MMPMOONROCK_H_

#include "main/dll/MMP/mmp_moonrock_state.h"
#include "main/carryable_interface.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/mapEventTypes.h"
#include "main/gamebits.h"

void mmp_moonrock_reconcilePlacement(GameObject* obj, u8 place, u8 mode);
int mmp_moonrock_probeFloor(GameObject* obj, f32 x, f32 y, f32 z, f32 y2, f32* outHeight, int* outObject);
void mmp_moonrock_setPosition(GameObject* obj, f32 x, f32 y, f32 z);
void mmp_moonrock_setFrozen(GameObject* obj, u8 flag);

#endif
