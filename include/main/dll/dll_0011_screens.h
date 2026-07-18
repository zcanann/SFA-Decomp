#ifndef MAIN_DLL_DLL_0011_SCREENS_H_
#define MAIN_DLL_DLL_0011_SCREENS_H_

#include "main/asset_load.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"
#include "main/gamebits.h"

void loadTaskTexts(void);
int hintTextMapFn_800ea264(void);
u8 getCurTaskHintTextMap(void);
void gameBitFn_800ea2e0(u8 id);
void screens_initialise(void);
void screens_release(void);
void screens_remove(void);
void screens_run(void);
void screens_show(int id);

#endif
