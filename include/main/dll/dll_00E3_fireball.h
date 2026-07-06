#ifndef MAIN_DLL_DLL_00E3_FIREBALL_H_
#define MAIN_DLL_DLL_00E3_FIREBALL_H_

#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/game_object.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"
#include "main/vecmath.h"

u8 fn_8016F16C(int* obj);


/* extern-cleanup: defining-file public prototypes */
void Fireball_free(int* obj);
void Fireball_hitDetect(int* obj);
void Fireball_update(int* obj);
void Fireball_init(int* obj);

#endif
