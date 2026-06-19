#ifndef MAIN_DLL_DLL_00E4_FLAMETHROWERSPE_H_
#define MAIN_DLL_DLL_00E4_FLAMETHROWERSPE_H_

#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"

void flamethrowerspe_setScale(int* obj, s16 a, s16 b, f32 f1, f32 f2, f32 f3);


/* extern-cleanup: defining-file public prototypes */
void flamethrowerspe_update(int* obj);
void flamethrowerspe_init(int* obj, int* params);

#endif
