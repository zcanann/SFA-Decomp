#ifndef MAIN_DLL_DLL_00E2_STAFF_H_
#define MAIN_DLL_DLL_00E2_STAFF_H_

#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/dll_00E2_staff_api.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"
#include "main/resource.h"
#include "main/objlib.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/camera.h"
#include "dolphin/gx/GXDraw.h"
#include "string.h"

void staffSetGlow(GameObject* obj, u8 attackType, u8 enable);
void staff_setupSwipe(int p1, u8* swipe, int p3, int p4);
void quakeSpellTextureFn_8016dbf4(void);

#endif
