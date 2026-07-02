#ifndef MAIN_DLL_DLL_00E2_STAFF_H_
#define MAIN_DLL_DLL_00E2_STAFF_H_

#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
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

void staff_func10(int* obj, s32 v);
void staff_setHitReactValue(int* obj, s32 v);
void staff_addHitReactValue(int* obj, s32 delta);
void staff_getHitGeometryPoints(int* obj, f32* outA, f32* outB);
void staff_func15(int* obj, s16 idx, f32 f1, f32 f2);
void staff_setupSwipe(int p1, u8* swipe, int p3, int p4);
void quakeSpellTextureFn_8016dbf4(void);

#endif
