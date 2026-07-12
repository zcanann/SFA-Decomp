#ifndef MAIN_DLL_DLL_80220608_SHARED_H
#define MAIN_DLL_DLL_80220608_SHARED_H

#include "ghidra_import.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/shader_api.h"
#include "main/audio/sfx.h"
#include "main/audio.h"
#include "main/camera_interface.h"
#include "main/camera.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/gamebits.h"
#include "main/game_timer.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/pad.h"
#include "main/object.h"
#include "main/game_ui_interface.h"
#include "main/gameplay_runtime.h"
#include "main/mapEventTypes.h"
#include "main/model_light.h"
#include "main/mm.h"
#include "main/render.h"
#include "main/obj_placement.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objfx.h"
#include "main/loaded_file_flags.h"
#include "main/objHitReact.h"
#include "main/objhits.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/objanim_update.h"
#include "main/objtexture.h"
#include "main/voxmaps.h"
#include "main/vecmath.h"
#include "main/vec_types.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/screen_transition.h"
#include "main/frame_timing.h"

/* Pattern wrappers. */


#pragma dont_inline on
#pragma dont_inline reset
extern void logPrintf(void* fmt, ...);

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset








extern int getAngle(f32 dx, f32 dz);

#pragma dont_inline on
#pragma dont_inline reset











#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset







#pragma dont_inline on
#pragma dont_inline reset







#pragma dont_inline on

#pragma dont_inline reset

extern void vecRotateZXY(int obj, f32* vec);
#pragma dont_inline on

#pragma dont_inline reset


extern int* gPlayerInterface;
extern int Curve_AdvanceAlongPath(RomCurveWalker* curve, f32 val);


extern ModgfxInterface** gModgfxInterface;

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on

#pragma dont_inline on

#pragma dont_inline reset

#pragma dont_inline reset



#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset




#pragma dont_inline on

#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset


extern f32 fn_802945E0(f32 ratio);

#pragma dont_inline on
#pragma dont_inline reset
#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset



#pragma dont_inline on
#pragma dont_inline reset





extern f32 fn_80291FF4(f32 x);

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline reset

#pragma dont_inline on








#endif
