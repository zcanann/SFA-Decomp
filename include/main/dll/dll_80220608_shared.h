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

struct AndrossState;

/* Pattern wrappers. */
extern int lbl_803DC380;
extern f32 lbl_803E6BB0;

extern f32 lbl_803E6DB4;
extern f32 lbl_803E6DB8;
extern f32 lbl_803E6DBC;
extern f32 lbl_803E6DC0;
extern void mapGetBlockOriginForPos(f32 x, f32 y, f32 z, f32* outX, f32* outZ);
extern const f32 lbl_803E6DA8;
extern void* memcpy(void* dst, const void* src, u32 n);

#pragma dont_inline on
#pragma dont_inline reset
extern int fn_80138F84(int tricky);
extern int trickyFn_80138f14(int tricky);
extern void logPrintf(void* fmt, ...);

extern void mapTextureOverrideSetValue(int a, int b, int c);
#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset



extern f32 lbl_803E72E8;
extern f32 lbl_803E72B0;

extern int fn_80065640(void);
extern void fn_80065574(int a, GameObject* b, int c);
extern f32 lbl_803E6EA0;




extern int getAngle(f32 dx, f32 dz);

#pragma dont_inline on
#pragma dont_inline reset




extern f32 lbl_803E70C4;
extern f32 lbl_803E70D8;


extern int arrayIndexOf(int array, int count, int value);




extern f32 lbl_803E7078;
extern f32 lbl_803E7150;

extern f32 lbl_803E7218;
extern f32 lbl_803E71E4;
extern f32 lbl_803E704C;

#pragma dont_inline on
#pragma dont_inline reset

extern f32 lbl_803E7188;

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset


extern f32 lbl_803E6ED0;
extern f32 lbl_803E6EE8;
extern f32 lbl_803E6EFC;
extern f32 lbl_803E6F00;



extern f32 lbl_803E7154;

extern const f32 lbl_803E75B0;

#pragma dont_inline on
#pragma dont_inline reset

extern const f32 lbl_803E75AC;
extern const f32 lbl_803E75B4;
extern const f32 lbl_803E75C0;
extern const f32 lbl_803E75C4;
extern const f32 lbl_803E75C8;
extern double lbl_803E75D0;
extern const f32 lbl_803E75D8;
extern const f32 lbl_803E75DC;
extern const f32 lbl_803E75E0;
extern double lbl_803E75E8;
extern const f32 lbl_803E75F0;
extern const f32 lbl_803E75F4;
extern const f32 lbl_803E75F8;


extern void DIMexplosionFn_8009a96c(int obj, f32 a, f32 b, f32 c, f32 d, int e, int f, int g, int h, int i, int j,
                                    int k);
extern const f32 lbl_803E75A8;





extern f32 lbl_803E7364;
extern f32 lbl_803E7368;
extern f32 lbl_803E736C;
extern f32 lbl_803E7370;
extern f32 lbl_803E73A8;
extern f32 lbl_803E73AC;
extern f32 lbl_803E73B0;
extern f32 lbl_803E73B4;
extern f32 lbl_803E73B8;
extern f32 lbl_803E73BC;
extern f32 lbl_803E73C0;

#pragma dont_inline on

#pragma dont_inline reset

extern void fn_8003B608(int r, int g, int b);
extern void vecRotateZXY(int obj, f32* vec);
#pragma dont_inline on

#pragma dont_inline reset


extern int* gPlayerInterface;
extern int Curve_AdvanceAlongPath(RomCurveWalker* curve, f32 val);
extern void doNothing_80062A50(int obj, f32 x, f32 y, f32 z);
extern void dll_2E_func09(int p1, void* p2, void* p3, int p4);
extern void dll_2E_setLookAtMaxDistance(int state, f32 a);


extern ModgfxInterface** gModgfxInterface;

typedef struct Vec12
{
    int a, b, c;
} Vec12;

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on

#pragma dont_inline on

#pragma dont_inline reset

#pragma dont_inline reset

extern f32 lbl_803E70A0;

extern f32 lbl_803E6ECC;

#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset

extern f32 lbl_803E71A8;


extern f32 lbl_803E6EF8;

#pragma dont_inline on

#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

extern int objGetFirstChild(void);
extern void staffSetGlow(int staff, int p2, int p3);

extern f32 fn_802945E0(f32 ratio);
extern f32 lbl_803E6F80;
extern f32 lbl_803E6F84;
extern f32 lbl_803E6EF0;
extern f32 lbl_803E6EF4;

#pragma dont_inline on
#pragma dont_inline reset
#pragma dont_inline on
#pragma dont_inline reset


extern f32 lbl_803E7044;
#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset

extern f32 lbl_803E7040;
extern f32 lbl_803E7048;


#pragma dont_inline on
#pragma dont_inline reset

extern f32 lbl_803E6F40;




extern f32 fn_80291FF4(f32 x);

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline reset

#pragma dont_inline on




extern int dll_2E_func0A(int a, void* out);

extern void* playerGetFocusObject(void);
extern void setAButtonIcon(int icon);



extern f32 lbl_803E6ED8;


#endif
