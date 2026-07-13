#ifndef SFA_DLL_PLAYER_80295318_SHARED_H
#define SFA_DLL_PLAYER_80295318_SHARED_H

#include "main/game_object.h"
#include "main/object_api.h"
#include "main/object_transform.h"
#include "main/object.h"
#include "ghidra_import.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/objseq_api.h"
#include "main/shader_api.h"
#include "main/dll/player_state.h"
#include "main/dll/baddie_control_interface.h"
#include "main/camera_interface.h"
#include "main/camera.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/mapEventTypes.h"
#include "main/model.h"
#include "main/mm.h"
#include "main/render.h"
#include "main/objanim.h"
#include "main/objanim_update.h"
#include "main/objhits.h"
#include "main/objtexture.h"
#include "main/objseq.h"
#include "main/dll/player_motion.h"
#include "main/dll/player_objects.h"
#include "main/dll/player_status.h"
#include "main/dll/player_target.h"
#include "main/dll/player_api.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/vecmath.h"
#include "main/dll/path_control_interface.h"
#include "main/frame_timing.h"
#include "main/byte_flags.h"
#include "main/pad.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTransform.h"
#include "track/intersect_api.h"
#include "string.h"

/* external symbol declarations */
extern void fn_8005D108();
extern u32 FUN_8006f764();
extern u32 FUN_80070ec8();
extern u32 FUN_80071d70();
extern u32 FUN_80071f8c();
extern u32 FUN_80071f90();
extern int FUN_8007f3c8();
extern int FUN_8007f7c0();
extern int FUN_8007f810();
extern u32 FUN_80080f34();
extern u32 FUN_80080f3c();
extern u32 FUN_800810d8();
extern u32 FUN_800810dc();
extern u32 FUN_800810f4();
extern u32 FUN_800810f8();
extern u32 FUN_80081110();
extern u32 FUN_8008111c();
extern u32 FUN_80081120();
extern u32 FUN_80081124();
extern void fn_8011F6E0(int button, u8 angle, int mag);
extern void fn_8011F6D4(int flag);
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, int*** out, int a, int b);
extern void objRenderFuzz(int obj);
extern void objRenderFn_800413d4(int obj);
extern void fuzzRenderFn_800412dc(int obj);
extern void fn_8011F34C(int a);
extern int audioPickSoundEffect_8006ed24(u8 id, int bank);
extern void playerShadowFn_80062a30(int obj);
extern int lbl_803DCF34;
extern int lbl_803DCF38;
extern int hitDetectFn_800658a4(int a, void* p, int flag, f32 x, f32 y, f32 z);
extern void fn_80189C68(int a);
extern int objBboxFn_800640cc(f32 radius, void* from, void* to, int mode, void* hit, int obj, int p7, int p8, int p9,
                              int p10);
extern void setTextColor(u32* objAndParam, u8 blue, u8 green, u8 red, int alpha);
extern void fn_80078740(void);
extern void drawFn_8005cf8c(void* matrix, void* displayList, int count);

extern f32 vec3f_distanceSquared(void* a, void* b);
extern void hudFn_8011f38c(int arg);
extern void __set_debug_bba(int a);
#endif
