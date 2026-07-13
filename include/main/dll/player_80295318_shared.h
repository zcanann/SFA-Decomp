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
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, int*** out, int a, int b);
extern void objRenderFuzz(int obj);
extern void objRenderFn_800413d4(int obj);
extern void fuzzRenderFn_800412dc(int obj);
extern int audioPickSoundEffect_8006ed24(u8 id, int bank);
extern int hitDetectFn_800658a4(int a, void* p, int flag, f32 x, f32 y, f32 z);
extern void fn_80189C68(int a);
extern int objBboxFn_800640cc(f32 radius, void* from, void* to, int mode, void* hit, int obj, int p7, int p8, int p9,
                              int p10);
extern void setTextColor(u32* objAndParam, u8 blue, u8 green, u8 red, int alpha);
extern void drawFn_8005cf8c(void* matrix, void* displayList, int count);

extern f32 vec3f_distanceSquared(void* a, void* b);
extern void __set_debug_bba(int a);
#endif
