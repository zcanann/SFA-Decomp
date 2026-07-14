#ifndef DR_SHARED_H
#define DR_SHARED_H

#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/obj_link.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/obj_trigger.h"
#include "main/camera.h"
#include "main/object_api.h"
#include "main/object.h"
#include "ghidra_import.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx.h"
#include "main/dll_000A_expgfx.h"
#include "main/camera_interface.h"
#include "main/gamebits.h"
#include "main/game_ui_interface.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/mapEventTypes.h"
#include "main/render.h"
#include "main/shader_api.h"
#include "main/model_engine.h"
#include "main/mm.h"
#include "main/objanim.h"
#include "main/objanim_update.h"
#include "main/objhits.h"
#include "main/objtexture.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "main/voxmaps.h"
#include "main/vecmath.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/screen_transition.h"
#include "main/frame_timing.h"
#include "main/dll/DR/dr_types.h"

extern f32 lbl_803E67A0;
extern f32 lbl_803E6978;
extern f32 lbl_803E69D0;
extern f32 lbl_803E69D8;
extern f32 lbl_803E69E0;
extern f32 lbl_803E69E8;
extern f32 lbl_803E68B8;
extern s16 lbl_8032A730[];
extern u8 lbl_803DC968;
extern f32 lbl_803E68BC;
extern f32 lbl_803E67A4;
extern f32 lbl_803E67A8;
extern int lbl_803DDD40;
extern f32 lbl_803E6A2C;
extern void** gBaddieControlInterface;
extern f32 lbl_803E68C0;
extern f32 lbl_803E6A28;
extern int lbl_803DC2F0;
extern int lbl_803DDD70;
extern f32 lbl_803E6A30;
extern f32 lbl_803E69E4;
extern f32 lbl_803E68B0;
extern f32 lbl_803E68B4;
extern CameraInterface** gCameraInterface;

#endif
