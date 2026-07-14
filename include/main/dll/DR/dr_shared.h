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

extern f32 lbl_803E6AA8;
extern f32 lbl_803E6AB4;
extern f32 lbl_803E6AB8;
extern f32 lbl_803E6ABC;
extern f32 lbl_803E6AC0;
extern f32 lbl_803E6AC4;
extern f32 lbl_803E6AC8;
extern f32 lbl_803E6B34;
extern f32 lbl_803E67A0;
extern const f32 lbl_803E67B8;
extern f32 lbl_803E6808;
extern f32 lbl_803E6978;
extern f32 lbl_803E69D0;
extern f32 lbl_803E69D8;
extern f32 lbl_803E69E0;
extern f32 lbl_803E69E8;
extern f32 lbl_803E6B00;
extern f32 lbl_803E68B8;
extern f32 lbl_803E6B38;
extern f32 lbl_803E6B3C;
extern int lbl_8032AB48[];
extern s16 lbl_8032A730[];
extern u8 lbl_803DC968;
extern int lbl_803E6AA0;
extern int lbl_803DC318;
extern f32 lbl_803E6B4C;
extern f32 lbl_803E6B50;
extern f32 lbl_803E6B54;
extern f32 lbl_803E68BC;
extern f32 lbl_803E67A4;
extern f32 lbl_803E67A8;
extern int lbl_803DDD40;
extern f32 lbl_803E6A2C;
extern f32 lbl_803E6B30;
extern f32 lbl_803E6840;
extern f32 lbl_803E6844;
extern void** gBaddieControlInterface;
extern s16 gHighTopLookYawOffset;
extern f32 lbl_803E68C0;
extern f32 lbl_803E6A28;
extern int lbl_803DC2F0;
extern int lbl_803DDD70;
extern f32 lbl_803E67BC;
extern f32 lbl_803E67B4;
extern f32 lbl_803E67C0;
extern f32 lbl_803E67C4;
extern f32 lbl_803E67E8;
extern f32 lbl_803E6A30;
extern f32 lbl_803E69E4;
extern f32 lbl_803E68B0;
extern f32 lbl_803E68B4;
extern f32 lbl_803E6B40;
extern u8 lbl_803DC308;
extern f32 lbl_803DC324;
extern s16 lbl_803DC314;
extern u8 lbl_8032AAB0[];
extern f32 lbl_803E6B44;
extern f32 lbl_803E6ADC;
extern f32 lbl_803E6818;
extern f32 lbl_803E6848;
extern s16 lbl_803DC290[4];
extern s16 lbl_803DC298[4];
extern u32 lbl_803E67B0;
extern s16 lbl_803DC250;
extern f32 lbl_803E6810;
extern f32 lbl_803E67F4;
extern f32 lbl_803E67F8;
extern f32 lbl_803E680C;
extern f32 lbl_803E6814;
extern s16 lbl_803DC260;
extern u16 lbl_803DC288;
extern f32 lbl_8032A51C[];
extern s16 lbl_803DC258;
extern u16 lbl_803DC268;
extern u16 lbl_803DC270;
extern u16 lbl_803DC278;
extern u16 lbl_803DC280;
extern s16 lbl_8032A510[];
extern f32 lbl_8032A528[];
extern f32 lbl_803E681C;
extern f32 lbl_803E684C;
extern f32 lbl_803E6850;
extern f32 lbl_803E67F0;
extern f32 lbl_803E6824;
extern f32 lbl_803E6828;
extern f32 lbl_803E682C;
extern f32 lbl_803E6830;
extern f32 lbl_803E6834;
extern f32 lbl_803E6838;
extern f32 lbl_803E67C8;
extern f32 lbl_803E67CC;
extern f32 lbl_803E6820;
extern CameraInterface** gCameraInterface;
extern f32 lbl_803E67D8;
extern f32 lbl_803E67D0;
extern f32 lbl_803E67D4;
extern f32 lbl_803E67EC;
extern f32 lbl_803E6B24;
extern f32 lbl_803E6B28;
extern f32 lbl_803E6B2C;
extern f32 lbl_803E6AAC;
extern f32 lbl_803E6AB0;
extern f32 lbl_803E6AD8;
extern f32 lbl_803E6AE0;
extern f32 lbl_803E6AE4;
extern f32 lbl_803E6AE8;
extern f32 lbl_803E6AEC;
extern f32 lbl_803E6AF0;
extern f32 lbl_803E6B04;
extern f32 lbl_803E6B0C;
extern f32 lbl_803E6B10;
extern f32 lbl_803E6B14;
extern f32 lbl_803E6B1C;
extern f32 lbl_803E6B20;
extern f32 lbl_803E6AA4;

#endif
