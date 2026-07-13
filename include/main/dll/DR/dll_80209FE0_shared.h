#ifndef MAIN_DLL_DR_DLL_80209FE0_SHARED_H_
#define MAIN_DLL_DR_DLL_80209FE0_SHARED_H_

#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/obj_link.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/obj_trigger.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/frame_timing.h"
#include "ghidra_import.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/audio/sfx.h"
#include "main/effect_interfaces.h"
#include "main/gamebits.h"
#include "main/game_ui_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/mapEventTypes.h"
#include "main/objHitReact.h"
#include "main/render.h"
#include "main/objhits.h"
#include "main/objanim.h"
#include "main/objanim_update.h"

extern f32 lbl_803E6588;
extern f32 gThornBushLightScaleMax;
extern f32 lbl_803E6590;
extern f32 lbl_803E6594;
extern f32 lbl_803E651C;
extern f32 lbl_803E6510;
extern f32 lbl_803E657C;
extern f32 lbl_803E65C0;
extern f32 lbl_803E65C4;
extern f32 lbl_803E65C8;
extern f32 lbl_803E6598;
extern f32 lbl_803E65A8;
extern f32 gThornBushLightScaleRate;
extern f32 lbl_803E65B0;
extern f32 lbl_803E6540;
extern f32 lbl_803E6544;
extern f32 lbl_803E6548;
extern f32 lbl_803E654C;
extern int gBossDrakorMoveStateTable[];
extern f32 lbl_803E6514;
extern f32 lbl_803E6518;
extern f32 lbl_803E6520;
extern f32 lbl_803E6550;
extern f32 lbl_803E6554;
extern f32 lbl_803E6558;
extern f32 lbl_803E655C;
extern int gThornBushLightningHitTable;
extern int gThornBushThornHitTable;
extern f32 gThornBushLightningTimerInit;

typedef struct
{
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b10 : 1;
    u8 b08 : 1;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} DrakorFlags;

extern int gBossDrakorMoveSpeedTable[];
extern int gBossDrakorTurnMoveStates[];
extern s16 lbl_803DC198;
extern s16 lbl_803DC19A;
extern f32 lbl_803DC188;
extern f32 lbl_803DC18C;
extern f32 lbl_803DC190;
extern f32 lbl_803DC194;
extern f32 gBossDrakorDegToAngle;
extern f32 lbl_803E6534;
extern f32 lbl_803E6538;
extern f32 lbl_803E653C;
extern f32 lbl_803E6560;
extern f32 lbl_803E6564;
extern f32 lbl_803E6568;
extern f32 lbl_803E656C;
extern f32 lbl_803E6570;
extern f32 lbl_803E6574;
extern f32 lbl_803E6578;

#endif
