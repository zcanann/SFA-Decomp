#ifndef MAIN_DLL_DR_DR_802BBC10_SHARED_H
#define MAIN_DLL_DR_DR_802BBC10_SHARED_H

#include "main/game_object.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/frame_timing.h"
#include "ghidra_import.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/voxmaps.h"
#include "main/audio/sfx.h"
#include "main/camera.h"
#include "main/effect_interfaces.h"
#include "main/gamebits.h"
#include "main/game_ui_interface.h"
#include "main/mapEventTypes.h"
#include "main/model.h"
#include "main/objHitReact.h"
#include "main/objhits.h"
#include "main/objanim.h"
#include "main/objanim_update.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/unknown/autos/placeholder_802BBC10.h"
#include "main/obj_group.h"
#include "main/obj_link.h"
#include "main/obj_path.h"

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
} ByteFlags;

typedef struct
{
    f32 f0;
    f32 f4;
    f32 f8;
    s16 hc;
    u8 pad_e[2];
    f32 f10;
    f32 f14;
    f32 f18;
    s16 h1c;
    u16 h1e;
    u16 h20;
    u8 pad_22[2];
} SnowHornEntry;

extern f32 lbl_803E83E8;
extern f32 lbl_803E83A4;
extern void* gEarthWarriorResource;
extern GameUIInterface** gGameUIInterface;
extern int gDRCloudRunnerStateHandlers[];
extern void* gDRCloudRunnerDefaultStateHandler;
extern int gDREarthWarriorStateHandlers[];
extern void* gDREarthWarriorDefaultStateHandler;
extern f32 lbl_803E82C0;
extern f32 lbl_803E83F4;
extern f32 lbl_803E83F8;
extern f32 lbl_803E83BC;
extern f32 lbl_803E8408;
extern f32 lbl_803E840C;
extern s16 gDRCloudRunnerDefaultRotX;
extern s16 gDRCloudRunnerHeadingAngleOffset;
extern s16 gDRCloudRunnerSmoothedRotX;
extern s16 gDRCloudRunnerGameBitIds;
extern int gDRCloudRunnerCurveIds[];
extern f32 lbl_803E8304;
extern f32 GX_F32_256;
extern f32 lbl_803DC76C;
extern const f32 lbl_803E8338;
extern f32 lbl_803E83A8;
extern f32 lbl_803E8360;
extern f32 lbl_803E8354;
extern f32 lbl_803E8364;
extern f32 lbl_803E82E8;
extern int lbl_8033527C[];
extern void* gDIMSnowHorn1Texture;
extern f32 lbl_803E8410;
extern f32 lbl_803DC78C;
extern f32 lbl_803DC790;
extern f32 gEarthWarriorMatrix[];
extern f32 lbl_803E8414;
extern f32 lbl_803E8424;
extern u8 gDRCloudRunnerMoveParamTable[];
extern int lbl_803E83A0;
extern int lbl_803DC770;
extern int lbl_803DC774;
extern int lbl_803DC778;
extern int lbl_803DC77C;
extern int lbl_803DC780;
extern int lbl_803DC784;
extern int gDRCloudRunnerAirMeterBaseline;
extern f32 lbl_803E83B4;
extern f32 lbl_803E83B8;
extern f32 lbl_803E83C0;
extern f32 lbl_803E83C4;
extern f32 lbl_803E83C8;
extern f32 lbl_803E83CC;
extern f32 lbl_803E83D0;
extern f32 lbl_803E83D4;
extern f32 lbl_803E83D8;
extern f32 lbl_803E83DC;
extern f32 lbl_803E83E0;
extern f32 lbl_803E83E4;
extern f32 lbl_803E83EC;
extern f32 lbl_803E83F0;
extern int gDRCloudRunnerVecTable[];
extern s16 gDRCloudRunnerRollAngleLimits;
extern char sOnCloudFormat[];
extern f32 lbl_803E8418;
extern f32 lbl_803E841C;
extern f32 lbl_803E8420;
extern f32 lbl_803E83AC;
extern f32 lbl_803E83B0;
extern f32 lbl_803E82EC;
extern f32 GXInit_ClearColor;
extern f32 GXInit_BlackColor;
extern f32 GXInit_WhiteColor;
extern f32 lbl_803E82FC;
extern f32 lbl_803E8300;
extern f32 lbl_803E8308;
extern f32 lbl_803E830C;
extern f32 lbl_803E83FC;

#endif
