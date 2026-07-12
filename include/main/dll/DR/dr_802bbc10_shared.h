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

extern u64 ObjGroup_RemoveObject();
extern u32 ObjGroup_AddObject();
extern u64 ObjLink_DetachChild();
extern u32 ObjLink_AttachChild();
extern u32 ObjPath_GetPointWorldPositionArray();
extern u32 ObjPath_GetPointLocalPosition();
extern u32 ObjPath_GetPointModelMtx();
extern u32 ObjPath_GetPointWorldPosition();
extern u32 objAnimFn_80038f38();
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 lbl_803E83E8;
extern f32 lbl_803E83A4;
extern void fn_8003B950(int mtx);
extern void* gEarthWarriorResource;
extern GameUIInterface** gGameUIInterface;
extern int gDRCloudRunnerStateHandlers[];
extern void* gDRCloudRunnerDefaultStateHandler;
extern int DR_CloudRunner_stateHandler00(GameObject* obj);
extern int DR_CloudRunner_stateHandler01(GameObject* obj, int p2);
extern int DR_CloudRunner_stateHandler02(GameObject* obj, int p2);
extern int DR_CloudRunner_stateHandler03(GameObject* obj, int p2);
extern int DR_CloudRunner_stateHandler04(GameObject* obj, int p2);
extern int DR_CloudRunner_stateHandler05(int obj, int p2, f32 f);
extern int DR_CloudRunner_stateHandler06(GameObject* obj, int p2);
extern int gDREarthWarriorStateHandlers[];
extern void* gDREarthWarriorDefaultStateHandler;
int DR_EarthWarrior_stateHandler01(GameObject* obj, int p2);
int DR_EarthWarrior_stateHandler02(GameObject* obj, int p2);
extern int DR_EarthWarrior_stateHandler03(GameObject* obj, int p2);
extern f32 lbl_803E82C0;
extern int RandomTimer_UpdateRangeTrigger(void* timer, f32 lo, f32 hi);
extern void buttonDisable(int a, int b);
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
extern void fn_802BF0C8(int obj, int p2, int mode);
extern f32 lbl_803E8304;
extern f32 GX_F32_256;
extern f32 lbl_803DC76C;
extern void CameraShake_SetAllMagnitudes(f32 m);
extern void playerAddHealth(int obj, int amt);
extern const f32 lbl_803E8338;
extern f32 lbl_803E83A8;
extern f32 lbl_803E8360;
extern f32 lbl_803E8354;
extern f32 lbl_803E8364;
extern int objAudioFn_800393f8(int obj, void* audio, int soundId, int volume, int p5, int p6);
extern f32 lbl_803E82E8;
extern int lbl_8033527C[];
extern void* gDIMSnowHorn1Texture;
extern f32 lbl_803E8410;
extern f32 lbl_803DC78C;
extern f32 lbl_803DC790;
extern f32 gEarthWarriorMatrix[];
extern void dll_2E_func08(int q, int a, int b);
extern f32 lbl_803E8414;
extern f32 lbl_803E8424;
extern void characterDoEyeAnims(GameObject* obj, int q);
extern u8 gDRCloudRunnerMoveParamTable[];
extern int lbl_803E83A0;
extern int lbl_803DC770;
extern int lbl_803DC774;
extern int lbl_803DC778;
extern int lbl_803DC77C;
extern int lbl_803DC780;
extern int lbl_803DC784;
extern int padGetStickX(int p);
extern int padGetStickY(int p);
extern int getButtonsJustPressed(int p);
extern int getButtonsHeld(int p);
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
extern void fn_802B0EA4(GameObject* obj, int q, int inner);
extern void fn_802B1BF8(int obj, int q, int inner, f32 t);
extern void fn_802B1B28(int obj, f32 t);
extern char sOnCloudFormat[];
extern void fn_8003B500(GameObject* obj, int q, f32 f);
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
extern f32 interpolate(f32 cur, f32 target, f32 t);
extern f32 lbl_803E83FC;
int dim2prisonmammoth_SeqFn(int obj, int p2, ObjAnimUpdateState* animUpdate);
void fn_802BF0C8(int obj, int inner, int bit);
void fn_802BF4D8(GameObject* obj);

#endif
