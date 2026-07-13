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
#include "main/effect_interfaces.h"
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
#include "main/maketex.h"
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

typedef struct
{
    int v[3];
} QuestTriple;

typedef struct
{
    u8 bit80 : 1;
    u8 b40 : 1;
    u8 bit20 : 1;
    u8 state : 4;
    u8 b01 : 1;
} HoverpadFlags;

typedef struct
{
    u8 p0 : 1;
    u8 p1 : 1;
    u8 p2 : 1;
    u8 f10 : 1;
    u8 f08 : 1;
    u8 f04 : 1;
    u8 p6 : 1;
    u8 p7 : 1;
} Flags377;

extern const f32 lbl_803E6A3C;
extern f32 lbl_803E6A40;
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
extern f32 lbl_803E6858;
extern f32 lbl_803E6994;
extern f32 lbl_803E6978;
extern f32 lbl_803E69D0;
extern f32 lbl_803E69D8;
extern f32 lbl_803E69E0;
extern f32 lbl_803E69E8;
extern f32 lbl_803E6A44;
extern f32 lbl_803E6B00;
extern f32 lbl_803E6B58;
extern void objRenderModelAndHitVolumes(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, double scale);
extern GameUIInterface** gGameUIInterface;
extern char sDrCreatorTimeFormat[];
extern const f32 lbl_803E69A8;
extern f32 lbl_803E68B8;
extern f32 lbl_803E689C;
extern f32 lbl_803E68A0;
extern f32 lbl_803E68A4;
extern f32 lbl_803E6B38;
extern f32 lbl_803E6B3C;
extern f32 lbl_803E6A48;
extern f32 lbl_803E6A88;
extern f32 lbl_803DC300;
extern f32 lbl_803DC304;
extern f32 lbl_803E68E8;
extern f32 lbl_803E68EC;
extern f32 lbl_803E6A38;
extern f32 lbl_803E6A74;
extern int lbl_8032AB48[];
extern s16 lbl_8032A730[];
extern u8 lbl_803DC968;
extern int lbl_803E6AA0;
extern int lbl_803DC318;
extern f32 lbl_803E6B4C;
extern f32 lbl_803E6B50;
extern f32 lbl_803E6B54;
extern f32 lbl_803E69C0;
extern f32 lbl_803E69C4;
extern f32 lbl_803E69C8;
extern f32 lbl_803E69BC;
extern f32 lbl_803E69B8;
extern f32 lbl_803E6898;
extern f32 lbl_803E68BC;
extern f32 lbl_803E67A4;
extern f32 lbl_803E67A8;
extern int lbl_803DDD40;
extern f32 lbl_803E6A2C;
extern f32 lbl_803E6B30;
extern void fn_8009A8C8(int obj, f32 v);
extern f32 lbl_803E6840;
extern f32 lbl_803E6844;
extern int gKTrexFloorSwitchCurveFindResult;
extern f32 gDrakorHoverpadMtx[];
extern void** gBaddieControlInterface;
extern void fn_8003B950(f32* mtx);
extern s16 gHighTopLookYawOffset;
extern f32 lbl_803E69F0;
extern f32 lbl_803E68C0;
extern void ObjModel_CopyJointTranslation(void* model, int joint, f32* out);
extern void objSetMtxFn_800412d4(void* mtx);
extern f32 gDrCageWithFindObjMaxDist;
extern f32 lbl_803E69F8;
extern f32 lbl_803E69FC;
extern f32 lbl_803E6A00;
extern f32 gDrCageWithAngVelRateMin;
extern f32 gDrCageWithAngVelRateMax;
extern f32 lbl_803E6A0C;
extern f32 lbl_803E6A10;
extern f32 lbl_803E6A14;
extern f32 lbl_803E6A28;
extern int lbl_803DC2F0;
extern int lbl_803DDD70;
extern f32 lbl_803E6940;
extern f32 lbl_803E6944;
extern f32 lbl_803E6948;
extern f32 lbl_803E694C;
extern f32 lbl_803E6950;
extern f32 lbl_803E6954;
extern f32 lbl_803E6958;
extern f32 lbl_803E6B68;
extern f32 lbl_803E6B6C;
extern f32 lbl_803E6964;
extern f32* ObjModel_GetJointMatrix(int* model, int jointIdx);
extern f32 lbl_803E67BC;
extern f32 lbl_803E67B4;
extern f32 lbl_803E67C0;
extern f32 lbl_803E67C4;
extern f32 lbl_803E67E8;
extern f32 lbl_803E6A30;
extern f32 lbl_803E6960;
extern f32 lbl_803DC2B0;
extern f32 lbl_803DC2B4;
extern f32 lbl_803DC2B8;
extern f32 gDrakorMissileProximityDetonateDist;
extern f32 gDrakorMissileFadeOutDuration;
extern f32 gLaserCannonAngleRateScale;
extern f32 lbl_803E68E4;
extern s16 gLaserCannonMaxAimStep;
extern f32 gKytesMumNearestSearchDist;
extern f32 lbl_803E69A0;
extern char sKytesMumYawDiffMessage[];
extern f32 lbl_803E6A4C;
extern f32 lbl_803E6A50;
extern f32 gDrakorHoverpadPi;
extern f32 gDrakorHoverpadAngleScale;
extern f32 lbl_803E6A8C;
extern f32 lbl_803E6A90;
extern f32 lbl_803E6A94;
extern f32 lbl_803E6A98;
extern f32 lbl_803E6A9C;
extern f32 lbl_803DC2F8;
extern s16 lbl_803DC2FC;
extern f32 lbl_803E6A78;
extern f32 lbl_803E6A7C;
extern f32 lbl_803E6A80;
extern f32 lbl_803E6A84;
extern f32 lbl_803E69E4;
extern f32 lbl_803E6A18;
extern f32 lbl_803E6A1C;
extern f32 lbl_803E695C;
extern f32 lbl_803E68B0;
extern f32 lbl_803E68B4;
extern f32 lbl_803E6B5C;
extern f32 lbl_803E6B60;
extern f32 lbl_803E6B64;
extern int gKytesMumQuestBits[];
extern int gKytesMumTriggerIds[];
extern int gKytesMumQuestIdleSfxTable[];
extern int objGetAnimState80A(GameObject* obj);
extern f32 gKytesMumFleeDistance;
extern f32 lbl_803E698C;
extern f32 lbl_803E6990;
extern u8 gKytesMumMoveSets[];
extern int gKytesMumRoamEventSfxTable;
extern int lbl_803DC2D0;
extern f32 lbl_803E699C;
extern f32 lbl_803E690C;
extern f32 lbl_803E6920;
extern f32 lbl_803E6938;
extern int fn_801702D4(int obj, f32 v);
extern void staffFn_80170380(int handle, int v);
extern f32 lbl_803E68F0;
extern f32 lbl_803E68F4;
extern f32 lbl_803E68F8;
extern f32 lbl_803E6B40;
extern u8 lbl_803DC308;
extern void objSoundFn_800392f0(int obj, int a, void* b, int c);
extern f32 lbl_803DC324;
extern s16 lbl_803DC314;
extern u8 lbl_8032AAB0[];
extern f32 lbl_803E6B44;
extern f32 lbl_803E6ADC;
extern f32 lbl_803E6A70;
extern f32 lbl_803E6818;
extern f32 lbl_803E6848;
extern void fn_8003B5E0(int a, int b, int c, int d);
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
extern f32 lbl_802C2560[];
extern f32 lbl_802C256C[];
extern f64 gKTrexFloorSwitchPi;
extern f64 gKTrexFloorSwitchBamHalfCircle;
extern f32 gKTrexFloorSwitchTriggerBoxInset;
extern f32 gKTrexFloorSwitchRiseSpeed;
extern f32 gKTrexFloorSwitchRetractSpeed;
extern f32 lbl_803E687C;
extern f32 gKTrexFloorSwitchScrollSpeed;
extern int gKTrexFloorSwitchPrevMoved;
extern f32 lbl_803E6824;
extern f32 lbl_803E6828;
extern f32 lbl_803E682C;
extern f32 lbl_803E6830;
extern f32 lbl_803E6834;
extern f32 lbl_803E6838;
extern f32 lbl_803E67C8;
extern f32 lbl_803E67CC;
extern f32 lbl_803E68FC;
extern f32 lbl_803E6900;
extern f32 lbl_803E6904;
extern f32 lbl_803E6908;
extern f32 lbl_803E6910;
extern f32 lbl_803E6914;
extern f32 lbl_803E6918;
extern f32 lbl_803E691C;
extern f32 lbl_803E6924;
extern f32 lbl_803E6928;
extern f32 lbl_803E692C;
extern f32 lbl_803DC2A8;
extern s16 lbl_803DC2AC;
extern f32 lbl_803DDD68;
extern void objfx_spawnFrameTimedHitPulse(int obj, f32 a, int b, int c, f32 d);
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
extern void fn_80039264(void* p);
extern void objModelAndSoundFn_80039118(int obj, void* p);
extern f32 lbl_803E6B04;
extern f32 lbl_803E6B0C;
extern f32 lbl_803E6B10;
extern f32 lbl_803E6B14;
extern f32 lbl_803E6B1C;
extern f32 lbl_803E6B20;
extern f32 lbl_803E6AA4;
extern void getYButtonItem(s16* out);
extern void objModelClearVecFn_8003aa40(GameObject* obj);

void kytesmum_playAnimationEventSfx(int obj, u8* arg, s16* sfxData);
int kytesmum_updateNearPlayerCallback(GameObject* obj, int unused, u8* arg);
int kytesmum_updateQuestStateCallback(GameObject* obj, int unused, u8* arg);

#endif
