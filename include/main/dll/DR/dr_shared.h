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

typedef struct
{
    s16 v[9];
} HtInitData;

typedef struct
{
    int v[3];
} QuestTriple;

typedef struct
{
    u8 b0 : 1;
    u8 b1 : 1;
    u8 b2 : 1;
    u8 b3 : 1;
    u8 b4 : 1;
    u8 b5 : 1;
    u8 b6 : 1;
    u8 b7 : 1;
} BitFlags8;

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
extern void* gKTRexState;
extern void* gKTRexRuntime;
extern void ktrex_initialiseStateHandlerTables(void);
extern int ktrex_animEventCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
extern void objRenderModelAndHitVolumes(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, double scale);
extern void ModelLightStruct_free(void* p);
extern void Music_Trigger(int trackId, int restart);
extern void storeZeroToFloatParam(void* timer);
extern GameUIInterface** gGameUIInterface;
extern int GM_MazeWell_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
extern int DR_CageControl_SeqFn(GameObject* obj);
extern void firepipe_clearLinkedUpdateFlag(int handle);
extern void* objCreateLight(int v1, int v2);
extern void modelLightStruct_setLightKind(void* light, int v);
extern void modelLightStruct_setPosition(void* light, f32 x, f32 y, f32 z);
extern void buttonDisable(int index, u32 flags);
extern void* gHighTopStateHandlers[];
extern void* gHighTopDefaultStateHandler;
extern int hightop_stateHandler01();
extern int hightop_stateHandler02(GameObject* obj, int p, f32 t);
extern int hightop_stateHandler04();
extern int hightop_stateHandler07();
extern int hightop_stateHandler09();
extern int hightop_stateHandler10();
extern int DR_Creator_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
extern char sDrCreatorTimeFormat[];
extern const f32 lbl_803E69A8;
extern void ktrexfloorswitch_spawnEnergyArc(GameObject* obj, f32 scale, int b);
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
extern int getCurMapLayer(void);
extern void saveFileStruct_unlockCheat(int v);
extern HtInitData gHighTopLookInitData1;
extern HtInitData gHighTopLookInitData2;
extern int lbl_803E6AA0;
extern int lbl_803DC318;
extern f32 lbl_803E6B4C;
extern f32 lbl_803E6B50;
extern f32 lbl_803E6B54;
extern int gHighTopAirMeterInitValue;
extern void dll_2E_func08(void* p, int a, int b);
extern f32 lbl_803E69C0;
extern f32 lbl_803E69C4;
extern f32 lbl_803E69C8;
extern f32 lbl_803E69BC;
extern f32 lbl_803E69B8;
extern void modelLightStruct_updateGlowAlpha(void* p);
extern f32 lbl_803E6898;
extern f32 lbl_803E68BC;
extern f32 lbl_803E67A4;
extern f32 lbl_803E67A8;
extern int lbl_803DDD40;
extern void skyFn_80088c94(int a, int b);
extern int drshackle_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
extern f32 lbl_803E6A2C;
extern f32 lbl_803E6B30;
extern s16 gHighTopMovementSfxIds;
extern void fn_8009A8C8(int obj, f32 v);
extern f32 gKTRexLaneThreatHalfWidth;
extern f32 lbl_803E6840;
extern f32 lbl_803E6844;
extern MapRomList* gKTRexMapBlock;
extern void* gKTRexResource;
extern int gKTrexFloorSwitchCurveFindResult;
extern f32 gDrakorHoverpadMtx[];
extern void** gBaddieControlInterface;
extern void fn_8003B950(f32* mtx);
extern s16 gHighTopLookYawOffset;
extern int* getTrickyObject(void);
extern f32 lbl_803E69F0;
extern f32 gHighTopGroundMarkerMtx[];
extern void Obj_RemoveFromUpdateList(int obj);
extern f32 lbl_803E68C0;
extern void modelLightStruct_setEnabled(void* light, int v, f32 f);
extern void modelLightStruct_setDiffuseColor(void* light, int a, int b, int c, int d);
extern void ObjModel_CopyJointTranslation(void* model, int joint, f32* out);
extern void objSetMtxFn_800412d4(void* mtx);
extern void objParticleFn_80099d84(int obj, f32 a, int b, f32 c, int d);
extern f32 interpolate(f32 a, f32 b, f32 c);
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
extern void modelLightStruct_setupGlow(void* light, int a, int b, int c, int d, int e, f32 f);
extern f32 lbl_803E6940;
extern f32 lbl_803E6944;
extern f32 lbl_803E6948;
extern f32 lbl_803E694C;
extern f32 lbl_803E6950;
extern f32 lbl_803E6954;
extern f32 lbl_803E6958;
extern void modelLightStruct_setDistanceAttenuation(void* light, f32 a, f32 b);
extern f32 lbl_803E6B68;
extern f32 lbl_803E6B6C;
extern f32 lbl_803E6964;
extern f32* ObjModel_GetJointMatrix(int* model, int jointIdx);
extern void PSMTXMultVec(f32* mtx, f32* in, f32* out);
extern f32 lbl_803E67BC;
extern f32 lbl_803E67B4;
extern f32 lbl_803E67C0;
extern f32 lbl_803E67C4;
extern f32 lbl_803E67E8;
extern void queueGlowRender(void* p);
extern f32 lbl_803E6A30;
extern void PSVECSubtract(f32* a, f32* b, f32* out);
extern f32 PSVECMag(f32* v);
extern f32 lbl_803E6960;
extern void PSVECNormalize(f32* out, f32* in);
extern void PSVECScale(f32* out, f32* in, f32 scale);
extern void PSVECAdd(f32* out, f32* a, f32* b);
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
extern int Curve_AdvanceAlongPath(RomCurveWalker* curve, f32 v);
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
extern void CameraShake_SetAllMagnitudes(f32 m);
extern f32 lbl_803E6A78;
extern f32 lbl_803E6A7C;
extern f32 lbl_803E6A80;
extern f32 lbl_803E6A84;
extern void s16toFloat(void* timer, int v);
extern void objRenderFn_80041018(int obj);
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
extern f32 gHighTopAirMeterSfxInterval;
extern void ktrex_updateAttackEffects(GameObject* obj);
extern void curvesSetupMoveNetworkCurve(void* curve);
extern f32 lbl_803E6A70;
extern void* gKTRexStateHandlersA[];
extern void* gKTRexStateHandlersB[];
extern f32 gKTRexLaneSpeedMin[];
extern f32 gKTRexLaneSpeedMax[];
extern f32 lbl_803E6818;
extern f32 lbl_803E6848;
extern void fn_8003B5E0(int a, int b, int c, int d);
extern void PSMTXMultVecSR(f32* m, f32* src, f32* dst);
extern s16 lbl_803DC290[4];
extern s16 lbl_803DC298[4];
extern u32 lbl_803E67B0;
extern void ktrex_updateContactEffects(GameObject* obj, void* runtime);
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
extern void streamFn_8000a380(int a, int b, int c);
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
extern void PSMTXRotRad(f32* m, int axis, f32 rad);
extern f32 lbl_803E6824;
extern f32 lbl_803E6828;
extern f32 lbl_803E682C;
extern f32 lbl_803E6830;
extern f32 lbl_803E6834;
extern f32 lbl_803E6838;
extern f32 lbl_803E67C8;
extern f32 lbl_803E67CC;
extern void doRumble(f32 m);
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
extern void firepipe_setLinkedUpdateFlag(int handle);
extern void objfx_spawnFrameTimedHitPulse(int obj, f32 a, int b, int c, f32 d);
extern int gKTRexMsgTemplate[];
extern int gKTRexContactEffectCooldown;
extern f32 lbl_803E6820;
extern s16 gKTRexEffectSpawnWork[];
extern int RandomTimer_UpdateRangeTrigger(void* timer, f32 lo, f32 hi);
extern CameraInterface** gCameraInterface;
extern f32 lbl_803E67D8;
extern f32 lbl_803E67D0;
extern f32 lbl_803E67D4;
extern void unlockLevel(int a, int b, int c);
extern f32 lbl_803E67EC;
extern f32 lbl_803E6B24;
extern f32 lbl_803E6B28;
extern f32 lbl_803E6B2C;
extern s16 gHighTopBandMoveIds;
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
extern f32 gHighTopDegToAngle;
extern f32 lbl_803E6B0C;
extern f32 lbl_803E6B10;
extern f32 lbl_803E6B14;
extern f32 gHighTopPi;
extern f32 lbl_803E6B1C;
extern f32 lbl_803E6B20;
extern f32 gHighTopBandSpeedThresholds[];
extern int randFn_80080100(int n);
extern int gHighTopIdleSequenceWeights[];
extern int gHighTopIdleSequenceIds[];
extern f32 lbl_803E6AA4;
extern s16 gHighTopProgressGameBitIds;
extern void getYButtonItem(s16* out);
extern void objModelClearVecFn_8003aa40(GameObject* obj);

void kytesmum_playAnimationEventSfx(int obj, u8* arg, s16* sfxData);
int drakorhoverpad_handlePathPointEvent(GameObject* obj, u8 a, u8 b, void* out);
int drakorhoverpad_update(RomCurveWalker* curve, int arg);
int kytesmum_updateNearPlayerCallback(GameObject* obj, int unused, u8* arg);
int kytesmum_updateQuestStateCallback(GameObject* obj, int unused, u8* arg);
int ktrex_stateHandlerB01(GameObject* obj, int runtime);
int ktrex_stateHandlerB02(GameObject* obj, int runtime);
int ktrex_stateHandlerB03(GameObject* obj, int runtime);
int ktrex_stateHandlerB04(int obj, int runtime);
int ktrex_stateHandlerB05(int obj, int runtime);
int ktrex_stateHandlerB06(int obj, int runtime);
int ktrex_stateHandlerB07(int obj, int runtime);
int ktrex_stateHandlerB08(int obj, int runtime);
int ktrex_stateHandlerA01(GameObject* obj, int runtime);
int ktrex_stateHandlerA02(int obj, int runtime);
int ktrex_stateHandlerA03(int obj, int runtime);
int ktrex_stateHandlerA04(int obj, int runtime);
int ktrex_stateHandlerA05(GameObject* obj, int runtime);
int ktrex_stateHandlerA07(int obj, int runtime);
int ktrex_stateHandlerA08(int obj, int runtime);
int ktrex_stateHandlerA09(int obj, int runtime);
int ktrex_stateHandlerA10(GameObject* obj, int runtime);
int ktrex_stateHandlerA11(GameObject* obj, int runtime);

#endif
