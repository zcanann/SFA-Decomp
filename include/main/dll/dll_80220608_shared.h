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
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/screen_transition.h"
#include "main/frame_timing.h"

struct AndrossState;

/* Pattern wrappers. */
extern int lbl_803DC380;
extern f32 lbl_803E6BB0;
extern f32 lbl_803E6BC8;
extern void cloudClearOverridePosition(int obj);
extern f32 lbl_803E6C20;
extern int lbl_803DC398;
extern void gunpowderbarrel_clearHeldState(int obj);
extern f32 lbl_803E6CE0;
extern void dll_2E_func06(GameObject* obj, int state, int flags);
extern int seqFn_800394a0(void);
extern void fn_8003AAE0(GameObject* obj, int seq, int hitId, int p4, int p5);
extern f32 lbl_803E6D38;
extern f32 lbl_803E6D54;
extern f32 lbl_803E6DA0;
extern f32 lbl_803E6DE0;
extern f32 lbl_803E6DF0;
extern f32 lbl_803E6E00;
extern f32 lbl_803E6DFC;
extern f32 lbl_803E6E10;
extern f32 lbl_803E6E14;
extern f32 lbl_803E6E18;
extern f32 lbl_803E6E20;
extern f32 lbl_803E6E24;
extern int Obj_GetActiveModel(int obj);
extern void ObjModel_SetPostRenderCallback(int model, void* callback);
extern void postRenderSetAlphaBlendState(void);

extern void dll_2E_func03(int obj, int p2);
extern void characterDoEyeAnims(GameObject* obj, int p2);

extern u8 fn_80296414(GameObject* player, int obj, int dir);
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern void objfx_spawnBoxBurst(void* obj, u8 idx, u8 kind, u8 mode, u8 chance, void* origin, int flags, f32 f8val,
                                f32 mulX, f32 mulY, f32 mulZ);
extern int gameBitIncrement(int id);

extern f32 lbl_803E6DB0;
extern f32 lbl_803E6DB4;
extern f32 lbl_803E6DB8;
extern f32 lbl_803E6DBC;
extern f32 lbl_803E6DC0;
extern f32 lbl_803E6DD0;
extern f32 lbl_803E6DD4;
extern f32 lbl_803E6DD8;
extern void mapGetBlockOriginForPos(f32 x, f32 y, f32 z, f32* outX, f32* outZ);
extern const f32 lbl_803E6DA8;
extern void skyFn_80088e54(int a, f32 b);
extern void* memcpy(void* dst, const void* src, u32 n);

#pragma dont_inline on
#pragma dont_inline reset
extern int fn_80138F84(int tricky);
extern int trickyFn_80138f14(int tricky);
extern f32 lbl_803E6DE4;
extern f32 lbl_803E6DE8;

extern f32 lbl_803E6DF4;
extern f32 lbl_803E6DF8;

extern void logPrintf(void* fmt, ...);
extern char sWCPressuresActivateFormat[];
extern f32 lbl_803E6E04;

extern u8* mapGetBlock(int idx);
extern int fn_8006070C(int block, int index);
extern void mapTextureOverrideSetValue(int a, int b, int c);
extern f32 lbl_803E6E58;
#pragma dont_inline on
#pragma dont_inline reset
extern s16 gWcTempleDiaGameBitsA;
extern s16 gWcTempleDiaGameBitsB;
extern f32 gWcTempleDiaTargetSpeedTableA[];
extern f32 gWcTempleDiaTargetSpeedTableB[];
extern f32 gWcTempleDiaSpeedLerpRate;
int wctempledia_interactCallback(GameObject* obj, int p2, ObjAnimUpdateState* animUpdate);
extern f32 lbl_803E6E5C;
extern f32 lbl_803E6E60;
extern f32 lbl_803E6E64;
extern f32 lbl_803E6E68;

extern f32 lbl_803E6E90;
#pragma dont_inline on
#pragma dont_inline reset

extern int ObjModel_GetCurrentVertexCoords(int model, int idx);
extern int ObjModel_GetBaseVertexCoords(int model, int idx);
extern f32 lbl_803E6E70;
extern f32 lbl_803E6E74;
extern f32 lbl_803E6E78;
extern f32 lbl_803E6E7C;

extern f32 PSVECDistance(void* a, void* b);
extern f32 lbl_803E6E94;

extern f32 lbl_803E6E98;
extern f32 lbl_803E6E2C;
extern f32 lbl_803E72E8;
extern f32 lbl_803E72B0;

extern int fn_80065640(void);
extern void fn_80065574(int a, GameObject* b, int c);
extern f32 lbl_803E6E9C;
extern f32 lbl_803E6EA0;
extern f32 lbl_803E6EA4;
extern f32 lbl_803E6EA8;
extern f32 lbl_803E6EAC;
extern f32 lbl_803E6EB0;
extern f32 lbl_803E6EB4;
extern f32 lbl_803E6EB8;
extern f32 lbl_803E6EBC;

extern f32 lbl_803E6E28;
extern f32 lbl_803E6E30;
extern f32 lbl_803E6E34;

extern f32 lbl_803E6E3C;
extern f32 lbl_803E6E40;

extern int fn_802969F0(int player);
extern f32 lbl_803E6E38;

extern int getAngle(f32 dx, f32 dz);

int suntemple_interactCallback(GameObject* obj, int p2, ObjAnimUpdateState* animUpdate);

extern f32 lbl_802C25D8[];
extern int getCurMapLayer(void);

typedef struct
{
    f32 x, y, z;
} SunVec3;



extern void getAmbientColor(int id, u8* r, u8* g, u8* b);
extern void Obj_SetActiveModelIndex(int obj, int index);

#pragma dont_inline on
#pragma dont_inline reset



extern int fn_80080150(int state);

extern f32 lbl_803E70C4;
extern f32 lbl_803E70D8;

extern void spawnExplosion(int obj, f32 v, int a, int b, int c, int d, int e, int f, int g);

extern int arrayIndexOf(int array, int count, int value);
extern void Obj_SetModelColorFadeRecursive(int obj, int r, int g, int b, int a, int frames);

extern void objfx_spawnMaskedHitEffect(int obj, int a, int b, f32 c, int d, int e);
extern void hitDetectFn_80097070(int obj, int a, int b, f32 c, int d, int e);
extern void objfx_spawnBoxBurst(void* obj, u8 idx, u8 kind, u8 mode, u8 chance, void* origin, int flags, f32 f8val,
                                f32 mulX, f32 mulY, f32 mulZ);
extern void objfx_spawnDirectionalBurst(int obj, int a, int b, int c, f32 e, f32 f, int g, int h, int i);
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind, int particleId, int lifetime,
                                  f32 scaleX, f32 scaleY, f32 scaleZ, void* args, int arg9);

extern int ObjHits_PollPriorityHitEffectWithCooldown(GameObject* obj, u32 hitFxMode, u32 colorR, u32 colorG, u32 colorB,
                                                     u32 sfxId, float* cooldown);


extern f32 lbl_803E7078;
extern f32 lbl_803E7150;

extern f32 lbl_803E7218;
extern f32 lbl_803E71E4;
extern f32 lbl_803E704C;

#pragma dont_inline on
#pragma dont_inline reset

/* Arwing family (untouched: arwarwing, arwarwinggu, arwingandrossstuff, arwlevelcon, arwsquadron). */
extern int gArwing;
extern f32 lbl_803E701C;
extern f32 lbl_803E7058;
extern f32 lbl_803E70E0;
extern f32 lbl_803E7188;
extern void arwingHudSetVisible(int mode);
extern void setIsOvercast(int value);

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

extern int getArwing(void);
extern void PSVECNormalize(void* src, void* dst);
extern void C_VECHalfAngle(void* out, void* a, void* b);
extern void projectileParticleFxFn_80099660(int obj, f32 p2, int p3);
extern f32 lbl_803E7008;
extern f32 lbl_803E7014;
extern f32 lbl_803E7028;
extern f32 lbl_803E702C;
extern f32 gArwingAndrossPi;
extern f32 gArwingAndrossBinAngScale;
extern f32 lbl_803E7038;
extern f32 lbl_803E703C;

#pragma dont_inline on
#pragma dont_inline reset

extern f32 lbl_803E70EC;
extern f32 lbl_803E70F0;
extern f32 lbl_803E70F4;

#pragma dont_inline on
#pragma dont_inline reset

int arwlevelcon_SeqFn(GameObject* obj, int p2, int data);

extern f32 lbl_803E6ED0;
extern f32 lbl_803E6EE8;
extern f32 lbl_803E6EFC;
extern f32 lbl_803E6F00;
extern f32 lbl_803E6F5C;
extern f32 lbl_803E6FF4;
extern f32 lbl_803E6FF8;
extern void Obj_BuildWorldTransformMatrix(int obj, void* mtx, int p3);
extern void PSMTXMultVec(void* mtx, void* src, void* dst);
extern void fn_8008020C(int rx, int ry, int rz, f32 x, f32 y, f32 z, f32 p7);

extern f32 lbl_803E705C;
extern f32 lbl_803E7060;
extern f32 lbl_803DC3D0;
extern f32 lbl_803DC3D4;
extern f32 lbl_803DC3D8;
extern int ObjModel_GetTexture(int p1, int p2);
extern void fn_800541A4(int p1, int p2);
extern void textureAnimFn_80053f2c(int p1, int p2, int p3);

extern f32 lbl_803E70E4;
extern f32 lbl_803E70E8;
extern void skyFn_80089710(int p1, u8 p2, int p3);
extern void skyFn_800895e0(int p1, int p2, int p3, int p4, int p5, int p6);
extern void skyFn_800894a8(int p1, f32 p2, f32 p3, f32 p4);
extern void setDrawLights(int value);
extern int mapBlockFn_800592e4(void);
extern int arwarwing_getRequiredRingCount(int arwing);
extern int arwarwing_getCollectedRingCount(int arwing);

extern f32 lbl_803E7154;

extern void fn_8006CB24(int obj);
extern void Rcp_DisableDistortionFilter(void);
extern void lightningRender(void* p);
extern const f32 lbl_803E75B0;

#pragma dont_inline on
#pragma dont_inline reset

extern int ObjList_FindObjectById(int id);
extern void androsshand_handleDamage(GameObject* obj, int hand);
extern void androsshand_spawnShot(int p1, int p2, int p3);
extern const f32 lbl_803E75AC;
extern f32 gAndrossHandMoveAnimSpeeds[];
extern f32 lbl_803DC4F0;
extern f32 lbl_803DC4F4;
extern f32 lbl_803DC4F8;
extern int lbl_803DC4FC;
extern int lbl_803DC500;
extern int lbl_803DC504;
extern const f32 lbl_803E75B4;
extern f32 gAndrossHandPi;
extern f32 gAndrossHandHalfAngleScale;
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

extern void fn_8006CB50(void);
extern int ObjModel_GetRenderOp(int model, int idx);

extern void DIMexplosionFn_8009a96c(int obj, f32 a, f32 b, f32 c, f32 d, int e, int f, int g, int h, int i, int j,
                                    int k);
extern int lbl_803DC508;
extern const f32 lbl_803E75A8;


extern void androssligh_updateBeam(GameObject* obj, int state);

extern void* lightningCreate(f32* pos, f32* dir, f32 a, f32 b, u16 angle, int c, int d);
extern void PSVECScale(void* dst, void* src, f32 scale);
extern void PSVECAdd(int p1, int p2, int p3);
extern f32 lbl_803DC518;
extern f32 lbl_803DC51C;
extern f32 lbl_803DC520;
extern f32 lbl_803DC524;
extern f32 lbl_803DC528;
extern f32 lbl_803DC52C;


extern const f32 lbl_803E7480;
extern int gf_levelcon_SeqFn(int obj, int eventId, ObjAnimUpdateState* animUpdate);
extern void gf_levelcon_findLinkedObjects(int obj);
extern void creditsStart(void);
extern const f32 lbl_803E7460;
extern const f32 lbl_803E7464;
extern const f32 lbl_803E7468;
extern const f32 lbl_803E746C;
extern const f32 lbl_803E7470;
extern const f32 lbl_803E7474;
extern const f32 lbl_803E7478;
extern const f32 lbl_803E747C;
extern const f32 lbl_803E7484;
extern const f32 lbl_803E7488;
extern const f32 lbl_803E748C;

extern const f32 lbl_803E745C;
extern int mclightning_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
extern f32 lbl_803E7440;

extern const f32 lbl_803E7450;
extern const f32 lbl_803E7454;
extern const f32 lbl_803E7458;

extern f32 lbl_803E738C;

extern f32 lbl_803E7360;
extern f32 lbl_803E7364;
extern f32 lbl_803E7368;
extern f32 lbl_803E736C;
extern f32 lbl_803E7370;
extern f32 lbl_803E7374;
extern f32 lbl_803E7384;
extern f32 lbl_803E7378;
extern f32 lbl_803E737C;
extern f32 lbl_803E7380;
extern f32 lbl_803E7388;
extern f32 lbl_803E7390;
extern f32 lbl_803E7394;
extern f32 lbl_803E7398;
extern void objfx_spawnLightPulse(GameObject* obj, f32 brightness, int b, int c, int d, f32 e, int f);
extern void fn_80098B18(int obj, f32 brightness, int b, int c, int d, void* vec);
extern void lightSetField4D(void* light, int v);
extern void ObjHits_SyncObjectPositionIfDirty(u32 obj);
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
extern void objfx_spawnRandomBurst(int obj, int mode, int p3, void* vec, f32 f, int flag);

#pragma dont_inline on

#pragma dont_inline reset


extern int* gPlayerInterface;
extern int Curve_AdvanceAlongPath(RomCurveWalker* curve, f32 val);
extern void doNothing_80062A50(int obj, f32 x, f32 y, f32 z);
extern void dll_2E_func05(GameObject* obj, int p2, int p3, int p4, int p5);
extern void dll_2E_func09(int p1, void* p2, void* p3, int p4);
extern int gDll28BMoveBlendDataA[];
extern int gDll28BMoveBlendDataB[];
extern void* gDll28BSubstateHandlers[];
extern void* gDll28BStateHandlers[];
extern f32 gWcEarthWalkerFarPlayerDistance;
extern f32 gWcEarthWalkerNearPlayerDistance;
extern f32 gWcEarthWalkerIdleTimerThreshold;
extern f32 gWcEarthWalkerCurveAdvanceStep;
extern f32 gWcEarthWalkerApproachPlayerDistance;
extern f32 gWcEarthWalkerChaseMoveSpeed;
extern f32 gWcEarthWalkerWalkMoveSpeed;
extern f32 lbl_803E6D18;
extern f32 gDll28BCurveInitParam;

typedef struct Blob16
{
    int a, b, c, d;
} Blob16;
extern int dll_2E_func07(GameObject* obj, int p2, int state, int p4, int p5);
extern void dll_2E_setLookAtMaxDistance(int state, f32 a);

extern f32 lbl_803E6C24;
extern f32 lbl_803E6C28;
extern f32 lbl_803E6C2C;
extern f32 lbl_803E6C30;
extern f32 lbl_803E6C34;

extern ModgfxInterface** gModgfxInterface;
extern void* lbl_803DDD80;

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
extern f32 gArwBombCollHitToleranceY;
extern f32 gArwBombCollHitRadiusSq;
extern f32 gArwBombCollPlaneHitRadius;

extern f32 lbl_803E6ECC;

#pragma dont_inline on
#pragma dont_inline reset

extern void PSVECSubtract(void* a, void* b, void* ab);

extern f32 lbl_803E6F08;
extern f32 lbl_803E6F0C;
extern f32 lbl_803E6F10;
extern f32 lbl_803E6F14;
extern f32 lbl_803E6F18;
extern f32 lbl_803E6F1C;
extern f32 lbl_803E6F20;


#pragma dont_inline on
#pragma dont_inline reset

extern void lightSetFieldBC_8001db14(void* light, int v);
extern f32 lbl_803E700C;
extern f32 lbl_803E7010;
extern f32 lbl_803E7018;

#pragma dont_inline on
#pragma dont_inline reset

extern f32 lbl_803E721C;
extern f32 lbl_803E7220;

extern f32 lbl_803E71D8;
extern f32 lbl_803E71DC;
extern f32 lbl_803E71E0;
extern f32 gArwProximityTauntDistance;
extern f32 gArwProximityActivateDistance;
extern f32 lbl_803E71F0;
extern f32 lbl_803E71F4;
extern f32 lbl_803E71F8;
extern f32 gArwProximityFadeInRate;
extern f32 gArwProximityWarningDistance;

extern f32 lbl_803E71A8;


extern void arwarwing_spawnLaserShot(GameObject* obj, int state, int a, int b, int c);
extern f32 gArwingFireTimerReset;

extern f32 lbl_803E6F34;
extern f32 gArwingExplodeModeTime;
extern f32 lbl_803E6F28;
extern f32 lbl_803E6F6C;
extern f32 lbl_803E6EF8;
extern f32 lbl_803E6FFC;
extern f32 lbl_803E7000;

#pragma dont_inline on

#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

extern int fn_80296A9C(GameObject* player, int p2);
extern int objGetFirstChild(void);
extern void staffSetGlow(int staff, int p2, int p3);

extern f32 lbl_803E6BF0;
extern f32 lbl_803E6BF4;
extern f32 lbl_803E6BF8;

extern int objModelGetVecFn_800395d8(GameObject* model, int idx);
extern f32 fn_802945E0(f32 ratio);
extern double lbl_803E6F48;
extern double lbl_803E6F50;
extern f32 lbl_803E6F58;
extern f32 lbl_803E6F60;
extern f32 lbl_803E6F64;
extern f32 lbl_803E6F68;
extern f32 lbl_803E6F38;
void arwarwinggu_setTextureFrame(GameObject* obj, int p2);

extern f32 lbl_803E6F2C;
extern f32 lbl_803E6F70;
extern f32 lbl_803E6F74;
extern f32 lbl_803E6F78;
extern f32 lbl_803E6F7C;
extern f32 lbl_803E6F80;
extern f32 lbl_803E6F84;
extern f32 lbl_803E6F88;
extern f32 lbl_803E6F8C;
extern f32 lbl_803E6F90;
extern f32 lbl_803E6F94;
extern f32 lbl_803E6F98;
extern f32 lbl_803E6F9C;
extern f32 lbl_803E6FA0;
extern f32 lbl_803E6FA4;
extern f32 lbl_803E6FA8;
extern f32 lbl_803E6FAC;
extern f32 lbl_803E6FB0;
extern f32 lbl_803E6FB4;
extern f32 lbl_803E6FB8;
extern f32 lbl_803E6FBC;
extern f32 gArwingEscortSearchRadius;
extern f32 lbl_803E6FC4;
extern f32 lbl_803E6FC8;
extern f32 lbl_803E6FCC;
extern f32 lbl_803E6FD0;
extern f32 lbl_803E6FD4;
extern f32 lbl_803E6FD8;
extern f32 lbl_803E6FDC;
extern f32 lbl_803E6FE0;
extern f32 lbl_803E6FE4;
extern f32 lbl_803E6FE8;
extern f32 lbl_803E6FEC;
extern f32 lbl_803E6FF0;
extern f32 lbl_803E6EF0;
extern f32 lbl_803E6EF4;

#pragma dont_inline on
#pragma dont_inline reset
#pragma dont_inline on
#pragma dont_inline reset


extern f32 lbl_803E7044;
#pragma dont_inline on
#pragma dont_inline reset

extern int loadObjectAtObject(int obj);

#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset

extern int gAndrossProjectileForwardStep;


extern int gAndrossAimedProjectileSpeed;
extern int gAndrossAimedProjectileLifetime;
extern int gAndrossRingProjectileLifetime;
extern f32 gAndrossRingProjectileScale;
extern int gGfLevelConProjectilePitch;
extern int gGfLevelConRingProjectilePitch;
extern s16 gGfLevelConProjectileYaw;
extern s16 gGfLevelConRingProjectilePitchSource;

extern f32 gAndrossForwardDistanceThreshold;
extern f32 gAndrossArwingVelDamp;

extern u8 gAndrossPartTextureIndices[4];

extern f32 WCBLOCK_PLAYER_CELL_MARGIN;


extern f32 lbl_803E7040;
extern f32 lbl_803E7048;


#pragma dont_inline on
#pragma dont_inline reset

extern f32 lbl_803E6F30;
extern f32 lbl_803E6F3C;
extern f32 lbl_803E6F40;


extern int gAndrossHandShotPitch;
extern int lbl_803DC50C;
extern int lbl_803DC510;

extern void registerNewScore(int a, int b, int c, int d);
extern u8 gArwingCourseMapIds[8];
typedef struct
{
    u8 scoreFlag : 1;
} Arw339Flags;

typedef struct
{
    int a;
    int b;
    u16 c;
} ArwInitCfg;
extern ArwInitCfg gArwingInitConfig;
extern int gArwingPathSetupData[];
extern int sArwingPathName[];

extern f32 PSVECMag(f32* v);
extern void PSVECCrossProduct(f32* a, f32* b, f32* out);
extern f32 PSVECDotProduct(f32* a, f32* b);
extern void PSMTXRotAxisRad(f32* mtx, f32* axis, f32 angle);
extern void PSMTXMultVecSR(f32* mtx, f32* in, f32* out);
extern f32 fn_80291FF4(f32 x);
extern f32 lbl_803E6C38;
extern f32 lbl_803E6C6C;
extern f32 lbl_803E6C70;
extern f32 lbl_803E6C74;

extern f32 gBarrelGenPi;
extern f32 gBarrelGenAngleHalfRange;
extern f32 lbl_803E6C78;
extern f32 lbl_803E6C7C;
extern f32 lbl_803E6C80;

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline reset

#pragma dont_inline on

extern void Obj_SmoothTurnAnglesTowardVelocity(GameObject* a, int b, int c, f32 d, f32 e);

extern f32 lbl_803E6C68;

extern void cloudSetOverridePosition(int obj, f32 a, f32 b, f32 c);
extern f32 gDrMusicControlCloudOverridePosX;
extern f32 gDrMusicControlCloudOverridePosY;
extern f32 gDrMusicControlCloudOverridePosZ;
extern f32 lbl_803E6BD8;
extern f32 gDrMusicControlStingerTimerDuration;
extern f32 gDrMusicControlRestartPointX;
extern f32 gDrMusicControlRestartPointY;
extern f32 gDrMusicControlRestartPointZ;

extern f32 lbl_803E6CA4;
extern f32 lbl_803E6CD0;

extern int gunpowderbarrel_isHeld(int obj);
extern int gunpowderbarrel_canBeGrabbed(int obj);
extern void gunpowderbarrel_addThrowVelocity(int obj, void* vec);
extern void gunpowderbarrel_setHeldState(int obj);
extern int Obj_UpdateRomCurveFollowVelocity(GameObject* obj, int p2, f32 a, f32 b, f32 c, int p6);
extern int voxmaps_traceWorldLine(void* p1, void* p2);
extern f32 lbl_803E6CA0;
extern f32 lbl_803E6CA8;
extern f32 gDrBarrelGenGrabRange;
extern f32 lbl_803E6CB4;
extern f32 gDrBarrelGenCarrySpeedScale;
extern f32 lbl_803E6CBC;
extern f32 lbl_803E6CC0;
extern f32 lbl_803DC3B0;
extern f32 gDrBarrelGenGrabYOffset;

extern f32 lbl_803E6CAC;

typedef struct DrBarrelGrRenderParams
{
    s16 a;
    s16 b;
    s16 c;
    f32 d;
} DrBarrelGrRenderParams;

extern int dll_2E_func0A(int a, void* out);
extern f32 lbl_803E6BB8;
extern f32 lbl_803E6BBC;
extern f32 lbl_803E6BC0;

extern void* playerGetFocusObject(void);
extern void setAButtonIcon(int icon);
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind, int particleId, int lifetime,
                                  f32 scaleX, f32 scaleY, f32 scaleZ, void* args, int arg9);
extern f32 lbl_803E6C08;
extern f32 lbl_803E6C0C;
extern f32 lbl_803E6C10;
extern f32 lbl_803E6C14;
extern f32 lbl_803E6C18;
extern f32 lbl_803E6C1C;

extern f32 lbl_803E6C58;

extern void mm_free_(void* ptr);
extern f32 lbl_803E6C3C;
extern f32 lbl_803E6C40;
extern f32 lbl_803E6C44;
extern f32 lbl_803DC3A0;
extern f32 lbl_803DC3A4;
extern f32 lbl_803DC3A8;
extern u16 lbl_803DC3AC;

extern f32 lbl_803E6C5C;
extern f32 gBarrelGenAngleWrapNeg;
extern f32 gBarrelGenAngleWrapPos;
extern f32 gBarrelGenAngleWrapThreshold;
extern f32 gBarrelGenTurnRateClampMin;
extern f32 gBarrelGenTurnRateClampMax;
extern f32 lbl_803E6C98;


extern f32 lbl_803E6EC8;
extern f32 lbl_803E6ED4;
extern f32 lbl_803E6ED8;
extern void debugPrintSetColor(int r, int g, int b, int a);
extern f32 lbl_8032B4A8[];


/* Forward declarations for graduated functions (split from placeholder_80220608). */
int drearthcal_setScale(void);
int drearthcal_getExtraSize(void);
int drearthcal_getObjectTypeId(void);
void drearthcal_free(void);
void drearthcal_render(void);
void drearthcal_hitDetect(void);
void drearthcal_init(GameObject* obj, int setup);
void drearthcal_release(void);
void drearthcal_initialise(void);
int barrelgener_getLinkId(GameObject* obj);
void barrelgener_queueObjectRelease(GameObject* obj, int queuedObj, int releaseFrame);
int barrelgener_getExtraSize(void);
int barrelgener_getObjectTypeId(void);
void barrelgener_free(int obj);
void barrelgener_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void barrelgener_hitDetect(void);
void barrelgener_init(GameObject* obj);
void barrelgener_release(void);
void barrelgener_initialise(void);
int wcbeacon_aButtonCallback(GameObject* obj);
int wcbeacon_getExtraSize(void);
int wcbeacon_getObjectTypeId(GameObject* obj);
void wcbeacon_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wcbeacon_init(u8* obj, u8* setup);
void wcbeacon_update(GameObject* obj);
int wcpressures_getExtraSize(void);
int wcpressures_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int wcpressures_getObjectTypeId(int obj);
void wcpressures_free(int obj);
void wcpressures_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wcpressures_hitDetect(void);
void wcpressures_update(int obj);
void wcpressures_init(u8* obj, u8* setup);
void wcpressures_release(void);
void wcpressures_initialise(void);
int wctrexstatu_interactCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int wctrexstatu_getExtraSize(void);
int wctrexstatu_getObjectTypeId(GameObject* obj);
void wctrexstatu_free(void);
void wctrexstatu_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wctrexstatu_hitDetect(u8* obj);
void wctrexstatu_update(void);
void wctrexstatu_init(GameObject* obj, int setup, int fromLoad);
void wctrexstatu_release(void);
void wctrexstatu_initialise(void);
void wctempledia_syncPartVisibility(GameObject* obj, u8 mask);
int wctempledia_getExtraSize(void);
int wctempledia_getObjectTypeId(void);
void wctempledia_free(void);
void wctempledia_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wctempledia_hitDetect(void);
int wctempledia_interactCallback(GameObject* obj, int p2, ObjAnimUpdateState* animUpdate);
void wctempledia_update(GameObject* obj);
void wctempledia_init(GameObject* obj, int setup);
void wctempledia_release(void);
void wctempledia_initialise(void);
int wcfloortile_getExtraSize(void);
int wcfloortile_getObjectTypeId(void);
void wcfloortile_free(void);
void wcfloortile_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wcfloortile_hitDetect(void);
void wcfloortile_init(GameObject* obj);
void wcfloortile_release(void);
void wcfloortile_initialise(void);
void wcfloortile_update(int obj);
int wcapertures_getExtraSize(void);
int wcapertures_getObjectTypeId(GameObject* obj);
void wcapertures_free(GameObject* obj);
void wcapertures_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wcapertures_hitDetect(GameObject* obj);
void wcapertures_release(void);
void wcapertures_initialise(void);
int wcapertures_interactCallback(GameObject* obj, int p2, ObjAnimUpdateState* animUpdate);
void wcapertures_init(GameObject* obj, int initData);
void wcapertures_update(GameObject* obj);
int suntemple_getExtraSize(void);
int suntemple_getObjectTypeId(void);
void suntemple_free(void);
void suntemple_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void suntemple_hitDetect(GameObject* obj);
int suntemple_interactCallback(GameObject* obj, int p2, ObjAnimUpdateState* animUpdate);
void suntemple_init(u8* obj, u8* setup);
void suntemple_update(GameObject* obj);
void suntemple_release(void);
void suntemple_initialise(void);
int wctemple_getExtraSize(void);
int wctemple_getObjectTypeId(void);
void wctemple_free(void);
void wctemple_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wctemple_hitDetect(void);
void wctemple_update(GameObject* obj);
void wctemple_init(GameObject* obj, int setup);
void wctemple_release(void);
void wctemple_initialise(void);
int dll_299_getExtraSize_ret_2(void);
int dll_299_getObjectTypeId(void);
void dll_299_render_nop(void);
void dll_299_hitDetect_nop(void);
void dll_299_release_nop(void);
void dll_299_initialise_nop(void);
int Dummy29E_getExtraSize(void);
int Dummy29E_getObjectTypeId(void);
void Dummy29E_free(void);
void Dummy29E_render(void);
void Dummy29E_hitDetect(void);
void Dummy29E_update(void);
void Dummy29E_init(void);
void Dummy29E_release(void);
void Dummy29E_initialise(void);
int arwarwingbo_getExtraSize(void);
int arwarwingbo_getObjectTypeId(void);
void arwarwingbo_free(int obj);
void arwarwingbo_hitDetect(void);
void arwarwingbo_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void arwarwingbo_init(GameObject* obj, int setup);
void arwarwingbo_setActiveVisible(GameObject* obj, u8 active, u8 visible);
void arwarwingbo_release(void);
void arwarwingbo_initialise(void);
int getArwing(void);
int arwarwing_getExtraSize(void);
int arwarwing_getObjectTypeId(void);
void arwarwing_free(GameObject* obj);
void arwarwing_release(void);
void arwarwing_initialise(void);
int ARWArwingGu_getExtraSize(GameObject* obj);
int ARWArwingGu_getObjectTypeId(void);
void ARWArwingGu_free(void);
void ARWArwingGu_render(void);
void ARWArwingGu_hitDetect(void);
void ARWArwingGu_init(GameObject* obj);
void arwarwinggu_setActiveVisible(GameObject* obj, u8 active, u8 visible);
void ARWArwingGu_release(void);
void ARWArwingGu_initialise(void);
int arwingandrossstuff_getExtraSize(void);
int arwingandrossstuff_getObjectTypeId(void);
void arwingandrossstuff_free(GameObject* obj);
void arwingandrossstuff_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void arwingandrossstuff_release(void);
void arwingandrossstuff_initialise(void);
void arwingandrossstuff_hitDetect(GameObject* obj);
int arwlevelcon_getExtraSize(void);
int arwlevelcon_getObjectTypeId(void);
void arwlevelcon_free(void);
void arwlevelcon_render(int obj, int p2, int p3, int p4, int p5);
void arwlevelcon_hitDetect(void);
void arwlevelcon_onSeqFree(GameObject* obj);
void arwlevelcon_release(void);
void arwlevelcon_initialise(void);
void arwprojectile_setLifetime(GameObject* obj, int lifetime);
void arwprojectile_placeForward(GameObject* obj, f32 dist);
void arwingandrossstuff_init(GameObject* obj, u8* setup);
void arwlevelcon_init(GameObject* obj, u8* setup);
int arwlevelcon_SeqFn(GameObject* obj, int p2, int data);
void arwarwing_render(GameObject* obj, int p2, int p3, int p4, int p5);
void arwarwing_hitDetect(GameObject* obj);
void ARWArwingGu_update(GameObject* obj);
void arwingandrossstuff_update(GameObject* obj);
void arwlevelcon_update(GameObject* obj);
int andross_getExtraSize(void);
int andross_getObjectTypeId(void);
void andross_free(int obj);
void andross_hitDetect(void);
void andross_render(int obj, int p2, int p3, int p4, int p5);
void andross_setPartSignal(GameObject* obj, u8 signal);
int AndrossHand_getExtraSize(void);
int AndrossHand_getObjectTypeId(void);
void AndrossHand_free(void);
void AndrossHand_render(int obj, int p2, int p3, int p4, int p5);
void AndrossHand_update(int obj);
int androssligh_getExtraSize(void);
int androssligh_getObjectTypeId(void);
void androssligh_free(void);
void androssligh_render(GameObject* obj);
void androssligh_setState(GameObject* obj, int newState, u8 force);
int andross_SeqFn(GameObject* obj);
void andross_init(int obj, u8* setup);
int AndrossBrain_getExtraSize(void);
int AndrossBrain_getObjectTypeId(void);
void AndrossBrain_free(void);
void AndrossBrain_render(int obj, int p2, int p3, int p4, int p5);
void AndrossHand_hitDetect(void);
void androssligh_hitDetect(void);
void AndrossBrain_hitDetect(void);
void androsshand_setState(GameObject* obj, int newState, u8 force);
void androssbrain_setState(GameObject* obj, int newState, u8 force);
void androsshand_handleDamage(GameObject* obj, int hand);
void androssligh_init(void);
void AndrossBrain_init(GameObject* obj);
void AndrossHand_init(int obj, u8* setup);
void androssligh_update(GameObject* obj);
void androssligh_updateBeam(GameObject* obj, int beam);
void AndrossBrain_update(GameObject* obj);
int gf_levelcon_SeqFn(int obj, int eventId, ObjAnimUpdateState* animUpdate);
int gf_levelcon_getExtraSize(void);
int gf_levelcon_getObjectTypeId(void);
void gf_levelcon_hitDetect(void);
void gf_levelcon_initialise(void);
void gf_levelcon_release(void);
void gf_levelcon_free(void);
void gf_levelcon_update(GameObject* obj);
void gf_levelcon_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void gf_levelcon_init(int obj);
int mclightning_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int mclightning_getExtraSize(void);
void mclightning_free(GameObject* obj);
void mclightning_update(GameObject* obj);
void mclightning_init(GameObject* obj, u8* setup);
void mclightning_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale);
void gf_levelcon_findLinkedObjects(int obj);
void barrelgener_update(GameObject* obj);
void dll_299_free(int obj);
void dll_299_update(int obj);
void dll_299_init(GameObject* obj, int setup);
void arwarwing_setFlightHalfWidth(int arwing, f32 width);
int arwarwing_getRotY(int arwing);
void arwarwing_setRotY(int arwing, int rotY);
void arwarwing_getVelocity(int out, int arwing);
void arwarwing_setVelocity(int arwing, int in);
void arwarwing_addVelocity(int arwing, int in);
void arwarwing_clearActiveBomb(int arwing);
int arwarwing_getRequiredRingCount(int arwing);
int arwarwing_getCollectedRingCount(int arwing);
void arwarwing_addScore(int arwing, u8 amount);
int arwarwing_getScore(int arwing);
int arwarwing_getBombCount(int arwing);
int arwarwing_getMaxHealth(int arwing);
int arwarwing_getHealth(int arwing);
int arwarwing_incrementPickup6DACount(int arwing);
int arwarwing_incrementPickup6DBCount(int arwing);
int arwarwing_incrementPickup6D9Count(int arwing);
int arwarwing_incrementPickup6D8Count(int arwing);
int arwarwing_incrementCollectedRingCount(int arwing);
void arwarwing_addMaxHealth(int arwing, int p2);
void arwarwing_addHealth(int arwing, int p2);
void arwarwing_clampToFlightBounds(GameObject* obj, int state);
void arwarwing_updateFlightPhysics(GameObject* obj, int state);
void arwarwing_updateBombFire(GameObject* obj, int state);
void arwarwing_emitDamageEffects(int obj, int state);
void arwarwing_warpByCourse(GameObject* obj);
void arwprojectile_createLinkedEffect(GameObject* obj, u8 enable);
void arwarwing_updateWeaponFire(GameObject* obj, int state);
void arwarwing_update(GameObject* obj);
void arwarwing_spawnLaserShot(GameObject* obj, int state, int side, int level, int linkEffect);
void arwarwing_addBomb(int arwing);
void arwarwing_upgradeLaserLevel(int arwing);
int arwarwing_isExplodingOrWarping(int arwing);
int arwarwing_isBarrelRolling(int arwing);
int arwarwing_isDead(int arwing);
int mcupgradema_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int mcstaffeffe_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
void mcupgrade_update(GameObject* obj);
void mcupgrade_init(GameObject* obj);
void mcupgradema_update(GameObject* obj);
void mcupgradema_init(GameObject* obj);
void mcstaffeffe_render(int obj);
void mcstaffeffe_update(void);
void mcstaffeffe_init(int obj, int setup);
void arwarwing_updateRollAndEngine(int obj, int state);
void arwarwinggu_setTextureFrame(GameObject* obj, int p2);
void arwarwing_clearAimSnapshot(GameObject* obj);
void arwarwing_initAttachments(GameObject* obj, int state);
void fn_8022ED74(GameObject* obj, int v);
void arwarwinggu_applyTextureFrame(GameObject* obj);
void fn_8022ECE0(GameObject* obj, f32 param);
void arwarwing_spawnBomb(GameObject* obj, int state, int side);
void fn_80239DD8(GameObject* obj, struct AndrossState* state);
void fn_80239EAC(int p1, int p2);
void fn_8023A168(int p1, int p2);
void fn_8023A87C(GameObject* obj, struct AndrossState* state);
void fn_8023A268(int p1, int p2, int p3);
void fn_80239FCC(int p1, int p2);
int fn_8023A6A4(struct AndrossState* state, f32 a, f32 b, f32 c);
void fn_8023A3E4(GameObject* obj, struct AndrossState* state);
void arwarwing_resetFlightState(GameObject* obj);
void arwarwingbo_update(int obj);
void arwarwing_updateThrusters(GameObject* obj, int state);
void arwarwing_handlePathDamage(GameObject* obj, int state);
void arwarwing_handleObjectDamage(GameObject* obj, int state);
void androsshand_spawnShot(int obj, int hand, int p3);
int arwarwing_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void arwarwing_init(GameObject* obj);
void Obj_SteerVelocityTowardVector(int out, f32* v1, f32* v2, f32 a, f32 b, f32 c);
int Obj_UpdateRomCurveFollowVelocity(GameObject* p1, int p2, f32 a, f32 b, f32 c, int flag);
int Obj_UpdateRomCurveFollowVelocityIndexed(GameObject* p1, int p2, f32 a, f32 b, f32 c, int flag, int* p6);
void Obj_SpawnHitLightAndFade(int obj, f32* p2);
void drearthcal_update(int obj);
int Obj_UpdateLightningCluster(int obj, void** entries, int count, f32 intensity, ModelLight** light);
void Obj_SmoothTurnAnglesTowardVelocity(GameObject* a, int b, int c, f32 d, f32 e);
int Obj_PredictInterceptPoint(GameObject* obj, f32 dt, int p3, int p4);
int voxmaps_traceWorldLine(void* p1, void* p2);
void voxmaps_traceScaledVectorEnd(f32* p1, void* p2, f32* p3, f32 scale);
void arwarwing_readControls(GameObject* obj, int state);
void arwarwing_updateBarrelRoll(GameObject* obj, int state);

#endif
