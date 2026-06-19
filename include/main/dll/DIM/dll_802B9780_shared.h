#ifndef MAIN_DLL_DIM_DLL_802B9780_SHARED_H_
#define MAIN_DLL_DIM_DLL_802B9780_SHARED_H_

#include "ghidra_import.h"
#include "main/objHitReact.h"
#include "main/objanim.h"
#include "main/newclouds.h"
#include "main/unknown/autos/placeholder_80295318.h"
#include "main/dll/player_80295318_shared.h"
#include "main/unknown/autos/placeholder_802BBC10.h"

extern f32 lbl_803E8298;
extern f32 lbl_803E829C;
extern f32 lbl_803E82A0;

extern void ObjPath_GetPointLocalPosition(int obj, int point, f32 *out_x, f32 *out_y,
                                          f32 *out_z);
extern void mtx44_mult(void *lhs, void *rhs, void *out);
extern void fn_8003B950(void *matrix);

extern u8 gDIMSnowHorn1ModelMtx[];

/*
 * Build a transform from a packed rotation/translation record and sample
 * one fixed local point through it.
 */

/*
 * DIMSnowHorn1_animEventCallback - large interrupt-init helper (~140 instructions).
 */
extern f32 lbl_803E82A4;
extern f32 lbl_803E82A8;
extern f32 gDIMSnowHorn1DefaultStateHandler;
extern int gDIMSnowHorn1StateHandlers[];

extern void fn_802BB998(int obj, int state, int state2);
/* DLL 0x76 (DIMSnowHorn1 / dim2prisonmammoth) fragment: head/vtable live in placeholder_802BACC0 + placeholder_802BB4B0; consolidate when those adjacent units are graduated. */

extern int FUN_80006a64();
extern u64 FUN_80006a68();
extern u32 FUN_80006a6c();
extern double FUN_80017708();
extern u32 FUN_8001776c();
extern u32 ObjHits_RegisterActiveHitVolumeObject();
extern u32 objAnimFn_80038f38();
extern u32 FUN_80039468();
extern u32 FUN_8003a1c4();
extern u32 FUN_8003b444();
extern u32 FUN_8003b870();
extern u32 FUN_80053754();
extern u32 FUN_80053758();
extern int FUN_80056600();
extern u32 FUN_8007f6e4();
extern u32 FUN_8007f718();
extern u32 FUN_800e8630();
extern u32 FUN_801141dc();
extern u32 FUN_801141e8();
extern int FUN_80114340();
extern int FUN_801149b8();
extern u32 FUN_801149bc();
extern u32 FUN_80114b10();
extern u32 dll_2E_func03();
extern u32 FUN_801150ac();
extern u32 FUN_80135814();
extern u32 FUN_8020a498();
extern u32 FUN_8020a4a4();
extern u32 FUN_802bb420();
extern u32 FUN_802bb998();

extern u32 DAT_802c3428;
extern u32 DAT_802c342c;
extern u32 DAT_802c3430;
extern u32 DAT_802c3434;
extern u32 DAT_802c3438;
extern u32 DAT_802c343c;
extern u32 DAT_802c3440;
extern u32 DAT_802c3444;
extern u32 DAT_802c3448;
extern u32 DAT_802c344c;
extern u32 DAT_802c3450;
extern u32 DAT_802c3454;
extern u32 DAT_802c3458;
extern u32 DAT_802c345c;
extern u32 DAT_802c3460;
extern u32 DAT_802c3464;
extern u32 DAT_802c3468;
extern u32 DAT_802c346c;
extern u32 DAT_802c3470;
extern u32 DAT_802c3474;
extern u32 DAT_802c3478;
extern u32 DAT_802c347c;
extern u32 DAT_802c3498;
extern u32 DAT_802c349c;
extern u32 DAT_802c34a0;
extern u32 DAT_802c34a4;
extern u32 DAT_802c34a8;
extern u32 DAT_802c34ac;
extern u32 DAT_802c34b0;
extern u32 DAT_802c34b4;
extern u32 DAT_802c34b8;
extern u32 DAT_802c34bc;
extern u32 DAT_802c34c0;
extern u32 DAT_802c34c4;
extern u32 DAT_802c34c8;
extern u8 DAT_80335cfc;
extern u8 DAT_80335d10;
extern u32 DAT_80335d24;
extern u32 DAT_80335d30;
extern u32 DAT_80335d60;
extern u32 DAT_80335d70;
extern u32 DAT_80335e08;
extern u32 DAT_80335e64;
extern u32 DAT_80335e94;
extern u32 DAT_80335ea4;
extern u32 DAT_80335ebc;
extern u32 DAT_80335edc;
extern u32 DAT_80335ee4;
extern u32 DAT_80335f00;
extern u32 DAT_80335f0c;
extern u32 DAT_80335f30;
extern u32 DAT_80335f70;
extern u32 DAT_80336014;
extern u32 DAT_803360b8;
extern u32 DAT_8033635c;
extern u32 DAT_80336368;
extern u32 DAT_80336374;
extern u32 DAT_80336380;
extern u32 DAT_8033638c;
extern u32 DAT_80336398;
extern u16 DAT_803363b0;
extern u32 DAT_803363b8;
extern u32 DAT_803363c4;
extern u32 DAT_803dbd90;
extern u32 DAT_803dbd94;
extern u32 DAT_803dbd98;
extern u32 DAT_803dbd9c;
extern u32 DAT_803dbda0;
extern u32 DAT_803dbda4;
extern u32 DAT_803dbda8;
extern u32 DAT_803dbdac;
extern u32 DAT_803dbdb0;
extern u32 DAT_803dbdb4;
extern u32 DAT_803dbdb8;
extern u32 DAT_803dbdbc;
extern u32 DAT_803dbdc0;
extern u32 DAT_803dbdd0;
extern u32 DAT_803dbe10;
extern u32 DAT_803dbe14;
extern u32 DAT_803dbe18;
extern u32 DAT_803dbe1c;
extern u32 DAT_803dbe20;
extern u32 DAT_803dd39c;
extern u32 DAT_803dd3b8;
extern u32 DAT_803dd3bc;
extern u32 DAT_803dd3c0;
extern u32 DAT_803dd3d8;
extern u32 DAT_803dd3dc;
extern u32 DAT_803dd3e0;
extern u32 DAT_803dd3e4;
extern u32 DAT_803dd3e8;
extern u32 DAT_803dd3ec;
extern u32 DAT_803dd3fc;
extern u32 DAT_803dd402;
extern u32 DAT_803dd404;
extern u32* DAT_803dd6e0;
extern u32 DAT_803df144;
extern u32 DAT_803df148;
extern u32* DAT_803df150;
extern u32 DAT_803df154;
extern u32 DAT_803df158;
extern u32 DAT_803df15c;
extern u32 DAT_803df160;
extern u32 DAT_803e8ec8;
extern u32 DAT_803e8f70;
extern u32 DAT_803e9030;
extern u32 DAT_803e9034;
extern u32 DAT_803e9038;
extern f64 DOUBLE_803e8f78;
extern f64 DOUBLE_803e9098;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803dd3d4;
extern f32 FLOAT_803dd3f4;
extern f32 FLOAT_803dd3f8;
extern f32 FLOAT_803e8f3c;
extern f32 FLOAT_803e8f40;
extern f32 FLOAT_803e8f44;
extern f32 FLOAT_803e8f48;
extern f32 FLOAT_803e8f4c;
extern f32 FLOAT_803e8f50;
extern f32 FLOAT_803e8f58;
extern f32 FLOAT_803e8f5c;
extern f32 FLOAT_803e8f60;
extern f32 FLOAT_803e8f64;
extern f32 FLOAT_803e8f80;
extern f32 FLOAT_803e8f84;
extern f32 FLOAT_803e8f88;
extern f32 FLOAT_803e8f8c;
extern f32 FLOAT_803e8f90;
extern f32 FLOAT_803e8f94;
extern f32 FLOAT_803e8f98;
extern f32 FLOAT_803e8f9c;
extern f32 FLOAT_803e8fa0;
extern f32 FLOAT_803e8fa4;
extern f32 FLOAT_803e8fa8;
extern f32 FLOAT_803e8fac;
extern f32 FLOAT_803e8fb0;
extern f32 FLOAT_803e8fb4;
extern f32 FLOAT_803e8fb8;
extern f32 FLOAT_803e8fbc;
extern f32 FLOAT_803e8fc0;
extern f32 FLOAT_803e8fc4;
extern f32 FLOAT_803e8fc8;
extern f32 FLOAT_803e8fcc;
extern f32 FLOAT_803e8fd0;
extern f32 FLOAT_803e8fd4;
extern f32 FLOAT_803e8fd8;
extern f32 FLOAT_803e8fdc;
extern f32 FLOAT_803e8fe0;
extern f32 FLOAT_803e8fe4;
extern f32 FLOAT_803e8fe8;
extern f32 FLOAT_803e8fec;
extern f32 FLOAT_803e8ff0;
extern f32 FLOAT_803e8ff4;
extern f32 FLOAT_803e9004;
extern f32 FLOAT_803e9008;
extern f32 FLOAT_803e9010;
extern f32 FLOAT_803e9014;
extern f32 FLOAT_803e9018;
extern f32 FLOAT_803e901c;
extern f32 FLOAT_803e9020;
extern f32 FLOAT_803e9024;
extern f32 FLOAT_803e9028;
extern f32 FLOAT_803e902c;
extern f32 FLOAT_803e903c;
extern f32 FLOAT_803e9040;
extern f32 FLOAT_803e9044;
extern f32 FLOAT_803e9048;
extern f32 FLOAT_803e904c;
extern f32 FLOAT_803e9050;
extern f32 FLOAT_803e9054;
extern f32 FLOAT_803e9058;
extern f32 FLOAT_803e905c;
extern f32 FLOAT_803e9060;
extern f32 FLOAT_803e9064;
extern f32 FLOAT_803e9068;
extern f32 FLOAT_803e906c;
extern f32 FLOAT_803e9070;
extern f32 FLOAT_803e9074;
extern f32 FLOAT_803e9078;
extern f32 FLOAT_803e907c;
extern f32 FLOAT_803e9080;
extern f32 FLOAT_803e9084;
extern f32 FLOAT_803e9088;
extern f32 FLOAT_803e908c;
extern f32 FLOAT_803e9090;
extern f32 FLOAT_803e9094;
extern f32 FLOAT_803e90a0;
extern f32 FLOAT_803e90a4;
extern f32 FLOAT_803e90a8;
extern f32 FLOAT_803e90ac;
extern f32 FLOAT_803e90b0;
extern f32 FLOAT_803e90b4;
extern f32 FLOAT_803e90b8;
extern f32 FLOAT_803e90bc;
extern u32 _DAT_803df140;

/*
 * --INFO--
 *
 * Function: DIMSnowHorn1_update
 * EN v1.0 Address: 0x802BB720
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BBC14
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct {
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

typedef struct {
    u8 pad[0x94];
    u8 flag;
} SnowHornFlags;

extern u8 gDIMSnowHorn1ConfigTable[];
extern void fn_8003A168(int obj, int q);
extern void fn_8003B500(int obj, int q, f32 f);
extern void fn_802BB4B4(int obj, int a, int slot);
extern int getCurMapLayer(void);
extern f32 getXZDistance(int a, int b);
extern f32 lbl_803E82AC;
extern f32 lbl_803E82B0;
extern f32 lbl_803E82B4;

extern f32 lbl_803E82D0;

extern f32 lbl_803E83E8;
extern f32 lbl_803E83A4;

extern void *gEarthWarriorResource;

extern int gDRCloudRunnerStateHandlers[];
extern void *gDRCloudRunnerDefaultStateHandler;
extern int DR_CloudRunner_stateHandler00(int obj);
extern int DR_CloudRunner_stateHandler01(int obj, int p2);
extern int DR_CloudRunner_stateHandler02(int obj, int p2);
extern int DR_CloudRunner_stateHandler03(int obj, int p2);
extern int DR_CloudRunner_stateHandler04(int obj, int p2);
extern void DR_CloudRunner_stateHandler05();
extern void DR_CloudRunner_stateHandler06();

extern int gDim2PrisonMammothStateHandlers[];
extern int gDREarthWarriorStateHandlers[];
extern void *gDim2PrisonMammothDefaultStateHandler;
extern void *gDREarthWarriorDefaultStateHandler;
extern int dim2prisonmammoth_stateHandler01(int obj, int p2);
extern int dim2prisonmammoth_stateHandler02(int obj, int p2);
extern int dim2prisonmammoth_stateHandler03(int obj, int p2);
extern void DR_EarthWarrior_stateHandler01();
extern void DR_EarthWarrior_stateHandler02();
extern int DR_EarthWarrior_stateHandler03(int obj, int p2);

extern f32 lbl_803E82C0;
extern f32 gPrisonMammothMoveSpeed;
extern f32 lbl_803E82C8;
extern f32 lbl_803E82CC;
extern f32 gPrisonMammothMoveSpeedTable;
extern s16 gPrisonMammothMoveIdTable;

extern f32 lbl_803E83F4;
extern f32 lbl_803E83F8;
extern f32 lbl_803E83BC;
extern f32 lbl_803E8408;
extern f32 lbl_803E840C;
extern s16 gDRCloudRunnerDefaultRotX;
extern void fn_802BF0C8(int obj, int p2, int mode);
extern f32 lbl_803E8304;
extern f32 GX_F32_256;
extern f32 lbl_803DC76C;
extern f32 lbl_803E8338;
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 m);

extern void dll_2E_func06();
extern f32 lbl_803E83A8;
extern f32 lbl_803E8360;
extern f32 lbl_803E8354;
extern f32 lbl_803E8364;

extern int objAudioFn_800393f8(int obj, void *audio, int soundId, int volume, int p5, int p6);
extern void textureFree(int handle);
extern f32 lbl_803E82E8;
extern int lbl_8033527C[];
extern void *gDIMSnowHorn1Texture;

extern f32 lbl_803E8410;

int fn_802BC3F0(int obj, int p2, ObjAnimUpdateState *animUpdate);

extern f32 lbl_803DC78C;
extern f32 lbl_803DC790;

extern f32 gEarthWarriorMatrix[];

extern s16 gDIMSnowHorn1TextureId;
extern int textureLoad(int id, int p2);

extern int DIMSnowHorn1_animEventCallback(int obj, int unused, ObjAnimUpdateState *animUpdate);
extern int lbl_803E8230;
extern int gDIMSnowHorn1PathCollisionData;
extern f32 gDIMSnowHorn1Gravity;
extern void dll_2E_func05(int obj, int q, int a, int b, int c);

extern int dll_2E_func07(int obj, int p3, void *q, int a, int b);

extern int dll_2E_func0A(int a, void *out);
extern void dll_2E_func08(int q, int a, int b);
extern f32 lbl_803E8414;
extern f32 lbl_803E8424;
void fn_802BF0C8(int obj, int inner, int bit);

extern u8 gPrisonMammothStateFlagsTable;
extern ObjHitReactEntry gPrisonMammothHitReactEntry[];
extern void saveGame_saveObjectPos(int obj);

extern u8 gDRCloudRunnerMoveParamTable[];
extern int lbl_803E83A0;
extern int lbl_803DC770;
extern int lbl_803DC774;
extern int lbl_803DC778;
extern int lbl_803DC77C;
extern int lbl_803DC780;
extern int lbl_803DC784;

extern int Obj_UpdateRomCurveFollowVelocity(int obj, int q, f32 a, f32 b, f32 c, int d);
extern int gDRCloudRunnerAirMeterBaseline;
extern f32 lbl_803E83B4;
void fn_802BF4D8(int obj);

extern void fn_80137948(const char *fmt, ...);
extern char sOnCloudFormat[];
extern f32 lbl_803E8418;
extern f32 lbl_803E841C;
extern f32 lbl_803E8420;

extern void voxmaps_worldToGrid(void *src, void *grid);
extern int voxmaps_traceLine(void *a, void *b, void *c, int d, int e);
extern void voxmaps_gridToWorld(void *grid, void *out);
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
