#ifndef MAIN_SKY_80080E58_SHARED_H
#define MAIN_SKY_80080E58_SHARED_H

#include "ghidra_import.h"
#include "main/cloud_action_runtime.h"
#include "main/cloud_layer_state.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/newclouds.h"
#include "main/objtexture.h"
#include "main/resource.h"
#include "main/screen_transition.h"
#include "main/sky_interface.h"

typedef struct ObjSeqBgCmd {
    int object;
    s16 param;
    s8 opcode;
    s8 pad;
} ObjSeqBgCmd;

typedef struct SkyBlendStateFlags {
    u8 unused80 : 1;
    u8 active : 1;
    u8 bit20 : 1;
    u8 cloud : 2;
    u8 rest : 3;
} SkyBlendStateFlags;

extern void setDrawCloudsAndLights(int mode);
extern void fn_8008C9F4(u8 *cfg, u8 flags);
extern u8 gSkyConfigFieldIndices[];
extern void skyFn_80062a54(f32 x, f32 y, f32 z, int intensity);
extern void *mmAlloc(int size, int heap, int flags);
extern void mm_free(void *ptr);
extern void *Obj_GetPlayerObject(void);
extern void *getTrickyObject(void);
extern void *ObjList_FindObjectById(int id);
extern void **ObjList_GetObjects(void *unused, int *count);
extern void getEnvfxAct(void *obj, void *source, int actId, int flags);
extern void objSeq_onMapSetup(void);
extern void objSeqInitFn_80080078(void *entries, int count);
extern int ObjSeq_func20(void *obj, u8 *seq, int cmd, int maxCount, int paramOffset, int arg5, int arg6);
extern int ObjSeq_EvaluateCondition(int condition, u8 *seq, int obj);
extern int isGameTimerDisabled(void);
extern void playerEnvFxFn_80088ad4(u8 envFxValue);
extern void renderSunAndMoon();
extern void AudioStream_CancelPrepared(void);
extern void *Obj_AllocObjectSetup(int size, int objectId);
extern void *Obj_SetupObject(void *setup, int mode, int mapLayer, int objIndex, void *parent);
extern void *Obj_GetActiveModel(void *obj);
extern void ObjModel_SetRenderCallback(void *model, void *callback);
extern int moonFxCb_80074110(int obj, int *model, int param);
extern int getCurMapLayer(void);
extern void modelLightStruct_setDirection(void *model, f32 x, f32 y, f32 z);
extern void modelLightStruct_setDiffuseColor(void *model, int red, int green, int blue, int alpha);
extern void lightSetColor(int index, int red, int green, int blue);
extern void PSMTXScale(f32 mtx[3][4], f32 x, f32 y, f32 z);
extern void PSMTXConcat(f32 a[3][4], f32 b[3][4], f32 out[3][4]);
extern void Obj_BuildWorldTransformMatrix(void *obj, f32 mtx[3][4], int flags);
extern void skyFn_8008a04c(void);
extern void skyFn_8008a500(void);
extern void Obj_GetWorldPosition(void *obj, f32 *x, f32 *y, f32 *z);
extern s16 *Camera_GetCurrentViewSlot(void);
extern int randomGetRange(int min, int max);
extern int return0xFFFF_80008B6C(int obj, int a, int b, int c, int d, int e, int f);
extern void ObjSeq_ApplyFrameCurves(u8 *obj, u8 *seqObj, u8 *seq, int frame);
extern void ObjSeq_RebuildCurveStateToFrame(u8 *obj, u8 *seqObj, u8 *seq, int mode);
extern void ObjSeq_UpdateCurvePosition(u8 *obj, u8 *seq);
extern int hitDetectFn_800658a4(void *obj, f32 x, f32 y, f32 z, f32 *out, int flags);
extern void ObjSeq_ApplyLinkedObjectTransform(u8 *obj, u8 *seqObj, u8 *seq);
extern void animatedObjFreeAndSavePlayerPos(u8 *obj, u8 *seqObj, u8 *seq);
extern void objModelClearVecFn_8003aa40(void *obj);
extern s16 *objModelGetVecFn_800395d8(void *obj, int index);
extern long long OSGetTime(void);

extern s16 gObjSeqBgCmds[];
extern u8 objSeqXrotChanged[];
extern s16 objSeqXrotValues[];
extern s8 gObjSeqBoolFlags[];
extern s8 gObjSeqCondFlags[];
extern s8 gObjSeqSlotResults[];
extern ObjSeqBgCmd lbl_8039A5BC[];
extern u8 lbl_80396918[];
extern int lbl_8030EDA4[];
extern int gObjSeqStreamTableA[];
extern u8 lbl_803DB748;
extern int lbl_803DB720;
extern s16 seqGlobal1;
extern s16 seqGlobal2;
extern s8 seqGlobal3;
extern s8 gObjSeqBgCmdCount;
extern void *lbl_803DD0D4;
extern u8 lbl_803DD0D8;
extern u8 gObjSeqStop;
extern int lbl_803DD090;
extern int gObjSeqCamModeArgD;
extern int gObjSeqCamModeArgC;
extern int gObjSeqCamModeArgB;
extern int gObjSeqCamMode;
extern int lbl_803DD130;
extern int lbl_803DD134;
extern int lbl_803DD138;
extern int lbl_803DD13C;
extern u8 gSkyEnvFxFlags;
extern u8 *gSkyState;
extern u8 *gSkySunObject;
extern void *gSkyMoonObject;
extern void *gSkySkyTexture;
extern int gSkyObjectsInitialized;
extern u8 gSkyOverrideLightColor;
extern u8 gSkyOverrideLightColorEnabled;
extern f32 gSkyOverrideLightIntensity;
extern u8 gSkyOverrideLightDirectionEnabled;
extern void *gSkyMoonLight;
extern u8 gSkyCurrentLightColor;
extern u8 gSkyCurrentAmbientColor;
extern u8 gSkyCurrentTextureColor;
extern s8 lbl_803DD113;
extern u8 gObjSeqLinkedTransformValid;
extern s16 gObjSeqLinkedSavedPitch;
extern f32 gObjSeqLinkedSavedPosZ;
extern f32 gObjSeqLinkedSavedPosY;
extern f32 gObjSeqLinkedSavedPosX;
extern void *gSkySunLight;
extern u16 lbl_803DD0B6;
extern void *lbl_803DD0B8;
extern u8 gObjSeqCameraActive;
extern u8 lbl_803DD124;
extern f32 lbl_803DD0DC;
extern u8 lbl_803DD0F8;
extern u8 framesThisStep;
extern f32 gSkyOverrideLightDirection[];
extern const f32 pEXIInputFlag;
extern const f32 EXIInputFlag;
extern f32 timeDelta;
extern f32 lbl_803DEFB0;
extern f32 lbl_803DEFC8;
extern f32 lbl_803DEFF0;
extern f32 lbl_803DF024;
extern f32 lbl_803DF028;
extern f32 lbl_803DF060;
extern const f32 lbl_803DF06C;
extern f32 init_803DF080;
extern f32 gSkyDayStartTime;
extern f32 lbl_803DF064;
extern f32 lbl_803DF068;
extern f32 gSkySecondsPerDay;
extern f32 PSVECMag(f32 *vec);
extern void PSVECScale(f32 scale, f32 *src, f32 *dst);
extern void modelLightStruct_selectObjectLights(u8 *obj, u8 **outLights, int maxLights, int *outCount, int typeMask);
extern void modelLightStruct_getWorldPosition(u8 *p, f32 *a, f32 *b, f32 *c);
extern const f32 lbl_803DF0F0;
extern const f32 gSkyInitialTimeOfDay;
extern const f32 lbl_803DF0F8;
extern const f32 lbl_803DF0FC;
extern const f32 lbl_803DF100;
extern const f32 lbl_803DF104;
extern void *textureAlloc(int w, int h, int fmt, int a, int b, int c, int d, int e, int f);
extern f32 lbl_803DF07C;
extern f32 lbl_803DF088;
extern void fn_80089A60(int slot, f32 x, f32 y, f32 z, int r, int g, int b, int a2, int b2, int c2);
extern f32 Curve_EvalLinear(f32 *curve, f32 t, int mode);
extern f32 *Camera_GetInverseViewMatrix(void);
extern f32 Camera_GetFarPlane(void);
extern void Camera_SetFarPlane(f32 dist, int mode);
extern void Camera_RebuildProjectionMatrix(void);
extern void vecRotateZXY(void *rot, f32 *vec);
extern void objRender(int a, int b, int c, int d, void *obj, int mode);
extern u16 gSkySunAlpha;
extern u16 gSkyMoonAlpha;
extern u8 gSkyBaseSunDirection[];
extern u8 gSkyBaseMoonDirection[];
extern const f32 gSkySunMoonFarPlane;
extern const f32 gSkySunArcDuration;
extern const f32 gSkySunFadeInThreshold;
extern const f32 gSkyAlphaFadeScale;
extern const f32 gSkySunFadeOutThreshold;
extern const f32 lbl_803DF0AC;
extern const f32 gSkySunRiseDuration;
extern const f32 lbl_803DF0B4;
extern const f32 lbl_803DF0B8;
extern const f32 gSkySunMoonScale;
extern const f32 lbl_803DF0C0;
extern const f32 lbl_803DF0C4;

typedef struct SkyVec3 {
    f32 x, y, z;
} SkyVec3;

typedef struct SkyRotQ {
    u16 rx, ry, rz;
    f32 w;
    f32 x, y, z;
} SkyRotQ;
extern void PSMTXMultVecSR(f32 *m, f32 *src, f32 *dst);
extern f32 Curve_EvalCatmullRom(u8 *curve, f32 t, int mode);
extern const f32 lbl_803DF108;
extern const f32 lbl_803DF10C;
extern const f32 lbl_803DF110;
extern f32 lbl_803DF114;
extern f32 lbl_803DF118;
extern f32 lbl_803DF11C;
extern f32 lbl_803DF120;
extern f32 lbl_803DF138;
extern f32 lbl_803DF13C;
extern f32 lbl_803DF140;
extern const f32 lbl_803DF144;
extern f32 lbl_803DF1A0;
extern u8 colorScale;
extern int lbl_803DB610;
extern s8 gSky2DrawMode;
extern u8 *gSky2State;
extern u8 *lbl_803DD19C;
extern u8 gNewCloudInitialized;
extern void PSVECNormalize(void *src, void *dst);

extern void* ObjGroup_GetObjects();
extern void ObjMsg_SendToNearbyObjects(int, f32, int, void *, int, void *);
extern void ObjMsg_SendToObjects(int, int, void *, int, void *);
extern void ObjMsg_SendToObject(void *, int, void *, int);




/*
 * --INFO--
 *
 * Function: FUN_80080e60
 * EN v1.0 Address: 0x80080E60
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80081BF8
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80080e60(double param_1,double param_2,double param_3,double param_4,u64 param_5,
                u64 param_6,u64 param_7,u64 param_8,int param_9,
                u32 param_10,u32 param_11,int *param_12,int *param_13,int param_14,
                int *param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080e68
 * EN v1.0 Address: 0x80080E68
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80081E7C
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80080e68(int param_1)
{
    return 0;
}







/*
 * --INFO--
 *
 * Function: FUN_80080e88
 * EN v1.0 Address: 0x80080E88
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80082E7C
 * EN v1.1 Size: 652b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80080e88(u64 param_1,u64 param_2,double param_3,float *param_4,int param_5,
                   int param_6)
{
    return 0.0;
}



/*
 * --INFO--
 *
 * Function: FUN_80080e98
 * EN v1.0 Address: 0x80080E98
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80083E7C
 * EN v1.1 Size: 528b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 FUN_80080e98(u32 param_1,int param_2)
{
    return 0;
}






/*
 * --INFO--
 *
 * Function: FUN_80080eb4
 * EN v1.0 Address: 0x80080EB4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80084EE4
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80080eb4(int param_1,u32 param_2)
{
    return 0;
}






/*
 * --INFO--
 *
 * Function: FUN_80080ed0
 * EN v1.0 Address: 0x80080ED0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80086050
 * EN v1.1 Size: 660b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
short * FUN_80080ed0(double param_1,double param_2,double param_3,double param_4,u64 param_5,
                    u64 param_6,u64 param_7,u64 param_8,short *param_9,
                    int *param_10,int param_11,int *param_12,int *param_13,int param_14,
                    int *param_15,int param_16)
{
    return 0;
}






/*
 * --INFO--
 *
 * Function: FUN_80080eec
 * EN v1.0 Address: 0x80080EEC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80088554
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u8 FUN_80080eec(int param_1)
{
    return 0;
}





/*
 * --INFO--
 *
 * Function: FUN_80080f04
 * EN v1.0 Address: 0x80080F04
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800889EC
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 FUN_80080f04(void)
{
    return 0;
}









/*
 * --INFO--
 *
 * Function: FUN_80080f2c
 * EN v1.0 Address: 0x80080F2C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80089094
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u8 FUN_80080f2c(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080f34
 * EN v1.0 Address: 0x80080F34
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800890BC
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u8 FUN_80080f34(int param_1)
{
    return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_80080f40
 * EN v1.0 Address: 0x80080F40
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800892BC
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u8 FUN_80080f40(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080f48
 * EN v1.0 Address: 0x80080F48
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800893B8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 FUN_80080f48(void)
{
    return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_80080f54
 * EN v1.0 Address: 0x80080F54
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80089428
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u8 FUN_80080f54(int param_1)
{
    return 0;
}
















/*
 * --INFO--
 *
 * Function: FUN_80080f98
 * EN v1.0 Address: 0x80080F98
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80089CDC
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 FUN_80080f98(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080fa0
 * EN v1.0 Address: 0x80080FA0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80089CE4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 FUN_80080fa0(void)
{
    return 0;
}







/*
 * --INFO--
 *
 * Function: FUN_80080fc0
 * EN v1.0 Address: 0x80080FC0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8008BA7C
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 FUN_80080fc0(float *param_1)
{
    return 0;
}










/*
 * --INFO--
 *
 * Function: FUN_80080fec
 * EN v1.0 Address: 0x80080FEC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8008DB90
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80080fec(void)
{
    return 0;
}









/*
 * --INFO--
 *
 * Function: FUN_80081014
 * EN v1.0 Address: 0x80081014
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8008F014
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80081014(void)
{
    return 0.0;
}



























/*
 * --INFO--
 *
 * Function: FUN_80081084
 * EN v1.0 Address: 0x80081084
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8009461C
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 FUN_80081084(float *param_1,float *param_2)
{
    return 0;
}









/*
 * --INFO--
 *
 * Function: FUN_800810ac
 * EN v1.0 Address: 0x800810AC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80095980
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 FUN_800810ac(double param_1,float *param_2)
{
    return 0;
}

































/*
 * --INFO--
 *
 * Function: FUN_80081134
 * EN v1.0 Address: 0x80081134
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8009B078
 * EN v1.1 Size: 756b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80081134(u64 param_1,double param_2,double param_3,u64 param_4,
                u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                int param_9,u32 param_10,u32 param_11,u32 param_12,
                u32 param_13,u32 param_14,u32 param_15,u32 param_16)
{
    return 0;
}


#pragma push








#pragma pop

#pragma push











#pragma pop

#pragma push








extern u8 gSkySunPositionPrev;
extern void getEnvfxActImmediately(void *obj, void *target, int effectId, int flags);

#pragma push
#pragma pop















































#pragma pop

/* Pattern wrappers. */

#pragma push
#pragma pop

extern void padUpdate(void);
extern void checkReset(void);
void skyFn_80088c94(int flags, int mode);
void fn_8008D088(int slot);
void sky2_run(void);
extern void waitNextFrame(void);
extern void loadDataFiles(void);
extern void dvdCheckError(void);
extern void mmFreeTick(int);
extern void gameTextRun(void);
extern void GXFlush_(int, int);
extern int getLoadedFileFlags(int);
extern void *objCreateLight(int, int);
extern void modelLightStruct_setLightKind(void *, int);
extern void modelLightStruct_setSpecularColor(void *, int, int, int, int);
extern void *textureLoadAsset(int);
extern u8 gDvdErrorPauseActive;
extern f32 gSkySunDirection[];
extern f32 gSkyMoonDirection[];
void skyFn_80088e54(int mode, f32 brightness);
void fn_8008BDA8(void);

#pragma push
#pragma pop

extern void textureFree(void *handle);
extern void Music_Trigger(int id, int restart);
extern u8 gNewCloudInitialized;
extern f32 lbl_803DF1A0;
void snowFreeSnowCloud(int index);

#pragma push
#pragma pop

#pragma push
#pragma pop

extern void fn_8005D0BC(int unused, int a, int b, int c, int d);
extern void fogFn_80070404(f32 a, f32 b);
extern void setTextColor(int unused, int a, int b, int c, int d);
extern f32 lbl_803DF14C;
extern const f32 lbl_803DF108;
extern f32 lbl_803DF148;
extern f32 lbl_803DF118;
extern s8 lbl_803DB750;

#pragma push


extern void Obj_SetModelColorOverrideRecursive(int obj, int r, int g, int b, int a, int flag);

#pragma pop

#pragma push
#pragma pop

typedef struct RomCurveNode {
    u8 pad00[0x08];
    f32 x;
    f32 y;
    f32 z;
    u8 pad14[0x07];
    s8 directionMask;
    s32 links[4];
    s8 yaw;
    s8 pitch;
    u8 tangentScale;
} RomCurveNode;

typedef struct RomCurveInterpState {
    s32 fromNodeId;
    s32 toNodeId;
    f32 fromTime;
    f32 segmentTime1;
    f32 segmentTime2;
    f32 segmentTime3;
    f32 segmentTime4;
    f32 segmentTime5;
    f32 segmentTime6;
    f32 segmentTime7;
    f32 toTime;
} RomCurveInterpState;

#define ROM_CURVE_NODE_ANGLE(v) ((lbl_803DEFE8 * (f32)((s32)(v) << 8)) / lbl_803DEFEC)
#define ROM_CURVE_NODE_SCALE(node) (lbl_803DF008 * (f32)(u8)((node)->tangentScale))

extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern f32 sqrtf(f32 x);
extern s16 getAngle(f32 x, f32 z);
extern void Curve_SampleSegmentPoints(f32 *px, f32 *py, f32 *pz, f32 *outX, f32 *outY, f32 *outZ,
                             int count, void (*evalFn)(f32 *values, f32 *coefficients));
extern void Curve_BuildHermiteCoeffs(f32 *values, f32 *coefficients);
extern f32 Curve_EvalHermite(f32 t, f32 *values, f32 *outTangent);
extern f32 lbl_803DEFE8;
extern f32 lbl_803DEFEC;
extern f32 lbl_803DF008;
extern f32 lbl_803DF000;
extern f32 lbl_803DF01C;
extern f32 lbl_803DF020;

#pragma push
#pragma pop

#pragma push
#pragma pop

#pragma push
#pragma pop

#pragma push
#pragma pop

#pragma push
#pragma pop

#pragma push
#pragma pop

typedef struct ObjCurveKey {
    f32 value;
    s8 tangentAndMode;
    u8 pad05;
    s16 frame;
} ObjCurveKey;

#pragma push
#pragma pop

extern void getEnvfxActImmediately(void *obj, void *target, int effectId, int flags);

#pragma push
#pragma pop

typedef struct Dll06InterpState {
    u8 pad00[0x24];
    s32 targetX;
    s32 targetY;
    s32 targetZ;
    u8 pad30[0x2dc];
    f32 blend;
    u8 pad310[0x06];
    s8 active;
} Dll06InterpState;

#pragma push
#pragma pop

typedef struct FogColor {
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} FogColor;

extern void GXSetFog(int type, f32 startz, f32 endz, f32 nearz, f32 farz, FogColor color);
extern void GXSetTevOrder(int stage, int coord, int map, int color);
extern void GXSetTevDirect(int stage);
extern void GXSetTevColorIn(int stage, int a, int b, int c, int d);
extern void GXSetTevAlphaIn(int stage, int a, int b, int c, int d);
extern void GXSetTevSwapMode(int stage, int ras, int tex);
extern void GXSetTevColorOp(int stage, int op, int bias, int scale, int clamp, int reg);
extern void GXSetTevAlphaOp(int stage, int op, int bias, int scale, int clamp, int reg);
extern void GXSetTexCoordGen2(int coord, int func, int src, int mtx, int normalize, int pttexmtx);
extern void GXSetNumIndStages(int n);
extern void GXSetNumChans(int n);
extern void GXSetNumTexGens(int n);
extern void GXSetNumTevStages(int n);
extern void selectTexture(void *tex, int slot);
extern void fn_8007880C(void);
extern void fn_80069B1C(void *a, void *b, f32 t, void *c);

typedef struct SkyBestIdx {
    u8 best;
    u8 second;
    u8 pad;
} SkyBestIdx;

extern void fn_8005CECC(int mode);
extern const f32 lbl_803DF150;
extern const f32 lbl_803DF154;
extern const f32 lbl_803DF158;
extern const f32 lbl_803DF15C;
extern const f32 lbl_803DF160;
extern const f32 lbl_803DF164;
extern const f32 lbl_803DF168;
extern const f32 lbl_803DF16C;
extern const f32 lbl_803DF170;
extern const f32 lbl_803DF174;
extern const f32 lbl_803DF178;
extern const f32 lbl_803DF17C;
extern const f32 lbl_803DF180;
extern const f32 lbl_803DF184;
extern const f32 lbl_803DF188;
extern const f32 lbl_803DF18C;
extern u8 lbl_803DB758;
extern u16 lbl_803E8460;
extern u8 lbl_803E8462;
extern f32 lbl_8039A7B8[];
extern f32 lbl_802C1F98[];

typedef struct SkySlotAnim {
    u8 pad00[4];        /* 0x00 */
    u16 flags4;         /* 0x04 */
    u16 flags6;         /* 0x06 */
    u8 pad08[0x34];     /* 0x08 */
    int frameCount;     /* 0x3c */
    u8 pad40[0x30];     /* 0x40 */
    f32 cur[0x21];      /* 0x70 */
    f32 target[0x21];   /* 0xf4 */
    f32 vel[0x21];      /* 0x178 */
    f32 cur2[0x16];     /* 0x1fc */
    f32 target2[0x16];  /* 0x254 */
    f32 vel2[0x16];     /* 0x2ac */
    f32 t;              /* 0x304 */
    f32 step;           /* 0x308 */
    f32 prevT;          /* 0x30c */
    f32 blend;          /* 0x310 */
    s8 b314;            /* 0x314 */
    s8 b315;            /* 0x315 */
    s8 b316;            /* 0x316 */
} SkySlotAnim;

typedef struct SkyTimeBlend {
    void *texA;          /* 0x00 */
    void *texB;          /* 0x04 */
    void *texList[3];    /* 0x08 */
    int texAId;          /* 0x14 */
    int texBId;          /* 0x18 */
    u8 pad1C[0x1F0];     /* 0x1c */
    f32 time;            /* 0x20c */
    u8 pad210[0xC];      /* 0x210 */
    int palettes[8];     /* 0x21c */
    f32 blend;           /* 0x23c */
    u8 pad240[0xF];      /* 0x240 */
    u8 phase;            /* 0x24f */
    s8 prevPhase;        /* 0x250 */
    u8 texSel;           /* 0x251 */
} SkyTimeBlend;
extern void skyDrawFn_80075d5c(f32 a, f32 b, f32 c, f32 d, int e, int f, int g, int h, int i);
extern u8 gSkyColorBlendTable[];
extern int lbl_803E8458;
extern int coordsToMapCell(f32 x, f32 z);
extern f32 Camera_GetFovY(void);
extern u32 getScreenResolution(void);
extern const f32 lbl_803DF0C8;
extern const f32 lbl_803DF0CC;
extern const f32 lbl_803DF0D0;
extern const f32 lbl_803DF0D4;
extern const f32 lbl_803DF0D8;
extern const f32 lbl_803DF0DC;
extern const f32 gSkyPi;
extern const f32 lbl_803DF0E4;
extern const f32 lbl_803DF0E8;
extern const f32 lbl_803DF0EC;

#pragma push
#pragma pop

extern void debugPrintf(char *fmt, ...);

#pragma push
#pragma pop

extern int ObjModel_GetRenderOp(int model, int x);

#pragma push
#pragma pop

extern void *memset(void *dst, int c, int n);
extern int lbl_803DB754;
extern f32 lbl_803DF190;
extern f32 lbl_803DF194;

#pragma push
#pragma pop

extern u8 *saveGameGetEnvState(void);
extern int getSaveGameLoadStatus(void);

#pragma push
#pragma pop

/* Forward declarations for graduated functions (split from placeholder_80080E58). */
void ObjSeq_setCamVars(int camA, int camB, int camC, int camD);
int objSeqFindLabel(u8 *seq, int label);
int objSeqFindConditional(u8 *seq, u8 *seqState);
void objCallSeqFn(u8 *obj, u8 *sourceObj, u8 *seq, int action);
void objSeqDoBgCmds0D(u8 *seq, u8 *obj, int skipSpawns);
void ObjSeq_SetupInitialPlaybackState(u8 *obj, u8 **seqObj, u8 *seq, u8 *sourceObj, void **outAction);
void ObjSeq_ApplyLinkedObjectTransform(u8 *obj, u8 *seqObj, u8 *seq);
int ObjSeq_EvaluateCondition(int condition, u8 *seq, int obj);
void ObjSeq_setXrot(int index, int xrot);
int ObjSeq_getBool(int index);
void ObjSeq_setFlag(int index, int value);
void ObjSeq_addBgCmd(int index, int xrot, int yrot);
void ObjSeq_seqState_free(u8 *seq);
void ObjSeq_seqState_init(u8 *seq);
void *ObjSeq_FindTargetObject(u8 *obj);
void ObjSeq_RefreshActionCursor(void *obj, void *seqFile, u8 *seq);
void ObjSeq_release(void);
void ObjSeq_initialise(void);
int ObjSeq_takeXrotChanged(int index);
void fn_80088730(u8 *out);
int getEnvFxBit2BA(void);
void setGameBit2BA(int value);
void envFxFn_800887cc(void);
void envFxActFn_800887f8(u8 value);
void fn_80088870(int a, int b, int c, int d);
void envFxFn_80088884(void);
void loadSunAndMoon(void);
int getSkyColorFn_80088e08(int slot);
int getSkyColorFn_80088e30(int slot);
int getSkyStructField24C(void);
void skyGetCurrentTextureColor(u8 *red, u8 *green, u8 *blue);
void skyGetCurrentAmbientAndLightColors(u8 *ambientRed, u8 *ambientGreen, u8 *ambientBlue, u8 *lightRed, u8 *lightGreen, u8 *lightBlue);
void *fn_8008912C(void);
void skyBuildSunModelMatrix(f32 mtx[3][4]);
int skyFn_8008919c(int slot);
void skySetOverrideLightColor(u8 red, u8 green, u8 blue);
void skySetOverrideLightColorEnabled(u8 enabled);
void skySetOverrideLightDirection(f32 x, f32 y, f32 z, f32 intensity);
void skySetOverrideLightDirectionEnabled(u8 enabled);
void skyFn_800894a8(int flags, f32 x, f32 y, f32 z);
void fn_80089510(int flags, u8 red, u8 green, u8 blue);
void fn_80089578(int flags, u8 red, u8 green, u8 blue);
void skyFn_800895e0(int flags, u8 red, u8 green, u8 blue, u8 m1, u8 m2);
void getTimeOfDay(f32 *time);
void renderSky(void);
void getAmbientColor(int slot, u8 *red, u8 *green, u8 *blue);
void textureColorFn_8008991c(int slot, u8 *red, u8 *green, u8 *blue);
void modelTextureFn_80089970(int slot);
void *fn_80089A50(void);
void *fn_80089A58(void);
int getSunPos(f32 *outTime);
void fn_8008B88C(int *outTimer);
void skyFn_80089710(int flags, u8 enabled, int startComplete);
void fn_800897D4(int slot, f32 *x, f32 *y, f32 *z);
void objGetColor(int slot, u8 *red, u8 *green, u8 *blue);
void dll_06_func0B(int *x, int *y);
void dll_06_func0A(int *a, int *b, int *c, f32 *scale);
void dll_06_func0E(void);
void dll_06_func0D(void);
void sky2_initialise(void);
void fn_8008EDE8(f32 *out);
void lightningRenderActive(void);
int fn_8008B71C(int slot);
void skyTimeToDayHourMinute(f32 time, s16 *days, s16 *hours, s16 *minutes);
void skyGetClockTime(f32 *time);
int dll_06_func0F(void);
f32 fn_8008ED88(void);
void snowCloudBuildBoxVerts(f32 *out, f32 height, f32 scale);
void mm_free_(void *ptr);
void dll_07_func09(void);
int dll_07_func08(void);
void newclouds_initialise(void);
int return0_80088758(void);
void doNothing_800887C4(void);
void doNothing_800887C8(void);
int return0_8008B7E8(void);
void doNothing_8008B8B0(void);
void pDll_Sky_setTimeOfDay_nop(void);
void dll_06_func0C_nop(void);
int dll_06_func07_ret_0(void);
void sky2_release(void);
void dll_07_func0A_nop(void);
void cloudClearOverridePosition(void);
void cloudSetOverridePosition(f32 a, f32 b, f32 c);
void loadLightFn_8008bbc4(void);
void newclouds_release(void);
void newclouds_onMapSetup(void);
void dll_06_func06(int obj);
void dll_06_func08(int obj);
void fn_8008DAE8(int obj);
void *lightningCreate(f32 *a, f32 *b, f32 c, f32 d, int e, int f, int g);
void RomCurveInterp_BuildSegmentTimeTable(RomCurveInterpState *out, RomCurveNode *curve, RomCurveNode *next, f32 t, int flag);
void RomCurveInterp_UpdateSegmentWindow(RomCurveInterpState *state, f32 t);
void RomCurveInterp_InitFromNode(RomCurveInterpState *out, int id);
int RomCurveInterp_EvaluateOffsetPosition(RomCurveInterpState *state, f32 *offset, f32 *outPos, s16 *outAngle, int ignoreY);
void ObjSeq_UpdateCurvePosition(u8 *obj, u8 *seq);
void animatedObjFreeAndSavePlayerPos(u8 *obj, u8 *seqObj, u8 *seq);
f32 objCurveInterpolate(ObjCurveKey *keys, int count, int frame);
void playerEnvFxFn_80088ad4(u8 idx);
void dll_06_func09(s32 *x, s32 *y, s32 *z);
void dll_07_func07(int arg);
void newclouds_snowKillSnowCloud(int cloudId, int flag);
void *cloudGetLayerTextureSize(f32 *out1, f32 *out2);
void sky2_onMapSetup(void);
void skyFn_80088c94(int flags, int mode);
void fn_8008D088(int slot);
void sky2_run(void);

#endif
