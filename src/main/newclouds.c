#include "ghidra_import.h"
#include "main/newclouds.h"

typedef struct ObjSeqBgCmd {
    int object;
    s16 param;
    s8 opcode;
    s8 pad;
} ObjSeqBgCmd;

typedef struct SkyBlendStateFlags {
    u8 unused80 : 1;
    u8 active : 1;
    u8 rest : 6;
} SkyBlendStateFlags;

extern void *mmAlloc(int size, int heap, int flags);
extern void mm_free(void *ptr);
extern void *Resource_Acquire(int id, int mode);
extern void Resource_Release(void *handle);
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
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
extern void playerEnvFxFn_80088ad4(int envFxValue);
extern void renderSunAndMoon(void);
extern void AudioStream_CancelPrepared(void);
extern void *Obj_AllocObjectSetup(int size, int objectId);
extern void *Obj_SetupObject(void *setup, int mode, int mapLayer, int objIndex, void *parent);
extern void *Obj_GetActiveModel(void *obj);
extern void ObjModel_SetRenderCallback(void *model, void *callback);
extern int moonFxCb_80074110(int obj, int *model, int param);
extern int getCurMapLayer(void);
extern void modelLightStruct_setDirection(void *model, f32 x, f32 y, f32 z);
extern void modelLightStruct_setDiffuseColor(void *model, int red, int green, int blue, int alpha);
extern void colorFn_8001efe0(int index, int red, int green, int blue);
extern void PSMTXScale(f32 mtx[3][4], f32 x, f32 y, f32 z);
extern void PSMTXConcat(f32 a[3][4], f32 b[3][4], f32 out[3][4]);
extern void Obj_BuildWorldTransformMatrix(void *obj, f32 mtx[3][4], int flags);
extern void skyFn_8008a04c(void);
extern void skyFn_8008a500(void);
extern void lightningRender(void *state);
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

extern s16 lbl_80399398[];
extern u8 lbl_80399EA8[];
extern s16 lbl_80399F00[];
extern s8 lbl_8039A45C[];
extern s8 lbl_8039A4B4[];
extern s8 lbl_8039A50C[];
extern ObjSeqBgCmd lbl_8039A5BC[];
extern u8 lbl_80396918[];
extern int lbl_8030EDA4[];
extern u8 lbl_8030ECA8[];
extern u8 lbl_803DB748;
extern int lbl_803DB720;
extern int *gGameUIInterface;
extern int *gMapEventInterface;
extern int *gPartfxInterface;
extern int *gScreenTransitionInterface;
extern s16 seqGlobal1;
extern s16 seqGlobal2;
extern s8 seqGlobal3;
extern int *gSHthorntailAnimationInterface;
extern s8 lbl_803DD0BC;
extern void *lbl_803DD0D4;
extern u8 lbl_803DD0D8;
extern u8 lbl_803DD0DA;
extern int lbl_803DD090;
extern int lbl_803DD100;
extern int lbl_803DD104;
extern int lbl_803DD108;
extern int lbl_803DD10C;
extern int lbl_803DD130;
extern int lbl_803DD134;
extern int lbl_803DD138;
extern int lbl_803DD13C;
extern u8 lbl_803DD140;
extern u8 *lbl_803DD12C;
extern u8 *gSkySunObject;
extern void *gSkyMoonObject;
extern void *lbl_803DD150;
extern int lbl_803DD154;
extern u8 gSkyOverrideLightColor;
extern u8 gSkyOverrideLightColorEnabled;
extern f32 gSkyOverrideLightIntensity;
extern u8 gSkyOverrideLightDirectionEnabled;
extern void *lbl_803DD168;
extern u8 gSkyCurrentLightColor;
extern u8 gSkyCurrentAmbientColor;
extern u8 gSkyCurrentTextureColor;
extern s8 lbl_803DD113;
extern u8 lbl_803DD114;
extern s16 lbl_803DD116;
extern f32 lbl_803DD118;
extern f32 lbl_803DD11C;
extern f32 lbl_803DD120;
extern void *lbl_803DD144;
extern u16 lbl_803DD0B6;
extern void *lbl_803DD0B8;
extern u8 framesThisStep;
extern f32 gSkyOverrideLightDirection[];
extern f32 pEXIInputFlag;
extern f32 EXIInputFlag;
extern f32 timeDelta;
extern f32 lbl_803DEFB0;
extern f32 lbl_803DEFC8;
extern f32 lbl_803DEFF0;
extern f32 lbl_803DF024;
extern f32 lbl_803DF028;
extern f32 lbl_803DF06C;
extern f32 init_803DF080;
extern f32 lbl_803DF088;
extern f32 lbl_803DF108;
extern f64 lbl_803DF130;
extern f32 lbl_803DF118;
extern f32 lbl_803DF138;
extern f32 lbl_803DF13C;
extern f32 lbl_803DF140;
extern f32 lbl_803DF144;
extern f32 lbl_803DF1A0;
extern f32 lbl_803DF1D8;
extern f32 lbl_803DF1DC;
extern u8 colorScale;
extern int lbl_803DB610;
extern s8 lbl_803DD180;
extern u8 *lbl_803DD184;
extern u8 *lbl_803DD188;
extern u8 lbl_803DD19B;
extern u8 *lbl_803DD19C;
extern u8 lbl_803DD1C0;
extern void PSVECNormalize(void *src, void *dst);

extern undefined4 ABS();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjMsg_SendToNearbyObjects();
extern undefined8 ObjMsg_SendToObjects();
extern undefined4 ObjMsg_SendToObject();
extern void fn_8005D108();
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern void trackIntersect_updateColorBandRange(double param_1,double param_2);
extern undefined4 PSVECDotProduct();
extern double SeekTwiceBeforeRead();
extern undefined4 __GXSendFlushPrim();
extern undefined4 GXSetBlendMode();
extern undefined4 fcos16Precise();
extern undefined4 sinf();
extern undefined4 SQRT();
extern uint countLeadingZeros();

extern undefined4 DAT_802c2700;
extern undefined4 DAT_802c2704;
extern undefined4 DAT_802c2708;
extern undefined4 DAT_802c270c;
extern undefined4 DAT_802c2710;
extern undefined4 DAT_802c2714;
extern undefined4 DAT_802c2718;
extern undefined4 DAT_802c271c;
extern undefined4 DAT_802c2720;
extern undefined4 DAT_802c2728;
extern undefined4 DAT_802c272c;
extern undefined4 DAT_802c2730;
extern undefined4 DAT_802c2734;
extern undefined4 DAT_802c2738;
extern undefined4 DAT_802c273c;
extern undefined4 DAT_802c2740;
extern undefined4 DAT_802c2744;
extern undefined4 DAT_802c2748;
extern undefined4 DAT_802c274c;
extern undefined4 DAT_802c2750;
extern undefined4 DAT_802c2754;
extern undefined4 DAT_802c2758;
extern undefined4 DAT_802c275c;
extern undefined4 DAT_802c2760;
extern undefined4 DAT_802c2764;
extern undefined4 DAT_802c2768;
extern undefined4 DAT_802c276c;
extern undefined4 DAT_802c2770;
extern undefined4 DAT_802c2774;
extern undefined4 DAT_802c2778;
extern undefined4 DAT_802c277c;
extern undefined4 DAT_802c2780;
extern undefined4 DAT_802c2784;
extern undefined4 DAT_802c2788;
extern undefined4 DAT_802c278c;
extern undefined4 DAT_802c2790;
extern undefined4 DAT_802c2794;
extern undefined4 DAT_802c2798;
extern undefined4 DAT_802c279c;
extern undefined4 DAT_802c27a0;
extern undefined4 DAT_802c27a4;
extern undefined4 DAT_802c27a8;
extern undefined4 DAT_802c27ac;
extern undefined4 DAT_802c27b0;
extern undefined4 DAT_802c27b4;
extern undefined4 DAT_802c27b8;
extern undefined4 DAT_802c27bc;
extern undefined4 DAT_802c27c0;
extern undefined4 DAT_802c27c4;
extern undefined4 DAT_802c27c8;
extern undefined4 DAT_802c27cc;
extern undefined4 DAT_802c27d0;
extern undefined4 DAT_802c27d4;
extern undefined4 DAT_802c27d8;
extern undefined4 DAT_802c27dc;
extern undefined4 DAT_802c27e0;
extern undefined4 DAT_802c27e4;
extern undefined4 DAT_802c27e8;
extern undefined4 DAT_802c27ec;
extern undefined4 DAT_802c27f0;
extern undefined4 DAT_802c27f4;
extern undefined4 DAT_802c27f8;
extern undefined4 DAT_802c27fc;
extern undefined4 DAT_802c2800;
extern undefined4 DAT_802c2804;
extern undefined4 DAT_802c2808;
extern undefined4 DAT_802c280c;
extern undefined4 DAT_802c2810;
extern undefined4 DAT_802c2814;
extern undefined4 DAT_802c2818;
extern undefined4 DAT_802c281c;
extern undefined4 DAT_802c2820;
extern undefined4 DAT_802c2824;
extern undefined4 DAT_802c2828;
extern undefined4 DAT_802c282c;
extern undefined4 DAT_802c2830;
extern undefined4 DAT_802c2834;
extern undefined4 DAT_802c2838;
extern undefined4 DAT_802c283c;
extern undefined4 DAT_802c2840;
extern undefined4 DAT_802c2844;
extern undefined4 DAT_802c2848;
extern undefined4 DAT_802c284c;
extern undefined4 DAT_802c2850;
extern undefined4 DAT_802c2854;
extern undefined4 DAT_802c2858;
extern undefined4 DAT_802c285c;
extern undefined4 DAT_802c2860;
extern undefined4 DAT_802c2864;
extern undefined4 DAT_802c2868;
extern undefined4 DAT_802c286c;
extern undefined4 DAT_802c2870;
extern undefined4 DAT_802c2874;
extern undefined4 DAT_802c2878;
extern undefined4 DAT_802c287c;
extern undefined4 DAT_802c2880;
extern undefined4 DAT_802c2884;
extern undefined4 DAT_802c2888;
extern undefined4 DAT_802c288c;
extern undefined4 DAT_802c2890;
extern undefined4 DAT_802c2894;
extern undefined4 DAT_802c2898;
extern undefined4 DAT_802c289c;
extern undefined4 DAT_802c28a0;
extern undefined4 DAT_802c28a4;
extern undefined4 DAT_802c28a8;
extern undefined4 DAT_802c28ac;
extern undefined4 DAT_802c28b0;
extern undefined4 DAT_802c28b4;
extern undefined4 DAT_802c28b8;
extern undefined4 DAT_802c28bc;
extern undefined4 DAT_802c28c0;
extern undefined4 DAT_802c28c4;
extern undefined4 DAT_802c28c8;
extern undefined4 DAT_802c28cc;
extern undefined4 DAT_802c28d0;
extern undefined4 DAT_802c28d4;
extern undefined4 DAT_802c28d8;
extern undefined4 DAT_802c28dc;
extern undefined4 DAT_8030f868;
extern undefined4 DAT_8030f890;
extern undefined4 DAT_8030f8b8;
extern undefined4 DAT_8030f964;
extern undefined4 DAT_8030f980;
extern undefined4 DAT_8030f9dc;
extern float* DAT_8030fe88;
extern undefined4 DAT_8030fe8c;
extern float* DAT_8030fe90;
extern float* DAT_8030fe94;
extern undefined4 DAT_8030fe98;
extern float* DAT_8030fe9c;
extern undefined4 DAT_8030fea0;
extern undefined4 DAT_8030feb4;
extern undefined4 DAT_8030fec8;
extern undefined4 DAT_8030fedc;
extern undefined4 DAT_8030fedd;
extern undefined4 DAT_8030fede;
extern undefined4 DAT_8030fedf;
extern undefined4 DAT_8030fee0;
extern undefined4 DAT_8030fee1;
extern byte DAT_80310060;
extern undefined4 DAT_803100f0;
extern undefined4 DAT_803100f4;
extern undefined4 DAT_80310118;
extern undefined4 DAT_8031011c;
extern undefined4 DAT_80310160;
extern undefined4 DAT_80310330;
extern undefined4 DAT_80310331;
extern undefined4 DAT_80310332;
extern undefined4 DAT_80310333;
extern undefined4 DAT_80310334;
extern undefined4 DAT_80310335;
extern undefined4 DAT_80310370;
extern undefined4 DAT_80310384;
extern undefined4 DAT_80310394;
extern undefined4 DAT_80310598;
extern undefined4 DAT_803105f0;
extern undefined4 DAT_803105f1;
extern undefined4 DAT_803105f2;
extern undefined DAT_80397578;
extern undefined4 DAT_8039757c;
extern undefined4 DAT_80397580;
extern undefined4 DAT_80397588;
extern undefined4 DAT_80397590;
extern undefined4 DAT_80397598;
extern undefined4 DAT_803975a0;
extern undefined4 DAT_803975a8;
extern undefined4 DAT_803975b0;
extern undefined4 DAT_803975b8;
extern short DAT_80399ff8;
extern undefined4 DAT_80399ffa;
extern undefined4 DAT_80399ffc;
extern undefined4 DAT_8039a0ac;
extern undefined4 DAT_8039a0b0;
extern undefined4 DAT_8039a0b2;
extern undefined4 DAT_8039a14c;
extern undefined4 DAT_8039a150;
extern undefined4 DAT_8039a154;
extern undefined4 DAT_8039a158;
extern undefined4 DAT_8039a208;
extern undefined4 DAT_8039a4b0;
extern undefined4 DAT_8039a8ac;
extern char DAT_8039a904;
extern undefined DAT_8039a90c;
extern undefined4 DAT_8039a95c;
extern byte DAT_8039aab0;
extern undefined DAT_8039ab08;
extern undefined4 DAT_8039ab60;
extern undefined4 DAT_8039ac0c;
extern undefined4 DAT_8039acb8;
extern undefined4 DAT_8039ae0c;
extern undefined DAT_8039af60;
extern undefined DAT_8039afb8;
extern undefined2 DAT_8039b010;
extern undefined DAT_8039b0bc;
extern undefined DAT_8039b114;
extern char DAT_8039b16c;
extern char DAT_8039b1c4;
extern undefined4 DAT_8039b21c;
extern undefined4 DAT_8039b220;
extern undefined4 DAT_8039b222;
extern undefined4 DAT_8039b26c;
extern undefined4 DAT_8039b2c4;
extern undefined4 DAT_8039b2c8;
extern float* DAT_8039b408;
extern undefined4 DAT_8039b40c;
extern undefined4 DAT_8039b410;
extern undefined4 DAT_8039b418;
extern undefined4 DAT_8039b41c;
extern undefined4 DAT_8039b420;
extern undefined4 DAT_8039b424;
extern undefined4 DAT_8039b428;
extern undefined4 DAT_8039b42c;
extern undefined4 DAT_8039b430;
extern undefined4 DAT_8039b434;
extern undefined4 DAT_8039b438;
extern undefined4 DAT_8039b43c;
extern undefined4 DAT_8039b440;
extern undefined4 DAT_8039b444;
extern undefined4 DAT_8039b448;
extern undefined4 DAT_8039b44c;
extern undefined4 DAT_8039b450;
extern undefined4 DAT_8039b454;
extern undefined4 DAT_8039b458;
extern undefined4 DAT_8039b45c;
extern undefined4 DAT_8039b460;
extern undefined4 DAT_8039b464;
extern undefined4 DAT_8039b468;
extern undefined4 DAT_8039b46c;
extern undefined4 DAT_8039b470;
extern undefined4 DAT_8039b474;
extern int DAT_8039b478;
extern undefined4 DAT_8039b47c;
extern undefined4 DAT_8039b480;
extern undefined4 DAT_8039b484;
extern int DAT_8039b488;
extern undefined4 DAT_8039b48c;
extern undefined4 DAT_8039b490;
extern undefined4 DAT_8039b494;
extern undefined4 DAT_8039b498;
extern undefined4 DAT_8039b49c;
extern undefined4 DAT_8039b4a0;
extern undefined4 DAT_8039b4a4;
extern uint DAT_8039b4a8;
extern undefined4 DAT_8039b4ac;
extern float* DAT_8039b4b0;
extern float* DAT_8039b4b4;
extern float* DAT_8039b4b8;
extern float* DAT_8039b4bc;
extern undefined4 DAT_8039b4c0;
extern undefined4 DAT_8039b4c4;
extern undefined4 DAT_8039b4c8;
extern float* DAT_8039b4cc;
extern float* DAT_8039b4d0;
extern float* DAT_8039b4d4;
extern float* DAT_8039b4d8;
extern undefined4 DAT_8039b4dc;
extern undefined4 DAT_8039b4e0;
extern undefined4 DAT_8039b4e4;
extern float* DAT_8039b4e8;
extern float* DAT_8039b4ec;
extern float* DAT_8039b4f0;
extern float* DAT_8039b4f4;
extern undefined4 DAT_8039b4f8;
extern undefined4 DAT_8039b4fc;
extern undefined4 DAT_8039b500;
extern float* DAT_8039b504;
extern float* DAT_8039b508;
extern float* DAT_8039b50c;
extern float* DAT_8039b510;
extern undefined4 DAT_8039b514;
extern undefined4 DAT_8039b518;
extern undefined4 DAT_8039b51c;
extern float* DAT_8039b520;
extern float* DAT_8039b524;
extern float* DAT_8039b528;
extern float* DAT_8039b52c;
extern undefined4 DAT_8039b530;
extern undefined4 DAT_8039b534;
extern undefined4 DAT_8039b538;
extern float* DAT_8039b53c;
extern float* DAT_8039b540;
extern float* DAT_8039b544;
extern float* DAT_8039b548;
extern undefined4 DAT_8039b54c;
extern float* DAT_8039b550;
extern float* DAT_8039b554;
extern float* DAT_8039b558;
extern ushort DAT_8039b560;
extern uint DAT_8039b618;
extern undefined4 DAT_8039b788;
extern undefined4 DAT_8039b78c;
extern undefined4 DAT_8039b790;
extern undefined4 DAT_8039b794;
extern undefined4 DAT_8039b798;
extern undefined4 DAT_8039b79c;
extern undefined4 DAT_8039b7a0;
extern undefined4 DAT_8039b7a1;
extern undefined4 DAT_8039b7a2;
extern undefined4 DAT_8039b7a8;
extern undefined4 DAT_8039b7ac;
extern undefined4 DAT_8039b7b0;
extern int DAT_8039b7b8;
extern undefined4 DAT_8039b7bc;
extern undefined4 DAT_8039b7c0;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc071;
extern undefined4 DAT_803dc270;
extern undefined4 DAT_803dc278;
extern undefined4 DAT_803dc294;
extern undefined4 DAT_803dc374;
extern undefined4 DAT_803dc378;
extern undefined4 DAT_803dc37c;
extern undefined4 DAT_803dc380;
extern undefined4 DAT_803dc384;
extern undefined4 DAT_803dc388;
extern undefined4 DAT_803dc38c;
extern undefined4 DAT_803dc3a8;
extern undefined4 DAT_803dc3b0;
extern undefined4 DAT_803dc3b4;
extern undefined4 DAT_803dc3b8;
extern undefined4 DAT_803dc3cc;
extern undefined4 DAT_803dc3d0;
extern undefined4 DAT_803dc3d8;
extern undefined4 DAT_803dc3e8;
extern undefined4 DAT_803dd5d0;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6dc;
extern undefined4* DAT_803dd6e4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd734;
extern undefined4 DAT_803ddce0;
extern undefined4 DAT_803ddce2;
extern undefined4 DAT_803ddce4;
extern undefined4 DAT_803ddce8;
extern undefined4 DAT_803ddcec;
extern undefined4 DAT_803ddcee;
extern undefined4 DAT_803ddcf0;
extern undefined4 DAT_803ddcf8;
extern uint* DAT_803ddcfc;
extern undefined4 DAT_803ddd00;
extern undefined4 DAT_803ddd08;
extern undefined4 DAT_803ddd0a;
extern undefined4 DAT_803ddd0c;
extern undefined4 DAT_803ddd10;
extern undefined4 DAT_803ddd18;
extern undefined4 DAT_803ddd1c;
extern undefined4 DAT_803ddd20;
extern undefined4 DAT_803ddd34;
extern undefined4 DAT_803ddd36;
extern undefined4* DAT_803ddd38;
extern undefined4 DAT_803ddd3c;
extern undefined4 DAT_803ddd40;
extern undefined4* DAT_803ddd54;
extern undefined4 DAT_803ddd58;
extern undefined4 DAT_803ddd59;
extern undefined4 DAT_803ddd5a;
extern undefined4 DAT_803ddd78;
extern undefined4 DAT_803ddd80;
extern undefined4 DAT_803ddd84;
extern undefined4 DAT_803ddd88;
extern undefined4 DAT_803ddd8c;
extern undefined4 DAT_803ddd90;
extern undefined4 DAT_803ddd91;
extern undefined4 DAT_803ddd92;
extern undefined4 DAT_803ddd93;
extern undefined4 DAT_803ddd94;
extern undefined4 DAT_803ddd96;
extern undefined4 DAT_803ddda4;
extern undefined4 DAT_803ddda8;
extern undefined4 DAT_803dddaa;
extern int* DAT_803dddac;
extern undefined4 DAT_803dddb0;
extern undefined4 DAT_803dddb4;
extern undefined4 DAT_803dddb8;
extern undefined4 DAT_803dddbc;
extern undefined4 DAT_803dddc0;
extern undefined4 DAT_803dddc4;
extern undefined4* DAT_803dddc8;
extern undefined4* DAT_803dddcc;
extern undefined4 DAT_803dddd0;
extern undefined4 DAT_803dddd4;
extern undefined4 DAT_803dddd8;
extern undefined4 DAT_803ddddc;
extern undefined4 DAT_803ddde4;
extern undefined4 DAT_803ddde8;
extern undefined4 DAT_803dddec;
extern undefined4 DAT_803dddf0;
extern undefined4 DAT_803dddf4;
extern undefined4 DAT_803dddf8;
extern undefined4 DAT_803dde00;
extern int DAT_803dde04;
extern undefined4 DAT_803dde18;
extern undefined4 DAT_803dde19;
extern undefined4 DAT_803dde1a;
extern undefined4 DAT_803dde1b;
extern undefined4* DAT_803dde1c;
extern undefined4 DAT_803dde20;
extern undefined4 DAT_803dde24;
extern undefined4 DAT_803dde28;
extern undefined4 DAT_803dde40;
extern undefined4 DAT_803dde44;
extern undefined4 DAT_803dde48;
extern undefined4 DAT_803dde4c;
extern undefined4 DAT_803dde50;
extern undefined4 DAT_803dde54;
extern undefined4 DAT_803dde58;
extern undefined4 DAT_803dde6c;
extern undefined4 DAT_803dde70;
extern undefined4 DAT_803dde78;
extern undefined4 DAT_803dde7c;
extern undefined4 DAT_803dde80;
extern undefined4 DAT_803dde84;
extern undefined4 DAT_803dde88;
extern undefined4 DAT_803dde90;
extern undefined4 DAT_803dde94;
extern undefined4 DAT_803dde98;
extern undefined4 DAT_803dde9c;
extern undefined4 DAT_803ddea0;
extern undefined4 DAT_803ddea4;
extern undefined4 DAT_803ddea8;
extern undefined4 DAT_803ddeac;
extern undefined4 DAT_803ddeb0;
extern undefined4 DAT_803ddeb4;
extern undefined4 DAT_803ddeb8;
extern undefined4 DAT_803ddebc;
extern undefined4 DAT_803ddec0;
extern undefined4 DAT_803ddec4;
extern undefined4 DAT_803ddec8;
extern undefined4 DAT_803ddecc;
extern undefined4 DAT_803dded8;
extern undefined4 DAT_803dfe18;
extern undefined4 DAT_803dfe1c;
extern undefined4 DAT_803dffc0;
extern undefined4 DAT_803dffc4;
extern undefined4 DAT_803e90d8;
extern undefined4 DAT_803e90e0;
extern undefined4 DAT_803e90e2;
extern float* DAT_cc008000;
extern f64 DOUBLE_803dfc38;
extern f64 DOUBLE_803dfc60;
extern f64 DOUBLE_803dfcf0;
extern f64 DOUBLE_803dfd10;
extern f64 DOUBLE_803dfda8;
extern f64 DOUBLE_803dfdb0;
extern f64 DOUBLE_803dfe28;
extern f64 DOUBLE_803dfe30;
extern f64 DOUBLE_803dfe98;
extern f64 DOUBLE_803dfea0;
extern f64 DOUBLE_803dff28;
extern f64 DOUBLE_803dff38;
extern f64 DOUBLE_803dff88;
extern f64 DOUBLE_803dffe0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc370;
extern f32 FLOAT_803dc390;
extern f32 FLOAT_803dc3c0;
extern f32 FLOAT_803dc3c4;
extern f32 FLOAT_803dc3c8;
extern f32 FLOAT_803dc3e0;
extern f32 FLOAT_803dc3f0;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803ddcf4;
extern f32 FLOAT_803ddd24;
extern f32 FLOAT_803ddd28;
extern f32 FLOAT_803ddd2c;
extern f32 FLOAT_803ddd30;
extern f32 FLOAT_803ddd44;
extern f32 FLOAT_803ddd48;
extern f32 FLOAT_803ddd4c;
extern f32 FLOAT_803ddd50;
extern f32 FLOAT_803ddd5c;
extern f32 FLOAT_803ddd6c;
extern f32 FLOAT_803ddd70;
extern f32 FLOAT_803ddd74;
extern f32 FLOAT_803ddd98;
extern f32 FLOAT_803ddd9c;
extern f32 FLOAT_803ddda0;
extern f32 FLOAT_803ddde0;
extern f32 FLOAT_803dde10;
extern f32 FLOAT_803dde14;
extern f32 FLOAT_803dde2c;
extern f32 FLOAT_803dde30;
extern f32 FLOAT_803dde34;
extern f32 FLOAT_803dde38;
extern f32 FLOAT_803dde3c;
extern f32 FLOAT_803dde60;
extern f32 FLOAT_803dde64;
extern f32 FLOAT_803dde68;
extern f32 FLOAT_803dde8c;
extern f32 FLOAT_803ddedc;
extern f32 FLOAT_803ddee0;
extern f32 FLOAT_803dfc30;
extern f32 FLOAT_803dfc48;
extern f32 FLOAT_803dfc68;
extern f32 FLOAT_803dfc70;
extern f32 FLOAT_803dfc74;
extern f32 FLOAT_803dfc78;
extern f32 FLOAT_803dfc7c;
extern f32 FLOAT_803dfc80;
extern f32 FLOAT_803dfc84;
extern f32 FLOAT_803dfc88;
extern f32 FLOAT_803dfc8c;
extern f32 FLOAT_803dfc90;
extern f32 FLOAT_803dfc94;
extern f32 FLOAT_803dfc98;
extern f32 FLOAT_803dfc9c;
extern f32 FLOAT_803dfca0;
extern f32 FLOAT_803dfca4;
extern f32 FLOAT_803dfca8;
extern f32 FLOAT_803dfcac;
extern f32 FLOAT_803dfcb0;
extern f32 FLOAT_803dfcb4;
extern f32 FLOAT_803dfcb8;
extern f32 FLOAT_803dfcbc;
extern f32 FLOAT_803dfcc0;
extern f32 FLOAT_803dfcc4;
extern f32 FLOAT_803dfcc8;
extern f32 FLOAT_803dfccc;
extern f32 FLOAT_803dfcd0;
extern f32 FLOAT_803dfcd4;
extern f32 FLOAT_803dfcd8;
extern f32 FLOAT_803dfcdc;
extern f32 FLOAT_803dfce0;
extern f32 FLOAT_803dfce4;
extern f32 FLOAT_803dfce8;
extern f32 FLOAT_803dfcec;
extern f32 FLOAT_803dfcf8;
extern f32 FLOAT_803dfcfc;
extern f32 FLOAT_803dfd00;
extern f32 FLOAT_803dfd04;
extern f32 FLOAT_803dfd08;
extern f32 FLOAT_803dfd18;
extern f32 FLOAT_803dfd1c;
extern f32 FLOAT_803dfd20;
extern f32 FLOAT_803dfd24;
extern f32 FLOAT_803dfd28;
extern f32 FLOAT_803dfd2c;
extern f32 FLOAT_803dfd30;
extern f32 FLOAT_803dfd34;
extern f32 FLOAT_803dfd38;
extern f32 FLOAT_803dfd3c;
extern f32 FLOAT_803dfd40;
extern f32 FLOAT_803dfd44;
extern f32 FLOAT_803dfd48;
extern f32 FLOAT_803dfd4c;
extern f32 FLOAT_803dfd50;
extern f32 FLOAT_803dfd54;
extern f32 FLOAT_803dfd58;
extern f32 FLOAT_803dfd5c;
extern f32 FLOAT_803dfd64;
extern f32 FLOAT_803dfd68;
extern f32 FLOAT_803dfd6c;
extern f32 FLOAT_803dfd70;
extern f32 FLOAT_803dfd74;
extern f32 FLOAT_803dfd78;
extern f32 FLOAT_803dfd7c;
extern f32 FLOAT_803dfd80;
extern f32 FLOAT_803dfd84;
extern f32 FLOAT_803dfd88;
extern f32 FLOAT_803dfd8c;
extern f32 FLOAT_803dfd90;
extern f32 FLOAT_803dfd94;
extern f32 FLOAT_803dfd98;
extern f32 FLOAT_803dfd9c;
extern f32 FLOAT_803dfda0;
extern f32 FLOAT_803dfdb8;
extern f32 FLOAT_803dfdbc;
extern f32 FLOAT_803dfdc0;
extern f32 FLOAT_803dfdc4;
extern f32 FLOAT_803dfdc8;
extern f32 FLOAT_803dfdcc;
extern f32 FLOAT_803dfdd0;
extern f32 FLOAT_803dfdd4;
extern f32 FLOAT_803dfdd8;
extern f32 FLOAT_803dfddc;
extern f32 FLOAT_803dfde0;
extern f32 FLOAT_803dfde4;
extern f32 FLOAT_803dfde8;
extern f32 FLOAT_803dfdec;
extern f32 FLOAT_803dfdf0;
extern f32 FLOAT_803dfdf4;
extern f32 FLOAT_803dfdf8;
extern f32 FLOAT_803dfdfc;
extern f32 FLOAT_803dfe00;
extern f32 FLOAT_803dfe04;
extern f32 FLOAT_803dfe08;
extern f32 FLOAT_803dfe0c;
extern f32 FLOAT_803dfe10;
extern f32 FLOAT_803dfe14;
extern f32 FLOAT_803dfe20;
extern f32 FLOAT_803dfe24;
extern f32 FLOAT_803dfe38;
extern f32 FLOAT_803dfe3c;
extern f32 FLOAT_803dfe40;
extern f32 FLOAT_803dfe44;
extern f32 FLOAT_803dfe48;
extern f32 FLOAT_803dfe4c;
extern f32 FLOAT_803dfe50;
extern f32 FLOAT_803dfe54;
extern f32 FLOAT_803dfe58;
extern f32 FLOAT_803dfe5c;
extern f32 FLOAT_803dfe60;
extern f32 FLOAT_803dfe64;
extern f32 FLOAT_803dfe68;
extern f32 FLOAT_803dfe6c;
extern f32 FLOAT_803dfe78;
extern f32 FLOAT_803dfe7c;
extern f32 FLOAT_803dfe80;
extern f32 FLOAT_803dfe88;
extern f32 FLOAT_803dfe8c;
extern f32 FLOAT_803dfe90;
extern f32 FLOAT_803dfe94;
extern f32 FLOAT_803dfea8;
extern f32 FLOAT_803dfeac;
extern f32 FLOAT_803dfeb0;
extern f32 FLOAT_803dfeb4;
extern f32 FLOAT_803dfeb8;
extern f32 FLOAT_803dfebc;
extern f32 FLOAT_803dfec0;
extern f32 FLOAT_803dfec4;
extern f32 FLOAT_803dfec8;
extern f32 FLOAT_803dfecc;
extern f32 FLOAT_803dfed0;
extern f32 FLOAT_803dfed4;
extern f32 FLOAT_803dfed8;
extern f32 FLOAT_803dfedc;
extern f32 FLOAT_803dfee0;
extern f32 FLOAT_803dfee4;
extern f32 FLOAT_803dfee8;
extern f32 FLOAT_803dfeec;
extern f32 FLOAT_803dfef0;
extern f32 FLOAT_803dfef4;
extern f32 FLOAT_803dfef8;
extern f32 FLOAT_803dfefc;
extern f32 FLOAT_803dff00;
extern f32 FLOAT_803dff04;
extern f32 FLOAT_803dff08;
extern f32 FLOAT_803dff0c;
extern f32 FLOAT_803dff10;
extern f32 FLOAT_803dff14;
extern f32 FLOAT_803dff18;
extern f32 FLOAT_803dff1c;
extern f32 FLOAT_803dff20;
extern f32 FLOAT_803dff24;
extern f32 FLOAT_803dff30;
extern f32 FLOAT_803dff34;
extern f32 FLOAT_803dff40;
extern f32 FLOAT_803dff44;
extern f32 FLOAT_803dff48;
extern f32 FLOAT_803dff4c;
extern f32 FLOAT_803dff50;
extern f32 FLOAT_803dff54;
extern f32 FLOAT_803dff58;
extern f32 FLOAT_803dff5c;
extern f32 FLOAT_803dff60;
extern f32 FLOAT_803dff64;
extern f32 FLOAT_803dff68;
extern f32 FLOAT_803dff6c;
extern f32 FLOAT_803dff70;
extern f32 FLOAT_803dff74;
extern f32 FLOAT_803dff78;
extern f32 FLOAT_803dff7c;
extern f32 FLOAT_803dff80;
extern f32 FLOAT_803dff84;
extern f32 FLOAT_803dff94;
extern f32 FLOAT_803dff98;
extern f32 FLOAT_803dff9c;
extern f32 FLOAT_803dffa0;
extern f32 FLOAT_803dffa4;
extern f32 FLOAT_803dffa8;
extern f32 FLOAT_803dffac;
extern f32 FLOAT_803dffb0;
extern f32 FLOAT_803dffb4;
extern f32 FLOAT_803dffb8;
extern f32 FLOAT_803dffbc;
extern f32 FLOAT_803dffc8;
extern f32 FLOAT_803dffcc;
extern f32 FLOAT_803dffd0;
extern f32 FLOAT_803dffd4;
extern f32 FLOAT_803dffd8;
extern f32 FLOAT_803dffdc;
extern f32 FLOAT_803dffe8;
extern f32 FLOAT_803e0000;
extern f32 FLOAT_803e0004;
extern f32 FLOAT_803e0008;
extern f32 FLOAT_803e000c;
extern f32 FLOAT_803e0010;
extern f32 FLOAT_803e0014;
extern f32 FLOAT_803e0018;
extern f32 FLOAT_803e001c;
extern f32 FLOAT_803e0020;
extern f32 FLOAT_803e0024;
extern f32 FLOAT_803e0028;
extern f32 FLOAT_803e002c;
extern f32 FLOAT_803e0030;
extern int iRam803dc274;
extern char s_Could_not_allocate_memory_for_wa_8031042c[];
extern char s_____Error_non_existant_cloud_id___803101b0[];
extern char s_____Error_non_existant_cloud_id___803101f0[];
extern char s_____Error_non_existant_cloud_id___80310230[];
extern char s_____Error_non_existant_cloud_id___803102f0[];
extern char s_endObjSequence__max_number_of_ob_8030fa94[];
extern char s_warning_in_newcloud_dll_no_spare_80310270[];
extern char s_warning_in_newclouds_dll_no_spar_803102b0[];
extern undefined4 uRam803dc274;
extern undefined4 uRam803dc27c;
extern undefined uRam803dc3a9;
extern undefined2 uRam803dc3aa;
extern undefined uRam803dc3ab;
extern undefined uRam803dddd9;
extern undefined2 uRam803dddda;
extern undefined uRam803dddf1;
extern undefined2 uRam803dddf2;
extern undefined uRam803dddf5;
extern undefined2 uRam803dddf6;
extern undefined uRam803dddf9;
extern undefined2 uRam803dddfa;
extern undefined4 uRam803dde08;

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

extern u8 lbl_803DD16C;
extern void getEnvfxActImmediately(void *obj, void *target, int effectId, int flags);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

void lightningRenderActive(void)
{
    if (lbl_803DD19C != NULL) {
        lightningRender(lbl_803DD19C);
    }
}

void snowCloudBuildBoxVerts(f32 *out, f32 height, f32 scale)
{
    f32 side;
    f32 zero;
    f32 scaledHeight;
    f32 edge;

    side = lbl_803DF1D8 * scale;
    out[0] = side;
    zero = lbl_803DF1A0;
    out[1] = zero;
    out[2] = side;
    out[3] = side;
    scaledHeight = height * scale;
    out[4] = scaledHeight;
    out[5] = side;
    edge = lbl_803DF1DC * scale;
    out[6] = edge;
    out[7] = scaledHeight;
    out[8] = side;
    out[9] = edge;
    out[10] = zero;
    out[11] = side;
    out[12] = side;
    out[13] = zero;
    out[14] = edge;
    out[15] = side;
    out[16] = scaledHeight;
    out[17] = edge;
    out[18] = edge;
    out[19] = scaledHeight;
    out[20] = edge;
    out[21] = edge;
    out[22] = zero;
    out[23] = edge;
}

void mm_free_(void *ptr)
{
    mm_free(ptr);
}

void dll_07_func09(void)
{
    Camera_GetCurrentViewSlot();
    randomGetRange(5, 5);
}

int dll_07_func08(void)
{
    return lbl_803DD19B;
}

void newclouds_initialise(void)
{
    lbl_803DD1C0 = 0;
}

#pragma pop

/* Pattern wrappers. */
void dll_07_func0A_nop(void) {}

extern u8 lbl_803DD1EC;
extern f32 lbl_803DD1E8;
extern f32 lbl_803DD1E4;
extern f32 lbl_803DD1E0;

void cloudClearOverridePosition(void) {
    lbl_803DD1EC = 0;
}

#pragma push
#pragma scheduling off
void cloudSetOverridePosition(f32 a, f32 b, f32 c) {
    lbl_803DD1EC = 1;
    lbl_803DD1E8 = a;
    lbl_803DD1E4 = b;
    lbl_803DD1E0 = c;
}
#pragma pop

extern void padUpdate(void);
extern void checkReset(void);
void skyFn_80088c94(int flags, int mode);
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
extern u8 lbl_803DC950;
extern f32 lbl_8030F2C8[];
extern f32 lbl_8030F2D4[];
void skyFn_80088e54(int mode, f32 brightness);
void fn_8008BDA8(void);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

extern void textureFree(void *handle);
extern void ModelLightStruct_free(void *p);
extern void Music_Trigger(int id, int restart);
extern void *lbl_8039A818[];
extern void *lbl_8039A828[];
extern void *lbl_803DD1C8;
extern void *lbl_803DD1C4;
extern void *lbl_803DD1A0;
extern u8 lbl_803DD1C0;
extern f32 lbl_803DF1A0;
extern f32 lbl_803DF1A4;
extern f32 lbl_803DB760;
extern f32 lbl_803DB764;
extern f32 lbl_803DB768;
extern f32 lbl_803DD1BC;
extern f32 lbl_803DD1B8;
extern f32 lbl_803DD1B4;
extern f32 lbl_803DD190;
extern f32 lbl_803DD194;
extern u8 lbl_803DD198;
extern u8 lbl_803DD199;
extern u8 lbl_803DD19A;
extern u8 lbl_803DD1CC;
void snowFreeSnowCloud(int index);

#pragma push
#pragma scheduling off
void newclouds_release(void) {
    int i;

    if (lbl_803DD1C8 != NULL) {
        textureFree(lbl_803DD1C8);
        lbl_803DD1C8 = NULL;
    }
    for (i = 0; i < 4; i++) {
        if (lbl_8039A818[i] != NULL) {
            textureFree(lbl_8039A818[i]);
            lbl_8039A818[i] = NULL;
        }
    }
    if (lbl_803DD1C4 != NULL) {
        textureFree(lbl_803DD1C4);
        lbl_803DD1C4 = NULL;
    }
    if (lbl_803DD1A0 != NULL) {
        ModelLightStruct_free(lbl_803DD1A0);
    }
    lbl_803DD1C0 = 0;
}
#pragma pop

#pragma push
#pragma scheduling off
void newclouds_onMapSetup(void) {
    int i;
    f32 a;
    f32 b;

    for (i = 0; i < 8; i++) {
        if (lbl_8039A828[i] != NULL) {
            snowFreeSnowCloud(i);
        }
        lbl_8039A828[i] = NULL;
    }
    a = lbl_803DF1A0;
    lbl_803DD1BC = a;
    lbl_803DD1B8 = a;
    lbl_803DD1B4 = a;
    lbl_803DD190 = a;
    b = lbl_803DF1A4;
    lbl_803DB760 = b;
    lbl_803DD194 = a;
    lbl_803DD198 = 0;
    lbl_803DB764 = b;
    lbl_803DD199 = 0;
    lbl_803DD19A = 0;
    lbl_803DB768 = b;
    lbl_803DD1CC = 0;
    Music_Trigger(235, 0);
}
#pragma pop

extern void fn_8005D0BC(int unused, int a, int b, int c, int d);
extern void fogFn_80070404(f32 a, f32 b);
extern void setTextColor(int unused, int a, int b, int c, int d);
extern f32 lbl_803DF14C;
extern f32 lbl_803DF108;
extern f32 lbl_803DF148;
extern f32 lbl_803DF118;
extern s8 lbl_803DB750;

#pragma push
#pragma scheduling off
#pragma peephole off

extern void Obj_SetModelColorOverrideRecursive(int obj, int r, int g, int b, int a, int flag);

#pragma pop

#pragma push
#pragma scheduling off
#pragma dont_inline on
void *lightningCreate(f32 *a, f32 *b, f32 c, f32 d, int e, int f, int g) {
    u8 *p = mmAlloc(40, 23, 0);

    if (p == NULL) {
        return NULL;
    }
    *(f32 *)(p + 0) = a[0];
    *(f32 *)(p + 4) = a[1];
    *(f32 *)(p + 8) = a[2];
    *(f32 *)(p + 0xc) = b[0];
    *(f32 *)(p + 0x10) = b[1];
    *(f32 *)(p + 0x14) = b[2];
    *(f32 *)(p + 0x18) = c;
    *(f32 *)(p + 0x1c) = d;
    *(s16 *)(p + 0x22) = e;
    *(u8 *)(p + 0x26) = f;
    *(s16 *)(p + 0x20) = 0;
    *(u16 *)(p + 0x24) = 0xFFFF;
    *(u8 *)(p + 0x27) = g;
    return p;
}
#pragma dont_inline reset
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

extern void **gRomCurveInterface;
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
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
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

typedef struct ObjCurveKey {
    f32 value;
    s8 tangentAndMode;
    u8 pad05;
    s16 frame;
} ObjCurveKey;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

extern void getEnvfxActImmediately(void *obj, void *target, int effectId, int flags);

#pragma push
#pragma scheduling off
#pragma peephole off
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
#pragma scheduling off
#pragma peephole off
#pragma pop

typedef struct FogColor {
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} FogColor;

extern void GXSetFog(int type, f32 startz, f32 endz, f32 nearz, f32 farz, FogColor color);
extern int snowPrintSnowCloud(int arg, int x);
extern void drawFn_80079e64(double s1, double s2, double s3, u8 mtxIdx, void *vec, u8 a0, u8 a1);
extern f32 lbl_8039A8F0[];
extern int lbl_803DF198;

#pragma push
#pragma scheduling off
void dll_07_func07(int arg) {
    int i;
    int total;
    u8 *snow;

    GXSetFog(0, lbl_803DF1A0, lbl_803DF1A0, lbl_803DF1A0, lbl_803DF1A0,
             *(FogColor *)&lbl_803DF198);
    total = 0;
    for (i = 0; i < 8; i++) {
        snow = (u8 *)lbl_8039A828[i];
        if (snow != NULL && snow[0x144F] == 0) {
            total += snowPrintSnowCloud(arg, *(int *)(snow + 0x13F0));
        }
    }
    if (lbl_803DD198 != 0) {
        drawFn_80079e64(lbl_803DD190, lbl_803DB764, lbl_803DB768, lbl_803DD198,
                        lbl_8039A8F0, lbl_803DD199, lbl_803DD19A);
    }
}
#pragma pop

extern char sSnowKillSnowCloudInvalidCloudId[];
extern void debugPrintf(char *fmt, ...);

#pragma push
#pragma scheduling off
void newclouds_snowKillSnowCloud(int cloudId, int flag)
{
    void *p;
    int i;

    if (flag == 0) {
        if (cloudId == -1) {
            for (i = 0; i < 8; i++) {
                snowFreeSnowCloud(i);
            }
        } else {
            snowFreeSnowCloud(cloudId);
        }
        return;
    }
    for (i = 0; i < 8; i++) {
        p = lbl_8039A828[i];
        if (p != NULL && cloudId == *(int *)((char *)p + 0x13f0)) {
            break;
        }
    }
    p = lbl_8039A828[i];
    if (p == NULL) {
        return;
    }
    if (i == 8) {
        return;
    }
    if (cloudId != *(int *)((char *)p + 0x13f0)) {
        debugPrintf(sSnowKillSnowCloudInvalidCloudId, cloudId);
        return;
    }
    *(int *)((char *)p + 0x13f8) = 1;
    p = lbl_8039A828[i];
    *(f32 *)((char *)p + 0x1430) =
        -((f32)flag / (f32)*(int *)((char *)p + 0x13fc));
}
#pragma pop

extern int ObjModel_GetRenderOp(int model, int x);
extern int Shader_getLayer(int renderOp, int x);
extern int *objFindTexture(int obj, int idx, int p3);
extern void *textureIdxToPtr(int idx);
extern void *lbl_8039AB28[];
extern f32 lbl_803DF2B0;
extern f32 lbl_803DF2B4;

#pragma push
#pragma scheduling off
void *cloudGetLayerTextureSize(f32 *out1, f32 *out2) {
    int *tex;
    int *layer;

    if (lbl_8039AB28[0] != NULL) {
        layer = (int *)Shader_getLayer(
            ObjModel_GetRenderOp(*(int *)Obj_GetActiveModel(lbl_8039AB28[0]), 0), 0);
        tex = objFindTexture((int)lbl_8039AB28[0], 0, 0);
        if (tex != NULL) {
            f32 scale = lbl_803DF2B0;
            *out1 = scale * (f32) * (s16 *)((char *)tex + 8);
            *out2 = scale * (f32) * (s16 *)((char *)tex + 10);
        } else {
            f32 d = lbl_803DF2B4;
            *out1 = d;
            *out2 = d;
        }
        return textureIdxToPtr(*layer);
    }
    {
        f32 d = lbl_803DF2B4;
        *out1 = d;
        *out2 = d;
    }
    return NULL;
}
#pragma pop

extern void *memset(void *dst, int c, int n);
extern int lbl_803DB754;
extern f32 lbl_803DF190;
extern f32 lbl_803DF194;

#pragma push
#pragma scheduling off
#pragma pop

extern u8 *saveGameGetEnvState(void);
extern int getSaveGameLoadStatus(void);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

extern char sSnowFreeSnowCloudInvalidCloudId[];
extern void mm_free(void *p);

/*
 * --INFO--
 *
 * Function: snowFreeSnowCloud
 * EN v1.0 Address: 0x80090098
 * EN v1.0 Size: 504b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void snowFreeSnowCloud(int cloudId) {
    u8 *env;
    u8 *p;
    int i;

    env = saveGameGetEnvState();
    if (cloudId >= 0 && cloudId <= 2 && getSaveGameLoadStatus() == 0) {
        *(s16 *)(env + cloudId * 2 + 0xe) = -1;
        env[cloudId + 0x41] = -1;
    }
    for (i = 0; i < 8; i++) {
        p = lbl_8039A828[i];
        if (p != NULL && cloudId == *(int *)(p + 0x13f0)) {
            break;
        }
    }
    p = lbl_8039A828[i];
    if (p == NULL) {
        return;
    }
    if (i == 8) {
        return;
    }
    if (cloudId != *(int *)(p + 0x13f0)) {
        debugPrintf(sSnowFreeSnowCloudInvalidCloudId, cloudId);
        return;
    }
    if (*(u8 **)(p + 4) != NULL) {
        mm_free(*(u8 **)(p + 4));
        *(u8 **)((u8 *)lbl_8039A828[i] + 4) = NULL;
    }
    if (lbl_8039A828[i] != NULL) {
        mm_free(lbl_8039A828[i]);
        lbl_8039A828[i] = NULL;
    }
}
#pragma dont_inline reset
#pragma pop

extern inline float sqrtf__inline(float x) {
    static const double _half = .5;
    static const double _three = 3.0;
    volatile float y;
    if (x > 0.0f) {
        double guess = __frsqrte((double)x);
        guess = _half * guess * (_three - guess * guess * x);
        guess = _half * guess * (_three - guess * guess * x);
        guess = _half * guess * (_three - guess * guess * x);
        y = (float)(x * guess);
        return y;
    }
    return x;
}

typedef struct WindSource {
    s32 x;
    s32 z;
    f32 vx;
    f32 vy;
    f32 vz;
    f32 scale;
    s16 flag;
    s16 pad1a;
} WindSource;

extern WindSource lbl_8039A848[];
extern s16 renderModeSetOrGet(int mode);
extern void normalize(f32 *x, f32 *y, f32 *z);
extern f32 lbl_803DF1A4;
extern f32 lbl_803DF1DC;

/*
 * --INFO--
 *
 * Function: snowCloudComputeDrift
 * EN v1.0 Address: 0x800916C0
 * EN v1.0 Size: 776b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void snowCloudComputeDrift(f32 *out, f32 *pos, f32 scale) {
    f32 accX;
    f32 accZ;
    f32 dx;
    f32 dz;
    f32 dSq;
    f32 dists[6];
    int i;

    if (renderModeSetOrGet(-1) == 1) {
        return;
    }
    accX = 0.0f;
    accZ = 0.0f;
    for (i = 0; i < 6; i++) {
        dx = (f32)lbl_8039A848[i].x - pos[0];
        dSq = dx * dx;
        dz = (f32)lbl_8039A848[i].z - pos[2];
        dSq += dz * dz;
        if (dSq == 0.0f) {
            dists[i] = 0.0f;
        } else {
            dists[i] = sqrtf__inline(dSq);
        }
        if (dists[i] < lbl_803DF1DC) {
            dists[i] = lbl_803DF1DC;
        }
    }
    for (i = 0; i < 6; i++) {
        dists[i] = lbl_803DF1A4 / sqrtf__inline(dists[i]);
    }
    for (i = 0; i < 6; i++) {
        accX += lbl_8039A848[i].vx * dists[i];
        accZ += lbl_8039A848[i].vz * dists[i];
    }
    out[0] = -accX;
    out[2] = -accZ;
    out[1] = 0.0f;
    normalize(out, out + 1, out + 2);
    out[0] = out[0] * scale;
    out[1] = 0.0f;
    out[2] = out[2] * scale;
}
#pragma pop

extern void GXSetCullMode(int mode);
extern void Camera_RebuildProjectionMatrix(void);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern void textureSetupFn_800799c0(void);
extern void gxTextureFn_800794e0(void);
extern void textRenderSetupFn_80079804(void);
extern void fn_800788DC(void);
extern void fn_8006C51C(void *out);
extern void selectTexture(char *tex, int slot);
extern void Camera_UpdateViewMatrices(void);
extern f32 *Camera_GetViewMatrix(void);
extern void GXLoadPosMtxImm(f32 *matrix, s32 slot);
extern void GXSetCurrentMtx(int slot);
extern int rand(void);
extern void srand(int seed);
extern void PSVECSubtract(f32 *a, f32 *b, f32 *ab);
extern f32 PSVECMag(f32 *v);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern int lbl_803DF19C;
extern f32 lbl_803DF1D4;

void lightningDrawBolt(f32 *start, f32 *end, int width, f32 c, f32 d, int *seed, int e, int f);

/*
 * --INFO--
 *
 * Function: lightningRender
 * EN v1.0 Address: 0x8008F904
 * EN v1.0 Size: 496b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void lightningRender(void *state) {
    u8 *p = state;
    f32 start[3];
    f32 end[3];
    f32 diff[3];
    char *tex;
    int savedSeed;
    FogColor color;
    int a;
    int b;
    int half;

    color = *(FogColor *)&lbl_803DF19C;
    start[0] = *(f32 *)(p + 0) - playerMapOffsetX;
    start[1] = *(f32 *)(p + 4);
    start[2] = *(f32 *)(p + 8) - playerMapOffsetZ;
    end[0] = *(f32 *)(p + 0xc) - playerMapOffsetX;
    end[1] = *(f32 *)(p + 0x10);
    end[2] = *(f32 *)(p + 0x14) - playerMapOffsetZ;
    a = *(u16 *)(p + 0x20);
    b = *(u16 *)(p + 0x22);
    half = b >> 1;
    if (a <= half) {
        _gxSetTevColor2(0x80, 0x80, 0xff, 0xff);
    } else {
        _gxSetTevColor2(0x80, 0x80, 0xff,
                        (int)((lbl_803DF1D4 * (f32)(b - a)) / (f32)half));
    }
    GXSetCullMode(0);
    Camera_RebuildProjectionMatrix();
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
    textureSetupFn_800799c0();
    gxTextureFn_800794e0();
    textRenderSetupFn_80079804();
    fn_800788DC();
    fn_8006C51C(&tex);
    selectTexture(tex, 0);
    GXSetFog(0, lbl_803DF1A0, lbl_803DF1A0, lbl_803DF1A0, lbl_803DF1A0, color);
    Camera_UpdateViewMatrices();
    GXLoadPosMtxImm(Camera_GetViewMatrix(), 0);
    GXSetCurrentMtx(0);
    savedSeed = rand();
    if (*(u16 *)(p + 0x24) == 0xffff) {
        *(u16 *)(p + 0x24) = (u16)savedSeed;
    }
    srand(*(u16 *)(p + 0x24));
    PSVECSubtract(end, start, diff);
    PSVECMag(diff);
    lightningDrawBolt(start, end, p[0x26], *(f32 *)(p + 0x18), *(f32 *)(p + 0x1c), &savedSeed, 0,
                p[0x27]);
    srand(savedSeed);
}
#pragma pop

extern s16 lbl_803DD1A8;
extern f32 lbl_803DD1AC;
extern f32 lbl_803DD1B0;
extern f32 lbl_803DF1E0;
extern f32 lbl_803DF1E4;
extern f32 lbl_803DF1E8;
extern f32 lbl_803DF1EC;
extern const f32 lbl_803DF1F0;
extern const f32 lbl_803DF1F4;
extern const f32 lbl_803DF1F8;

/*
 * --INFO--
 *
 * Function: snowCloudInitFlakes
 * EN v1.0 Address: 0x8008FC9C
 * EN v1.0 Size: 988b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void snowCloudInitFlakes(f32 *buf, int cloudId, f32 a, f32 b) {
    u8 *p;
    u8 *e;
    f32 *dst;
    int i;
    int j;
    int widx;
    f32 amp;
    f32 size;
    f32 negSize;
    f32 halfNeg;

    amp = a * b * lbl_803DF1E0;
    for (i = 0; i < 8; i++) {
        p = lbl_8039A828[i];
        if (p != NULL && cloudId == *(int *)(p + 0x13f0)) {
            break;
        }
    }
    p = lbl_8039A828[i];
    if (p == NULL) {
        return;
    }
    if (lbl_803DF1E4 == lbl_803DD1AC) {
        return;
    }
    if (cloudId != *(int *)(p + 0x13f0)) {
        debugPrintf(sSnowFreeSnowCloudInvalidCloudId, cloudId);
        return;
    }
    if (*(int *)(p + 0x13f4) == 4) {
        size = lbl_803DF1E4;
    } else {
        size = lbl_803DF1E8;
    }
    e = p + 0x1008;
    negSize = -size;
    halfNeg = lbl_803DF1EC * negSize;
    for (j = 0; j < 20; j++) {
        *(f32 *)(e + 0x0) = negSize;
        *(f32 *)(e + 0x18) = 0.0f;
        *(f32 *)(e + 0x4) = size;
        *(f32 *)(e + 0x1c) = 0.0f;
        *(f32 *)(e + 0x8) = 0.0f;
        *(f32 *)(e + 0x20) = 0.0f;
        if (*(int *)((u8 *)lbl_8039A828[i] + 0x13f4) == 0) {
            *(f32 *)(e + 0xc) = negSize;
            *(f32 *)(e + 0x10) = negSize;
            *(f32 *)(e + 0x14) = size;
        } else {
            *(f32 *)(e + 0xc) = negSize;
            *(f32 *)(e + 0x10) = negSize;
            *(f32 *)(e + 0x14) = halfNeg;
        }
        *(u16 *)(e + 0x28) = (u16)randomGetRange(0, 0xffff);
        *(u16 *)(e + 0x2a) = (u16)randomGetRange(0, 0xffff);
        *(u16 *)(e + 0x24) = (u16)randomGetRange(0x96, 0x1f4);
        *(u16 *)(e + 0x26) = (u16)randomGetRange(0x96, 0x1f4);
        e += 0x2c;
    }
    widx = *(int *)((u8 *)lbl_8039A828[i] + 0x1408);
    dst = buf + widx;
    while (widx < *(int *)((u8 *)lbl_8039A828[i] + 0x1408) + 0xfa0) {
        if (widx == 0x400) {
            *(int *)((u8 *)lbl_8039A828[i] + 0x1400) = 0;
            *(int *)((u8 *)lbl_8039A828[i] + 0x1408) = 0;
            return;
        }
        if (widx == 0) {
            lbl_803DD1A8 = 0;
            lbl_803DD1AC = 0.0f;
            lbl_803DD1B0 = 0.0f;
        }
        fn_80293E80((lbl_803DF1F0 * (f32)lbl_803DD1A8) / lbl_803DF1F4);
        sin((lbl_803DF1F0 * (f32)lbl_803DD1A8) / lbl_803DF1F4);
        *dst = lbl_803DD1AC * amp;
        lbl_803DD1A8 = (f32)lbl_803DD1A8 + lbl_803DF1F8;
        lbl_803DD1AC = lbl_803DD1AC + lbl_803DF1A4;
        dst++;
        widx++;
    }
    *(int *)((u8 *)lbl_8039A828[i] + 0x1408) = *(int *)((u8 *)lbl_8039A828[i] + 0x1408) + 0xfa0;
}
#pragma pop

extern u8 isOvercast(void);
extern void fn_800790AC(void);
extern void gxBlendFn_800789ac(void);
extern void textRenderSetupFn_800795e8(void);
extern f32 *Camera_GetViewRotationMatrix(void);
extern void GXSetPointSize(int size, int fmt);
extern void GXCallDisplayList(void *list, int size);
extern int lbl_803DB778;
extern u8 lbl_803DB770[8];
extern u8 lbl_8030F770[];
extern u16 lbl_8039A900[];
extern void *lbl_8039A9B8[];
extern char *lbl_803DD1D0;
extern char *lbl_803DD1D4;
extern f32 lbl_803DF280;
extern f32 lbl_803DF284;
extern f32 lbl_803DF288;
extern f32 lbl_803DF28C;

/*
 * --INFO--
 *
 * Function: drawSkyStars
 * EN v1.0 Address: 0x80093AF8
 * EN v1.0 Size: 724b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void drawSkyStars(void) {
    int timeOk;
    int start;
    int alpha;
    int div;
    int i;
    int red;
    int green;
    int blue;
    int a;
    u8 *colRange;
    FogColor color;
    f32 t;

    timeOk = (int)(*(code *)(*(int *)gSHthorntailAnimationInterface + 0x24))(&t);
    if (isOvercast() != 0) {
        if (timeOk != 0) {
            if (t > lbl_803DF280) {
                alpha = 0xff;
            } else {
                alpha = (int)(lbl_803DF284 * (t / lbl_803DF280));
            }
        } else {
            if (t > lbl_803DF288) {
                return;
            }
            if (lbl_803DF28C == t) {
                return;
            }
            alpha = (int)(lbl_803DF284 - lbl_803DF284 * (t / lbl_803DF288));
        }
        start = 0x4c;
        div = 2;
    } else {
        start = 0;
        alpha = 0xff;
        div = 1;
    }
    GXSetCullMode(0);
    Camera_RebuildProjectionMatrix();
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
    textureSetupFn_800799c0();
    fn_800790AC();
    textRenderSetupFn_80079804();
    gxBlendFn_800789ac();
    color = *(FogColor *)&lbl_803DB778;
    GXSetFog(0, lbl_803DF28C, lbl_803DF28C, lbl_803DF28C, lbl_803DF28C, color);
    Camera_UpdateViewMatrices();
    GXLoadPosMtxImm(Camera_GetViewRotationMatrix(), 0);
    GXSetCurrentMtx(0);
    for (i = start; i < 0x5c; i++) {
        colRange = &lbl_8030F770[(i & 3) * 6];
        red = randomGetRange(colRange[0], colRange[1]);
        green = randomGetRange(colRange[2], colRange[3]);
        blue = randomGetRange(colRange[4], colRange[5]);
        if (i < 0x4c) {
            a = (alpha * randomGetRange(lbl_803DB770[((i & 0xc) >> 2) * 2],
                                        lbl_803DB770[((i & 0xc) >> 2) * 2 + 1])) >>
                8;
        } else {
            a = alpha;
        }
        _gxSetTevColor2((u8)red, (u8)green, (u8)blue, (u8)a);
        if (i == 0x4c) {
            selectTexture(lbl_803DD1D0, 0);
            textureSetupFn_800799c0();
            textRenderSetupFn_800795e8();
            textRenderSetupFn_80079804();
        } else if (i == 0x54) {
            selectTexture(lbl_803DD1D4, 0);
        }
        if (i < 0x4c) {
            GXSetPointSize((u8)randomGetRange(0xc, 0xc), 5);
        } else if (i & 4) {
            GXSetPointSize((u8)(randomGetRange(0x30, 0x3c) / div), 5);
        } else {
            GXSetPointSize((u8)(randomGetRange(0x48, 0x60) / div), 5);
        }
        GXCallDisplayList(lbl_8039A9B8[i], lbl_8039A900[i]);
    }
}
#pragma pop

typedef union PPCWGPipe2 {
    u8 u8;
    u16 u16;
    u32 u32;
    s8 s8;
    s16 s16;
    s32 s32;
    f32 f32;
    f64 f64;
} PPCWGPipe2;

volatile PPCWGPipe2 GXWGFifo : (0xCC008000);

extern int getHudHiddenFrameCount(void);
extern void PSVECScale(f32 *in, f32 *out, f32 scale);
extern void PSVECCrossProduct(f32 *a, f32 *b, f32 *axb);
extern void PSMTXRotAxisRad(f32 *mtx, f32 *axis, f32 rad);
extern void PSMTXMultVecSR(f32 *mtx, f32 *src, f32 *dst);
extern void GXSetLineWidth(int width, int fmt);
extern void GXBegin(int prim, int fmt, u16 count);
extern f32 lbl_803DF1B8;
extern f32 lbl_803DF1BC;
extern f32 lbl_803DF1C0;
extern f32 lbl_803DF1C4;
extern f32 lbl_803DF1C8;
extern f32 lbl_803DF1CC;

/*
 * --INFO--
 *
 * Function: lightningDrawStrand
 * EN v1.0 Address: 0x8008EE18
 * EN v1.0 Size: 1200b
 */
#pragma push
#pragma scheduling off
void lightningDrawStrand(f32 *from, f32 *to, int width, f32 segScale, int *seed) {
    int savedRand;
    int segs;
    int i;
    f32 total;
    f32 len;
    f32 weight;
    f32 px;
    f32 py;
    f32 pz;
    f32 step;
    f32 mtx[12];
    f32 dir[3];
    f32 scaled[3];
    f32 up[3];
    f32 side[3];
    f32 offset[3];

    if (getHudHiddenFrameCount() == 0) {
        savedRand = rand();
        srand(*seed);
    }
    PSVECSubtract(to, from, dir);
    len = PSVECMag(dir);
    PSVECScale(dir, scaled, lbl_803DF1A4 / len);
    if (__fabs(scaled[0]) < lbl_803DF1B8) {
        up[0] = lbl_803DF1A4;
        up[1] = lbl_803DF1A0;
        up[2] = lbl_803DF1A0;
    } else {
        up[0] = lbl_803DF1A0;
        up[1] = lbl_803DF1A0;
        up[2] = lbl_803DF1A4;
    }
    PSVECCrossProduct(scaled, up, side);
    PSVECCrossProduct(side, scaled, up);
    PSVECNormalize(up, up);
    segs = (int)(len * segScale);
    if (segs > 10) {
        segs = 10;
    }
    if (segs == 0) {
        segs = 1;
    }
    total = lbl_803DF1A0;
    for (i = 0; i < segs; i++) {
        total += (f32)(i + 1);
    }
    weight = lbl_803DF1A4 / total;
    GXSetLineWidth(width, 5);
    GXBegin(0xb0, 2, segs + 1);
    for (i = 0; i <= segs; i++) {
        if (i == 0) {
            GXWGFifo.f32 = from[0];
            GXWGFifo.f32 = from[1];
            GXWGFifo.f32 = from[2];
            GXWGFifo.f32 = lbl_803DF1A0;
            GXWGFifo.f32 = lbl_803DF1A0;
            px = from[0];
            py = from[1];
            pz = from[2];
        } else if (i < segs) {
            PSVECScale(up, offset,
                       lbl_803DF1BC *
                           (lbl_803DF1C0 * (len * (f32)(int)randomGetRange(1, 100))));
            PSMTXRotAxisRad(
                mtx, scaled,
                lbl_803DF1C4 *
                    (lbl_803DF1C8 * (lbl_803DF1CC * (f32)(int)randomGetRange(0, 1000))));
            PSMTXMultVecSR(mtx, offset, offset);
            step = weight * (len * (f32)(segs - i));
            px += scaled[0] * step;
            py += scaled[1] * step;
            pz += scaled[2] * step;
            GXWGFifo.f32 = px + offset[0];
            GXWGFifo.f32 = py + offset[1];
            GXWGFifo.f32 = pz + offset[2];
            GXWGFifo.f32 = lbl_803DF1A0;
            GXWGFifo.f32 = lbl_803DF1A0;
        } else {
            GXWGFifo.f32 = to[0];
            GXWGFifo.f32 = to[1];
            GXWGFifo.f32 = to[2];
            GXWGFifo.f32 = lbl_803DF1A0;
            GXWGFifo.f32 = lbl_803DF1A0;
        }
    }
    if (getHudHiddenFrameCount() == 0) {
        *seed = rand();
        srand(savedRand);
    }
}
#pragma pop

/*
 * --INFO--
 *
 * Function: snowCloudUpdateFlakes
 * EN v1.0 Address: 0x80090C0C
 * EN v1.0 Size: 892b
 */
#pragma push
#pragma scheduling off
void snowCloudUpdateFlakes(u8 *snow) {
    s16 *cam;
    u8 *e;
    f32 *m;
    int i;
    int c;
    f32 c1;
    f32 s1;
    f32 c2;
    f32 s2;
    f32 c3;
    f32 s3;

    cam = Camera_GetCurrentViewSlot();
    e = snow + 0x1008;
    if (*(int *)(snow + 0x13f4) == 0) {
        f32 size = lbl_803DF1E8;
        f32 negSize = -size;
        for (i = 0; i < 20; i++) {
            m = (f32 *)e;
            m[0] = negSize;
            m[3] = negSize;
            m[6] = lbl_803DF1A0;
            m[1] = size;
            m[4] = negSize;
            m[7] = lbl_803DF1A0;
            m[2] = lbl_803DF1A0;
            m[5] = size;
            m[8] = lbl_803DF1A0;
            *(u16 *)(e + 0x28) =
                timeDelta * (f32)*(u16 *)(e + 0x24) + (f32)*(u16 *)(e + 0x28);
            *(u16 *)(e + 0x2a) =
                timeDelta * (f32)*(u16 *)(e + 0x26) + (f32)*(u16 *)(e + 0x2a);
            angleToVec2((u16)(0xffff - *cam), &c1, &s1);
            angleToVec2(*(u16 *)(e + 0x28), &c2, &s2);
            angleToVec2(*(u16 *)(e + 0x2a), &c3, &s3);
            for (c = 0; c < 3; c++) {
                f32 m0 = m[c];
                f32 m1 = m[c + 3];
                f32 m2 = m[c + 6];
                f32 t1 = m0 * s3 - m1 * c3;
                f32 t2 = m0 * c3 + m1 * s3;
                m[c] = t1 * s1 + c1 * (t2 * c2) + c1 * (m2 * s2);
                m[c + 3] = -m2 * c2 + t2 * s2;
                m[c + 6] = -t1 * c1 + s1 * (t2 * c2) + s1 * (m2 * s2);
            }
            e += 0x2c;
        }
    } else {
        f32 size2;
        f32 negSize2;
        angleToVec2((u16)(0xffff - *cam), &c1, &s1);
        size2 = lbl_803DF1E4;
        negSize2 = -size2;
        m = (f32 *)e;
        for (i = 0; i < 20; i++) {
            m[0] = negSize2 * s1;
            m[6] = size2 * c1;
            m[1] = size2 * s1;
            m[7] = size2 * -c1;
            m += 0xb;
        }
    }
}
#pragma pop

extern void PSVECAdd(f32 *a, f32 *b, f32 *ab);
extern f32 lbl_803DF1D0;

/*
 * --INFO--
 *
 * Function: lightningDrawBolt
 * EN v1.0 Address: 0x8008F2C8
 * EN v1.0 Size: 1596b
 */
#pragma push
#pragma scheduling off
void lightningDrawBolt(f32 *start, f32 *end, int width, f32 segScale, f32 d, int *seed, int depth,
                 int flags) {
    f32 len;
    int segs;
    f32 total;
    f32 weight;
    f32 px;
    f32 py;
    f32 pz;
    f32 nx;
    f32 ny;
    f32 nz;
    f32 progress;
    f32 step;
    int i;
    int oddFlag;
    int halfWidth;
    f32 mtx[12];
    f32 dir[3];
    f32 scaled[3];
    f32 up[3];
    f32 side[3];
    f32 offset[3];
    f32 cur[3];
    f32 next[3];
    f32 branchEnd[3];

    if ((u32)depth > 2) {
        return;
    }
    PSVECSubtract(end, start, dir);
    len = PSVECMag(dir);
    PSVECScale(dir, scaled, lbl_803DF1A4 / len);
    if (__fabs(scaled[0]) < lbl_803DF1B8) {
        up[0] = lbl_803DF1A4;
        up[1] = lbl_803DF1A0;
        up[2] = lbl_803DF1A0;
    } else {
        up[0] = lbl_803DF1A0;
        up[1] = lbl_803DF1A0;
        up[2] = lbl_803DF1A4;
    }
    PSVECCrossProduct(scaled, up, side);
    PSVECCrossProduct(side, scaled, up);
    PSVECNormalize(up, up);
    segs = (int)(len * segScale);
    if (segs > 10) {
        segs = 10;
    }
    if (segs == 0) {
        return;
    }
    total = lbl_803DF1A0;
    for (i = 0; i < segs; i++) {
        total += (f32)(i + 1);
    }
    weight = lbl_803DF1A4 / total;
    px = start[0];
    py = start[1];
    pz = start[2];
    cur[0] = px;
    cur[1] = py;
    cur[2] = pz;
    progress = lbl_803DF1A0;
    oddFlag = (u8)flags & 1;
    halfWidth = (u8)width >> 1;
    for (i = 0; i <= segs; i++) {
        if (i < segs) {
            PSVECScale(up, offset,
                       lbl_803DF1BC *
                           (lbl_803DF1C0 * (len * (f32)(int)randomGetRange(1, 100))));
            PSMTXRotAxisRad(
                mtx, scaled,
                lbl_803DF1C4 *
                    (lbl_803DF1C8 * (lbl_803DF1CC * (f32)(int)randomGetRange(0, 1000))));
            PSMTXMultVecSR(mtx, offset, offset);
            progress += weight * (f32)(segs - i);
            step = weight * (len * (f32)(segs - i));
            nx = px + scaled[0] * step;
            ny = py + scaled[1] * step;
            nz = pz + scaled[2] * step;
            next[0] = nx + offset[0];
            next[1] = ny + offset[1];
            next[2] = nz + offset[2];
            if (randomGetRange(1, 3) == 1 && (u8)width >= 0xc && oddFlag == 0) {
                PSVECScale(up, offset,
                           lbl_803DF1BC * (lbl_803DF1D0 *
                                           (len * (f32)(int)randomGetRange(0x32, 0x64))));
                PSMTXRotAxisRad(mtx, scaled,
                                lbl_803DF1C4 *
                                    (lbl_803DF1C8 *
                                     (lbl_803DF1CC * (f32)(int)randomGetRange(0, 1000))));
                PSMTXMultVecSR(mtx, offset, offset);
                PSVECScale(scaled, branchEnd,
                           (lbl_803DF1CC * ((lbl_803DF1A4 - progress) *
                                            (f32)(int)randomGetRange(0, 1000)) +
                            progress) *
                               len);
                PSVECAdd(start, branchEnd, branchEnd);
                PSVECAdd(branchEnd, offset, branchEnd);
                lightningDrawBolt(next, branchEnd, (u8)halfWidth, segScale, d, seed, depth + 1,
                            flags);
            }
        } else {
            next[0] = end[0];
            next[1] = end[1];
            next[2] = end[2];
        }
        lightningDrawStrand(cur, next, width, d, seed);
        px = nx;
        py = ny;
        pz = nz;
        cur[0] = next[0];
        cur[1] = next[1];
        cur[2] = next[2];
    }
}
#pragma pop

extern void GXSetMisc(int token, u32 val);
extern void DCInvalidateRange(void *addr, u32 nBytes);
extern int GXBeginDisplayList(void *list, u32 size);
extern u32 GXEndDisplayList(void);
extern void GXResetWriteGatherPipe(void);
extern void PSMTXRotRad(f32 *mtx, int axis, f32 rad);
extern u8 lbl_803DD1D8;
extern f32 lbl_803DF290;
extern f32 lbl_803DF294;
extern f32 lbl_803DF298;
extern f32 lbl_803DF29C;
extern f32 lbl_803DF2A0;
extern f32 lbl_803DF2A4;

/*
 * --INFO--
 *
 * Function: titleScreenDrawFn_80093db4
 * EN v1.0 Address: 0x80093DB4
 * EN v1.0 Size: 1464b
 */
#pragma push
#pragma scheduling off
void titleScreenDrawFn_80093db4(void) {
    f32 *constellation;
    f32 *cp;
    int i;
    int j;
    int k;
    int idx;
    f32 zero;
    f32 v[3];
    f32 mtx2[12];
    f32 mtx1[12];

    GXSetMisc(1, 0);
    testAndSet_onlyUseHeap3(0);
    constellation = mmAlloc(0x4b0, 0x7f7f7fff, 0);
    testAndSet_onlyUseHeap3(1);
    cp = constellation;
    zero = lbl_803DF28C;
    for (i = 0; i < 0x64; i++) {
        do {
            v[0] = (f32)(int)randomGetRange(-5000, 5000);
            v[1] = (f32)(int)randomGetRange(-5000, 5000);
            v[2] = (f32)(int)randomGetRange(-5000, 5000);
        } while (zero == v[0] && zero == v[1] && zero == v[2]);
        PSVECNormalize(v, v);
        PSVECScale(v, v, lbl_803DF290);
        cp[0] = v[0];
        cp[1] = v[1];
        cp[2] = v[2];
        cp += 3;
    }
    lbl_803DD1D8 = 1;
    lbl_803DD1D0 = textureLoadAsset(0xc21);
    lbl_803DD1D4 = textureLoadAsset(0xc22);
    for (k = 0; k < 0x5c; k++) {
        lbl_8039A9B8[k] = mmAlloc(0x220, 0x7f7f7fff, 0);
        DCInvalidateRange(lbl_8039A9B8[k], 0x220);
        GXBeginDisplayList(lbl_8039A9B8[k], 0x220);
        GXResetWriteGatherPipe();
        GXBegin(0xb8, 0, 0x32);
        for (j = 0; j < 0x32; j++) {
            if (randomGetRange(0, 9) < 5) {
                f32 z2 = lbl_803DF28C;
                do {
                    v[0] = (f32)(int)randomGetRange(-5000, 5000);
                    v[1] = (f32)(int)randomGetRange(-5000, 5000);
                    v[2] = (f32)(int)randomGetRange(-5000, 5000);
                } while (z2 == v[0] && z2 == v[1] && z2 == v[2]);
                PSVECNormalize(v, v);
                PSVECScale(v, v, lbl_803DF290);
            } else {
                idx = randomGetRange(0, 0x63);
                v[0] = constellation[idx * 3];
                v[1] = constellation[idx * 3 + 1];
                v[2] = constellation[idx * 3 + 2];
                if (__fabs(v[0]) > lbl_803DF294) {
                    PSMTXRotRad(mtx1, 0x79,
                                (lbl_803DF298 *
                                 (lbl_803DF29C *
                                  (lbl_803DF2A0 *
                                   (f32)(int)randomGetRange(-0x8000, 0x8000)))) /
                                    lbl_803DF2A4);
                    PSMTXRotRad(mtx2, 0x7a,
                                (lbl_803DF298 *
                                 (lbl_803DF29C *
                                  (lbl_803DF2A0 *
                                   (f32)(int)randomGetRange(-0x8000, 0x8000)))) /
                                    lbl_803DF2A4);
                } else if (__fabs(v[1]) > lbl_803DF294) {
                    PSMTXRotRad(mtx1, 0x78,
                                (lbl_803DF298 *
                                 (lbl_803DF29C *
                                  (lbl_803DF2A0 *
                                   (f32)(int)randomGetRange(-0x8000, 0x8000)))) /
                                    lbl_803DF2A4);
                    PSMTXRotRad(mtx2, 0x7a,
                                (lbl_803DF298 *
                                 (lbl_803DF29C *
                                  (lbl_803DF2A0 *
                                   (f32)(int)randomGetRange(-0x8000, 0x8000)))) /
                                    lbl_803DF2A4);
                } else {
                    PSMTXRotRad(mtx1, 0x78,
                                (lbl_803DF298 *
                                 (lbl_803DF29C *
                                  (lbl_803DF2A0 *
                                   (f32)(int)randomGetRange(-0x8000, 0x8000)))) /
                                    lbl_803DF2A4);
                    PSMTXRotRad(mtx2, 0x79,
                                (lbl_803DF298 *
                                 (lbl_803DF29C *
                                  (lbl_803DF2A0 *
                                   (f32)(int)randomGetRange(-0x8000, 0x8000)))) /
                                    lbl_803DF2A4);
                }
                PSMTXConcat((void *)mtx2, (void *)mtx1, (void *)mtx1);
                PSMTXMultVecSR(mtx1, v, v);
            }
            GXWGFifo.s16 = v[0];
            GXWGFifo.s16 = v[1];
            GXWGFifo.s16 = v[2];
            GXWGFifo.s16 = 0;
            GXWGFifo.s16 = 0;
        }
        lbl_8039A900[k] = (u16)GXEndDisplayList();
    }
    mm_free(constellation);
    GXSetMisc(1, 8);
}
#pragma pop

extern void Sfx_PlayAtPositionFromObject(int obj, int sfx, f32 x, f32 y, f32 z);
extern u8 framesThisStep;
extern char lbl_8030F670[];
extern f32 lbl_803DF228;
extern f32 lbl_803DF22C;
extern f32 lbl_803DF230;

/*
 * --INFO--
 *
 * Function: snowReposSnowCloud
 * EN v1.0 Address: 0x80090F58
 * EN v1.0 Size: 1848b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void snowReposSnowCloud(int cloudId) {
    u8 *p;
    u8 *part;
    f32 *cam;
    f32 *m;
    u8 *q;
    int i;
    int j;
    int dx;
    int dy;
    int dz;
    int distSq;
    u8 fl;
    struct {
        s16 f8;
        s16 fa;
        s16 fc;
        s16 pad_e;
        f32 f10;
        f32 f14;
        f32 f18;
        f32 f1c;
    } args;
    f32 dir[3] = {0.0f, 0.0f, 0.0f};
    f32 fwd[3];
    f32 from[3];
    f32 to[3];

    if (renderModeSetOrGet(-1) == 1) {
        return;
    }
    srand(randomGetRange(1, 0xffff));
    for (i = 0; i < 8; i++) {
        p = lbl_8039A828[i];
        if (p != NULL && cloudId == *(int *)(p + 0x13f0)) {
            break;
        }
    }
    p = lbl_8039A828[i];
    if (p == NULL) {
        return;
    }
    if (i == 8) {
        return;
    }
    if (cloudId != *(int *)(p + 0x13f0)) {
        debugPrintf(lbl_8030F670, cloudId);
        return;
    }
    part = *(u8 **)(p + 4);
    cam = (f32 *)Camera_GetCurrentViewSlot();
    dx = cam[0x44 / 4] - *(f32 *)((u8 *)lbl_8039A828[i] + 0x140c);
    dy = cam[0x48 / 4] - *(f32 *)((u8 *)lbl_8039A828[i] + 0x1410);
    dz = cam[0x4c / 4] - *(f32 *)((u8 *)lbl_8039A828[i] + 0x1414);
    distSq = dx * dx + (dy * dy + dz * dz);
    sqrtf__inline((f32)distSq);
    *(s16 *)((u8 *)lbl_8039A828[i] + 0x1448) =
        (f32)*(s16 *)((u8 *)lbl_8039A828[i] + 0x1448) - timeDelta;
    q = lbl_8039A828[cloudId];
    if (*(int *)(q + 0x13f4) == 4 && (q[0x144b] & 0x38) != 0 &&
        *(s16 *)(q + 0x1448) <= 0 && q[0x144d] == 0 && lbl_803DD19C == 0) {
        if (q[0x1452] != 0 && cam != NULL) {
            dir[0] = lbl_803DF1A0;
            dir[1] = lbl_803DF1A0;
            dir[2] = lbl_803DF228;
            args.f14 = lbl_803DF1A0;
            args.f18 = lbl_803DF1A0;
            args.f1c = lbl_803DF1A0;
            args.f10 = lbl_803DF1A4;
            args.fc = 0;
            args.fa = 0;
            args.f8 = 0xffff - (*(s16 *)cam + randomGetRange(-5000, 5000));
            mathFn_80021ac8(&args.f8, dir);
        }
        args.f14 = dir[0];
        args.f18 = dir[1];
        args.f1c = dir[2];
        args.f10 = lbl_803DF1A4;
        args.f8 = 0;
        args.fc = 0;
        args.fa = 0;
        m = Camera_GetViewMatrix();
        fwd[0] = m[8];
        fwd[1] = m[9];
        fwd[2] = m[10];
        PSVECNormalize(fwd, fwd);
        from[0] = (cam[0x44 / 4] + (f32)(int)randomGetRange(-3000, 3000)) -
                  lbl_803DF22C * fwd[0];
        from[1] = (cam[0x48 / 4] + (f32)(int)randomGetRange(2000, 4000)) -
                  lbl_803DF22C * fwd[1];
        from[2] = (cam[0x4c / 4] + (f32)(int)randomGetRange(-3000, 3000)) -
                  lbl_803DF22C * fwd[2];
        to[0] = (cam[0x44 / 4] + (f32)(int)randomGetRange(-3000, 3000)) -
                lbl_803DF22C * fwd[0];
        to[1] = (cam[0x48 / 4] - (f32)(int)randomGetRange(2000, 4000)) -
                lbl_803DF22C * fwd[1];
        to[2] = (cam[0x4c / 4] + (f32)(int)randomGetRange(-3000, 3000)) -
                lbl_803DF22C * fwd[2];
        lbl_803DD19C = (u8 *)lightningCreate(from, to, lbl_803DF230, lbl_803DF1BC, 0xf, 0xc0, 0);
        Sfx_PlayAtPositionFromObject(0, 0x2c9, from[0], from[1], from[2]);
        fl = ((u8 *)lbl_8039A828[cloudId])[0x144b];
        if (fl & 8) {
            *(s16 *)((u8 *)lbl_8039A828[cloudId] + 0x1448) = (s16)randomGetRange(0x78, 0xf0);
        } else if (fl & 0x10) {
            *(s16 *)((u8 *)lbl_8039A828[cloudId] + 0x1448) = (s16)randomGetRange(0x78, 0xf0);
        } else if (fl & 0x20) {
            *(s16 *)((u8 *)lbl_8039A828[cloudId] + 0x1448) = (s16)randomGetRange(0x5a, 0xb4);
        }
    }
    snowCloudUpdateFlakes(lbl_8039A828[i]);
    for (j = 0; j < *(int *)((u8 *)lbl_8039A828[i] + 0x13fc); j++) {
        if (*(int *)((u8 *)lbl_8039A828[i] + 0x13f4) == 0) {
            *(u16 *)(part + 0x10) =
                *(u16 *)(part + 0x10) + (s8)part[0x14] * framesThisStep;
            if (*(u16 *)(part + 0x10) > 0x3ff) {
                *(u16 *)(part + 0x10) = *(u16 *)(part + 0x10) - 0x3ff;
            }
        } else if (*(int *)((u8 *)lbl_8039A828[i] + 0x13f4) == 4) {
            *(u16 *)(part + 0x10) = *(u16 *)(part + 0x10) +
                                    framesThisStep * ((s8)part[0x14] + (s8)part[0x14]);
            if (*(u16 *)(part + 0x10) > 0x3ff) {
                *(u16 *)(part + 0x10) = *(u16 *)(part + 0x10) - 0x3ff;
            }
        }
        part += 0x18;
    }
}
#pragma pop

extern char lbl_8030F500[];
extern int lbl_803DB76C;
extern f32 lbl_803DF1FC;
extern f32 lbl_803DF214;
extern f32 lbl_803DF234;
extern f32 lbl_803DF238;
extern f32 lbl_803DF23C;
extern f32 lbl_803DF240;
extern f32 lbl_803DF244;

#define NC_CLOUD ((u8 *)lbl_8039A828[id])
#define NC_PARTS ((u8 *)*(void **)(NC_CLOUD + 4))

/*
 * --INFO--
 *
 * Function: newClouds
 * EN v1.0 Address: 0x800919DC
 * EN v1.0 Size: 2632b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void newClouds(u8 *params, void *owner, f32 x, f32 y, f32 z) {
    char *strs;
    int ok;
    int id;
    int i;
    u8 fl;
    WindSource *w;

    strs = lbl_8030F500;
    ok = 1;
    id = *(u16 *)(params + 0x26);
    if (lbl_8039A828[id] != NULL) {
        snowFreeSnowCloud(id);
    }
    lbl_8039A828[id] = mmAlloc(0x1454, 0x17, 0);
    if (lbl_8039A828[id] == NULL) {
        debugPrintf(strs + 0x1b0);
        return;
    }
    memset(lbl_8039A828[id], 0, 0x1454);
    *(int *)(NC_CLOUD + 0x13f0) = id;
    NC_CLOUD[0x1453] = 0;
    *(int *)(NC_CLOUD + 0x13f4) = params[0x5c];
    *(void **)(NC_CLOUD + 0x0) = owner;
    NC_CLOUD[0x144a] = params[0x58];
    NC_CLOUD[0x144b] = params[0x59];
    *(f32 *)(NC_CLOUD + 0x140c) = x;
    *(f32 *)(NC_CLOUD + 0x1410) = y;
    *(f32 *)(NC_CLOUD + 0x1414) = z;
    if (params[0x58] & 1) {
        NC_CLOUD[0x1451] = 1;
    }
    if (params[0x58] & 0x10) {
        NC_CLOUD[0x144e] = 1;
    }
    NC_CLOUD[0x1452] = 1;
    NC_CLOUD[0x144d] = params[0x5d];
    if (*(int *)(NC_CLOUD + 0x13f4) == 0) {
        *(int *)(NC_CLOUD + 0x13fc) = *(u16 *)(params + 0x28) << 3;
    } else {
        *(int *)(NC_CLOUD + 0x13fc) = *(u16 *)(params + 0x28);
    }
    if (*(u16 *)(params + 0x2a) != 0) {
        *(f32 *)(NC_CLOUD + 0x142c) =
            (f32)*(int *)(NC_CLOUD + 0x13fc) / (f32)*(u16 *)(params + 0x2a);
    } else {
        *(f32 *)(NC_CLOUD + 0x142c) = (f32)*(int *)(NC_CLOUD + 0x13fc);
    }
    if (*(u16 *)(params + 0x2c) != 0) {
        *(f32 *)(NC_CLOUD + 0x1430) =
            (f32)*(int *)(NC_CLOUD + 0x13fc) / (f32)*(u16 *)(params + 0x2c);
    } else {
        *(f32 *)(NC_CLOUD + 0x1430) = (f32)*(int *)(NC_CLOUD + 0x13fc);
    }
    *(f32 *)(NC_CLOUD + 0x1438) = *(f32 *)(params + 8);
    if (*(int *)(NC_CLOUD + 0x13f4) == 0) {
        *(f32 *)(NC_CLOUD + 0x1418) = lbl_803DF234;
        *(f32 *)(NC_CLOUD + 0x141c) = lbl_803DF238;
    } else {
        *(f32 *)(NC_CLOUD + 0x1418) = *(f32 *)(params + 4);
        *(f32 *)(NC_CLOUD + 0x141c) = lbl_803DF1E4 * *(f32 *)(params + 0);
    }
    if (*(f32 *)(params + 8) < lbl_803DF1A4) {
        *(f32 *)(params + 8) = lbl_803DF1A0;
    }
    if (lbl_803DF1A0 != *(f32 *)(params + 8)) {
        *(f32 *)(NC_CLOUD + 0x1444) = lbl_803DF23C;
        *(f32 *)(NC_CLOUD + 0x143c) =
            (f32)(int)randomGetRange(1, (int)*(f32 *)(params + 8)) * lbl_803DF214;
    }
    *(int *)(NC_CLOUD + 0x1400) = 1;
    fl = NC_CLOUD[0x144b];
    if (fl & 8) {
        *(s16 *)(NC_CLOUD + 0x1448) = 0x320;
    } else if (fl & 0x10) {
        *(s16 *)(NC_CLOUD + 0x1448) = 0xc8;
    } else if (fl & 0x20) {
        *(s16 *)(NC_CLOUD + 0x1448) = 0x64;
    }
    snowCloudInitFlakes((f32 *)(NC_CLOUD + 8), id, *(f32 *)(NC_CLOUD + 0x1418),
                         *(f32 *)(NC_CLOUD + 0x141c));
    snowCloudBuildBoxVerts((f32 *)(NC_CLOUD + 0x1378), *(f32 *)(NC_CLOUD + 0x1418),
                *(f32 *)(NC_CLOUD + 0x141c));
    *(void **)(NC_CLOUD + 4) = mmAlloc(*(int *)(NC_CLOUD + 0x13fc) * 0x18, 0x17, 0);
    if (*(void **)(NC_CLOUD + 4) == NULL) {
        ok = 0;
    }
    if (ok == 0) {
        debugPrintf(strs + 0x1f0);
        mm_free(lbl_8039A828[id]);
        lbl_8039A828[id] = NULL;
        return;
    }
    for (i = 0; i < *(int *)(NC_CLOUD + 0x13fc); i++) {
        *(f32 *)(NC_PARTS + i * 0x18) =
            (f32)(int)randomGetRange((int)*(f32 *)(NC_CLOUD + 0x1378),
                                     (int)*(f32 *)(NC_CLOUD + 0x139c));
        *(f32 *)(NC_PARTS + i * 0x18 + 4) = *(f32 *)(NC_CLOUD + 0x1388);
        *(f32 *)(NC_PARTS + i * 0x18 + 8) =
            (f32)(int)randomGetRange((int)*(f32 *)(NC_CLOUD + 0x1380),
                                     (int)*(f32 *)(NC_CLOUD + 0x13b0));
        *(u16 *)(NC_PARTS + i * 0x18 + 0x10) = (u16)randomGetRange(0, 0x3d0);
        *(u16 *)(NC_PARTS + i * 0x18 + 0x12) = (u16)randomGetRange(0, 0x13);
        if (*(int *)(NC_CLOUD + 0x13f4) == 0) {
            *(s8 *)(NC_PARTS + i * 0x18 + 0x14) =
                (s8)(randomGetRange(*(int *)(strs + params[0x5a] * 8 + 0x58),
                                    *(int *)(strs + params[0x5a] * 8 + 0x5c)) /
                     4);
            *(f32 *)(NC_PARTS + i * 0x18 + 0xc) =
                (f32)(int)randomGetRange(0x4b, 0x64) / lbl_803DF1FC;
            *(u8 *)(NC_PARTS + i * 0x18 + 0x16) =
                (u8)(i / (*(int *)(NC_CLOUD + 0x13fc) / 4));
        } else {
            *(s8 *)(NC_PARTS + i * 0x18 + 0x14) =
                (s8)(randomGetRange(*(int *)(strs + params[0x5a] * 8 + 0x58),
                                    *(int *)(strs + params[0x5a] * 8 + 0x5c)) *
                     2);
            *(f32 *)(NC_PARTS + i * 0x18 + 0xc) = lbl_803DF1A4;
            *(u8 *)(NC_PARTS + i * 0x18 + 0x16) = 0;
        }
        if (*(s8 *)(NC_PARTS + i * 0x18 + 0x14) < 1) {
            *(s8 *)(NC_PARTS + i * 0x18 + 0x14) = 1;
        }
        *(s8 *)(NC_PARTS + i * 0x18 + 0x15) =
            (s8)(*(int *)(strs + params[0x5b] * 8 + 0x34) / 2 -
                 randomGetRange(*(int *)(strs + params[0x5b] * 8 + 0x30),
                                *(int *)(strs + params[0x5b] * 8 + 0x34)));
    }
    if (lbl_803DB76C != 0) {
        lbl_8039A848[0].x = 0x31e;
        lbl_8039A848[0].z = 0xa9c;
        lbl_8039A848[0].vx = lbl_803DF240;
        lbl_8039A848[0].vy = lbl_803DF1A0;
        lbl_8039A848[0].vz = lbl_803DF1A0;
        normalize(&lbl_8039A848[0].vx, &lbl_8039A848[0].vy, &lbl_8039A848[0].vz);
        lbl_8039A848[0].scale = lbl_803DF1A4;
        lbl_8039A848[0].flag = 0;
        lbl_8039A848[1].x = 0x3c5;
        lbl_8039A848[1].z = 0xb72;
        lbl_8039A848[1].vx = lbl_803DF1A0;
        lbl_8039A848[1].vy = lbl_803DF1A0;
        lbl_8039A848[1].vz = lbl_803DF240;
        normalize(&lbl_8039A848[1].vx, &lbl_8039A848[1].vy, &lbl_8039A848[1].vz);
        lbl_8039A848[1].scale = lbl_803DF1A4;
        lbl_8039A848[1].flag = 0;
        lbl_8039A848[2].x = 0x335;
        lbl_8039A848[2].z = 0xe13;
        lbl_8039A848[2].vx = lbl_803DF1FC;
        lbl_8039A848[2].vy = lbl_803DF1A0;
        lbl_8039A848[2].vz = lbl_803DF1A0;
        normalize(&lbl_8039A848[2].vx, &lbl_8039A848[2].vy, &lbl_8039A848[2].vz);
        lbl_8039A848[2].scale = lbl_803DF1A4;
        lbl_8039A848[2].flag = 0;
        lbl_8039A848[3].x = 0x254;
        lbl_8039A848[3].z = 0xc70;
        lbl_8039A848[3].vx = lbl_803DF1A0;
        lbl_8039A848[3].vy = lbl_803DF1A0;
        lbl_8039A848[3].vz = lbl_803DF1FC;
        normalize(&lbl_8039A848[3].vx, &lbl_8039A848[3].vy, &lbl_8039A848[3].vz);
        lbl_8039A848[3].scale = lbl_803DF1A4;
        lbl_8039A848[3].flag = 0;
        lbl_8039A848[4].x = 0x107;
        lbl_8039A848[4].z = 0xb4a;
        lbl_8039A848[4].vx = lbl_803DF1FC;
        lbl_8039A848[4].vy = lbl_803DF1A0;
        lbl_8039A848[4].vz = lbl_803DF1CC;
        normalize(&lbl_8039A848[4].vx, &lbl_8039A848[4].vy, &lbl_8039A848[4].vz);
        lbl_8039A848[4].scale = lbl_803DF1A4;
        lbl_8039A848[4].flag = 0;
        lbl_8039A848[5].x = 0x68;
        lbl_8039A848[5].z = 0xdf6;
        lbl_8039A848[5].vx = lbl_803DF1A0;
        lbl_8039A848[5].vy = lbl_803DF1A0;
        lbl_8039A848[5].vz = lbl_803DF240;
        normalize(&lbl_8039A848[5].vx, &lbl_8039A848[5].vy, &lbl_8039A848[5].vz);
        lbl_8039A848[5].scale = lbl_803DF1A4;
        lbl_8039A848[5].flag = 0;
        lbl_8039A848[0].x = 0x31e;
        lbl_8039A848[0].z = 0xa9c;
        lbl_8039A848[0].vx = lbl_803DF1A0;
        lbl_8039A848[0].vy = lbl_803DF1A0;
        lbl_8039A848[0].vz = lbl_803DF1A0;
        lbl_8039A848[0].scale = lbl_803DF1A0;
        lbl_8039A848[0].flag = 0;
        lbl_8039A848[1].x = 0x3c5;
        lbl_8039A848[1].z = 0xb72;
        lbl_8039A848[1].vx = lbl_803DF1A0;
        lbl_8039A848[1].vy = lbl_803DF1A0;
        lbl_8039A848[1].vz = lbl_803DF1A0;
        lbl_8039A848[1].scale = lbl_803DF1A0;
        lbl_8039A848[1].flag = 0;
        lbl_8039A848[2].x = 0x335;
        lbl_8039A848[2].z = 0xe13;
        lbl_8039A848[2].vx = lbl_803DF1A0;
        lbl_8039A848[2].vy = lbl_803DF1A0;
        lbl_8039A848[2].vz = lbl_803DF1A0;
        lbl_8039A848[2].scale = lbl_803DF1A0;
        lbl_8039A848[2].flag = 0;
        lbl_8039A848[3].x = 0x254;
        lbl_8039A848[3].z = 0xc70;
        lbl_8039A848[3].vx = lbl_803DF1A0;
        lbl_8039A848[3].vy = lbl_803DF1A0;
        lbl_8039A848[3].vz = lbl_803DF1A0;
        lbl_8039A848[3].scale = lbl_803DF1A0;
        lbl_8039A848[3].flag = 0;
        lbl_8039A848[4].x = 0x107;
        lbl_8039A848[4].z = 0xb4a;
        lbl_8039A848[4].vx = lbl_803DF1A0;
        lbl_8039A848[4].vy = lbl_803DF1A0;
        lbl_8039A848[4].vz = lbl_803DF1A0;
        lbl_8039A848[4].scale = lbl_803DF1A0;
        lbl_8039A848[4].flag = 0;
        lbl_8039A848[5].x = 0;
        lbl_8039A848[5].z = 0x7d0;
        lbl_8039A848[5].vx = lbl_803DF1A0;
        lbl_8039A848[5].vy = lbl_803DF1A0;
        lbl_8039A848[5].vz = lbl_803DF244;
        normalize(&lbl_8039A848[5].vx, &lbl_8039A848[5].vy, &lbl_8039A848[5].vz);
        lbl_8039A848[5].scale = lbl_803DF1FC;
        lbl_8039A848[5].flag = 0;
        lbl_803DB76C = 0;
    }
}
#pragma pop

extern int lbl_8030F5A0[];
extern f32 lbl_803DF27C;

/*
 * --INFO--
 *
 * Function: newclouds_update
 * EN v1.0 Address: 0x80093124
 * EN v1.0 Size: 2324b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void newclouds_update(u8 *objA, u8 *objB, u8 *params) {
    u8 *env;
    u8 *p;
    int id;
    u8 fl;
    f32 vec[3];
    struct {
        s16 f8;
        s16 fa;
        s16 fc;
        s16 pad_e;
        f32 f10;
        f32 f14;
        f32 f18;
        f32 f1c;
    } args;
    f32 posA[3] = {0.0f, 0.0f, 0.0f};
    f32 posB[3] = {0.0f, 0.0f, 0.0f};

    env = saveGameGetEnvState();
    if (params == NULL) {
        return;
    }
    if (objA != NULL) {
        posA[0] = *(f32 *)(objA + 0x18);
        posA[1] = *(f32 *)(objA + 0x1c);
        posA[2] = *(f32 *)(objA + 0x20);
    }
    if (objB != NULL) {
        posB[0] = *(f32 *)(objB + 0x18);
        posB[1] = *(f32 *)(objB + 0x1c);
        posB[2] = *(f32 *)(objB + 0x20);
    }
    id = *(u16 *)(params + 0x26);
    if ((u32)id > 8) {
        return;
    }
    p = lbl_8039A828[id];
    if (p == NULL) {
        fl = params[0x58];
        if (!(fl & 4) && !(fl & 8) && !(fl & 0x20)) {
            if ((fl & 2) && (fl & 0x10) && params[0x5d] != 0) {
                newClouds(params, objB, posA[0], posA[1], posA[2]);
            } else if ((fl & 2) && (fl & 0x10)) {
                newClouds(params, objB, posB[0], posB[1], posB[2]);
            } else if (fl & 2) {
                newClouds(params, objB, posA[0], posA[1], posA[2]);
            }
        }
        if (params[0x58] & 2) {
            if (params[0x5c] == 0 || params[0x5c] == 4) {
                switch (*(u16 *)(params + 0x26)) {
                case 0:
                    *(s16 *)(env + 0xe) = (s16)*(u16 *)(params + 0x24) - 1;
                    *(int *)(env + 0x14) = posA[0];
                    *(int *)(env + 0x18) = posA[1];
                    *(int *)(env + 0x1c) = posA[2];
                    if ((s8)env[*(u16 *)(params + 0x26) + 0x41] == -1) {
                        return;
                    }
                    NC_CLOUD[0x144d] = 1 - env[*(u16 *)(params + 0x26) + 0x41];
                    if ((s8)env[*(u16 *)(params + 0x26) + 0x41] != 0) {
                        return;
                    }
                    *(f32 *)(NC_CLOUD + 0x140c) =
                        (f32)*(int *)(env + *(u16 *)(params + 0x26) * 0xc + 0x14);
                    *(f32 *)(NC_CLOUD + 0x1410) =
                        (f32)*(int *)(env + *(u16 *)(params + 0x26) * 0xc + 0x18);
                    *(f32 *)(NC_CLOUD + 0x1414) =
                        (f32)*(int *)(env + *(u16 *)(params + 0x26) * 0xc + 0x1c);
                    break;
                case 1:
                    *(s16 *)(env + 0x10) = (s16)*(u16 *)(params + 0x24) - 1;
                    *(int *)(env + 0x20) = posA[0];
                    *(int *)(env + 0x24) = posA[1];
                    *(int *)(env + 0x28) = posA[2];
                    if ((s8)env[*(u16 *)(params + 0x26) + 0x41] == -1) {
                        return;
                    }
                    NC_CLOUD[0x144d] = 1 - env[*(u16 *)(params + 0x26) + 0x41];
                    if ((s8)env[*(u16 *)(params + 0x26) + 0x41] != 0) {
                        return;
                    }
                    *(f32 *)(NC_CLOUD + 0x140c) =
                        (f32)*(int *)(env + *(u16 *)(params + 0x26) * 0xc + 0x14);
                    *(f32 *)(NC_CLOUD + 0x1410) =
                        (f32)*(int *)(env + *(u16 *)(params + 0x26) * 0xc + 0x18);
                    *(f32 *)(NC_CLOUD + 0x1414) =
                        (f32)*(int *)(env + *(u16 *)(params + 0x26) * 0xc + 0x1c);
                    break;
                case 2:
                    *(s16 *)(env + 0x12) = (s16)*(u16 *)(params + 0x24) - 1;
                    *(int *)(env + 0x2c) = posA[0];
                    *(int *)(env + 0x30) = posA[1];
                    *(int *)(env + 0x34) = posA[2];
                    if ((s8)env[*(u16 *)(params + 0x26) + 0x41] == -1) {
                        return;
                    }
                    NC_CLOUD[0x144d] = 1 - env[*(u16 *)(params + 0x26) + 0x41];
                    if ((s8)env[*(u16 *)(params + 0x26) + 0x41] != 0) {
                        return;
                    }
                    *(f32 *)(NC_CLOUD + 0x140c) =
                        (f32)*(int *)(env + *(u16 *)(params + 0x26) * 0xc + 0x14);
                    *(f32 *)(NC_CLOUD + 0x1410) =
                        (f32)*(int *)(env + *(u16 *)(params + 0x26) * 0xc + 0x18);
                    *(f32 *)(NC_CLOUD + 0x1414) =
                        (f32)*(int *)(env + *(u16 *)(params + 0x26) * 0xc + 0x1c);
                    break;
                }
            }
        }
    }
    if (p == NULL) {
        return;
    }
    fl = params[0x58];
    if (fl & 2) {
        return;
    }
    if ((fl & 8) && p[0x144e] != 0) {
        env[id + 0x41] = (s8)p[0x144d];
        NC_CLOUD[0x144d] = 1 - NC_CLOUD[0x144d];
        if (NC_CLOUD[0x144d] == 1) {
            vec[0] = lbl_803DF1A0;
            vec[1] = lbl_803DF1A0;
            vec[2] = lbl_803DF1A0;
            args.f14 = lbl_803DF1A0;
            args.f18 = lbl_803DF1A0;
            args.f1c = lbl_803DF1A0;
            args.f10 = lbl_803DF1A4;
            args.fc = 0;
            args.fa = 0;
            args.f8 = *(s16 *)objA;
            mathFn_80021ac8(&args.f8, vec);
            *(f32 *)(NC_CLOUD + 0x140c) = vec[0] + *(f32 *)(objA + 0x18);
            *(f32 *)(NC_CLOUD + 0x1410) = vec[1] + *(f32 *)(objA + 0x1c);
            *(f32 *)(NC_CLOUD + 0x1414) = vec[2] + *(f32 *)(objA + 0x20);
            if (*(f32 *)(NC_CLOUD + 0x1438) > lbl_803DF27C) {
                Music_Trigger(lbl_8030F5A0[*(int *)(NC_CLOUD + 0x13f4)], 0);
            }
        } else {
            if (*(f32 *)(NC_CLOUD + 0x1438) > lbl_803DF27C) {
                Music_Trigger(lbl_8030F5A0[*(int *)(NC_CLOUD + 0x13f4)], 1);
            }
        }
        if ((s8)env[*(u16 *)(params + 0x26) + 0x41] == 0) {
            *(int *)(env + *(u16 *)(params + 0x26) * 0xc + 0x14) = posA[0];
            *(int *)(env + *(u16 *)(params + 0x26) * 0xc + 0x18) = posA[1];
            *(int *)(env + *(u16 *)(params + 0x26) * 0xc + 0x1c) = posA[2];
        }
    } else if (fl & 0x20) {
        newclouds_snowKillSnowCloud(id, 0);
    } else if (fl & 4) {
        if (p[0x144f] != 0) {
            p[0x144f] = 0;
        }
        *(int *)(NC_CLOUD + 0x13f8) = 1 - *(int *)(NC_CLOUD + 0x13f8);
        if (*(u16 *)(params + 0x2a) != 0) {
            *(f32 *)(NC_CLOUD + 0x142c) =
                (f32)*(int *)(NC_CLOUD + 0x13fc) / (f32)*(u16 *)(params + 0x2a);
        } else {
            *(f32 *)(NC_CLOUD + 0x142c) = (f32)(*(int *)(NC_CLOUD + 0x13fc) - 1);
        }
        if (*(u16 *)(params + 0x2c) != 0) {
            *(f32 *)(NC_CLOUD + 0x1430) =
                -((f32)*(int *)(NC_CLOUD + 0x13fc) / (f32)*(u16 *)(params + 0x2c));
        } else {
            *(f32 *)(NC_CLOUD + 0x1430) = (f32)(-(*(int *)(NC_CLOUD + 0x13fc) - 1));
        }
    }
}
#pragma pop

extern void PSMTXIdentity(f32 *m);
extern void PSMTXMultVec(f32 *matrix, f32 *in, f32 *out);
extern f32 lbl_803DF200;
extern f32 lbl_803DF208;
extern f32 lbl_803DF20C;
extern f32 lbl_803DF210;
extern f32 lbl_803DF248;
extern f32 lbl_803DF24C;
extern f32 lbl_803DF250;
extern f32 lbl_803DF254;
extern f32 lbl_803DF258;
extern f32 lbl_803DF25C;
extern f32 lbl_803DF260;
extern f32 lbl_803DF264;
extern f32 lbl_803DF268;
extern f32 lbl_803DF26C;
extern f32 lbl_803DF270;
extern f32 lbl_803DF274;
extern f32 lbl_803DF278;

#define D7_CLOUD ((u8 *)lbl_8039A818[i + 4])

/*
 * --INFO--
 *
 * Function: dll_07_func06
 * EN v1.0 Address: 0x80092548
 * EN v1.0 Size: 2376b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void dll_07_func06(void) {
    s16 *cam;
    u8 *p;
    u8 *nearestCloud;
    u8 activeCount;
    int i;
    f32 *m;
    f32 *py;
    f32 *pz;
    f32 nearest;
    f32 mag;
    f32 t;
    f32 rot;
    f32 d[3];
    f32 vec[3];
    f32 pos[3];
    f32 wind[3];
    f32 inpos[3];
    struct {
        s16 f8;
        s16 fa;
        s16 fc;
        s16 pad_e;
        f32 f10;
        f32 f14;
        f32 f18;
        f32 f1c;
    } args;
    f32 mtx[12];

    nearestCloud = NULL;
    cam = Camera_GetCurrentViewSlot();
    activeCount = 0;
    nearest = lbl_803DF248;
    if (lbl_803DD1C0 == 0) {
        lbl_803DD1C8 = textureLoadAsset(0x16a);
        lbl_8039A818[0] = textureLoadAsset(0x5da);
        lbl_8039A818[1] = textureLoadAsset(0x63f);
        lbl_8039A818[2] = textureLoadAsset(0x640);
        lbl_8039A818[3] = textureLoadAsset(0x641);
        lbl_803DD1C4 = textureLoadAsset(0x151);
        lbl_803DD1C0 = 1;
    }
    if (renderModeSetOrGet(-1) == 1) {
        return;
    }
    lbl_803DD1CC = lbl_803DD19B;
    lbl_803DD19B = 0;
    py = &pos[1];
    pz = &pos[2];
    for (i = 0; i < 8; i++) {
        p = D7_CLOUD;
        if (p != NULL &&
            (*(u8 **)p == NULL || !(*(u16 *)(*(u8 **)p + 0xb0) & 0x40))) {
            snowFreeSnowCloud(*(int *)(p + 0x13f0));
            continue;
        }
        if (p != NULL && *(int *)(p + 0x1400) != 0) {
            snowCloudInitFlakes((f32 *)(p + 8), i, *(f32 *)(p + 0x1418),
                                 *(f32 *)(p + 0x141c));
        } else if (p != NULL && p[0x144f] == 0) {
            if (*(int *)(p + 0x13f4) == 4) {
                lbl_803DD19B = 1;
            }
            if (*(int *)(p + 0x13f8) != 0) {
                *(f32 *)(p + 0x1434) =
                    (f32)framesThisStep * *(f32 *)(p + 0x1430) + *(f32 *)(p + 0x1434);
                if (*(f32 *)(D7_CLOUD + 0x1434) <= lbl_803DF1A0) {
                    D7_CLOUD[0x144f] = 1;
                }
            } else {
                if ((int)*(f32 *)(p + 0x1434) < *(int *)(p + 0x13fc)) {
                    *(f32 *)(p + 0x1434) = (f32)framesThisStep * *(f32 *)(p + 0x142c) +
                                           *(f32 *)(p + 0x1434);
                }
            }
            if ((int)*(f32 *)(D7_CLOUD + 0x1434) > *(int *)(D7_CLOUD + 0x13fc)) {
                *(f32 *)(D7_CLOUD + 0x1434) = (f32)*(int *)(D7_CLOUD + 0x13fc);
            }
            if (*(f32 *)(D7_CLOUD + 0x1434) < lbl_803DF1A0) {
                *(f32 *)(D7_CLOUD + 0x1434) = lbl_803DF1A0;
            }
            if (*(u8 **)D7_CLOUD != NULL) {
                Obj_GetWorldPosition(*(u8 **)D7_CLOUD, &pos[0], py, pz);
            }
            if (D7_CLOUD[0x1452] != 0 && cam != NULL) {
                if (*(int *)(D7_CLOUD + 0x13f4) == 4) {
                    vec[0] = lbl_803DF1A0;
                    vec[1] = lbl_803DF1A0;
                    vec[2] = lbl_803DF1FC;
                    args.f14 = lbl_803DF1A0;
                    args.f18 = lbl_803DF1A0;
                    args.f1c = lbl_803DF1A0;
                    args.f10 = lbl_803DF1A4;
                    args.fc = 0;
                    args.fa = 0;
                    args.f8 = 0xffff - *cam;
                    mathFn_80021ac8(&args.f8, vec);
                    pos[0] = *(f32 *)((u8 *)cam + 0x44) + vec[0];
                    pos[1] = (*(f32 *)((u8 *)cam + 0x48) - lbl_803DF24C) + vec[1];
                    pos[2] = *(f32 *)((u8 *)cam + 0x4c) + vec[2];
                } else {
                    pos[0] = *(f32 *)((u8 *)cam + 0x44);
                    pos[1] = *(f32 *)((u8 *)cam + 0x48) - lbl_803DF24C;
                    pos[2] = *(f32 *)((u8 *)cam + 0x4c);
                }
            }
            *(f32 *)(D7_CLOUD + 0x1440) = (f32)framesThisStep * *(f32 *)(D7_CLOUD + 0x1444) +
                                          *(f32 *)(D7_CLOUD + 0x1440);
            if (lbl_803DF1A0 != *(f32 *)(D7_CLOUD + 0x1438)) {
                if (*(f32 *)(D7_CLOUD + 0x1440) > *(f32 *)(D7_CLOUD + 0x143c)) {
                    *(f32 *)(D7_CLOUD + 0x1444) =
                        *(f32 *)(D7_CLOUD + 0x1444) * lbl_803DF244;
                    *(f32 *)(D7_CLOUD + 0x1440) = *(f32 *)(D7_CLOUD + 0x143c);
                } else if (*(f32 *)(D7_CLOUD + 0x1440) < lbl_803DF1A0) {
                    *(f32 *)(D7_CLOUD + 0x1444) =
                        *(f32 *)(D7_CLOUD + 0x1444) * lbl_803DF244;
                    *(f32 *)(D7_CLOUD + 0x143c) = (f32)(int)randomGetRange(
                        1, (int)(lbl_803DF1C8 * *(f32 *)(D7_CLOUD + 0x1438)));
                    *(f32 *)(D7_CLOUD + 0x1440) = lbl_803DF1A0;
                }
            }
            if (D7_CLOUD[0x144d] == 0) {
                inpos[0] = pos[0];
                inpos[1] = pos[1];
                inpos[2] = pos[2];
                snowCloudComputeDrift(wind, inpos, *(f32 *)(D7_CLOUD + 0x1438));
                if (*(int *)(D7_CLOUD + 0x13f4) == 0) {
                    *(f32 *)(D7_CLOUD + 0x1420) = -wind[0];
                    *(f32 *)(D7_CLOUD + 0x1424) = -wind[2];
                } else {
                    *(f32 *)(D7_CLOUD + 0x1420) =
                        -(wind[0] + *(f32 *)(D7_CLOUD + 0x1440));
                    *(f32 *)(D7_CLOUD + 0x1424) =
                        -(wind[2] + *(f32 *)(D7_CLOUD + 0x1440));
                    *(f32 *)(D7_CLOUD + 0x1428) = lbl_803DF1A0;
                }
                *(f32 *)(D7_CLOUD + 0x140c) = pos[0];
                *(f32 *)(D7_CLOUD + 0x1410) = pos[1];
                *(f32 *)(D7_CLOUD + 0x1414) = pos[2];
            } else {
                inpos[0] = *(f32 *)(p + 0x140c);
                inpos[1] = *(f32 *)(p + 0x1410);
                inpos[2] = *(f32 *)(p + 0x1414);
                snowCloudComputeDrift(wind, inpos, *(f32 *)(p + 0x1438));
                *(f32 *)(D7_CLOUD + 0x1420) = -wind[0] + *(f32 *)(D7_CLOUD + 0x1440);
                *(f32 *)(D7_CLOUD + 0x1424) = -wind[2] + *(f32 *)(D7_CLOUD + 0x1440);
                *(f32 *)(D7_CLOUD + 0x1428) = lbl_803DF1A0;
            }
            if (D7_CLOUD[0x1453] != 0) {
                *(f32 *)(D7_CLOUD + 0x13e4) = *(f32 *)(D7_CLOUD + 0x13d8);
                *(f32 *)(D7_CLOUD + 0x13e8) = *(f32 *)(D7_CLOUD + 0x13dc);
                *(f32 *)(D7_CLOUD + 0x13ec) = *(f32 *)(D7_CLOUD + 0x13e0);
            } else {
                *(f32 *)(D7_CLOUD + 0x13e4) = pos[0];
                *(f32 *)(D7_CLOUD + 0x13e8) = pos[1];
                *(f32 *)(D7_CLOUD + 0x13ec) = pos[2];
                D7_CLOUD[0x1453] = 1;
            }
            *(f32 *)(D7_CLOUD + 0x13d8) = pos[0];
            *(f32 *)(D7_CLOUD + 0x13dc) = pos[1];
            *(f32 *)(D7_CLOUD + 0x13e0) = pos[2];
            snowReposSnowCloud(*(int *)(D7_CLOUD + 0x13f0));
            if (*(f32 *)(D7_CLOUD + 0x1434) > lbl_803DF1A0) {
                d[0] = *(f32 *)(D7_CLOUD + 0x140c) - *(f32 *)((u8 *)cam + 0xc);
                d[1] = *(f32 *)(D7_CLOUD + 0x1410) - *(f32 *)((u8 *)cam + 0x10);
                d[2] = *(f32 *)(D7_CLOUD + 0x1414) - *(f32 *)((u8 *)cam + 0x14);
                mag = PSVECMag(d);
                if (mag < nearest) {
                    nearest = mag;
                    nearestCloud = D7_CLOUD;
                }
            }
        }
        if (D7_CLOUD != NULL && *(int *)(D7_CLOUD + 0x13f4) == 4 &&
            D7_CLOUD[0x144d] == 0) {
            activeCount++;
        }
    }
    if (activeCount != 0) {
        lbl_803DD194 = lbl_803DF1BC;
    } else {
        lbl_803DD194 = lbl_803DF250;
    }
    if (lbl_803DD19C != NULL) {
        *(u16 *)(lbl_803DD19C + 0x20) = *(u16 *)(lbl_803DD19C + 0x20) + 1;
        if (*(u16 *)(lbl_803DD19C + 0x20) >= *(u16 *)(lbl_803DD19C + 0x22)) {
            mm_free(lbl_803DD19C);
            lbl_803DD19C = NULL;
        }
    }
    t = lbl_803DF254 * timeDelta + lbl_803DD1BC;
    lbl_803DD1BC = t;
    if (t > lbl_803DF258) {
        lbl_803DD1BC = t - lbl_803DF258;
    }
    t = lbl_803DF25C * timeDelta + lbl_803DD1B8;
    lbl_803DD1B8 = t;
    if (t > lbl_803DF258) {
        lbl_803DD1B8 = t - lbl_803DF258;
    }
    t = lbl_803DD1B4 - lbl_803DF260 * timeDelta;
    lbl_803DD1B4 = t;
    if (t < lbl_803DF264) {
        lbl_803DD1B4 = t + lbl_803DF258;
    }
    t = lbl_803DB760 + lbl_803DD194;
    lbl_803DB760 = t;
    if (t > lbl_803DF1A4) {
        lbl_803DB760 = lbl_803DF1A4;
    } else if (t < lbl_803DF1A0) {
        lbl_803DB760 = lbl_803DF1A0;
    }
    lbl_803DD198 = 0;
    if (nearestCloud != NULL && *(int *)(nearestCloud + 0x13f4) == 4) {
        lbl_803DD198 = lbl_803DF1D4 * lbl_803DB760;
        if (lbl_803DD198 != 0) {
            rot = lbl_803DF1C4 *
                  (lbl_803DF1C8 *
                   -(lbl_803DF20C * (*(f32 *)(nearestCloud + 0x1440) / lbl_803DF210) +
                     lbl_803DF208)) /
                  lbl_803DF268;
            *(f32 *)((u8 *)lbl_8039A818 + 0xd8) = lbl_803DF1A0;
            *(f32 *)((u8 *)lbl_8039A818 + 0xdc) = lbl_803DF244;
            *(f32 *)((u8 *)lbl_8039A818 + 0xe0) = lbl_803DF1A0;
            m = Camera_GetViewRotationMatrix();
            if (*(int *)(nearestCloud + 0x13f4) == 0) {
                lbl_803DD190 = lbl_803DF200 * (lbl_803DF26C * timeDelta) + lbl_803DD190;
                lbl_803DB764 = lbl_803DF270;
                lbl_803DD199 = 0xf9;
                lbl_803DD19A = 0xfd;
                lbl_803DB768 = lbl_803DF274;
                PSMTXIdentity(mtx);
            } else {
                lbl_803DD190 = lbl_803DF26C * timeDelta + lbl_803DD190;
                lbl_803DB764 = lbl_803DF1A4;
                lbl_803DD199 = 0xf8;
                lbl_803DD19A = 0xfc;
                lbl_803DB768 = lbl_803DF1A4;
                PSMTXRotRad(mtx, 0x7a, rot);
            }
            PSMTXConcat((void *)m, (void *)mtx, (void *)mtx);
            PSMTXMultVec(mtx, (f32 *)((u8 *)lbl_8039A818 + 0xd8),
                         (f32 *)((u8 *)lbl_8039A818 + 0xd8));
            if (lbl_803DD190 < lbl_803DF278) {
                lbl_803DD190 = lbl_803DD190 + lbl_803DF1E8;
            }
        }
    }
    if (lbl_803DD19B != 0 && lbl_803DD1CC == 0) {
        Music_Trigger(0xeb, 1);
    } else if (lbl_803DD19B == 0 && lbl_803DD1CC != 0) {
        Music_Trigger(0xeb, 0);
    }
}
#pragma pop

extern char sSnowPrintSnowCloudInvalidCloudId[];
extern void initRotationMtx(f32 *mtx, f32 xScale, f32 yScale, f32 zScale);
extern void mtx44_mult(f32 *a, f32 *b, f32 *out);
extern void mtx44Transpose(f32 *in, f32 *out);
extern void getAmbientColor(int mode, u8 *r, u8 *g, u8 *b);
extern void gxBlendFn_80078b4c(void);
extern int lbl_803DD1A4;
extern f32 lbl_803DF204;

/*
 * --INFO--
 *
 * Function: snowPrintSnowCloud
 * EN v1.0 Address: 0x80090250
 * EN v1.0 Size: 2456b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
int snowPrintSnowCloud(int arg, int cloudId) {
    u8 *p;
    u8 *part;
    int i;
    int j;
    int texIdx;
    u8 hudHidden;
    u8 cr;
    u8 cg;
    u8 cb;
    f32 scale;
    f32 driftX;
    f32 driftZ;
    f32 stepX;
    f32 stepZ;
    f32 yb;
    f32 size;
    int base;
    f32 mtxA[16];
    f32 mtxB[16];
    f32 mtxOut[16];
    f32 mtxT[12];
    f32 vx[3];
    f32 vy[3];
    f32 vz[3];
    s16 uvs[6] = {-0x30, 0, 0xb0, 0, 0x40, 0x100};

    scale = lbl_803DF1A4;
    if (renderModeSetOrGet(-1) == 1) {
        return 0;
    }
    for (i = 0; i < 8; i++) {
        p = lbl_8039A828[i];
        if (p != NULL && cloudId == *(int *)(p + 0x13f0)) {
            break;
        }
    }
    p = lbl_8039A828[i];
    if (p == NULL || i == 8) {
        return 0;
    }
    if (cloudId != *(int *)(p + 0x13f0)) {
        debugPrintf(sSnowPrintSnowCloudInvalidCloudId, cloudId);
        return 0;
    }
    lbl_803DD1A4 = lbl_803DF1FC * timeDelta + (f32)lbl_803DD1A4;
    if (lbl_803DD1A4 > 0xffff) {
        lbl_803DD1A4 = 0;
    }
    scale = scale * lbl_803DF200;
    initRotationMtx(mtxA, scale, scale, scale);
    memset(mtxB, 0, 0x40);
    mtxB[0] = lbl_803DF1A4;
    mtxB[5] = lbl_803DF1A4;
    mtxB[10] = lbl_803DF1A4;
    mtxB[15] = lbl_803DF1A4;
    if (*(int *)(p + 0x13f4) != 4 && p[0x1451] != 0) {
        mtxB[0] = sin((lbl_803DF1F0 * (f32)lbl_803DD1A4) / lbl_803DF1F4);
        mtxB[1] = -fn_80293E80((lbl_803DF1F0 * (f32)lbl_803DD1A4) / lbl_803DF1F4);
        mtxB[4] = fn_80293E80((lbl_803DF1F0 * (f32)lbl_803DD1A4) / lbl_803DF1F4);
        mtxB[5] = sin((lbl_803DF1F0 * (f32)lbl_803DD1A4) / lbl_803DF1F4);
    } else if (*(int *)(p + 0x13f4) == 4) {
        if (p[0x144a] & 0x80) {
            mtxB[0] = sin(lbl_803DF204);
            mtxB[1] = -fn_80293E80(lbl_803DF204);
            mtxB[4] = fn_80293E80(lbl_803DF204);
            mtxB[5] = sin(lbl_803DF204);
        } else if (p[0x1451] != 0) {
            lbl_803DD1A4 =
                lbl_803DF20C * (*(f32 *)(p + 0x1440) / lbl_803DF210) + lbl_803DF208;
            mtxB[0] = sin((lbl_803DF1F0 * (f32)-lbl_803DD1A4) / lbl_803DF1F4);
            mtxB[1] = -fn_80293E80((lbl_803DF1F0 * (f32)-lbl_803DD1A4) / lbl_803DF1F4);
            mtxB[4] = fn_80293E80((lbl_803DF1F0 * (f32)-lbl_803DD1A4) / lbl_803DF1F4);
            mtxB[5] = sin((lbl_803DF1F0 * (f32)-lbl_803DD1A4) / lbl_803DF1F4);
        }
    }
    mtxB[12] = *(f32 *)(p + 0x140c) - playerMapOffsetX;
    mtxB[13] = *(f32 *)(p + 0x1410);
    mtxB[14] = *(f32 *)(p + 0x1414) - playerMapOffsetZ;
    mtx44_mult(mtxA, mtxB, mtxOut);
    mtx44Transpose(mtxOut, mtxT);
    PSMTXConcat((void *)Camera_GetViewMatrix(), (void *)mtxT, (void *)mtxT);
    GXLoadPosMtxImm(mtxT, 0);
    texIdx = 0;
    if (*(int *)(p + 0x13f4) == 0) {
        selectTexture(lbl_8039A818[0], 0);
    } else {
        selectTexture(lbl_803DD1C4, 0);
    }
    GXSetCullMode(0);
    textureSetupFn_800799c0();
    textRenderSetupFn_800795e8();
    textRenderSetupFn_80079804();
    if (*(int *)(p + 0x13f4) == 4) {
        setTextColor(arg, 0x7d, 0x7d, 0x9b, 0xff);
    } else if (*(int *)(p + 0x13f4) == 0) {
        getAmbientColor(0, &cr, &cg, &cb);
        setTextColor(arg, cr, cg, cb, 0xff);
    }
    gxBlendFn_80078b4c();
    GXClearVtxDesc();
    GXSetVtxDesc(0, 1);
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xb, 1);
    GXSetVtxDesc(0xd, 1);
    GXSetCurrentMtx(0);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
    hudHidden = getHudHiddenFrameCount();
    driftX = lbl_803DF1E4 * (*(f32 *)(p + 0x13e4) - *(f32 *)(p + 0x13d8));
    stepX = lbl_803DF214 * *(f32 *)(p + 0x1378);
    if (driftX < stepX) {
    } else {
        stepX = lbl_803DF214 * *(f32 *)(p + 0x1390);
        if (driftX > stepX) {
        } else {
            stepX = driftX;
        }
    }
    driftZ = lbl_803DF1E4 * (*(f32 *)(p + 0x13ec) - *(f32 *)(p + 0x13e0));
    stepZ = lbl_803DF214 * *(f32 *)(p + 0x1380);
    if (driftZ < stepZ) {
    } else {
        stepZ = lbl_803DF214 * *(f32 *)(p + 0x13b0);
        if (driftZ > stepZ) {
        } else {
            stepZ = driftZ;
        }
    }
    if (*(int *)(p + 0x13f4) == 4) {
        GXBegin(0x90, 4, (u16)(*(int *)(p + 0x13fc) * 3));
    } else {
        GXBegin(0x90, 4, (u16)(*(int *)(p + 0x13fc) * 3 / 4));
    }
    part = *(u8 **)(p + 4);
    for (j = 0; j < *(int *)(p + 0x13fc); j++) {
        if (part[0x16] != (u8)texIdx) {
            texIdx = part[0x16];
            selectTexture(lbl_8039A818[texIdx], 0);
            GXBegin(0x90, 4, (u16)(*(int *)(p + 0x13fc) * 3 / 4));
        }
        if (hudHidden == 0) {
            if (p[0x144d] == 0) {
                *(f32 *)part = *(f32 *)part + stepX;
                *(f32 *)(part + 8) = *(f32 *)(part + 8) + stepZ;
            }
            *(f32 *)part = *(f32 *)(p + 0x1420) * timeDelta + *(f32 *)part;
            *(f32 *)(part + 8) = *(f32 *)(p + 0x1424) * timeDelta + *(f32 *)(part + 8);
            if (*(f32 *)part < *(f32 *)(p + 0x1378)) {
                *(f32 *)part = lbl_803DF1C8 * *(f32 *)(p + 0x1390) + *(f32 *)part;
            } else if (*(f32 *)part > *(f32 *)(p + 0x1390)) {
                *(f32 *)part = *(f32 *)part - lbl_803DF1C8 * *(f32 *)(p + 0x1390);
            }
            if (*(f32 *)(part + 8) < *(f32 *)(p + 0x1380)) {
                *(f32 *)(part + 8) =
                    lbl_803DF1C8 * *(f32 *)(p + 0x13b0) + *(f32 *)(part + 8);
            } else if (*(f32 *)(part + 8) > *(f32 *)(p + 0x13b0)) {
                *(f32 *)(part + 8) =
                    *(f32 *)(part + 8) - lbl_803DF1C8 * *(f32 *)(p + 0x13b0);
            }
        }
        yb = *(f32 *)(part + 4) - *(f32 *)(p + *(u16 *)(part + 0x10) * 4 + 8);
        base = *(u16 *)(part + 0x12) * 0x2c;
        size = *(f32 *)(part + 0xc);
        vx[0] = *(f32 *)(p + base + 0x1008) * size + *(f32 *)part;
        vy[0] = *(f32 *)(p + base + 0x1014) * size + yb;
        vz[0] = *(f32 *)(p + base + 0x1020) * size + *(f32 *)(part + 8);
        vx[1] = *(f32 *)(p + base + 0x100c) * size + *(f32 *)part;
        vy[1] = *(f32 *)(p + base + 0x1018) * size + yb;
        vz[1] = *(f32 *)(p + base + 0x1024) * size + *(f32 *)(part + 8);
        vx[2] = *(f32 *)(p + base + 0x1010) * size + *(f32 *)part;
        vy[2] = *(f32 *)(p + base + 0x101c) * size + yb;
        vz[2] = *(f32 *)(p + base + 0x1028) * size + *(f32 *)(part + 8);
        GXWGFifo.f32 = vx[0];
        GXWGFifo.f32 = vy[0];
        GXWGFifo.f32 = vz[0];
        GXWGFifo.s16 = uvs[0];
        GXWGFifo.s16 = uvs[1];
        GXWGFifo.f32 = vx[1];
        GXWGFifo.f32 = vy[1];
        GXWGFifo.f32 = vz[1];
        GXWGFifo.s16 = uvs[2];
        GXWGFifo.s16 = uvs[3];
        GXWGFifo.f32 = vx[2];
        GXWGFifo.f32 = vy[2];
        GXWGFifo.f32 = vz[2];
        GXWGFifo.s16 = uvs[4];
        GXWGFifo.s16 = uvs[5];
        part += 0x18;
    }
    return 0;
}
#pragma pop
