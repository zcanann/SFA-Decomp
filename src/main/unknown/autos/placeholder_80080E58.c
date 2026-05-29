#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80080E58.h"

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
extern int seqEvalCondition(int condition, u8 *seq, int obj);
extern int isGameTimerDisabled(void);
extern void playerEnvFxFn_80088ad4(int envFxValue);
extern void renderSunAndMoon(void);
extern void *Obj_AllocObjectSetup(int size, int objectId);
extern void *Obj_SetupObject(void *setup, int mode, int mapLayer, int objIndex, void *parent);
extern void *Obj_GetActiveModel(void *obj);
extern void ObjModel_SetRenderCallback(void *model, void *callback);
extern int moonFxCb_80074110(int obj, int *model, int param);
extern void modelStruct2_setVectors(void *model, f32 x, f32 y, f32 z);
extern void modelLightStruct_setColorsA8AC(void *model, int red, int green, int blue, int alpha);
extern void colorFn_8001efe0(int index, int red, int green, int blue);
extern void PSMTXScale(f32 mtx[3][4], f32 x, f32 y, f32 z);
extern void PSMTXConcat(f32 a[3][4], f32 b[3][4], f32 out[3][4]);
extern void Obj_BuildWorldTransformMatrix(void *obj, f32 mtx[3][4], int flags);
extern void skyFn_8008a04c(void);
extern void skyFn_8008a500(void);
extern void renderFn_8008f904(void *state);
extern void Obj_GetWorldPosition(void *obj, f32 *x, f32 *y, f32 *z);
extern void Camera_GetCurrentViewSlot(void);
extern int randomGetRange(int min, int max);
extern int return0xFFFF_80008B6C(int obj, int a, int b, int c, int d, int e, int f);
extern void objSeqUpdateMoreCurves(u8 *obj, u8 *seqObj, u8 *seq, int mode);
extern void objSeqUpdateCurves(u8 *obj, u8 *seqObj, u8 *seq, int mode);
extern void objAnimCurvFn_800849e8(u8 *obj, u8 *seq);
extern int hitDetectFn_800658a4(void *obj, f32 x, f32 y, f32 z, f32 *out, int flags);
extern void objAnimFn_8008718c(u8 *obj, u8 *seqObj, u8 *seq);
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
extern int *gGameUIInterface;
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
extern u8 *lbl_803DD148;
extern void *lbl_803DD14C;
extern void *lbl_803DD150;
extern int lbl_803DD154;
extern u8 lbl_803DD158;
extern u8 lbl_803DD15C;
extern f32 lbl_803DD160;
extern u8 lbl_803DD164;
extern void *lbl_803DD168;
extern u8 lbl_803DD170;
extern u8 lbl_803DD174;
extern u8 lbl_803DD178;
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
extern f32 lbl_8039A7A8[];
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
extern f32 lbl_803DF118;
extern f32 lbl_803DF138;
extern f32 lbl_803DF13C;
extern f32 lbl_803DF140;
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
extern undefined4 FUN_800033a8();
extern int FUN_80006714();
extern undefined4 FUN_8000671c();
extern undefined8 FUN_80006724();
extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern bool FUN_800067f8();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006818();
extern undefined4 FUN_80006820();
extern undefined4 FUN_80006824();
extern undefined8 FUN_80006898();
extern int FUN_800068a0();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern undefined4 FUN_800068f4();
extern undefined4 FUN_800068fc();
extern undefined4 FUN_8000691c();
extern undefined4 FUN_80006930();
extern undefined4 FUN_80006938();
extern undefined4 FUN_80006940();
extern undefined4 FUN_80006958();
extern undefined4 FUN_80006964();
extern void* FUN_80006974();
extern undefined4 FUN_8000697c();
extern undefined4 FUN_80006984();
extern void* FUN_800069a8();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_800069d4();
extern double FUN_800069d8();
extern undefined4 FUN_800069e0();
extern double FUN_800069f8();
extern undefined4 FUN_80006a0c();
extern double FUN_80006a20();
extern double FUN_80006a28();
extern double FUN_80006a30();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_80006b98();
extern uint FUN_80006c00();
extern undefined8 FUN_80006c1c();
extern undefined4 FUN_80006c28();
extern undefined4 FUN_800174b8();
extern undefined4 FUN_800174f4();
extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017588();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175d4();
extern undefined4 FUN_800175d8();
extern undefined4 FUN_800175e8();
extern undefined4 FUN_800175ec();
extern undefined4 FUN_80017610();
extern undefined4 FUN_80017618();
extern undefined4 FUN_80017620();
extern undefined4 FUN_80017624();
extern undefined8 FUN_80017640();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_800176a8();
extern int FUN_800176d0();
extern undefined4 FUN_80017704();
extern undefined4 FUN_80017710();
extern int FUN_80017730();
extern undefined4 FUN_80017740();
extern undefined4 FUN_80017748();
extern undefined4 FUN_8001776c();
extern undefined4 FUN_800177bc();
extern undefined8 FUN_80017810();
extern undefined8 FUN_80017814();
extern int FUN_80017830();
extern undefined4 FUN_800178e8();
extern int FUN_8001792c();
extern undefined4 FUN_80017964();
extern undefined4 FUN_80017a2c();
extern undefined4 FUN_80017a50();
extern int FUN_80017a54();
extern undefined8 FUN_80017a78();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined8 FUN_80017ac8();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern undefined4 FUN_80017b00();
extern int FUN_8002f6ac();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjMsg_SendToNearbyObjects();
extern undefined8 ObjMsg_SendToObjects();
extern undefined4 ObjMsg_SendToObject();
extern void* FUN_80039518();
extern int FUN_80039520();
extern undefined4 FUN_8003964c();
extern undefined4 FUN_8003aa48();
extern undefined4 FUN_8003b878();
extern undefined4 FUN_8003ba74();
extern undefined4 FUN_8004034c();
extern int FUN_80042838();
extern int FUN_80042c18();
extern undefined8 FUN_80044400();
extern undefined4 FUN_80044424();
extern undefined4 FUN_80045c4c();
extern undefined8 FUN_8004600c();
extern undefined4 FUN_800480a0();
extern undefined4 FUN_8004812c();
extern uint FUN_80053078();
extern undefined4 FUN_80053740();
extern undefined8 FUN_80053754();
extern int FUN_800537a0();
extern int FUN_8005398c();
extern undefined8 FUN_80053c08();
extern undefined8 FUN_80053c20();
extern undefined4 FUN_80053c98();
extern int FUN_80056600();
extern int FUN_8005b024();
extern uint FUN_8005d084();
extern uint FUN_8005d130();
extern undefined4 FUN_8005d160();
extern undefined4 FUN_8005d17c();
extern void fn_8005D108();
extern undefined4 FUN_8005d314();
extern undefined4 FUN_8005d370();
extern undefined4 FUN_8005fdf0();
extern undefined4 FUN_800616c4();
extern int FUN_800632e8();
extern undefined4 FUN_80064030();
extern undefined4 FUN_8006af68();
extern int FUN_8006f690();
extern uint FUN_8006f764();
extern undefined4 FUN_8006f7a0();
extern undefined4 FUN_8006f8a4();
extern undefined4 FUN_8006f8fc();
extern void trackIntersect_updateColorBandRange(double param_1,double param_2);
extern undefined4 FUN_8006fd7c();
extern undefined4 FUN_8007076c();
extern undefined4 FUN_80070f94();
extern undefined4 FUN_80071064();
extern undefined4 FUN_80071134();
extern undefined4 FUN_800712d4();
extern undefined4 FUN_80071834();
extern undefined4 FUN_80071c68();
extern undefined4 FUN_80071d70();
extern undefined4 FUN_80071f8c();
extern undefined4 FUN_80071f90();
extern undefined4 FUN_80071fb4();
extern undefined4 FUN_80072038();
extern undefined4 FUN_80072048();
extern undefined4 FUN_800722e0();
extern undefined4 FUN_800722e4();
extern undefined4 FUN_800722ec();
extern int FUN_8007f56c();
extern undefined4 FUN_8007f5ec();
extern undefined4 FUN_8007f818();
extern undefined4 FUN_8007fa8c();
extern int FUN_8007fb80();
extern void* FUN_800e87a8();
extern int FUN_800e8b98();
extern int FUN_8012ef0c();
extern undefined8 FUN_80130298();
extern undefined8 FUN_80135810();
extern undefined4 FUN_80135814();
extern undefined4 FUN_802420b0();
extern undefined4 FUN_80242114();
extern undefined8 FUN_802473b4();
extern undefined4 FUN_802475b8();
extern undefined4 FUN_80247618();
extern undefined4 PSVECDotProduct();
extern undefined4 FUN_80247944();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247a7c();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_80247cd8();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined8 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double SeekTwiceBeforeRead();
extern undefined4 FUN_80247fb0();
extern double FUN_802480c0();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_802585d8();
extern undefined4 FUN_80258674();
extern undefined4 FUN_80258944();
extern undefined4 __GXSendFlushPrim();
extern undefined4 FUN_80258a60();
extern undefined4 FUN_80259000();
extern undefined4 FUN_80259178();
extern undefined4 FUN_802591d0();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025be54();
extern undefined4 FUN_8025be80();
extern undefined4 FUN_8025c1a4();
extern undefined4 FUN_8025c224();
extern undefined4 FUN_8025c2a8();
extern undefined4 FUN_8025c368();
extern undefined4 FUN_8025c510();
extern undefined4 GXSetBlendMode();
extern undefined4 FUN_8025c5f0();
extern undefined4 FUN_8025c65c();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025c828();
extern undefined4 FUN_8025ca04();
extern undefined8 FUN_8025ca38();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025cdec();
extern undefined4 FUN_8025d4a0();
extern undefined4 FUN_8025d568();
extern undefined4 FUN_8025d63c();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d888();
extern undefined4 FUN_8025da88();
extern undefined4 FUN_8025db38();
extern longlong FUN_8028680c();
extern undefined4 FUN_80286814();
extern undefined4 FUN_80286818();
extern undefined8 FUN_8028681c();
extern undefined8 FUN_80286820();
extern undefined8 FUN_80286828();
extern undefined8 FUN_8028682c();
extern int FUN_80286830();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern uint FUN_80286840();
extern undefined4 FUN_80286858();
extern undefined4 FUN_80286860();
extern undefined4 FUN_80286864();
extern undefined4 FUN_80286868();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286874();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern int FUN_80291d74();
extern undefined4 FUN_80293520();
extern undefined8 FUN_80293544();
extern undefined4 FUN_80293470();
extern double FUN_80293900();
extern undefined4 fcos16Precise();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80293f94();
extern undefined4 FUN_80294964();
extern undefined4 sinf();
extern undefined8 FUN_80294c34();
extern undefined8 FUN_80294d18();
extern undefined8 FUN_80294d1c();
extern undefined8 FUN_80294d7c();
extern uint FUN_80294d80();
extern undefined4 FUN_80294da8();
extern undefined4 FUN_80294dac();
extern undefined4 FUN_80294db0();
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

/*
 * --INFO--
 *
 * Function: FUN_80080e58
 * EN v1.0 Address: 0x80080E58
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80080EA4
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080e58(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080e5c
 * EN v1.0 Address: 0x80080E5C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80081074
 * EN v1.1 Size: 2948b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080e5c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

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
int FUN_80080e60(double param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
                undefined4 param_10,undefined4 param_11,int *param_12,int *param_13,int param_14,
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
 * Function: FUN_80080e70
 * EN v1.0 Address: 0x80080E70
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80081F84
 * EN v1.1 Size: 952b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080e70(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080e74
 * EN v1.0 Address: 0x80080E74
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008233C
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080e74(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080e78
 * EN v1.0 Address: 0x80080E78
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80082398
 * EN v1.1 Size: 320b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080e78(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080e7c
 * EN v1.0 Address: 0x80080E7C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800824D8
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080e7c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080e80
 * EN v1.0 Address: 0x80080E80
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80082728
 * EN v1.1 Size: 1588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080e80(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080e84
 * EN v1.0 Address: 0x80080E84
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80082D5C
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080e84(undefined4 param_1,int param_2,int *param_3)
{
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
double FUN_80080e88(undefined8 param_1,undefined8 param_2,double param_3,float *param_4,int param_5,
                   int param_6)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080e90
 * EN v1.0 Address: 0x80080E90
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80083108
 * EN v1.1 Size: 2196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080e90(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,uint param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080e94
 * EN v1.0 Address: 0x80080E94
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008399C
 * EN v1.1 Size: 1248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080e94(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,uint *param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,uint param_16)
{
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
undefined4 FUN_80080e98(undefined4 param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080ea0
 * EN v1.0 Address: 0x80080EA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008408C
 * EN v1.1 Size: 912b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ea0(undefined4 param_1,undefined4 param_2,int param_3,char param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080ea4
 * EN v1.0 Address: 0x80080EA4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008441C
 * EN v1.1 Size: 564b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ea4(double param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080ea8
 * EN v1.0 Address: 0x80080EA8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80084650
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ea8(undefined4 *param_1,undefined4 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080eac
 * EN v1.0 Address: 0x80080EAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80084744
 * EN v1.1 Size: 1328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080eac(undefined4 param_1,undefined4 param_2,float *param_3,short *param_4,char param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080eb0
 * EN v1.0 Address: 0x80080EB0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80084C74
 * EN v1.1 Size: 624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080eb0(int param_1,int param_2)
{
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
int FUN_80080eb4(int param_1,uint param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080ebc
 * EN v1.0 Address: 0x80080EBC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80084F70
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ebc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080ec0
 * EN v1.0 Address: 0x80080EC0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008504C
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ec0(int param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080ec4
 * EN v1.0 Address: 0x80080EC4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800852AC
 * EN v1.1 Size: 824b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ec4(undefined4 param_1,undefined4 param_2,uint param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080ec8
 * EN v1.0 Address: 0x80080EC8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800855E4
 * EN v1.1 Size: 2012b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ec8(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,undefined4 *param_11,undefined **param_12,undefined4 param_13,
                 undefined4 param_14,int *param_15,int param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080ecc
 * EN v1.0 Address: 0x80080ECC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80085DC0
 * EN v1.1 Size: 656b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ecc(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,int *param_11,int param_12,int *param_13,int param_14,
                 int *param_15,int param_16)
{
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
short * FUN_80080ed0(double param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                    undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,
                    int *param_10,int param_11,int *param_12,int *param_13,int param_14,
                    int *param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080ed8
 * EN v1.0 Address: 0x80080ED8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800862E4
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ed8(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080edc
 * EN v1.0 Address: 0x80080EDC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80086404
 * EN v1.1 Size: 1728b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080edc(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,int *param_11,int *param_12,int *param_13,int param_14,
                 int *param_15,int param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080ee0
 * EN v1.0 Address: 0x80080EE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80086AC4
 * EN v1.1 Size: 2388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ee0(undefined8 param_1,undefined8 param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,int param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080ee4
 * EN v1.0 Address: 0x80080EE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80087418
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ee4(short *param_1,short *param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080ee8
 * EN v1.0 Address: 0x80080EE8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008760C
 * EN v1.1 Size: 3912b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ee8(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
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
undefined FUN_80080eec(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080ef4
 * EN v1.0 Address: 0x80080EF4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80088644
 * EN v1.1 Size: 760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ef4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080ef8
 * EN v1.0 Address: 0x80080EF8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008893C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ef8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080efc
 * EN v1.0 Address: 0x80080EFC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80088960
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080efc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f00
 * EN v1.0 Address: 0x80080F00
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800889BC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f00(undefined *param_1)
{
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
uint FUN_80080f04(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080f0c
 * EN v1.0 Address: 0x80080F0C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80088A14
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f0c(byte param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f10
 * EN v1.0 Address: 0x80080F10
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80088A58
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f10(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f14
 * EN v1.0 Address: 0x80080F14
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80088A84
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f14(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 byte param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f18
 * EN v1.0 Address: 0x80080F18
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80088AFC
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f18(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f1c
 * EN v1.0 Address: 0x80080F1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80088B10
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f1c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f20
 * EN v1.0 Address: 0x80080F20
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80088D60
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f20(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 byte param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f24
 * EN v1.0 Address: 0x80080F24
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80088E98
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f24(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f28
 * EN v1.0 Address: 0x80080F28
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80088F20
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f28(uint param_1,char param_2)
{
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
byte FUN_80080f2c(int param_1)
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
undefined FUN_80080f34(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080f3c
 * EN v1.0 Address: 0x80080F3C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800890E0
 * EN v1.1 Size: 476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f3c(double param_1,uint param_2)
{
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
undefined FUN_80080f40(void)
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
undefined4 FUN_80080f48(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080f50
 * EN v1.0 Address: 0x80080F50
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800893C0
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f50(float *param_1)
{
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
undefined FUN_80080f54(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080f5c
 * EN v1.0 Address: 0x80080F5C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80089468
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f5c(undefined param_1,undefined param_2,undefined param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f60
 * EN v1.0 Address: 0x80080F60
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008947C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f60(undefined param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f64
 * EN v1.0 Address: 0x80080F64
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80089484
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f64(double param_1,double param_2,double param_3,double param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f68
 * EN v1.0 Address: 0x80080F68
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800894C0
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f68(undefined param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f6c
 * EN v1.0 Address: 0x80080F6C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800894C8
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f6c(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f70
 * EN v1.0 Address: 0x80080F70
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80089734
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f70(double param_1,double param_2,double param_3,uint param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f74
 * EN v1.0 Address: 0x80080F74
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008979C
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f74(uint param_1,undefined param_2,undefined param_3,undefined param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f78
 * EN v1.0 Address: 0x80080F78
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80089804
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f78(uint param_1,undefined param_2,undefined param_3,undefined param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f7c
 * EN v1.0 Address: 0x80080F7C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008986C
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f7c(uint param_1,byte param_2,byte param_3,byte param_4,uint param_5,uint param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f80
 * EN v1.0 Address: 0x80080F80
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008999C
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f80(uint param_1,uint param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f84
 * EN v1.0 Address: 0x80080F84
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80089A60
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f84(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f88
 * EN v1.0 Address: 0x80080F88
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80089AB8
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f88(int param_1,byte *param_2,byte *param_3,byte *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f8c
 * EN v1.0 Address: 0x80080F8C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80089B54
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f8c(int param_1,undefined *param_2,undefined *param_3,undefined *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f90
 * EN v1.0 Address: 0x80080F90
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80089BA8
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f90(int param_1,undefined *param_2,undefined *param_3,undefined *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080f94
 * EN v1.0 Address: 0x80080F94
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80089BFC
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080f94(int param_1)
{
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
undefined4 FUN_80080f98(void)
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
undefined4 FUN_80080fa0(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080fa8
 * EN v1.0 Address: 0x80080FA8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80089CEC
 * EN v1.1 Size: 1516b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fa8(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6,uint param_7,int param_8,int param_9,
                 undefined param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080fac
 * EN v1.0 Address: 0x80080FAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008A2D8
 * EN v1.1 Size: 1204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fac(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080fb0
 * EN v1.0 Address: 0x80080FB0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008A78C
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fb0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080fb4
 * EN v1.0 Address: 0x80080FB4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008A9D8
 * EN v1.1 Size: 1948b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fb4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080fb8
 * EN v1.0 Address: 0x80080FB8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008B174
 * EN v1.1 Size: 2140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fb8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080fbc
 * EN v1.0 Address: 0x80080FBC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008B9D0
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fbc(double param_1,short *param_2,short *param_3,short *param_4)
{
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
undefined4 FUN_80080fc0(float *param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80080fc8
 * EN v1.0 Address: 0x80080FC8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008BB40
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fc8(float *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080fcc
 * EN v1.0 Address: 0x80080FCC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008BBB0
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fcc(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080fd0
 * EN v1.0 Address: 0x80080FD0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008BBF0
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fd0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080fd4
 * EN v1.0 Address: 0x80080FD4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008BE50
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fd4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080fd8
 * EN v1.0 Address: 0x80080FD8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008C034
 * EN v1.1 Size: 1120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fd8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080fdc
 * EN v1.0 Address: 0x80080FDC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008C494
 * EN v1.1 Size: 1900b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fdc(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080fe0
 * EN v1.0 Address: 0x80080FE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008CC00
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fe0(int *param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080fe4
 * EN v1.0 Address: 0x80080FE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008CC80
 * EN v1.1 Size: 1684b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fe4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080fe8
 * EN v1.0 Address: 0x80080FE8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008D314
 * EN v1.1 Size: 2172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080fe8(int param_1)
{
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
 * Function: FUN_80080ff4
 * EN v1.0 Address: 0x80080FF4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008DC00
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ff4(uint *param_1,uint *param_2,uint *param_3,undefined4 param_4,int param_5,
                 int param_6,int param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080ff8
 * EN v1.0 Address: 0x80080FF8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008DD74
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ff8(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80080ffc
 * EN v1.0 Address: 0x80080FFC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008DE70
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80080ffc(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081000
 * EN v1.0 Address: 0x80081000
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008DF3C
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081000(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081004
 * EN v1.0 Address: 0x80081004
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008DFDC
 * EN v1.1 Size: 2824b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081004(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081008
 * EN v1.0 Address: 0x80081008
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008EAE4
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081008(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8008100c
 * EN v1.0 Address: 0x8008100C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008EC0C
 * EN v1.1 Size: 932b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8008100c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081010
 * EN v1.0 Address: 0x80081010
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008EFB0
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081010(void)
{
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
 * Function: FUN_8008101c
 * EN v1.0 Address: 0x8008101C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008F074
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8008101c(undefined4 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081020
 * EN v1.0 Address: 0x80081020
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008F0A4
 * EN v1.1 Size: 1200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081020(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081024
 * EN v1.0 Address: 0x80081024
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008F554
 * EN v1.1 Size: 1596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081024(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,undefined4 *param_6,uint param_7,uint param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081028
 * EN v1.0 Address: 0x80081028
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008FB90
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081028(float *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8008102c
 * EN v1.0 Address: 0x8008102C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008FD80
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8008102c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081030
 * EN v1.0 Address: 0x80081030
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008FDAC
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081030(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 undefined2 param_5,undefined param_6,undefined param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081034
 * EN v1.0 Address: 0x80081034
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008FE8C
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081034(double param_1,double param_2,float *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081038
 * EN v1.0 Address: 0x80081038
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008FF08
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081038(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8008103c
 * EN v1.0 Address: 0x8008103C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008FF28
 * EN v1.1 Size: 988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8008103c(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081040
 * EN v1.0 Address: 0x80081040
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80090304
 * EN v1.1 Size: 508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081040(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081044
 * EN v1.0 Address: 0x80081044
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80090500
 * EN v1.1 Size: 2456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081044(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081048
 * EN v1.0 Address: 0x80081048
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80090E98
 * EN v1.1 Size: 892b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081048(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8008104c
 * EN v1.0 Address: 0x8008104C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80091214
 * EN v1.1 Size: 1848b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8008104c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081050
 * EN v1.0 Address: 0x80081050
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009194C
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081050(double param_1,float *param_2,float *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081054
 * EN v1.0 Address: 0x80081054
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80091C54
 * EN v1.1 Size: 2632b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081054(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081058
 * EN v1.0 Address: 0x80081058
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009269C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081058(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8008105c
 * EN v1.0 Address: 0x8008105C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800926D0
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8008105c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081060
 * EN v1.0 Address: 0x80081060
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800927A8
 * EN v1.1 Size: 2376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081060(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,float *param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081064
 * EN v1.0 Address: 0x80081064
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800930F0
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081064(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,uint param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081068
 * EN v1.0 Address: 0x80081068
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800932E8
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081068(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8008106c
 * EN v1.0 Address: 0x8008106C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009339C
 * EN v1.1 Size: 2324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8008106c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10,int param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081070
 * EN v1.0 Address: 0x80081070
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80093CB0
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081070(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081074
 * EN v1.0 Address: 0x80081074
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80093D6C
 * EN v1.1 Size: 724b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081074(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081078
 * EN v1.0 Address: 0x80081078
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80094040
 * EN v1.1 Size: 1464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081078(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8008107c
 * EN v1.0 Address: 0x8008107C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800945F8
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8008107c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081080
 * EN v1.0 Address: 0x80081080
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80094604
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081080(double param_1,double param_2,double param_3)
{
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
uint FUN_80081084(float *param_1,float *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8008108c
 * EN v1.0 Address: 0x8008108C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80094734
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8008108c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081090
 * EN v1.0 Address: 0x80081090
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800947E0
 * EN v1.1 Size: 1612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081090(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081094
 * EN v1.0 Address: 0x80081094
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80094E2C
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081094(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081098
 * EN v1.0 Address: 0x80081098
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80094E9C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081098(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8008109c
 * EN v1.0 Address: 0x8008109C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80094ECC
 * EN v1.1 Size: 828b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8008109c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 uint param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810a0
 * EN v1.0 Address: 0x800810A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80095208
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810a0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810a4
 * EN v1.0 Address: 0x800810A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800953F0
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810a4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810a8
 * EN v1.0 Address: 0x800810A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80095688
 * EN v1.1 Size: 760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810a8(void)
{
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
undefined4 FUN_800810ac(double param_1,float *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800810b4
 * EN v1.0 Address: 0x800810B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800959F0
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810b4(double param_1,double param_2,double param_3,double param_4,undefined2 param_5,
                 uint param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810b8
 * EN v1.0 Address: 0x800810B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80095C8C
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810b8(double param_1,double param_2,double param_3,double param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810bc
 * EN v1.0 Address: 0x800810BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80095DA4
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810bc(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810c0
 * EN v1.0 Address: 0x800810C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80095F3C
 * EN v1.1 Size: 860b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810c0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810c4
 * EN v1.0 Address: 0x800810C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80096298
 * EN v1.1 Size: 916b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810c4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810c8
 * EN v1.0 Address: 0x800810C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009662C
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810c8(undefined4 param_1,undefined4 param_2,float *param_3,int param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810cc
 * EN v1.0 Address: 0x800810CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80096768
 * EN v1.1 Size: 788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810cc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810d0
 * EN v1.0 Address: 0x800810D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80096A7C
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810d0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810d4
 * EN v1.0 Address: 0x800810D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80096B50
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810d8
 * EN v1.0 Address: 0x800810D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80096C20
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810d8(double param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810dc
 * EN v1.0 Address: 0x800810DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80096C30
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810dc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810e0
 * EN v1.0 Address: 0x800810E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80096C3C
 * EN v1.1 Size: 740b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810e0(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 undefined4 param_6,undefined4 param_7,uint param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810e4
 * EN v1.0 Address: 0x800810E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80096F20
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810e4(undefined4 param_1,undefined4 param_2,uint param_3,int param_4,ushort param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810e8
 * EN v1.0 Address: 0x800810E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80097228
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810e8(undefined4 *param_1,uint param_2,uint param_3,uint param_4,uint param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810ec
 * EN v1.0 Address: 0x800810EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800972FC
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810ec(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,int param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810f0
 * EN v1.0 Address: 0x800810F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009742C
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810f0(double param_1,undefined4 param_2,byte param_3,uint param_4,uint param_5,
                 int param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810f4
 * EN v1.0 Address: 0x800810F4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80097568
 * EN v1.1 Size: 1112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810f4(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,uint param_6,uint param_7,int param_8,uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810f8
 * EN v1.0 Address: 0x800810F8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800979C0
 * EN v1.1 Size: 1020b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810f8(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,uint param_7,uint param_8,uint param_9,int param_10,
                 uint param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800810fc
 * EN v1.0 Address: 0x800810FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80097DBC
 * EN v1.1 Size: 1140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800810fc(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,uint param_7,uint param_8,uint param_9,int param_10,
                 uint param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081100
 * EN v1.0 Address: 0x80081100
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80098230
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081100(double param_1,undefined4 param_2,byte param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081104
 * EN v1.0 Address: 0x80081104
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800984FC
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081104(undefined8 param_1,double param_2,undefined4 param_3,char param_4,uint param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081108
 * EN v1.0 Address: 0x80081108
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80098608
 * EN v1.1 Size: 1452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081108(undefined8 param_1,double param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8008110c
 * EN v1.0 Address: 0x8008110C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80098BB4
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8008110c(double param_1,undefined4 param_2,byte param_3,undefined2 param_4,
                 undefined2 param_5,undefined4 param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081110
 * EN v1.0 Address: 0x80081110
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80098DA4
 * EN v1.1 Size: 2888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081110(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,
                 undefined4 *param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081114
 * EN v1.0 Address: 0x80081114
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800998EC
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081114(undefined4 param_1,undefined4 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081118
 * EN v1.0 Address: 0x80081118
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80099C40
 * EN v1.1 Size: 976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081118(double param_1,undefined4 param_2,int param_3,uint param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8008111c
 * EN v1.0 Address: 0x8008111C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009A010
 * EN v1.1 Size: 1112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8008111c(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int *param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081120
 * EN v1.0 Address: 0x80081120
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009A468
 * EN v1.1 Size: 1772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081120(undefined4 param_1,undefined4 param_2,uint param_3,int *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081124
 * EN v1.0 Address: 0x80081124
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009AB54
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081124(double param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081128
 * EN v1.0 Address: 0x80081128
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009ABF8
 * EN v1.1 Size: 516b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081128(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,uint param_11,uint param_12,uint param_13,uint param_14,
                 uint param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8008112c
 * EN v1.0 Address: 0x8008112C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009ADFC
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8008112c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint param_13,
                 uint param_14,uint param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80081130
 * EN v1.0 Address: 0x80081130
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009AFD0
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80081130(void)
{
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
int FUN_80081134(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

void ObjSeq_setCamVars(int camA, int camB, int camC, int camD)
{
    lbl_803DD10C = camA;
    lbl_803DD108 = camB;
    lbl_803DD104 = camC;
    lbl_803DD100 = camD;
}

#pragma push
#pragma scheduling off
#pragma peephole off

int objSeqFindLabel(u8 *seq, int label)
{
    int currentLabel;
    int commandIndex;
    int commandCount;
    u8 *command;
    int repeatCount;
    u32 packed;

    currentLabel = 0;
    commandIndex = 0;
    commandCount = *(s16 *)(seq + 0x62);
    while (commandIndex < commandCount) {
        command = *(u8 **)(seq + 0x94) + commandIndex * 4;
        if ((s8)command[0] == 0) {
            currentLabel = *(s16 *)(command + 2);
        } else if ((s8)command[0] == 0xb) {
            repeatCount = *(s16 *)(command + 2);
            if (repeatCount > 0) {
                packed = *(u32 *)(command + 4);
                if ((int)(packed & 0x3f) == 9 && (int)(packed >> 16) == label) {
                    return currentLabel;
                }
                commandIndex += repeatCount;
            }
        }
        currentLabel += command[1];
        commandIndex++;
    }
    return -1;
}

int objSeqFindConditional(u8 *seq, u8 *seqState)
{
    int currentLabel;
    int commandIndex;
    u8 *command;
    int repeatCount;
    u32 packed;

    currentLabel = -1;
    commandIndex = 0;
    while (commandIndex < *(s16 *)(seq + 0x62)) {
        command = *(u8 **)(seq + 0x94) + commandIndex * 4;
        if ((s8)command[0] == 0) {
            currentLabel = *(s16 *)(command + 2);
        } else if ((s8)command[0] == 0xb) {
            repeatCount = *(s16 *)(command + 2);
            if (repeatCount > 0) {
                packed = *(u32 *)(command + 4);
                if ((int)(packed & 0x3f) == 4 &&
                    seqEvalCondition((packed >> 6) & 0x3ff, seq, *(int *)(seqState + 0x4c)) != 0) {
                    currentLabel -= 10;
                    if (currentLabel < 0) {
                        currentLabel = 0;
                    }
                    return currentLabel;
                }
                commandIndex += repeatCount;
            }
        }
        currentLabel += command[1];
        commandIndex++;
    }
    return -1;
}

void objCallSeqFn(u8 *obj, u8 *sourceObj, u8 *seq, int action)
{
    int callbackResult;
    s8 actionSlot;
    int movementState;
    int flags;
    u8 *sourceModel;

    (void)action;

    sourceModel = *(u8 **)(sourceObj + 0x4c);
    *(f32 *)(obj + 0x80) = *(f32 *)(obj + 0xc);
    *(f32 *)(obj + 0x84) = *(f32 *)(obj + 0x10);
    *(f32 *)(obj + 0x88) = *(f32 *)(obj + 0x14);
    *(f32 *)(obj + 0x8c) = *(f32 *)(obj + 0x18);
    *(f32 *)(obj + 0x90) = *(f32 *)(obj + 0x1c);
    *(f32 *)(obj + 0x94) = *(f32 *)(obj + 0x20);

    if (*(void **)(obj + 0xbc) != NULL) {
        callbackResult = (*(int (**)(void))(obj + 0xbc))();
        if (callbackResult == 4) {
            lbl_803DD0DA = 1;
        } else if (callbackResult != 0) {
            actionSlot = seq[0x57];
            if (lbl_8039A50C[actionSlot] < 2) {
                lbl_8039A50C[actionSlot] = callbackResult;
            }
        }
        seq[0x8b] = 0;
        seq[0x80] = 0;
    } else {
        if ((s8)seq[0x7b] != 0) {
            seq[0x56] = 0;
            return;
        }

        movementState = (s8)seq[0x56];
        if (movementState >= 4) {
            if (ObjSeq_func20(obj, seq, 6, 0x1e, 0x50, -1, -1) != 0) {
                actionSlot = seq[0x57];
                if (lbl_8039A50C[actionSlot] < 2) {
                    lbl_8039A50C[actionSlot] = 1;
                }
            }
        } else if (movementState != 0) {
            if (movementState != 2) {
                *(f32 *)(seq + 0x4c) = lbl_803DEFC8;
                *(f32 *)(seq + 0x40) = *(f32 *)(obj + 0xc) - *(f32 *)(sourceObj + 0xc);
                *(f32 *)(seq + 0x44) = *(f32 *)(obj + 0x10) - *(f32 *)(sourceObj + 0x10);
                *(f32 *)(seq + 0x48) = *(f32 *)(obj + 0x14) - *(f32 *)(sourceObj + 0x14);
                seq[0x56] = 2;
            }
            if ((s8)sourceModel[0x20] == 1) {
                *(f32 *)(seq + 0x24) = lbl_803DF024;
                actionSlot = seq[0x57];
                if (lbl_8039A50C[actionSlot] < 2) {
                    lbl_8039A50C[actionSlot] = 1;
                }
            }
            *(f32 *)(seq + 0x4c) = *(f32 *)(seq + 0x4c) - *(f32 *)(seq + 0x24) * timeDelta;
            if (*(f32 *)(seq + 0x4c) <= lbl_803DEFB0) {
                seq[0x56] = 0;
            }
        }
    }

    flags = obj[0xaf];
    flags &= 0xf8;
    obj[0xaf] = flags;
    Obj_GetWorldPosition(obj, (f32 *)(obj + 0x18), (f32 *)(obj + 0x1c), (f32 *)(obj + 0x20));
    if (*(void **)(obj + 0x54) != NULL) {
        *(void **)(*(u8 **)(obj + 0x54) + 0x50) = NULL;
        *(u8 *)(*(u8 **)(obj + 0x54) + 0x71) = 0;
    }
    if (*(void **)(obj + 0x58) != NULL) {
        *(u8 *)(*(u8 **)(obj + 0x58) + 0x10f) = 0;
    }
}

void objSeqDoBgCmds0D(u8 *seq, u8 *obj, int skipSpawns)
{
    ObjSeqBgCmd *cmd;
    int cmdObj;
    int cmdParam;
    void *resource;
    int transitionSlot;
    int uiId;

    if (lbl_803DD090 != 0 && *(s16 *)(obj + 0xb4) != (s8)seq[0x57]) {
        (*(void (*)(int, int, int))(*(int *)(*gGameUIInterface + 0x44)))(0, 0, 0);
    }

    while (lbl_803DD113 > 0) {
        lbl_803DD113--;
        cmd = &lbl_8039A5BC[(s8)lbl_803DD113];
        cmdParam = cmd->param;
        cmdObj = cmd->object;

        switch (cmd->opcode) {
        case 3:
            if ((u8)skipSpawns == 0) {
                (*(void (*)(int, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(
                    cmdObj, cmdParam, 0, 0x10000, -1, 0);
            }
            break;
        case 4:
            if ((u8)skipSpawns == 0) {
                return0xFFFF_80008B6C(cmdObj, 0, 0, 1, -1, (u8)cmdParam, 0);
            }
            break;
        case 5:
            if ((u8)skipSpawns == 0) {
                resource = Resource_Acquire((u16)(cmdParam + 0xab), 1);
                if (resource != NULL) {
                    (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*(int *)resource + 0x4)))(
                        cmdObj, 0, 0, 1, -1, (u8)cmdParam, 0);
                }
                if (resource != NULL) {
                    Resource_Release(resource);
                }
            }
            break;
        case 9:
            if ((u8)skipSpawns == 0) {
                switch (cmdParam & 0x2f) {
                case 6:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0x8)))(
                        transitionSlot, 3);
                    break;
                case 7:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0xc)))(
                        transitionSlot, 3);
                    break;
                case 8:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0x8)))(
                        transitionSlot, 2);
                    break;
                case 9:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0xc)))(
                        transitionSlot, 2);
                    break;
                case 0xb:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0x8)))(
                        transitionSlot, 4);
                    break;
                case 0xc:
                    transitionSlot = (cmdParam & 0xfc0) >> 4;
                    (*(void (*)(int, int, f32))(*(int *)(*gScreenTransitionInterface + 0x10)))(
                        transitionSlot, 4, lbl_803DF028);
                    break;
                }
            }
            break;
        case 0xb:
            GameBit_Set(cmdParam, 1);
            break;
        case 0xc:
            GameBit_Set(cmdParam, 0);
            break;
        case 0xd:
            if ((u8)skipSpawns == 0) {
                uiId = lbl_8030EDA4[cmdParam];
                (*(void (*)(int, int, int))(*(int *)(*gGameUIInterface + 0x44)))(uiId, 0, 0);
                if (lbl_8030EDA4[cmdParam] != -1) {
                    lbl_803DD090 = 1;
                } else {
                    lbl_803DD090 = 0;
                }
            }
            break;
        }
    }
}

void objSeqSetupFn_80085b34(u8 *obj, u8 **seqObj, u8 *seq, u8 *sourceObj, void **outAction)
{
    u8 *activeObj;
    s16 *modelVec;
    f32 groundY[2];
    long long time;
    u8 *historyBase;

    historyBase = lbl_80396918;
    if ((s8)seq[0x7b] != 0) {
        lbl_803DD108 = 1;
        lbl_803DD100 = 0x5a;
        lbl_803DD10C = 0x42;
    }

    *(s16 *)(seq + 0x58) = *(s16 *)(seq + 0x5e);
    *(s16 *)(seq + 0x5a) = -0x3c;
    objSeqUpdateMoreCurves(obj, *seqObj, seq, 0);
    objSeqUpdateCurves(obj, *seqObj, seq, 1);

    activeObj = *(u8 **)(*(u8 **)(obj + 0xb8));
    if (activeObj == NULL) {
        activeObj = obj;
    }
    *outAction = *(void **)(*(u8 **)(activeObj + 0x7c) + (s8)activeObj[0xad] * 4);
    *seqObj = activeObj;

    objAnimCurvFn_800849e8(obj, seq);
    if ((s8)seq[0x7a] == 1 &&
        hitDetectFn_800658a4(obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10),
                             *(f32 *)(obj + 0x14), groundY, 0) == 0) {
        *(f32 *)(obj + 0x10) =
            *(f32 *)(obj + 0x10) + ((*(f32 *)(obj + 0x10) - groundY[0]) - *(f32 *)(sourceObj + 0xc));
    }

    *(u16 *)obj = *(s16 *)obj + *(s16 *)(seq + 0x1a);
    if (*seqObj != obj && (s8)lbl_803DD0D8 == 0) {
        objCallSeqFn(*seqObj, obj, seq, *(u8 *)(historyBase + (s8)seq[0x57] + 0x3c4c));
    }

    objAnimFn_8008718c(obj, *seqObj, seq);
    seq[0x8d] = 0;
    seq[0x8e] = 0;
    seq[0x7e] = 1;
    *(s16 *)(seq + 0x5a) = *(s16 *)(seq + 0x58);
    if ((s8)lbl_803DD0DA != 0) {
        animatedObjFreeAndSavePlayerPos(obj, *seqObj, seq);
    }

    *(f32 *)(historyBase + (s8)seq[0x57] * 4 + 0x3740) = (f32)*(s16 *)(seq + 0x58);
    *(s16 *)(historyBase + (s8)seq[0x57] * 2 + 0x2be0) = *(s16 *)(seq + 0x58);
    time = OSGetTime();
    *(long long *)(historyBase + (s8)seq[0x57] * 8 + 0x2f38) = time;
    time = OSGetTime();
    *(long long *)(historyBase + (s8)seq[0x57] * 8 + 0x2c90) = time;

    if (*seqObj != NULL) {
        objModelClearVecFn_8003aa40(*seqObj);
        if (*(s16 *)(*seqObj + 0x44) == 1) {
            modelVec = objModelGetVecFn_800395d8(obj, 1);
            if (modelVec != NULL) {
                modelVec[0] = 0;
                modelVec[1] = 0;
                modelVec[2] = 0;
            }
        }
    }
}

void objAnimFn_8008718c(u8 *obj, u8 *seqObj, u8 *seq)
{
    s16 basePitch;
    s16 baseYaw;
    s16 baseRoll;
    f32 baseX;
    f32 baseY;
    f32 baseZ;

    if (*(void **)(seqObj + 0x30) == *(void **)(obj + 0x30) || (s8)lbl_803DD114 == 0) {
        baseX = *(f32 *)(obj + 0xc);
        baseY = *(f32 *)(obj + 0x10);
        baseZ = *(f32 *)(obj + 0x14);
        basePitch = *(s16 *)(obj + 0);
    } else {
        baseX = lbl_803DD120;
        baseY = lbl_803DD11C;
        baseZ = lbl_803DD118;
        basePitch = lbl_803DD116;
    }

    baseYaw = *(s16 *)(obj + 2);
    baseRoll = *(s16 *)(obj + 4);
    if (seqObj != obj) {
        if ((*(s16 *)(seq + 0x6e) & 1) != 0) {
            if ((s8)seq[0x56] == 2) {
                *(f32 *)(seqObj + 0xc) = *(f32 *)(seq + 0x40) * *(f32 *)(seq + 0x4c) + baseX;
                *(f32 *)(seqObj + 0x10) = *(f32 *)(seq + 0x44) * *(f32 *)(seq + 0x4c) + baseY;
                *(f32 *)(seqObj + 0x14) = *(f32 *)(seq + 0x48) * *(f32 *)(seq + 0x4c) + baseZ;
            } else {
                *(f32 *)(seqObj + 0xc) = baseX;
                *(f32 *)(seqObj + 0x10) = baseY;
                *(f32 *)(seqObj + 0x14) = baseZ;
            }
        }
        if ((*(s16 *)(seq + 0x6e) & 2) != 0) {
            if ((s8)seq[0x56] == 2) {
                *(s16 *)(seqObj + 0) =
                    (s16)(basePitch + (s32)((f32)*(s16 *)(seq + 0x50) * *(f32 *)(seq + 0x4c)));
                *(s16 *)(seqObj + 2) =
                    (s16)(baseYaw + (s32)((f32)*(s16 *)(seq + 0x52) * *(f32 *)(seq + 0x4c)));
                *(s16 *)(seqObj + 4) =
                    (s16)(baseRoll + (s32)((f32)*(s16 *)(seq + 0x54) * *(f32 *)(seq + 0x4c)));
            } else {
                *(s16 *)(seqObj + 0) = basePitch;
                *(s16 *)(seqObj + 2) = baseYaw;
                *(s16 *)(seqObj + 4) = baseRoll;
            }
        }
    }

    if ((s8)seq[0x7b] != 0 && (s8)seq[0x78] != 0) {
        lbl_803DD0B8 = obj;
        lbl_803DD0B6 = framesThisStep;
    }
    Obj_GetWorldPosition(seqObj, (f32 *)(seqObj + 0x18), (f32 *)(seqObj + 0x1c),
                         (f32 *)(seqObj + 0x20));
}

int seqEvalCondition(int condition, u8 *seq, int obj)
{
    int tailState;
    int result;

    result = 0;

    switch (condition) {
    case 0:
        if (*(s16 *)(seq + 0x60) <= 0) {
            result = 1;
        }
        break;
    case 1:
        if (*(s16 *)(seq + 0x60) > 0) {
            result = 1;
        }
        break;
    case 2:
        if ((*(int (**)(int *))((u8 *)(*gSHthorntailAnimationInterface) + 0x24))(&tailState) == 0) {
            result = 1;
        }
        break;
    case 3:
        if ((*(int (**)(int *))((u8 *)(*gSHthorntailAnimationInterface) + 0x24))(&tailState) != 0) {
            result = 1;
        }
        break;
    case 4:
        if (lbl_8039A45C[(s8)seq[0x57]] == 0) {
            result = 1;
        }
        break;
    case 5:
        if (lbl_8039A45C[(s8)seq[0x57]] == 1) {
            result = 1;
        }
        break;
    case 6:
        if (lbl_8039A4B4[(s8)seq[0x57]] == 0) {
            result = 1;
        }
        break;
    case 7:
        if (lbl_8039A4B4[(s8)seq[0x57]] != 0) {
            result = 1;
        }
        break;
    case 8:
        if (seqGlobal1 <= 0) {
            result = 1;
        }
        break;
    case 9:
        if (seqGlobal1 > 0) {
            result = 1;
        }
        break;
    case 10:
        if (seqGlobal2 <= 0) {
            result = 1;
        }
        break;
    case 11:
        if (seqGlobal2 > 0) {
            result = 1;
        }
        break;
    case 12:
        if (isGameTimerDisabled() != 0) {
            result = 1;
        }
        break;
    case 13:
        if (isGameTimerDisabled() == 0) {
            result = 1;
        }
        break;
    case 14:
        if (seqGlobal3 != 0) {
            result = 1;
        }
        break;
    case 15:
        if (seqGlobal3 == 0) {
            result = 1;
        }
        break;
    default:
        result = 1;
        break;
    }
    return result;
}

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

void ObjSeq_setXrot(int index, int xrot)
{
    s16 xrot16;

    lbl_80399EA8[index] = 1;
    xrot16 = xrot;
    lbl_80399F00[index] = xrot16;
}

int ObjSeq_getBool(int index)
{
    if (index < 0 || index >= 0x55) {
        return 0;
    }
    return lbl_8039A45C[index];
}

void ObjSeq_setFlag(int index, int value)
{
    s8 flag;

    if (index < 0) {
        return;
    }
    if (index >= 0x55) {
        return;
    }
    flag = value;
    lbl_8039A45C[index] = flag;
}

void ObjSeq_addBgCmd(int index, int xrot, int yrot)
{
    s8 count;
    s16 shortIndex;
    s16 shortXrot;
    s16 shortYrot;

    if (index < 0) {
        return;
    }
    if (index >= 0x55) {
        return;
    }

    count = lbl_803DD0BC;
    if (count >= 0x1e) {
        return;
    }

    shortIndex = index;
    shortYrot = yrot;
    lbl_80399398[count * 3] = shortIndex;
    lbl_80399398[count * 3 + 2] = shortYrot;
    shortXrot = xrot;
    lbl_803DD0BC++;
    lbl_80399398[count * 3 + 1] = shortXrot;
}

void ObjSeq_seqState_free(u8 *seq)
{
    void *ptr;

    ptr = *(void **)(seq + 0x94);
    if (ptr != NULL) {
        mm_free(ptr);
        *(void **)(seq + 0x94) = NULL;
        *(void **)(seq + 0x98) = NULL;
    }
    ptr = *(void **)(seq + 0x2c);
    if (ptr != NULL) {
        mm_free(ptr);
        *(void **)(seq + 0x2c) = NULL;
    }
}

void ObjSeq_seqState_init(u8 *seq)
{
    int animIndex;
    int runLength;
    int track;
    int animCount;
    u8 *animEntry;
    int commandIndex;
    u8 *command;

    for (track = 0; track < 0x13; track++) {
        *(s16 *)(seq + 0xc2 + track * 2) = 0;
    }

    track = 0;
    animIndex = 0;
    while (animIndex < *(s16 *)(seq + 0x64)) {
        runLength = 0;
        animCount = *(s16 *)(seq + 0x64);
        while (animIndex + runLength < animCount) {
            animEntry = *(u8 **)(seq + 0x98) + (animIndex + runLength) * 8;
            if (track == ((s8)animEntry[5] & 0x1f)) {
                runLength++;
            } else {
                break;
            }
        }
        *(s16 *)(seq + 0xc2 + track * 2) = runLength;
        *(s16 *)(seq + 0x9c + track * 2) = animIndex;
        track++;
        animIndex += runLength;
    }

    *(s16 *)(seq + 0x5c) = 1000;
    commandIndex = 0;
    while (commandIndex < 2 && commandIndex < *(s16 *)(seq + 0x62)) {
        command = *(u8 **)(seq + 0x94) + commandIndex * 4;
        if ((s8)command[0] == -1) {
            *(s16 *)(seq + 0x5c) = *(s16 *)(command + 2) + 1;
        }
        commandIndex++;
    }
}

void *objFindForSeqFn_80081bf0(u8 *obj)
{
    void *unused;
    int objectCount;
    void **objects;
    int targetId;
    int objectType;
    f32 bestDistSq;
    void *bestObj;
    int i;
    u8 *candidate;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distSq;

    targetId = *(int *)(*(u8 **)(obj + 0xb8) + 0x10c);
    if (targetId != 0) {
        return ObjList_FindObjectById(targetId);
    }

    objects = ObjList_GetObjects(&unused, &objectCount);
    objectType = *(s16 *)(*(u8 **)(obj + 0x4c) + 0x1c) - 4;
    if (objectType == 0x1f || objectType == 0) {
        return Obj_GetPlayerObject();
    }
    if (objectType == 0x24 || objectType == 0x25) {
        return getTrickyObject();
    }

    bestDistSq = lbl_803DEFF0;
    bestObj = NULL;
    for (i = 0; i < objectCount; i++) {
        candidate = objects[i];
        if (*(s16 *)(candidate + 0x46) == objectType) {
            dx = *(f32 *)(obj + 0xc) - *(f32 *)(candidate + 0xc);
            dy = *(f32 *)(obj + 0x10) - *(f32 *)(candidate + 0x10);
            dz = *(f32 *)(obj + 0x14) - *(f32 *)(candidate + 0x14);
            distSq = dx * dx + dy * dy + dz * dz;
            if (bestDistSq < lbl_803DEFB0 || distSq < bestDistSq) {
                bestDistSq = distSq;
                bestObj = candidate;
            }
        }
    }
    return bestObj;
}

void seq_findAction(void *obj, void *seqFile, u8 *seq)
{
    int stop;
    int actionIndex;
    u8 *command;
    s8 opcode;
    s16 repeatCount;

    if (*(void **)(seq + 0x94) == NULL) {
        return;
    }

    *(s16 *)(seq + 0x68) = -1;
    *(s16 *)(seq + 0x66) = 0;
    *(f32 *)(seq + 0x20) = lbl_803DEFB0;
    stop = 0;
    while (stop == 0 && *(s16 *)(seq + 0x66) < *(s16 *)(seq + 0x62)) {
        actionIndex = *(s16 *)(seq + 0x66);
        command = *(u8 **)(seq + 0x94) + actionIndex * 4;
        opcode = command[0];
        if (opcode == 0) {
            if (*(s16 *)(seq + 0x58) >= *(s16 *)(command + 2)) {
                *(s16 *)(seq + 0x68) = *(s16 *)(command + 2);
                *(s16 *)(seq + 0x66) = *(s16 *)(seq + 0x66) + 1;
            } else {
                stop = 1;
            }
        } else if (opcode == 0xb && (repeatCount = *(s16 *)(command + 2)) > 0) {
            if (*(s16 *)(seq + 0x58) >= *(s16 *)(seq + 0x68)) {
                *(s16 *)(seq + 0x68) = *(s16 *)(seq + 0x68) + command[1];
                *(s16 *)(seq + 0x66) = (s16)(*(s16 *)(seq + 0x66) + repeatCount + 1);
            } else {
                stop = 1;
            }
        } else if (*(s16 *)(seq + 0x58) >= *(s16 *)(seq + 0x68)) {
            if (opcode != 0xf) {
                *(s16 *)(seq + 0x68) = *(s16 *)(seq + 0x68) + command[1];
            }
            *(s16 *)(seq + 0x66) = *(s16 *)(seq + 0x66) + 1;
        } else {
            stop = 1;
        }
    }
}

void ObjSeq_release(void)
{
    mm_free(lbl_803DD0D4);
}

void ObjSeq_initialise(void)
{
    lbl_803DD0D4 = mmAlloc(0x10, 0x11, 0);
    objSeq_onMapSetup();
    lbl_803DD108 = 1;
    lbl_803DD100 = 0x5a;
    lbl_803DD10C = 0x42;
    objSeqInitFn_80080078(lbl_8030ECA8, 5);
}

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

int fn_800882C8(int index)
{
    int changed;

    changed = lbl_80399EA8[index];
    lbl_80399EA8[index] = 0;
    return changed;
}

void fn_80088730(u8 *out)
{
    u8 *src;

    out[0] = lbl_803DB748;
    src = &lbl_803DB748;
    out[1] = src[1];
    out[2] = src[2];
    out[3] = src[3];
}

int getEnvFxBit2BA(void)
{
    return (u8)GameBit_Get(0x2ba);
}

void setGameBit2BA(int value)
{
    int bitValue;

    bitValue = value;
    if ((u8)bitValue >= 0x1c) {
        bitValue = 0;
    }
    GameBit_Set(0x2ba, (u8)bitValue);
}

void envFxFn_800887cc(void)
{
    playerEnvFxFn_80088ad4((u8)GameBit_Get(0x2ba));
}

void envFxActFn_800887f8(u8 value)
{
    void *player;
    int masked;

    lbl_803DD140 = value;
    masked = (u8)value;
    masked &= 8;
    if (masked == 0) {
        player = Obj_GetPlayerObject();
        getEnvfxAct(player, player, 0x136, 0);
        getEnvfxAct(player, player, 0x137, 0);
        getEnvfxAct(player, player, 0x143, 0);
    }
}

void fn_80088870(int a, int b, int c, int d)
{
    lbl_803DD13C = a;
    lbl_803DD130 = b;
    lbl_803DD138 = c;
    lbl_803DD134 = d;
}

void loadSunAndMoon(void)
{
    void *moonObj;

    if (lbl_803DD154 == 0) {
        lbl_803DD148 = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x62b), 4, -1, -1, NULL);
        moonObj = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x62c), 4, -1, -1, NULL);
        lbl_803DD14C = moonObj;
        lbl_803DD154 = 1;
        ObjModel_SetRenderCallback(Obj_GetActiveModel(moonObj), moonFxCb_80074110);
    }
}

int getSkyColorFn_80088e08(int slot)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky != NULL) {
        slot *= 0xa4;
        slot += 0xc1;
        return (sky[slot] >> 7) & 1;
    }
    return 0;
}

int getSkyColorFn_80088e30(int slot)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky != NULL) {
        return sky[slot * 0xa4 + 0xc0];
    }
    return 0xff;
}

int getSkyStructField24C(void)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky != NULL) {
        return sky[0x24c];
    }
    return 0;
}

void fn_8008904C(u8 *red, u8 *green, u8 *blue)
{
    u8 *color;

    if (lbl_803DD12C != NULL) {
        *red = lbl_803DD178;
        color = &lbl_803DD178;
        *green = color[1];
        *blue = color[2];
        return;
    }
    *red = 0xff;
    *green = 0xff;
    *blue = 0xff;
}

void fn_8008908C(u8 *ambientRed, u8 *ambientGreen, u8 *ambientBlue, u8 *lightRed,
                 u8 *lightGreen, u8 *lightBlue)
{
    u8 *color;
    u8 red;
    u8 green;
    u8 blue;

    if (lbl_803DD15C != 0) {
        red = lbl_803DD158;
        *ambientRed = red;
        *lightRed = red;
        color = &lbl_803DD158;
        green = color[1];
        *ambientGreen = green;
        *lightGreen = green;
        blue = color[2];
        *ambientBlue = blue;
        *lightBlue = blue;
        return;
    }

    if (lbl_803DD12C != NULL) {
        *ambientRed = lbl_803DD174;
        color = &lbl_803DD174;
        *ambientGreen = color[1];
        *ambientBlue = color[2];
        *lightRed = lbl_803DD170;
        color = &lbl_803DD170;
        *lightGreen = color[1];
        *lightBlue = color[2];
        return;
    }

    *ambientRed = 0xff;
    *ambientGreen = 0xff;
    *ambientBlue = 0xff;
    *lightRed = 0xff;
    *lightGreen = 0xff;
    *lightBlue = 0xff;
}

void *fn_8008912C(void)
{
    return lbl_803DD150;
}

void fn_80089134(f32 mtx[3][4])
{
    f32 scale;
    f32 scaleMtx[3][4];

    scale = EXIInputFlag / *(f32 *)(lbl_803DD148 + 8);
    PSMTXScale(scaleMtx, scale, scale, scale);
    Obj_BuildWorldTransformMatrix(lbl_803DD148, mtx, 0);
    PSMTXConcat(mtx, scaleMtx, mtx);
}

int skyFn_8008919c(int slot)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky == NULL) {
        return 0;
    }

    slot *= 0xa4;
    slot += 0xc1;
    if ((u32)((sky[slot] >> 7) & 1) != 0) {
        return 0;
    }
    return lbl_803DD148[0x37];
}

void fn_800891DC(u8 red, u8 green, u8 blue)
{
    u8 *color;

    lbl_803DD158 = red;
    color = &lbl_803DD158;
    color[1] = green;
    color[2] = blue;
}

void fn_800891F0(u8 enabled)
{
    lbl_803DD15C = enabled;
}

void fn_800891F8(f32 x, f32 y, f32 z, f32 intensity)
{
    lbl_8039A7A8[0] = x;
    lbl_8039A7A8[1] = y;
    lbl_8039A7A8[2] = z;
    lbl_803DD160 = intensity;
    PSVECNormalize(lbl_8039A7A8, lbl_8039A7A8);
}

void fn_80089234(u8 enabled)
{
    lbl_803DD164 = enabled;
}

void skyFn_800894a8(int flags, f32 x, f32 y, f32 z)
{
    int bit;

    if (lbl_803DD12C == NULL) {
        return;
    }
    for (bit = 0; bit < 2; bit++) {
        if ((flags & (1 << bit)) != 0) {
            *(f32 *)(lbl_803DD12C + bit * 0xa4 + 0xa8) = x;
            *(f32 *)(lbl_803DD12C + bit * 0xa4 + 0xac) = y;
            *(f32 *)(lbl_803DD12C + bit * 0xa4 + 0xb0) = z;
        }
    }
}

void fn_80089510(int flags, u8 red, u8 green, u8 blue)
{
    int bit;

    if (lbl_803DD12C == NULL) {
        return;
    }
    for (bit = 0; bit < 2; bit++) {
        if ((flags & (1 << bit)) != 0) {
            lbl_803DD12C[bit * 0xa4 + 0x8c] = red;
            lbl_803DD12C[bit * 0xa4 + 0x8d] = green;
            lbl_803DD12C[bit * 0xa4 + 0x8e] = blue;
        }
    }
}

void fn_80089578(int flags, u8 red, u8 green, u8 blue)
{
    int bit;

    if (lbl_803DD12C == NULL) {
        return;
    }
    for (bit = 0; bit < 2; bit++) {
        if ((flags & (1 << bit)) != 0) {
            lbl_803DD12C[bit * 0xa4 + 0x84] = red;
            lbl_803DD12C[bit * 0xa4 + 0x85] = green;
            lbl_803DD12C[bit * 0xa4 + 0x86] = blue;
        }
    }
}

void skyFn_800895e0(int flags, u8 red, u8 green, u8 blue, u8 m1, u8 m2)
{
    int r1, g1, b1, r2, g2, b2;
    int bit;

    if (lbl_803DD12C == NULL) {
        return;
    }
    r1 = red * m1 >> 8;
    g1 = green * m1 >> 8;
    b1 = blue * m1 >> 8;
    r2 = red * m2 >> 8;
    g2 = green * m2 >> 8;
    b2 = blue * m2 >> 8;
    for (bit = 0; bit < 2; bit++) {
        if ((flags & (1 << bit)) != 0) {
            lbl_803DD12C[bit * 0xa4 + 0x7c] = red;
            lbl_803DD12C[bit * 0xa4 + 0x7d] = green;
            lbl_803DD12C[bit * 0xa4 + 0x7e] = blue;
            lbl_803DD12C[bit * 0xa4 + 0x84] = r1;
            lbl_803DD12C[bit * 0xa4 + 0x85] = g1;
            lbl_803DD12C[bit * 0xa4 + 0x86] = b1;
            lbl_803DD12C[bit * 0xa4 + 0x8c] = r2;
            lbl_803DD12C[bit * 0xa4 + 0x8d] = g2;
            lbl_803DD12C[bit * 0xa4 + 0x8e] = b2;
        }
    }
}

void getTimeOfDay(f32 *time)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky == NULL) {
        *time = pEXIInputFlag;
        return;
    }
    *time = *(f32 *)(sky + 0x20c);
}

void renderSky(void)
{
    if (lbl_803DD148 != NULL && lbl_803DD14C != NULL) {
        renderSunAndMoon();
    }
    skyFn_8008a500();
    skyFn_8008a04c();
}

void getAmbientColor(int slot, u8 *red, u8 *green, u8 *blue)
{
    u8 *sky;
    int offset;

    sky = lbl_803DD12C;
    if (sky == NULL) {
        *blue = 0xff;
        *green = 0xff;
        *red = 0xff;
        return;
    }

    offset = slot * 0xa4;
    *red = lbl_803DD12C[offset + 0x78];
    *green = lbl_803DD12C[offset + 0x79];
    *blue = lbl_803DD12C[offset + 0x7a];
}

void textureColorFn_8008991c(int slot, u8 *red, u8 *green, u8 *blue)
{
    u8 *sky;
    int offset;

    sky = lbl_803DD12C;
    if (sky == NULL) {
        *blue = 0xff;
        *green = 0xff;
        *red = 0xff;
        return;
    }

    offset = slot * 0xa4;
    *red = lbl_803DD12C[offset + 0x88];
    *green = lbl_803DD12C[offset + 0x89];
    *blue = lbl_803DD12C[offset + 0x8a];
}

void modelTextureFn_80089970(int slot)
{
    int offset;
    u8 *sky;

    if (lbl_803DD144 != NULL) {
        offset = slot * 0xa4;
        sky = lbl_803DD12C + offset;
        modelStruct2_setVectors(lbl_803DD144, *(f32 *)(sky + 0x90), *(f32 *)(sky + 0x94),
                                *(f32 *)(sky + 0x98));
        modelLightStruct_setColorsA8AC(lbl_803DD144, lbl_803DD12C[offset + 0x78],
                                       lbl_803DD12C[offset + 0x79],
                                       lbl_803DD12C[offset + 0x7a], 0xff);
    }
    if (lbl_803DD168 != NULL) {
        offset = slot * 0xa4;
        sky = lbl_803DD12C + offset;
        modelStruct2_setVectors(lbl_803DD168, *(f32 *)(sky + 0x9c), *(f32 *)(sky + 0xa0),
                                *(f32 *)(sky + 0xa4));
        modelLightStruct_setColorsA8AC(lbl_803DD168, lbl_803DD12C[offset + 0x80],
                                       lbl_803DD12C[offset + 0x81],
                                       lbl_803DD12C[offset + 0x82], 0xff);
    }
    offset = slot * 0xa4;
    colorFn_8001efe0(0, lbl_803DD12C[offset + 0x88], lbl_803DD12C[offset + 0x89],
                     lbl_803DD12C[offset + 0x8a]);
}

void *fn_80089A50(void)
{
    return lbl_803DD168;
}

void *fn_80089A58(void)
{
    return lbl_803DD144;
}

int getSunPos(f32 *outTime)
{
    f32 time;

    if (lbl_803DD12C == NULL) {
        if (outTime != NULL) {
            *outTime = pEXIInputFlag;
        }
        return 0;
    }

    time = *(f32 *)(lbl_803DD12C + 0x20c);
    if (time >= lbl_803DF088 || time < *(&init_803DF080 + 1)) {
        if (outTime != NULL) {
            if (time >= lbl_803DF088) {
                *outTime = *(&init_803DF080 + 1) + (time - lbl_803DF088);
            } else {
                *outTime = *(&init_803DF080 + 1) - time;
            }
        }
        return 1;
    }

    if (outTime != NULL) {
        *outTime = lbl_803DF088 - time;
    }
    return 0;
}

void fn_8008B88C(int *outTimer)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky == NULL) {
        *outTimer = 0;
        return;
    }
    *outTimer = *(int *)(sky + 0x218);
}

void skyFn_80089710(int flags, u32 enabled, int startComplete)
{
    u8 *sky;
    u32 flagBit;
    u32 stateActive;
    u32 requestedActive;

    sky = lbl_803DD12C;
    if (sky == NULL) {
        return;
    }

    flagBit = 0;
    if ((flags & (1 << flagBit)) != 0) {
        stateActive = ((SkyBlendStateFlags *)(sky + 0xc1))->active;
        requestedActive = (u8)enabled;
        if (stateActive != requestedActive) {
            if (startComplete != 0) {
                *(f32 *)(sky + 0xbc) = EXIInputFlag;
            } else {
                *(f32 *)(sky + 0xbc) = pEXIInputFlag;
            }
        }
        sky = lbl_803DD12C;
        ((SkyBlendStateFlags *)(sky + 0xc1))->active = enabled;
    }

    flagBit = 1;
    if ((flags & (1 << flagBit)) != 0) {
        sky = lbl_803DD12C;
        stateActive = ((SkyBlendStateFlags *)(sky + 0x165))->active;
        requestedActive = (u8)enabled;
        if (stateActive != requestedActive) {
            if (startComplete != 0) {
                *(f32 *)(sky + 0x160) = EXIInputFlag;
            } else {
                *(f32 *)(sky + 0x160) = pEXIInputFlag;
            }
        }
        sky = lbl_803DD12C;
        ((SkyBlendStateFlags *)(sky + 0x165))->active = enabled;
    }
}

void fn_800897D4(int slot, f32 *x, f32 *y, f32 *z)
{
    u8 *sky;
    int offset;
    f32 fallback;

    if (lbl_803DD12C == NULL) {
        fallback = pEXIInputFlag;
        *x = fallback;
        *y = lbl_803DF06C;
        *z = fallback;
        return;
    }

    offset = slot * 0xa4;
    sky = lbl_803DD12C + offset;
    *x = *(f32 *)(sky + 0x90);
    sky = lbl_803DD12C;
    sky += offset;
    *y = *(f32 *)(sky + 0x94);
    sky = lbl_803DD12C;
    sky += offset;
    *z = *(f32 *)(sky + 0x98);
}

void objGetColor(int slot, u8 *red, u8 *green, u8 *blue)
{
    u8 *sky;
    int offset;

    sky = lbl_803DD12C;
    if (sky == NULL) {
        *blue = 0xff;
        *green = 0xff;
        *red = 0xff;
    } else {
        offset = slot * 0xa4;
        *red = lbl_803DD12C[offset + 0x78];
        *green = lbl_803DD12C[offset + 0x79];
        *blue = lbl_803DD12C[offset + 0x7a];
    }

    *red = (u8)((*red * colorScale) >> 8);
    *green = (u8)((*green * colorScale) >> 8);
    *blue = (u8)((*blue * colorScale) >> 8);
}

void dll_06_func0B(int *x, int *y)
{
    u8 *state;
    f32 value;

    state = lbl_803DD184;
    if (state != NULL) {
        value = *(f32 *)(state + 0x14);
        *x = value;
        value = *(f32 *)(lbl_803DD184 + 0x18);
        *y = value;
    }
}

void dll_06_func0A(int *a, int *b, int *c, f32 *scale)
{
    u8 *state;

    state = lbl_803DD184;
    if (state == NULL) {
        return;
    }
    *a = *(int *)(state + 0x24);
    *b = *(int *)(lbl_803DD184 + 0x28);
    *c = *(int *)(lbl_803DD184 + 0x2c);
    *scale = *(f32 *)(lbl_803DD184 + 0x30c);
}

void dll_06_func0E(void)
{
    if (lbl_803DD184 == NULL) {
        return;
    }
    if (lbl_803DD180 != 1) {
        lbl_803DD180 = 1;
    }
}

void dll_06_func0D(void)
{
    if (lbl_803DD184 == NULL) {
        return;
    }
    if (lbl_803DD180 != 2) {
        lbl_803DD180 = 2;
    }
}

void sky2_initialise(void)
{
    u8 **states;
    u8 *state;

    lbl_803DB610 = -1;
    (&lbl_803DB610)[1] = -1;
    if (lbl_803DD184 != NULL) {
        mm_free(lbl_803DD184);
    }
    states = &lbl_803DD184;
    state = states[1];
    if (state != NULL) {
        mm_free(state);
    }
    lbl_803DD184 = NULL;
    states[1] = NULL;
}

void fn_8008EDE8(f32 *out)
{
    u8 *state;

    state = lbl_803DD19C;
    if (state == NULL) {
        return;
    }
    out[0] = *(f32 *)(state + 0);
    out[1] = *(f32 *)(lbl_803DD19C + 4);
    out[2] = *(f32 *)(lbl_803DD19C + 8);
}

void renderFn_8008faf4(void)
{
    if (lbl_803DD19C != NULL) {
        renderFn_8008f904(lbl_803DD19C);
    }
}

int fn_8008B71C(int slot)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky != NULL) {
        slot *= 0xa4;
        slot += 0xc1;
        return (sky[slot] >> 5) & 1;
    }
    return 0;
}

void fn_8008B744(f32 time, s16 *days, s16 *hours, s16 *minutes)
{
    s32 remaining;

    remaining = (s32)time;
    *days = remaining / 0x34bc0;
    remaining -= *days * 0x34bc0;
    *hours = remaining / 0xe10;
    remaining -= *hours * 0xe10;
    *minutes = remaining / 0x3c;
}

void fn_8008B8B4(f32 *time)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky == NULL) {
        *time = pEXIInputFlag;
    } else {
        *time = *(s32 *)(sky + 0x210);
    }
}

int dll_06_func0F(void)
{
    u8 *state;
    f32 y;

    state = lbl_803DD184;
    if (state == NULL) {
        return 0xff;
    }
    y = *(f32 *)(state + 0x14);
    if (y < lbl_803DF138) {
        return 0;
    }
    if (y > lbl_803DF13C) {
        return 0xff;
    }
    return (int)(lbl_803DF118 * ((y - lbl_803DF138) / lbl_803DF140));
}

f32 fn_8008ED88(void)
{
    u8 *state;
    u16 totalFrames;
    u16 currentFrame;

    state = lbl_803DD19C;
    if (state != NULL) {
        totalFrames = *(u16 *)(state + 0x22);
        currentFrame = *(u16 *)(state + 0x20);
        return (f32)(s32)(totalFrames - currentFrame) / (f32)totalFrames;
    }
    return lbl_803DF1A0;
}

void fn_8008FC00(f32 *out, f32 height, f32 scale)
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
int return0_80088758(void) { return 0x0; }
void doNothing_800887C4(void) {}
void doNothing_800887C8(void) {}
int return0_8008B7E8(void) { return 0x0; }
void doNothing_8008B8B0(void) {}
void pDll_Sky_setTimeOfDay_nop(void) {}
void dll_06_func0C_nop(void) {}
int dll_06_func07_ret_0(void) { return 0x0; }
void sky2_release(void) {}
void dll_07_func0A_nop(void) {}

extern u8 lbl_803DD1EC;
extern f32 lbl_803DD1E8;
extern f32 lbl_803DD1E4;
extern f32 lbl_803DD1E0;

void fn_8009436C(void) {
    lbl_803DD1EC = 0;
}

#pragma push
#pragma scheduling off
void fn_80094378(f32 a, f32 b, f32 c) {
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
extern void modelLightStruct_setField50(void *, int);
extern void modelLightStruct_setColors100104(void *, int, int, int, int);
extern void *textureLoadAsset(int);
extern u8 lbl_803DC950;
extern f32 lbl_8030F2C8[];
extern f32 lbl_8030F2D4[];
void skyFn_80088e54(int mode, f32 brightness);
void fn_8008BDA8(void);

#pragma push
#pragma scheduling off
#pragma peephole off
void loadLightFn_8008bbc4(void)
{
    u8 done = 0;

    while (getLoadedFileFlags(0) != 0) {
        padUpdate();
        checkReset();
        if (done) {
            waitNextFrame();
        }
        loadDataFiles();
        dvdCheckError();
        if (done) {
            mmFreeTick(0);
            gameTextRun();
            GXFlush_(1, 0);
        }
        if (lbl_803DC950 != 0) {
            done = 1;
        }
    }
    lbl_803DD164 = 0;
    lbl_803DD15C = 0;
    lbl_803DD158 = 0xff;
    (&lbl_803DD158)[1] = 0xff;
    (&lbl_803DD158)[2] = 0xff;
    if (lbl_803DD144 == NULL) {
        lbl_803DD144 = objCreateLight(0, 1);
        if (lbl_803DD144 != NULL) {
            modelLightStruct_setField50(lbl_803DD144, 4);
            modelStruct2_setVectors(lbl_803DD144, pEXIInputFlag, lbl_803DF06C, pEXIInputFlag);
            modelLightStruct_setColorsA8AC(lbl_803DD144, 0xff, 0xff, 0xff, 0xff);
            modelLightStruct_setColors100104(lbl_803DD144, 0xff, 0xff, 0xff, 0xff);
        }
        lbl_803DD168 = objCreateLight(0, 1);
        if (lbl_803DD168 != NULL) {
            modelLightStruct_setField50(lbl_803DD168, 4);
            modelStruct2_setVectors(lbl_803DD168, pEXIInputFlag, EXIInputFlag, pEXIInputFlag);
            modelLightStruct_setColorsA8AC(lbl_803DD168, 0xff, 0xff, 0xff, 0xff);
            modelLightStruct_setColors100104(lbl_803DD168, 0xff, 0xff, 0xff, 0xff);
        }
    }
    fn_8008BDA8();
    skyFn_80088c94(7, 0);
    skyFn_80088e54(0, pEXIInputFlag);
    skyFn_8008a500();
    skyFn_8008a04c();
    lbl_8030F2C8[0] = pEXIInputFlag;
    lbl_8030F2C8[1] = lbl_803DF06C;
    lbl_8030F2C8[2] = pEXIInputFlag;
    lbl_8030F2D4[0] = pEXIInputFlag;
    lbl_8030F2D4[1] = lbl_803DF06C;
    lbl_8030F2D4[2] = pEXIInputFlag;
    lbl_803DD150 = textureLoadAsset(0x5fa);
}
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
void dll_06_func06(int obj) {
    u8 *s = lbl_803DD184;

    if (s != NULL) {
        lbl_803DD180 = 2;
        fn_8005D0BC(obj, (u8) * (int *)(s + 0x24), (u8) * (int *)(s + 0x28),
                    (u8) * (int *)(s + 0x2c), 55);
        s = lbl_803DD184;
        if (*(f32 *)(s + 0x14) == *(f32 *)(s + 0x18)) {
            *(f32 *)(s + 0x14) = *(f32 *)(s + 0x14) - lbl_803DF14C;
        }
        s = lbl_803DD184;
        if (*(f32 *)(s + 0x14) > *(f32 *)(s + 0x18)) {
            *(f32 *)(s + 0x14) = *(f32 *)(s + 0x18) - lbl_803DF14C;
        }
        s = lbl_803DD184;
        fogFn_80070404(*(f32 *)(s + 0x14), *(f32 *)(s + 0x18));
    }
}

void dll_06_func08(int obj) {
    u8 *s = lbl_803DD184;
    f32 v;
    int alpha;

    if (s != NULL) {
        if (lbl_803DB750 == 0 && (*(u16 *)(s + 4) & 1) == 0) {
            v = *(f32 *)(s + 0x14);
            if (v < lbl_803DF108) {
                alpha = 255;
            } else if (v > lbl_803DF148) {
                alpha = 0;
            } else {
                alpha = (int)(lbl_803DF118 - lbl_803DF118 * (v / lbl_803DF148));
            }
            setTextColor(obj, (u8) * (int *)(s + 0x24), (u8) * (int *)(s + 0x28),
                         (u8) * (int *)(s + 0x2c), (u8)alpha);
        } else {
            setTextColor(obj, 255, 255, 255, 0);
        }
    }
}

extern void Obj_SetModelColorOverrideRecursive(int obj, int r, int g, int b, int a, int flag);

void fn_8008DAE8(int obj) {
    u8 *s;
    f32 v;
    int alpha;

    if (lbl_803DD184 == NULL) {
        Obj_SetModelColorOverrideRecursive(obj, 0, 0, 0, 0, 0);
    }
    if (lbl_803DB750 == 0 && (*(u16 *)((s = lbl_803DD184) + 4) & 1) == 0) {
        v = *(f32 *)(s + 0x14);
        if (v < lbl_803DF108) {
            alpha = 255;
        } else if (v > lbl_803DF148) {
            alpha = 0;
        } else {
            alpha = (int)(lbl_803DF118 - lbl_803DF118 * (v / lbl_803DF148));
        }
        Obj_SetModelColorOverrideRecursive(obj, (u8) * (int *)(s + 0x24),
                                           (u8) * (int *)(s + 0x28),
                                           (u8) * (int *)(s + 0x2c), (u8)alpha, 1);
    } else {
        Obj_SetModelColorOverrideRecursive(obj, 0, 0, 0, 0, 0);
    }
}
#pragma pop

#pragma push
#pragma scheduling off
void *fn_8008FB20(f32 *a, f32 *b, f32 c, f32 d, int e, int f, int g) {
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
#pragma pop

typedef struct RomCurveNode {
    u8 pad00[0x1b];
    s8 directionMask;
    s32 links[4];
} RomCurveNode;

typedef struct RomCurveInterpState {
    s32 fromNodeId;
    s32 toNodeId;
    f32 fromTime;
    u8 pad0C[0x28 - 0x0c];
    f32 toTime;
} RomCurveInterpState;

extern void **gRomCurveInterface;
extern void curveFn_80083e00(RomCurveInterpState *out, RomCurveNode *curve, RomCurveNode *x, f32 f,
                             int flag);

#pragma push
#pragma scheduling off
#pragma peephole off
void romCurveFn_80084190(RomCurveInterpState *state, f32 t) {
    RomCurveNode *node;
    RomCurveNode *prev;
    int found;
    int i;
    int mask;
    int val;
    f32 thr;

    node = NULL;
    if (t < state->fromTime) {
        node = (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(state->fromNodeId);
    }
    if (node != NULL) {
        while (t < (thr = state->fromTime)) {
            mask = 1;
            for (i = 0; i < 4; i++) {
                val = node->links[i];
                if (val > -1 && (node->directionMask & mask) != 0) {
                    found = val;
                    i = 5;
                }
                mask <<= 1;
            }
            if (i != 6) {
                state->toTime = thr;
                state->toNodeId = state->fromNodeId;
                state->fromNodeId = -1;
                return;
            }
            state->toNodeId = state->fromNodeId;
            state->fromNodeId = found;
            prev = node;
            node = (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(state->fromNodeId);
            curveFn_80083e00(state, node, prev, state->fromTime, 1);
        }
    }
    node = (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(state->toNodeId);
    if (node != NULL) {
        while (t >= (thr = state->toTime)) {
            mask = 1;
            for (i = 0; i < 4; i++) {
                val = node->links[i];
                if (val > -1 && (node->directionMask & mask) == 0) {
                    found = val;
                    i = 5;
                }
                mask <<= 1;
            }
            if (i != 6) {
                state->fromTime = thr;
                state->fromNodeId = state->toNodeId;
                state->toNodeId = -1;
                return;
            }
            state->fromNodeId = state->toNodeId;
            state->toNodeId = found;
            prev = node;
            node = (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(state->toNodeId);
            curveFn_80083e00(state, prev, node, state->toTime, 0);
        }
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void curveFindFn_800843c4(RomCurveInterpState *out, int id) {
    RomCurveNode *curve;
    int i;
    int mask;
    int found;
    int val;

    out->fromNodeId = id;
    out->toNodeId = -1;
    curve = (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(out->fromNodeId);
    mask = 1;
    for (i = 0; i < 4; i++) {
        val = curve->links[i];
        if (val > -1 && (curve->directionMask & mask) == 0) {
            found = val;
            i = 5;
        }
        mask <<= 1;
    }
    if (i != 6) {
        out->fromNodeId = -1;
    } else {
        out->toNodeId = found;
        curveFn_80083e00(out, curve,
                         (RomCurveNode *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(out->toNodeId),
                         lbl_803DEFB0, 0);
    }
}
#pragma pop

extern void getEnvfxActImmediately(void *obj, void *target, int effectId, int flags);

#pragma push
#pragma scheduling off
#pragma peephole off
void playerEnvFxFn_80088ad4(int idx) {
    void *player;
    int alt;
    s16 val;

    player = Obj_GetPlayerObject();
    if ((void *)lbl_803DD134 == NULL) {
        return;
    }
    if (player == NULL) {
        return;
    }
    if ((lbl_803DD140 & 0x8) == 0) {
        return;
    }
    if (GameBit_Get(944) != 0) {
        return;
    }
    alt = (s8)(idx - 1);
    if (alt < 0) {
        alt = 27;
    }
    val = ((s16 *)lbl_803DD134)[(u8)idx];
    if (val <= 0 || ((s16 *)lbl_803DD134)[(s8)alt] != val) {
        getEnvfxAct(player, player, 310, 0);
        getEnvfxAct(player, player, 311, 0);
        getEnvfxAct(player, player, 323, 0);
    }
    val = ((s16 *)lbl_803DD134)[(u8)idx];
    if (val > 0) {
        if (lbl_803DD140 & 0x20) {
            getEnvfxActImmediately(player, player, (u16)val, 0);
        } else {
            getEnvfxAct(player, player, (u16)val, 0);
        }
    }
}
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

extern int ObjModel_GetRenderOp(int model, int x);
extern int Shader_getLayer(int renderOp, int x);
extern int *objFindTexture(int obj, int idx, int p3);
extern void *textureIdxToPtr(int idx);
extern void *lbl_8039AB28[];
extern f32 lbl_803DF2B0;
extern f32 lbl_803DF2B4;

#pragma push
#pragma scheduling off
void *skyTextureFn_80094390(f32 *out1, f32 *out2) {
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
void sky2_onMapSetup(void) {
    int i;
    void **slot;
    f32 b;
    f32 a;

    lbl_803DB610 = -1;
    (&lbl_803DB610)[1] = -1;
    slot = (void **)&lbl_803DD184;
    a = lbl_803DF190;
    b = lbl_803DF194;
    for (i = 0; i < 2; i++) {
        if (slot[i] == NULL) {
            slot[i] = mmAlloc(792, 23, 0);
        }
        memset(slot[i], 0, 792);
        *(int *)((char *)slot[i] + 0x24) = 255;
        *(int *)((char *)slot[i] + 0x28) = 255;
        *(int *)((char *)slot[i] + 0x2c) = 255;
        *(f32 *)((char *)slot[i] + 0x14) = a;
        *(f32 *)((char *)slot[i] + 0x18) = b;
        *(int *)((char *)slot[i] + 0x30) = 255;
        *(int *)((char *)slot[i] + 0x34) = 255;
        *(int *)((char *)slot[i] + 0x38) = 255;
        *(f32 *)((char *)slot[i] + 0x1c) = a;
        *(f32 *)((char *)slot[i] + 0x20) = b;
        if (lbl_803DB754 != 0) {
            getEnvfxAct(NULL, NULL, 9, 0);
            lbl_803DB754 = 0;
        }
    }
}
#pragma pop

extern u8 *saveGameGetEnvState(void);
extern int getSaveGameLoadStatus(void);

#pragma push
#pragma scheduling off
#pragma peephole off
void skyFn_80088c94(int flags, int mode) {
    u8 *env;
    u8 *sky;

    if ((flags & 1) != 0) {
        if ((u8)mode != 0) {
            ((SkyBlendStateFlags *)(lbl_803DD12C + 0xc1))->unused80 = 1;
        } else {
            ((SkyBlendStateFlags *)(lbl_803DD12C + 0xc1))->unused80 = 0;
        }
    }
    if ((flags & 2) != 0) {
        if ((u8)mode != 0) {
            ((SkyBlendStateFlags *)(lbl_803DD12C + 0x165))->unused80 = 1;
        } else {
            ((SkyBlendStateFlags *)(lbl_803DD12C + 0x165))->unused80 = 0;
        }
    }
    sky = lbl_803DD12C;
    ((SkyBlendStateFlags *)(sky + 0x209))->unused80 =
        ((SkyBlendStateFlags *)(sky + sky[0x24c] * 0xa4 + 0xc1))->unused80;
    env = saveGameGetEnvState();
    if (getSaveGameLoadStatus() == 0) {
        if (((SkyBlendStateFlags *)(lbl_803DD12C + 0xc1))->unused80 != 0) {
            env[0x40] |= 2;
        } else {
            env[0x40] &= ~2;
        }
        if (((SkyBlendStateFlags *)(lbl_803DD12C + 0x165))->unused80 != 0) {
            env[0x40] |= 4;
        } else {
            env[0x40] &= ~4;
        }
    }
}
#pragma pop
