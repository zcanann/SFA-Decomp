#include "ghidra_import.h"
#include "main/pi_dolphin.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_80006958();
extern undefined4 FUN_8000697c();
extern undefined4 FUN_80006988();
extern uint FUN_80006a90();
extern uint FUN_80006a98();
extern undefined4 FUN_80006aa0();
extern undefined4 FUN_80006aa4();
extern undefined4 FUN_80006aa8();
extern undefined4 FUN_80006aac();
extern uint FUN_80006c00();
extern undefined8 FUN_80006c1c();
extern undefined4 FUN_80006c28();
extern undefined4 FUN_80006c30();
extern undefined8 FUN_800174b8();
extern uint FUN_80017690();
extern undefined4 FUN_800176a8();
extern undefined8 FUN_800176b0();
extern double FUN_80017714();
extern undefined4 FUN_800177bc();
extern undefined4 FUN_800177c4();
extern undefined8 FUN_80017810();
extern undefined8 FUN_80017814();
extern int FUN_80017830();
extern void* FUN_80017844();
extern undefined4 FUN_8001784c();
extern undefined4 FUN_80017850();
extern undefined4 FUN_800179a0();
extern undefined4 FUN_800179ec();
extern int FUN_800179f0();
extern uint FUN_800179f8();
extern int FUN_80017a98();
extern undefined4 FUN_80040cdc();
extern undefined4 FUN_80040da0();
extern undefined4 FUN_800411ac();
extern undefined4 FUN_80041248();
extern undefined4 FUN_800412e4();
extern undefined4 FUN_80041380();
extern undefined4 FUN_8004141c();
extern undefined4 FUN_800414b8();
extern undefined4 FUN_8004151c();
extern undefined4 FUN_800415b8();
extern undefined4 FUN_80041664();
extern undefined4 FUN_80041710();
extern undefined4 FUN_800417ac();
extern undefined4 FUN_80041858();
extern undefined4 FUN_80041904();
extern undefined4 FUN_800419a0();
extern undefined4 FUN_80041a3c();
extern undefined4 FUN_80041ad8();
extern undefined4 FUN_80041b74();
extern undefined4 FUN_8004286c();
extern undefined4 clearLoadedFileFlags_blocks1();
extern uint FUN_80053078();
extern undefined4 FUN_800530b4();
extern undefined4 FUN_800530b8();
extern undefined4 FUN_800537a0();
extern undefined4 FUN_800563e8();
extern undefined4 FUN_80060650();
extern undefined4 FUN_8006af50();
extern void newshadows_getShadowTexture(int *textureOut);
extern void newshadows_getBlankShadowTexture(int *textureOut);
extern void newshadows_getSoftShadowTexture(int *textureOut);
extern void newshadows_getShadowRampTexture(int *textureOut);
extern void newshadows_getShadowNoiseTexture(int *textureOut);
extern double newshadows_getShadowNoiseScale(void);
extern void newshadows_bindShadowRenderTexture(int textureSlot);
extern int newshadows_getInverseShadowRampTexture(void);
extern int newshadows_getRadialFalloffTexture(void);
extern void newshadows_bindShadowCaptureTexture(int textureSlot);
extern void newshadows_getShadowNoiseScroll(float *xOffsetOut,float *yOffsetOut);
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_80080f88();
extern undefined4 FUN_8011810c();
extern undefined8 FUN_8013577c();
extern undefined4 FUN_80135814();
extern undefined8 FUN_80135b78();
extern undefined4 FUN_80241cfc();
extern int FUN_80241d0c();
extern int FUN_80241d7c();
extern uint FUN_80241de8();
extern int FUN_80241df0();
extern undefined4 FUN_80241e00();
extern undefined4 FUN_802420b0();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_80242114();
extern undefined4 FUN_80243e74();
extern undefined4 FUN_80243e9c();
extern uint FUN_8024533c();
extern undefined4 FUN_80246190();
extern undefined4 FUN_802461cc();
extern undefined8 FUN_80246298();
extern undefined4 FUN_80246308();
extern undefined4 FUN_802464dc();
extern undefined4 FUN_802464ec();
extern undefined4 FUN_802471c4();
extern undefined4 FUN_802472b0();
extern undefined4 FUN_802475b8();
extern undefined4 FUN_80247618();
extern undefined4 PSVECDotProduct();
extern undefined4 FUN_80247944();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247a7c();
extern undefined4 FUN_80247b70();
extern undefined4 FUN_80247dfc();
extern int FUN_80249300();
extern undefined4 FUN_802493c8();
extern undefined4 FUN_80249610();
extern undefined4 FUN_8024c8cc();
extern undefined4 FUN_8024c910();
extern undefined4 FUN_8024d054();
extern undefined4 FUN_8024d51c();
extern undefined4 FUN_8024dcb8();
extern undefined4 FUN_8024ddd4();
extern undefined4 FUN_8024de40();
extern undefined4 FUN_802554d0();
extern undefined4 FUN_8025665c();
extern undefined4 FUN_80256738();
extern undefined4 FUN_80256744();
extern undefined4 FUN_80256854();
extern undefined8 FUN_80256ac8();
extern undefined4 FUN_80256b2c();
extern undefined4 FUN_80256bc4();
extern undefined8 FUN_80256c08();
extern undefined8 FUN_80256ca0();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_80257ba8();
extern undefined4 FUN_80258664();
extern undefined4 FUN_80258674();
extern undefined4 __GXSendFlushPrim();
extern undefined4 FUN_80258a04();
extern undefined4 FUN_80258a94();
extern undefined4 FUN_80258b60();
extern short FUN_80258c18();
extern undefined4 FUN_80258dac();
extern undefined4 FUN_80259224();
extern undefined4 FUN_80259288();
extern undefined4 FUN_80259340();
extern undefined4 FUN_802594c0();
extern undefined4 FUN_8025971c();
extern undefined4 FUN_802597f0();
extern undefined4 FUN_80259858();
extern undefined4 FUN_80259a80();
extern undefined8 FUN_80259a9c();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025a608();
extern undefined4 FUN_8025aa74();
extern undefined4 FUN_8025ace8();
extern undefined4 FUN_8025aeac();
extern undefined4 FUN_8025b054();
extern undefined4 FUN_8025b210();
extern undefined4 FUN_8025b94c();
extern undefined4 FUN_8025b9e8();
extern undefined4 FUN_8025bb48();
extern undefined4 FUN_8025bd1c();
extern undefined4 FUN_8025be80();
extern undefined4 FUN_8025bec8();
extern undefined4 FUN_8025c000();
extern undefined4 FUN_8025c1a4();
extern undefined4 FUN_8025c224();
extern undefined4 FUN_8025c2a8();
extern undefined4 FUN_8025c368();
extern undefined4 FUN_8025c428();
extern undefined4 FUN_8025c49c();
extern undefined4 FUN_8025c510();
extern undefined4 GXSetBlendMode();
extern undefined4 FUN_8025c5f0();
extern undefined4 FUN_8025c65c();
extern undefined4 FUN_8025c6b4();
extern undefined4 FUN_8025c828();
extern undefined4 FUN_8025cce8();
extern undefined8 FUN_8025ce2c();
extern undefined4 FUN_8025cf24();
extern undefined4 FUN_8025d034();
extern undefined4 FUN_8025d100();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d888();
extern undefined4 FUN_8025d8c4();
extern undefined4 FUN_8025da64();
extern undefined4 FUN_8025da88();
extern undefined4 FUN_8025dc78();
extern undefined4 FUN_8025e520();
extern int FUN_80286718();
extern ulonglong FUN_80286820();
extern longlong FUN_8028682c();
extern uint FUN_80286830();
extern uint FUN_80286834();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80286cd0();
extern undefined8 FUN_8028fde8();
extern int FUN_80291d74();
extern undefined4 FUN_80293f88();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint countLeadingZeros();

extern undefined4 DAT_800000f8;
extern undefined1 DAT_802c23d0;
extern undefined4 DAT_802c23e4;
extern undefined4 DAT_802c23e6;
extern undefined4 DAT_802c2458;
extern undefined4 DAT_802c245a;
extern undefined4 DAT_802c24d0;
extern undefined4 DAT_802c24d4;
extern undefined4 DAT_802c24d8;
extern undefined4 DAT_802c24dc;
extern undefined4 DAT_802c24e0;
extern undefined4 DAT_802c24e4;
extern undefined4 DAT_802c24e8;
extern undefined4 DAT_802c24ec;
extern undefined4 DAT_802c24f0;
extern undefined4 DAT_802c24f4;
extern undefined4 DAT_802c24f8;
extern undefined4 DAT_802c24fc;
extern undefined4 DAT_802c2500;
extern undefined4 DAT_802c2504;
extern undefined4 DAT_802c2508;
extern undefined4 DAT_802c250c;
extern undefined4 DAT_802c2510;
extern undefined4 DAT_802c2514;
extern undefined4 DAT_802c2518;
extern undefined4 DAT_802c251c;
extern undefined4 DAT_802c2520;
extern undefined4 DAT_802c2524;
extern undefined4 DAT_802c2528;
extern undefined4 DAT_802c252c;
extern undefined4 DAT_802c2530;
extern undefined4 DAT_802c2534;
extern undefined4 DAT_802c2538;
extern undefined4 DAT_802c253c;
extern undefined4 DAT_802c2540;
extern undefined4 DAT_802c2544;
extern undefined4 DAT_802c2548;
extern undefined4 DAT_802c254c;
extern undefined4 DAT_802c2550;
extern undefined4 DAT_802c2554;
extern undefined4 DAT_802c2558;
extern undefined4 DAT_802c255c;
extern undefined4 DAT_802c2560;
extern undefined4 DAT_802c2564;
extern undefined4 DAT_802c2568;
extern undefined4 DAT_802c256c;
extern undefined4 DAT_802c2570;
extern undefined4 DAT_802c2574;
extern undefined4 DAT_802c2590;
extern undefined4 DAT_802c2594;
extern undefined4 DAT_802c2598;
extern undefined4 DAT_802c259c;
extern undefined4 DAT_802c25a0;
extern undefined4 DAT_802c25a4;
extern undefined4 DAT_802c25a8;
extern undefined4 DAT_802c25ac;
extern undefined4 DAT_802c25b0;
extern undefined4 DAT_802c25b4;
extern undefined4 DAT_802c25b8;
extern undefined4 DAT_802c25bc;
extern int DAT_802cc8a8;
extern undefined4 DAT_802cc9d4;
extern undefined4 DAT_802cd260;
extern undefined DAT_8030d440;
extern undefined DAT_8030d960;
extern undefined DAT_8030d980;
extern undefined4 DAT_8030d9a0;
extern undefined4 DAT_8030da9c;
extern undefined4 DAT_8032f2b4;
extern undefined4 DAT_80346bd0;
extern undefined4 DAT_80346d30;
extern undefined4 DAT_8034ec70;
extern undefined4 DAT_80350c70;
extern undefined4 DAT_80352c70;
extern undefined4 DAT_80356c70;
extern undefined4 DAT_8035ac70;
extern undefined4 DAT_8035db50;
extern undefined DAT_8035fb50;
extern int DAT_8035fba8;
extern undefined4 DAT_8035fbdc;
extern undefined4 DAT_8035fc28;
extern undefined4 DAT_8035fc34;
extern undefined4 DAT_8035fc3c;
extern undefined4 DAT_8035fc54;
extern undefined4 DAT_8035fc68;
extern undefined4 DAT_8035fcc0;
extern undefined4 DAT_8035fcc4;
extern undefined4 DAT_8035fcd0;
extern undefined4 DAT_8035fcd4;
extern undefined4 DAT_8035fcdc;
extern undefined4 DAT_8035fcfc;
extern int DAT_8035fd08;
extern undefined4 DAT_8035fd8c;
extern undefined4 DAT_8035fd98;
extern undefined4 DAT_8035fe68;
extern int DAT_80360048;
extern undefined4 DAT_8036007c;
extern undefined4 DAT_80360080;
extern undefined4 DAT_803600b0;
extern undefined4 DAT_803600b4;
extern undefined4 DAT_803600bc;
extern undefined4 DAT_803600c0;
extern undefined4 DAT_803600c8;
extern undefined4 DAT_803600cc;
extern undefined4 DAT_803600d4;
extern undefined4 DAT_803600d8;
extern undefined4 DAT_803600dc;
extern undefined4 DAT_803600e0;
extern undefined4 DAT_803600f0;
extern undefined4 DAT_803600f4;
extern undefined4 DAT_80360104;
extern undefined4 DAT_80360108;
extern undefined4 DAT_8036015c;
extern undefined4 DAT_80360160;
extern undefined4 DAT_80360164;
extern undefined4 DAT_80360168;
extern undefined4 DAT_8036016c;
extern undefined4 DAT_80360170;
extern undefined4 DAT_80360174;
extern undefined4 DAT_80360178;
extern undefined4 DAT_8036017c;
extern undefined4 DAT_80360180;
extern undefined4 DAT_80360184;
extern undefined4 DAT_80360188;
extern undefined4 DAT_80360190;
extern undefined4 DAT_80360194;
extern undefined4 DAT_80360198;
extern undefined4 DAT_8036019c;
extern undefined4 DAT_803601a0;
extern undefined2 DAT_803601a8;
extern undefined4 DAT_803601c2;
extern undefined4 DAT_803601c4;
extern undefined4 DAT_803601dc;
extern undefined4 DAT_803601de;
extern undefined4 DAT_803601e8;
extern undefined4 DAT_803601ea;
extern undefined4 DAT_803601ee;
extern undefined4 DAT_803601f0;
extern undefined4 DAT_803601f2;
extern undefined4 DAT_803601f4;
extern undefined4 DAT_803601fc;
extern undefined4 DAT_803601fe;
extern undefined4 DAT_80360206;
extern undefined4 DAT_80360208;
extern undefined4 DAT_80360232;
extern undefined4 DAT_80360234;
extern undefined4 DAT_80360236;
extern undefined4 DAT_80360238;
extern undefined4 DAT_8036023a;
extern undefined4 DAT_8036023c;
extern undefined4 DAT_8036023e;
extern undefined4 DAT_80360240;
extern undefined4 DAT_80360242;
extern undefined4 DAT_80360244;
extern undefined4 DAT_8036024e;
extern undefined4 DAT_80360250;
extern undefined4 DAT_80360252;
extern undefined4 DAT_80360254;
extern undefined4 DAT_80360318;
extern undefined4 DAT_80360390;
extern undefined DAT_803603a0;
extern undefined DAT_803704c0;
extern undefined DAT_803704e0;
extern undefined DAT_803784e0;
extern undefined2 DAT_803784f4;
extern short DAT_80378512;
extern undefined2 DAT_80378514;
extern undefined4 DAT_80378534;
extern undefined4 DAT_803785d4;
extern undefined4 DAT_80378600;
extern ushort DAT_80397240;
extern ushort DAT_80397330;
extern undefined4 DAT_80397480;
extern undefined4 DAT_803974e0;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc071;
extern undefined4 DAT_803dc218;
extern undefined4 DAT_803dc228;
extern undefined4 DAT_803dc22c;
extern undefined4 DAT_803dc22e;
extern undefined4 DAT_803dc230;
extern undefined4 DAT_803dc234;
extern undefined4 DAT_803dc23c;
extern undefined4 DAT_803dc248;
extern undefined4 DAT_803dc254;
extern undefined4 DAT_803dc258;
extern undefined4 DAT_803dd5d0;
extern undefined4* DAT_803dd71c;
extern undefined4 DAT_803dd8f0;
extern undefined4 DAT_803dd8f4;
extern undefined4 DAT_803dd8f8;
extern undefined4 DAT_803dd8fc;
extern undefined4 DAT_803dd900;
extern undefined4 DAT_803dd904;
extern undefined4 DAT_803dd908;
extern undefined4 DAT_803dd90c;
extern undefined4 DAT_803dd910;
extern undefined4 DAT_803dd912;
extern undefined4 DAT_803dd918;
extern undefined4 DAT_803dd920;
extern undefined4 DAT_803dd924;
extern undefined4 DAT_803dd925;
extern undefined4 DAT_803dd926;
extern undefined4 DAT_803dd927;
extern undefined4 DAT_803dd928;
extern undefined4 DAT_803dd929;
extern undefined4 DAT_803dd92a;
extern undefined4 DAT_803dd92c;
extern undefined4 DAT_803dd930;
extern undefined4 DAT_803dd938;
extern undefined4 DAT_803dd944;
extern undefined4 DAT_803dd94c;
extern undefined4 DAT_803dd950;
extern undefined4 DAT_803dd954;
extern undefined4* DAT_803dd958;
extern undefined4 DAT_803dd95c;
extern undefined4* DAT_803dd960;
extern undefined4 DAT_803dd964;
extern undefined4 DAT_803dd968;
extern undefined4 DAT_803dd96c;
extern undefined4* DAT_803dd970;
extern undefined4 DAT_803dd974;
extern undefined4 DAT_803dd978;
extern undefined4 DAT_803dd97c;
extern undefined4 DAT_803dd980;
extern undefined4 DAT_803dd988;
extern undefined4 DAT_803dd990;
extern undefined1 DAT_803dd998;
extern undefined DAT_803dd9a0;
extern undefined4 DAT_803dd9a8;
extern undefined4 DAT_803dd9ac;
extern undefined4 DAT_803dd9b0;
extern undefined4 DAT_803dd9b1;
extern undefined4 DAT_803dd9e8;
extern undefined4 DAT_803dd9e9;
extern undefined4 DAT_803dd9ea;
extern undefined4 DAT_803dd9eb;
extern undefined4 DAT_803dd9ec;
extern undefined4 DAT_803dd9f0;
extern undefined4 DAT_803dd9f4;
extern undefined4 DAT_803dd9f8;
extern undefined4 DAT_803dd9fc;
extern undefined4 DAT_803dda00;
extern undefined4 DAT_803dda04;
extern undefined4 DAT_803dda08;
extern undefined4 DAT_803dda0c;
extern undefined4 DAT_803dda10;
extern undefined4 DAT_803ddc80;
extern undefined4 DAT_803ddc82;
extern undefined4 DAT_803de288;
extern undefined4 DAT_803de6a8;
extern undefined4 DAT_803df730;
extern undefined4 DAT_803df734;
extern undefined4 DAT_803df738;
extern undefined4 DAT_803df73c;
extern undefined4 DAT_803df740;
extern undefined4 DAT_cc008000;
extern f64 DOUBLE_803df700;
extern f64 DOUBLE_803df728;
extern f64 DOUBLE_803df7b0;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DC250;
extern f32 lbl_803DD934;
extern f32 lbl_803DD940;
extern f32 lbl_803DD9B4;
extern f32 lbl_803DD9B8;
extern f32 lbl_803DD9BC;
extern f32 lbl_803DD9C0;
extern f32 lbl_803DD9C4;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DF6F0;
extern f32 lbl_803DF6F4;
extern f32 lbl_803DF6F8;
extern f32 lbl_803DF6FC;
extern f32 lbl_803DF708;
extern f32 lbl_803DF70C;
extern f32 lbl_803DF710;
extern f32 lbl_803DF714;
extern f32 lbl_803DF718;
extern f32 lbl_803DF71C;
extern f32 lbl_803DF720;
extern f32 lbl_803DF744;
extern f32 lbl_803DF748;
extern f32 lbl_803DF74C;
extern f32 lbl_803DF750;
extern f32 lbl_803DF754;
extern f32 lbl_803DF75C;
extern f32 lbl_803DF760;
extern f32 lbl_803DF764;
extern f32 lbl_803DF768;
extern f32 lbl_803DF76C;
extern f32 lbl_803DF770;
extern f32 lbl_803DF774;
extern f32 lbl_803DF778;
extern f32 lbl_803DF77C;
extern f32 lbl_803DF780;
extern f32 lbl_803DF784;
extern f32 lbl_803DF788;
extern f32 lbl_803DF78C;
extern f32 lbl_803DF790;
extern f32 lbl_803DF794;
extern f32 lbl_803DF798;
extern f32 lbl_803DF79C;
extern f32 lbl_803DF7A0;
extern f32 lbl_803DF7A4;
extern f32 lbl_803DF7A8;
extern f32 lbl_803DF7AC;
extern f32 lbl_803DF7B8;
extern f32 lbl_803DF7BC;
extern f32 lbl_803DF7C0;
extern void* PTR_LAB_802cd0ec;
extern char *sResourceFileNameTable[];
extern void* PTR_s_animtest_802cc784;
extern void* PTR_s_frontend_802cc518;
extern undefined4 _DAT_00360048;
extern undefined4 _DAT_803dc24c;
extern char s_GP_appears_to_be_not_hung__waiti_8030d314[];
extern char s_GP_hang_due_to_XF_stall_bug__8030d2a8[];
extern char s_GP_hang_due_to_illegal_instructi_8030d2f0[];
extern char s_GP_hang_due_to_unterminated_prim_8030d2c8[];
extern char s_GP_is_in_unknown_state__8030d344[];
extern char s_Suspected_graphics_hang_or_infin_8030d260[];
extern char s__s_animcurv_bin_802ccf30[];
extern char s__s_animcurv_tab_802ccf40[];
extern char s__s_mod_d_tab_802ccf98[];
extern char s__s_mod_d_zlb_bin_802ccf84[];
extern char sRomlistZlbPathFormat[];
extern char s__s_voxmap_bin_802ccf50[];
extern char s__s_voxmap_tab_802ccf74[];
extern char s_warlock_voxmap_bin_802ccf60[];
extern undefined4 uRam00000000;
extern undefined uRam803dc24f;

/*
 * --INFO--
 *
 * Function: mapLoadDataFile
 * EN v1.0 Address: 0x800443CC
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x80044510
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern char sResourceFileNameAudioTab[];
extern u8 lbl_80345E10[];
extern char sArchivePathFormat;
extern s16 lbl_803DCC92;
extern int lbl_803DCC70;
extern int lbl_803DCC7C;
extern int lbl_803DCC80;
extern int lbl_803DCC8C;
extern int sprintf(char *buf, const char *fmt, ...);
extern int AtomicSList_Pop(int list);
extern void AtomicSList_Push(int list, int e);
extern int DVDOpen(char *fileName, void *fileInfo);
extern int DVDRead(void *fileInfo, void *addr, int length, int offset);
extern int DVDClose(void *fileInfo);
extern void *mmAlloc(int size, int align, int zone);
extern void mm_free(void *p);
extern void DCInvalidateRange(void *p, u32 n);
extern int DVDReadAsyncPrio(void *fi, void *addr, int len, int off, void (*cb)(), int prio);
extern void mergeTableFiles(void *buf, int a, int b, int n);
extern void texRestructRefs(int a);
extern void piRomLoadSection(int a, int idx, int b);
extern void animCurvReadCb();
extern void animCurvTabReadCb();
extern void voxMapReadCb();
extern void voxMapTabReadCb();
extern void blocksReadCb();
extern void blocksTabReadCb();
extern void tex1ReadCb();
extern void tex1tab1readCb();
extern void tex1tab2readCb();
extern void tex0readCb();
extern void tex0tab1readCb();
extern void tex0tab2readCb();
extern void animReadCb();
extern void animTabReadCb();
extern void modelsReadCb();
extern void modelsTabReadCb();

struct MldfNames {
    u8 pad0[0x3ac];
    char *fileNames[0x22e];
    char *mapNames[0x49];
    int remapGroups[0x4b];
    s16 adjacency[0x2be];
    char fmtAnimCurvBin[0x10];
    char fmtAnimCurvTab[0x10];
    char fmtVoxmapBin[0x10];
    char fmtWarlockVoxmap[0x14];
    char fmtVoxmapTab[0x10];
    char fmtModBin[0x14];
    char fmtModTab[0x10];
};

struct MldfTables {
    u8 pad0[0x160];
    int fileInfo[0x58];
    u8 mergeAnimCurv[0x7f40];
    u8 mergeVoxMap[0x2000];
    u8 mergeBlocks[0x2000];
    u8 mergeTex1[0x4000];
    u8 mergeTex0[0x4000];
    u8 mergeAnim[0x2ee0];
    u8 mergeModels[0x2058];
    int ids[0x58];
    int sizes[0x58];
    int romList[0x78];
    u32 ptrs[0x58];
    s16 owners[0x60];
};

#define MLDF_MAP_NAME(i) (nm->mapNames[i])
#define MLDF_FILE_NAME(i) (nm->fileNames[i])
#define MLDF_ADJ(i) (nm->adjacency[i])
#define MLDF_REMAP (nm->remapGroups)
#define MLDF_FINFO(s) (t->fileInfo[s])
#define MLDF_ID(s) (t->ids[s])
#define MLDF_SIZE(s) (t->sizes[s])
#define MLDF_PTR(s) (t->ptrs[s])
#define MLDF_OWNER(s) (t->owners[s])
#define MLDF_FINFO4(s4) (t->fileInfo[slot])
#define MLDF_SP_ID(p) (t->ids[slot])
#define MLDF_SP_SIZE(p) (t->sizes[slot])
#define MLDF_SP_PTR(p) (t->ptrs[slot])

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
undefined4 mapLoadDataFile(int param_1,int param_2)
{
  struct MldfNames *nm = (struct MldfNames *)sResourceFileNameAudioTab;
  struct MldfTables *t = (struct MldfTables *)lbl_80345E10;
  int sync = 0;
  u32 result;
  int adj;
  int slot;
  int fi;
  int ok;
  u32 tmp;
  char buf[104];

  if (lbl_803DCC92 != 0) {
    lbl_803DCC92 = 0;
    sync = 1;
  }
  adj = MLDF_ADJ(param_1);
  if (adj != -1) {
    int c = 0;
    s16 o25 = MLDF_OWNER(0x25);
    s16 o47;
    if (o25 != -1) {
      c = 1;
    }
    o47 = MLDF_OWNER(0x47);
    if (o47 != -1) {
      c = c + 1;
    }
    if (c == 0) {
      tmp = 1;
      lbl_803DCC92 = 1;
      if (o25 == adj) {
        tmp = 0;
      } else if (o47 != adj) {
        tmp = -1;
      }
      if (tmp == -1) {
        mapLoadDataFile(adj, param_2);
      }
      sync = 1;
    }
  }
  sync = sync | lbl_803DCC70;
  switch (param_2) {
  case 0xd:
  case 0x55:
    result = MLDF_PTR(0xd);
    if ((result != 0) && (MLDF_OWNER(0xd) == param_1)) {
      break;
    }
    result = MLDF_PTR(0x55);
    if ((result != 0) && (MLDF_OWNER(0x55) == param_1)) {
      break;
    }
    {
      if (MLDF_ID(0xd) == param_1) {
        slot = 0xd;
        MLDF_ID(0xd) = -1;
      } else if (MLDF_ID(0x55) == param_1) {
        slot = 0x55;
        MLDF_ID(0x55) = -1;
      } else if (MLDF_OWNER(0xd) == -1) {
        slot = 0xd;
      } else {
        if (MLDF_OWNER(0x55) != -1) {
          result = 0;
          break;
        }
        slot = 0x55;
      }
      if (MLDF_SP_PTR(x) != 0) {
        mm_free((void *)MLDF_SP_PTR(x));
        MLDF_SP_PTR(x) = 0;
      }
      sprintf(buf, nm->fmtAnimCurvBin, MLDF_MAP_NAME(param_1));
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        result = 0;
      } else {
        MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
        if (MLDF_SP_SIZE(x) == 0) {
          result = 0;
        } else {
          MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
          DCInvalidateRange((void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
          tmp = MLDF_SP_PTR(x);
          if (tmp == 0) {
            if (MLDF_ID(param_2) == -1) {
              texRestructRefs(1);
            }
            DVDClose((void *)fi);
            AtomicSList_Push(lbl_803DCC8C, fi);
            MLDF_SP_SIZE(x) = 0;
            MLDF_SP_ID(x) = param_1;
            result = 0;
          } else {
            if (sync != 0) {
              DVDRead((void *)fi, (void *)tmp, MLDF_SP_SIZE(x), 0);
              DVDClose((void *)fi);
              AtomicSList_Push(lbl_803DCC8C, fi);
              if (((lbl_803DCC80 & 0x20000000) == 0) && ((lbl_803DCC80 & 0x80000000) == 0)) {
                mergeTableFiles(t->mergeAnimCurv, 0xe, 0x56, 0x1fd0);
              }
            } else {
              if (slot == 0xd) {
                lbl_803DCC80 = lbl_803DCC80 | 0x10000000;
              } else {
                lbl_803DCC80 = lbl_803DCC80 | 0x40000000;
              }
              DVDReadAsyncPrio((void *)fi, (void *)tmp, MLDF_SP_SIZE(x), 0, animCurvReadCb, 2);
              MLDF_FINFO4(x) = fi;
            }
            MLDF_OWNER(slot) = param_1;
            result = MLDF_SP_PTR(x);
          }
        }
      }
    }
    break;
  case 0xe:
  case 0x56:
    result = MLDF_PTR(0xe);
    if ((result != 0) && (MLDF_OWNER(0xe) == param_1)) {
      break;
    }
    result = MLDF_PTR(0x56);
    if ((result != 0) && (MLDF_OWNER(0x56) == param_1)) {
      break;
    }
    {
      if (MLDF_OWNER(0xe) == -1) {
        slot = 0xe;
      } else {
        if (MLDF_OWNER(0x56) != -1) {
          result = 0;
          break;
        }
        slot = 0x56;
      }
      if (MLDF_SP_PTR(x) != 0) {
        mm_free((void *)MLDF_SP_PTR(x));
        MLDF_SP_PTR(x) = 0;
      }
      sprintf(buf, nm->fmtAnimCurvTab, MLDF_MAP_NAME(param_1));
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        result = 0;
      } else {
        MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
        if (MLDF_SP_SIZE(x) == 0) {
          result = 0;
        } else {
          MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
          DCInvalidateRange((void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
          if (sync != 0) {
            DVDRead((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
            DVDClose((void *)fi);
            AtomicSList_Push(lbl_803DCC8C, fi);
            if (((lbl_803DCC80 & 0x20000000) == 0) && ((lbl_803DCC80 & 0x80000000) == 0)) {
              mergeTableFiles(t->mergeAnimCurv, 0xe, 0x56, 0x1fd0);
            }
          } else {
            if (slot == 0xe) {
              lbl_803DCC80 = lbl_803DCC80 | 0x20000000;
            } else {
              lbl_803DCC80 = lbl_803DCC80 | 0x80000000;
            }
            DVDReadAsyncPrio((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, animCurvTabReadCb, 2);
            MLDF_FINFO4(x) = fi;
          }
          MLDF_OWNER(slot) = param_1;
          result = MLDF_SP_PTR(x);
        }
      }
    }
    break;
  case 0x1b:
  case 0x54:
    result = MLDF_PTR(0x1b);
    if ((result != 0) && (MLDF_OWNER(0x1b) == param_1)) {
      break;
    }
    result = MLDF_PTR(0x54);
    if ((result != 0) && (MLDF_OWNER(0x54) == param_1)) {
      break;
    }
    {
      if (MLDF_OWNER(0x1b) == -1) {
        slot = 0x1b;
      } else {
        if (MLDF_OWNER(0x54) != -1) {
          result = 0;
          break;
        }
        slot = 0x54;
      }
      if (MLDF_SP_PTR(x) != 0) {
        mm_free((void *)MLDF_SP_PTR(x));
        MLDF_SP_PTR(x) = 0;
      }
      sprintf(buf, nm->fmtVoxmapBin, MLDF_MAP_NAME(param_1));
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        sprintf(buf, nm->fmtWarlockVoxmap);
        ok = DVDOpen(buf, (void *)fi);
        if (ok == 0) {
          result = 0;
          break;
        }
      }
      MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
      if (MLDF_SP_SIZE(x) == 0) {
        sprintf(buf, nm->fmtWarlockVoxmap);
        ok = DVDOpen(buf, (void *)fi);
        if (ok == 0) {
          result = 0;
          break;
        }
        MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
      }
      MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
      DCInvalidateRange((void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
      if (sync != 0) {
        DVDRead((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
        DVDClose((void *)fi);
        AtomicSList_Push(lbl_803DCC8C, fi);
        if (((lbl_803DCC80 & 0x2000000) == 0) && ((lbl_803DCC80 & 0x8000000) == 0)) {
          mergeTableFiles(t->mergeVoxMap, 0x1a, 0x53, 0x800);
        }
      } else {
        if (slot == 0x1b) {
          lbl_803DCC80 = lbl_803DCC80 | 0x1000000;
        } else {
          lbl_803DCC80 = lbl_803DCC80 | 0x4000000;
        }
        MLDF_FINFO4(x) = fi;
        DVDReadAsyncPrio((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, voxMapReadCb, 2);
      }
      MLDF_OWNER(slot) = param_1;
      result = MLDF_SP_PTR(x);
    }
    break;
  case 0x1a:
  case 0x53:
    result = MLDF_PTR(0x1a);
    if ((result != 0) && (MLDF_OWNER(0x1a) == param_1)) {
      break;
    }
    result = MLDF_PTR(0x53);
    if ((result != 0) && (MLDF_OWNER(0x53) == param_1)) {
      break;
    }
    {
      if (MLDF_OWNER(0x1a) == -1) {
        slot = 0x1a;
      } else {
        if (MLDF_OWNER(0x53) != -1) {
          result = 0;
          break;
        }
        slot = 0x53;
      }
      if (MLDF_SP_PTR(x) != 0) {
        mm_free((void *)MLDF_SP_PTR(x));
        MLDF_SP_PTR(x) = 0;
      }
      sprintf(buf, nm->fmtVoxmapTab, MLDF_MAP_NAME(param_1));
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        result = 0;
      } else {
        MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
        if (MLDF_SP_SIZE(x) == 0) {
          AtomicSList_Push(lbl_803DCC8C, fi);
          result = 0;
        } else {
          MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
          DCInvalidateRange((void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
          if (sync != 0) {
            DVDRead((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
            DVDClose((void *)fi);
            AtomicSList_Push(lbl_803DCC8C, fi);
            if (((lbl_803DCC80 & 0x2000000) == 0) && ((lbl_803DCC80 & 0x8000000) == 0)) {
              mergeTableFiles(t->mergeVoxMap, 0x1a, 0x53, 0x800);
            }
          } else {
            if (slot == 0x1a) {
              lbl_803DCC80 = lbl_803DCC80 | 0x2000000;
            } else {
              lbl_803DCC80 = lbl_803DCC80 | 0x8000000;
            }
            MLDF_FINFO4(x) = fi;
            DVDReadAsyncPrio((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, voxMapTabReadCb, 2);
          }
          MLDF_OWNER(slot) = param_1;
          result = MLDF_SP_PTR(x);
        }
      }
    }
    break;
  case 0x25:
  case 0x47:
    result = MLDF_PTR(0x25);
    if ((result != 0) && (MLDF_OWNER(0x25) == param_1)) {
      break;
    }
    result = MLDF_PTR(0x47);
    if ((result != 0) && (MLDF_OWNER(0x47) == param_1)) {
      break;
    }
    {
      if (MLDF_ID(0x25) == param_1) {
        slot = 0x25;
        MLDF_ID(0x25) = -1;
      } else if (MLDF_ID(0x47) == param_1) {
        slot = 0x47;
        MLDF_ID(0x47) = -1;
      } else if (MLDF_OWNER(0x25) == -1) {
        slot = 0x25;
      } else {
        if (MLDF_OWNER(0x47) != -1) {
          result = 0;
          break;
        }
        slot = 0x47;
      }
      if (MLDF_SP_PTR(x) != 0) {
        mm_free((void *)MLDF_SP_PTR(x));
        MLDF_SP_PTR(x) = 0;
      }
      if (param_1 > 4) {
        sprintf(buf, nm->fmtModBin, MLDF_MAP_NAME(param_1), param_1 + 1);
      } else {
        sprintf(buf, nm->fmtModBin, MLDF_MAP_NAME(param_1), param_1);
      }
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        result = 0;
      } else {
        MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
        MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
        DCInvalidateRange((void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
        tmp = MLDF_SP_PTR(x);
        if (tmp == 0) {
          if (MLDF_ID(param_2) == -1) {
            texRestructRefs(1);
          }
          DVDClose((void *)fi);
          AtomicSList_Push(lbl_803DCC8C, fi);
          MLDF_SP_SIZE(x) = 0;
          MLDF_SP_ID(x) = param_1;
          result = 0;
        } else {
          if (sync != 0) {
            DVDRead((void *)fi, (void *)tmp, MLDF_SP_SIZE(x), 0);
            DVDClose((void *)fi);
            AtomicSList_Push(lbl_803DCC8C, fi);
            if (((lbl_803DCC80 & 0x20000) == 0) && ((lbl_803DCC80 & 0x80000) == 0)) {
              mergeTableFiles(t->mergeBlocks, 0x26, 0x48, 0x800);
            }
          } else {
            if (slot == 0x25) {
              lbl_803DCC80 = lbl_803DCC80 | 0x10000;
            } else {
              lbl_803DCC80 = lbl_803DCC80 | 0x40000;
            }
            MLDF_FINFO4(x) = fi;
            DVDReadAsyncPrio((void *)fi, (void *)tmp, MLDF_SP_SIZE(x), 0, blocksReadCb, 2);
          }
          MLDF_OWNER(slot) = param_1;
          result = MLDF_SP_PTR(x);
        }
      }
    }
    break;
  case 0x26:
  case 0x48: {
    int idx;
    int *grp;
    int n;
    result = MLDF_PTR(0x26);
    if ((result != 0) && (MLDF_OWNER(0x26) == param_1)) {
      break;
    }
    result = MLDF_PTR(0x48);
    if ((result != 0) && (MLDF_OWNER(0x48) == param_1)) {
      break;
    }
    {
      if (MLDF_OWNER(0x26) == -1) {
        slot = 0x26;
      } else {
        if (MLDF_OWNER(0x48) != -1) {
          result = 0;
          break;
        }
        slot = 0x48;
      }
      if (MLDF_SP_PTR(x) != 0) {
        mm_free((void *)MLDF_SP_PTR(x));
        MLDF_SP_PTR(x) = 0;
      }
      idx = 0;
      grp = MLDF_REMAP;
      for (n = 0xf; n != 0; n--) {
        if (param_1 == grp[0]) goto remap_found;
        idx = idx + 1;
        if (param_1 == grp[1]) goto remap_found;
        idx = idx + 1;
        if (param_1 == grp[2]) goto remap_found;
        idx = idx + 1;
        if (param_1 == grp[3]) goto remap_found;
        idx = idx + 1;
        if (param_1 == grp[4]) goto remap_found;
        grp = grp + 5;
        idx = idx + 1;
      }
    remap_found:
      piRomLoadSection(0, idx, 0);
      if (param_1 > 4) {
        sprintf(buf, nm->fmtModTab, MLDF_MAP_NAME(param_1), param_1 + 1);
      } else {
        sprintf(buf, nm->fmtModTab, MLDF_MAP_NAME(param_1), param_1);
      }
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        result = 0;
      } else {
        MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
        MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
        DCInvalidateRange((void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
        if (sync != 0) {
          DVDRead((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
          DVDClose((void *)fi);
          AtomicSList_Push(lbl_803DCC8C, fi);
          if (((lbl_803DCC80 & 0x20000) == 0) && ((lbl_803DCC80 & 0x80000) == 0)) {
            mergeTableFiles(t->mergeBlocks, 0x26, 0x48, 0x800);
          }
        } else {
          if (slot == 0x26) {
            lbl_803DCC80 = lbl_803DCC80 | 0x20000;
          } else {
            lbl_803DCC80 = lbl_803DCC80 | 0x80000;
          }
          MLDF_FINFO4(x) = fi;
          DVDReadAsyncPrio((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, blocksTabReadCb, 2);
        }
        MLDF_OWNER(slot) = param_1;
        result = MLDF_SP_PTR(x);
      }
    }
    break;
  }
  case 0x2b:
  case 0x46:
    result = MLDF_PTR(0x2b);
    if ((result != 0) && (MLDF_OWNER(0x2b) == param_1)) {
      break;
    }
    result = MLDF_PTR(0x46);
    if ((result != 0) && (MLDF_OWNER(0x46) == param_1)) {
      break;
    }
    {
      if (MLDF_ID(0x2b) == param_1) {
        slot = 0x2b;
        MLDF_ID(0x2b) = -1;
      } else if (MLDF_ID(0x46) == param_1) {
        slot = 0x46;
        MLDF_ID(0x46) = -1;
      } else if (MLDF_OWNER(0x2b) == -1) {
        slot = 0x2b;
      } else {
        if (MLDF_OWNER(0x46) != -1) {
          result = 0;
          break;
        }
        slot = 0x46;
      }
      if (MLDF_SP_PTR(x) != 0) {
        mm_free((void *)MLDF_SP_PTR(x));
        MLDF_SP_PTR(x) = 0;
      }
      sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(param_1), MLDF_FILE_NAME(param_2));
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        result = 0;
      } else {
        MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
        MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
        DCInvalidateRange((void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
        tmp = MLDF_SP_PTR(x);
        if (tmp == 0) {
          if (MLDF_ID(param_2) == -1) {
            texRestructRefs(1);
          }
          DVDClose((void *)fi);
          AtomicSList_Push(lbl_803DCC8C, fi);
          MLDF_SP_SIZE(x) = 0;
          MLDF_SP_ID(x) = param_1;
          result = 0;
        } else {
          if (sync != 0) {
            DVDRead((void *)fi, (void *)tmp, MLDF_SP_SIZE(x), 0);
            DVDClose((void *)fi);
            AtomicSList_Push(lbl_803DCC8C, fi);
            if (((lbl_803DCC80 & 4) == 0) && ((lbl_803DCC80 & 8) == 0)) {
              mergeTableFiles(t->mergeModels, 0x2a, 0x45, 0x800);
            }
            lbl_803DCC7C = lbl_803DCC7C + 1;
          } else {
            lbl_803DCC7C = lbl_803DCC7C + 1;
            if (slot == 0x2b) {
              lbl_803DCC80 = lbl_803DCC80 | 1;
            } else {
              lbl_803DCC80 = lbl_803DCC80 | 2;
            }
            MLDF_FINFO4(x) = fi;
            DVDReadAsyncPrio((void *)fi, (void *)tmp, MLDF_SP_SIZE(x), 0, modelsReadCb, 2);
          }
          MLDF_OWNER(slot) = param_1;
          result = MLDF_SP_PTR(x);
        }
      }
    }
    break;
  case 0x2a:
  case 0x45:
    result = MLDF_PTR(0x2a);
    if ((result != 0) && (MLDF_OWNER(0x2a) == param_1)) {
      break;
    }
    result = MLDF_PTR(0x45);
    if ((result != 0) && (MLDF_OWNER(0x45) == param_1)) {
      break;
    }
    {
      if (MLDF_OWNER(0x2a) == -1) {
        slot = 0x2a;
      } else {
        if (MLDF_OWNER(0x45) != -1) {
          result = 0;
          break;
        }
        slot = 0x45;
      }
      if (MLDF_SP_PTR(x) != 0) {
        mm_free((void *)MLDF_SP_PTR(x));
        MLDF_SP_PTR(x) = 0;
      }
      sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(param_1), MLDF_FILE_NAME(param_2));
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        result = 0;
      } else {
        MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
        MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
        DCInvalidateRange((void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
        if (sync != 0) {
          DVDRead((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
          DVDClose((void *)fi);
          AtomicSList_Push(lbl_803DCC8C, fi);
          if (((lbl_803DCC80 & 4) == 0) && ((lbl_803DCC80 & 8) == 0)) {
            mergeTableFiles(t->mergeModels, 0x2a, 0x45, 0x800);
          }
        } else {
          if (slot == 0x2a) {
            lbl_803DCC80 = lbl_803DCC80 | 4;
          } else {
            lbl_803DCC80 = lbl_803DCC80 | 8;
          }
          MLDF_FINFO4(x) = fi;
          DVDReadAsyncPrio((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, modelsTabReadCb, 2);
        }
        MLDF_OWNER(slot) = param_1;
        result = MLDF_SP_PTR(x);
      }
    }
    break;
  case 0x30:
  case 0x4a:
    result = MLDF_PTR(0x30);
    if ((result != 0) && (MLDF_OWNER(0x30) == param_1)) {
      break;
    }
    result = MLDF_PTR(0x4a);
    if ((result != 0) && (MLDF_OWNER(0x4a) == param_1)) {
      break;
    }
    {
      if (MLDF_ID(0x30) == param_1) {
        slot = 0x30;
        MLDF_ID(0x30) = -1;
      } else if (MLDF_ID(0x4a) == param_1) {
        slot = 0x4a;
        MLDF_ID(0x4a) = -1;
      } else if (MLDF_OWNER(0x30) == -1) {
        slot = 0x30;
      } else {
        if (MLDF_OWNER(0x4a) != -1) {
          result = 0;
          break;
        }
        slot = 0x4a;
      }
      if (MLDF_SP_PTR(x) != 0) {
        mm_free((void *)MLDF_SP_PTR(x));
        MLDF_SP_PTR(x) = 0;
      }
      sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(param_1), MLDF_FILE_NAME(param_2));
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        result = 0;
      } else {
        MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
        MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
        DCInvalidateRange((void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
        tmp = MLDF_SP_PTR(x);
        if (tmp == 0) {
          if (MLDF_ID(param_2) == -1) {
            texRestructRefs(1);
          }
          DVDClose((void *)fi);
          AtomicSList_Push(lbl_803DCC8C, fi);
          MLDF_SP_SIZE(x) = 0;
          MLDF_SP_ID(x) = param_1;
          result = 0;
        } else {
          if (sync != 0) {
            DVDRead((void *)fi, (void *)tmp, MLDF_SP_SIZE(x), 0);
            DVDClose((void *)fi);
            AtomicSList_Push(lbl_803DCC8C, fi);
            if (((lbl_803DCC80 & 0x40) == 0) && ((lbl_803DCC80 & 0x80) == 0)) {
              mergeTableFiles(t->mergeAnim, 0x2f, 0x49, 3000);
            }
          } else {
            if (slot == 0x30) {
              lbl_803DCC80 = lbl_803DCC80 | 0x10;
            } else {
              lbl_803DCC80 = lbl_803DCC80 | 0x20;
            }
            MLDF_FINFO4(x) = fi;
            DVDReadAsyncPrio((void *)fi, (void *)tmp, MLDF_SP_SIZE(x), 0, animReadCb, 2);
          }
          MLDF_OWNER(slot) = param_1;
          result = MLDF_SP_PTR(x);
        }
      }
    }
    break;
  case 0x2f:
  case 0x49:
    result = MLDF_PTR(0x2f);
    if ((result != 0) && (MLDF_OWNER(0x2f) == param_1)) {
      break;
    }
    result = MLDF_PTR(0x49);
    if ((result != 0) && (MLDF_OWNER(0x49) == param_1)) {
      break;
    }
    {
      if (MLDF_OWNER(0x2f) == -1) {
        slot = 0x2f;
      } else {
        if (MLDF_OWNER(0x49) != -1) {
          result = 0;
          break;
        }
        slot = 0x49;
      }
      if (MLDF_SP_PTR(x) != 0) {
        mm_free((void *)MLDF_SP_PTR(x));
        MLDF_SP_PTR(x) = 0;
      }
      sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(param_1), MLDF_FILE_NAME(param_2));
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        result = 0;
      } else {
        MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
        MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
        DCInvalidateRange((void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
        if (sync != 0) {
          DVDRead((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
          DVDClose((void *)fi);
          AtomicSList_Push(lbl_803DCC8C, fi);
          if (((lbl_803DCC80 & 0x40) == 0) && ((lbl_803DCC80 & 0x80) == 0)) {
            mergeTableFiles(t->mergeAnim, 0x2f, 0x49, 3000);
          }
        } else {
          if (slot == 0x2f) {
            lbl_803DCC80 = lbl_803DCC80 | 0x40;
          } else {
            lbl_803DCC80 = lbl_803DCC80 | 0x80;
          }
          MLDF_FINFO4(x) = fi;
          DVDReadAsyncPrio((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, animTabReadCb, 2);
        }
        MLDF_OWNER(slot) = param_1;
        result = MLDF_SP_PTR(x);
      }
    }
    break;
  case 0x23:
  case 0x4d:
    result = MLDF_PTR(0x23);
    if ((result != 0) && (MLDF_OWNER(0x23) == param_1)) {
      break;
    }
    result = MLDF_PTR(0x4d);
    if ((result != 0) && (MLDF_OWNER(0x4d) == param_1)) {
      break;
    }
    {
      if (MLDF_ID(0x23) == param_1) {
        slot = 0x23;
        MLDF_ID(0x23) = -1;
      } else if (MLDF_ID(0x4d) == param_1) {
        slot = 0x4d;
        MLDF_ID(0x4d) = -1;
      } else if (MLDF_OWNER(0x23) == -1) {
        slot = 0x23;
      } else {
        if (MLDF_OWNER(0x4d) != -1) {
          result = 0;
          break;
        }
        slot = 0x4d;
      }
      if (MLDF_SP_PTR(x) != 0) {
        mm_free((void *)MLDF_SP_PTR(x));
        MLDF_SP_PTR(x) = 0;
      }
      sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(param_1), MLDF_FILE_NAME(param_2));
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        result = 0;
      } else {
        MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
        MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x) + 0x20, 0x7d7d7d7d, 0);
        DCInvalidateRange((void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
        tmp = MLDF_SP_PTR(x);
        if (tmp == 0) {
          if (MLDF_ID(param_2) == -1) {
            texRestructRefs(1);
          }
          DVDClose((void *)fi);
          AtomicSList_Push(lbl_803DCC8C, fi);
          MLDF_SP_SIZE(x) = 0;
          MLDF_SP_ID(x) = param_1;
          result = 0;
        } else {
          if (sync != 0) {
            DVDRead((void *)fi, (void *)tmp, MLDF_SP_SIZE(x), 0);
            DVDClose((void *)fi);
            AtomicSList_Push(lbl_803DCC8C, fi);
            if (((lbl_803DCC80 & 0x400) == 0) && ((lbl_803DCC80 & 0x800) == 0)) {
              mergeTableFiles(t->mergeTex0, 0x24, 0x4e, 0x1000);
            }
          } else {
            if (slot == 0x23) {
              lbl_803DCC80 = lbl_803DCC80 | 0x100;
            } else {
              lbl_803DCC80 = lbl_803DCC80 | 0x200;
            }
            MLDF_FINFO4(x) = fi;
            DVDReadAsyncPrio((void *)fi, (void *)tmp, MLDF_SP_SIZE(x), 0, tex0readCb, 2);
          }
          MLDF_OWNER(slot) = param_1;
          result = MLDF_SP_PTR(x);
        }
      }
    }
    break;
  case 0x24:
  case 0x4e:
    result = MLDF_PTR(0x24);
    if ((result != 0) && (MLDF_OWNER(0x24) == param_1)) {
      break;
    }
    result = MLDF_PTR(0x4e);
    if ((result != 0) && (MLDF_OWNER(0x4e) == param_1)) {
      break;
    }
    {
      if (MLDF_OWNER(0x24) == -1) {
        slot = 0x24;
      } else {
        if (MLDF_OWNER(0x4e) != -1) {
          result = 0;
          break;
        }
        slot = 0x4e;
      }
      if (MLDF_SP_PTR(x) != 0) {
        mm_free((void *)MLDF_SP_PTR(x));
        MLDF_SP_PTR(x) = 0;
      }
      sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(param_1), MLDF_FILE_NAME(param_2));
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        result = 0;
      } else {
        MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
        MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x) + 0x20, 0x7d7d7d7d, 0);
        DCInvalidateRange((void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
        if (sync != 0) {
          DVDRead((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
          DVDClose((void *)fi);
          AtomicSList_Push(lbl_803DCC8C, fi);
          if (((lbl_803DCC80 & 0x400) == 0) && ((lbl_803DCC80 & 0x800) == 0)) {
            mergeTableFiles(t->mergeTex0, 0x24, 0x4e, 0x1000);
          }
        } else {
          MLDF_FINFO4(x) = fi;
          if (slot == 0x24) {
            lbl_803DCC80 = lbl_803DCC80 | 0x400;
            DVDReadAsyncPrio((void *)fi, (void *)MLDF_PTR(0x24), MLDF_SIZE(0x24), 0, tex0tab1readCb, 2);
          } else {
            lbl_803DCC80 = lbl_803DCC80 | 0x800;
            DVDReadAsyncPrio((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, tex0tab2readCb, 2);
          }
        }
        MLDF_OWNER(slot) = param_1;
        result = MLDF_SP_PTR(x);
      }
    }
    break;
  case 0x20:
  case 0x4b:
    result = MLDF_PTR(0x20);
    if ((result != 0) && (MLDF_OWNER(0x20) == param_1)) {
      break;
    }
    result = MLDF_PTR(0x4b);
    if ((result != 0) && (MLDF_OWNER(0x4b) == param_1)) {
      break;
    }
    {
      if (MLDF_ID(0x20) == param_1) {
        slot = 0x20;
        MLDF_ID(0x20) = -1;
      } else if (MLDF_ID(0x4b) == param_1) {
        slot = 0x4b;
        MLDF_ID(0x4b) = -1;
      } else if (MLDF_OWNER(0x20) == -1) {
        slot = 0x20;
      } else {
        if (MLDF_OWNER(0x4b) != -1) {
          result = 0;
          break;
        }
        slot = 0x4b;
      }
      if (MLDF_SP_PTR(x) != 0) {
        mm_free((void *)MLDF_SP_PTR(x));
        MLDF_SP_PTR(x) = 0;
      }
      sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(param_1), MLDF_FILE_NAME(param_2));
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        result = 0;
      } else {
        MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
        MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x) + 0x20, 0x7d7d7d7d, 0);
        DCInvalidateRange((void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
        tmp = MLDF_SP_PTR(x);
        if (tmp == 0) {
          if (MLDF_ID(param_2) == -1) {
            texRestructRefs(1);
          }
          DVDClose((void *)fi);
          AtomicSList_Push(lbl_803DCC8C, fi);
          MLDF_SP_SIZE(x) = 0;
          MLDF_SP_ID(x) = param_1;
          result = 0;
        } else {
          if (sync != 0) {
            DVDRead((void *)fi, (void *)tmp, MLDF_SP_SIZE(x), 0);
            DVDClose((void *)fi);
            AtomicSList_Push(lbl_803DCC8C, fi);
            if (((lbl_803DCC80 & 0x4000) == 0) && ((lbl_803DCC80 & 0x8000) == 0)) {
              mergeTableFiles(t->mergeTex1, 0x21, 0x4c, 0x1000);
            }
          } else {
            if (slot == 0x20) {
              lbl_803DCC80 = lbl_803DCC80 | 0x1000;
            } else {
              lbl_803DCC80 = lbl_803DCC80 | 0x2000;
            }
            MLDF_FINFO4(x) = fi;
            DVDReadAsyncPrio((void *)fi, (void *)tmp, MLDF_SP_SIZE(x), 0, tex1ReadCb, 2);
          }
          MLDF_OWNER(slot) = param_1;
          result = MLDF_SP_PTR(x);
        }
      }
    }
    break;
  case 0x21:
  case 0x4c:
    result = MLDF_PTR(0x21);
    if ((result != 0) && (MLDF_OWNER(0x21) == param_1)) {
      break;
    }
    result = MLDF_PTR(0x4c);
    if ((result != 0) && (MLDF_OWNER(0x4c) == param_1)) {
      break;
    }
    {
      if (MLDF_OWNER(0x21) == -1) {
        slot = 0x21;
      } else {
        if (MLDF_OWNER(0x4c) != -1) {
          result = 0;
          break;
        }
        slot = 0x4c;
      }
      if (MLDF_SP_PTR(x) != 0) {
        mm_free((void *)MLDF_SP_PTR(x));
        MLDF_SP_PTR(x) = 0;
      }
      sprintf(buf, &sArchivePathFormat, MLDF_MAP_NAME(param_1), MLDF_FILE_NAME(param_2));
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        result = 0;
      } else {
        MLDF_SP_SIZE(x) = *(int *)(fi + 0x34);
        MLDF_SP_PTR(x) = (int)mmAlloc(MLDF_SP_SIZE(x), 0x7d7d7d7d, 0);
        DCInvalidateRange((void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x));
        if (sync != 0) {
          DVDRead((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0);
          DVDClose((void *)fi);
          AtomicSList_Push(lbl_803DCC8C, fi);
          if (((lbl_803DCC80 & 0x4000) == 0) && ((lbl_803DCC80 & 0x8000) == 0)) {
            mergeTableFiles(t->mergeTex1, 0x21, 0x4c, 0x1000);
          }
        } else {
          MLDF_FINFO4(x) = fi;
          if (slot == 0x21) {
            lbl_803DCC80 = lbl_803DCC80 | 0x4000;
            DVDReadAsyncPrio((void *)fi, (void *)MLDF_PTR(0x21), MLDF_SIZE(0x21), 0, tex1tab1readCb, 2);
          } else {
            lbl_803DCC80 = lbl_803DCC80 | 0x8000;
            DVDReadAsyncPrio((void *)fi, (void *)MLDF_SP_PTR(x), MLDF_SP_SIZE(x), 0, tex1tab2readCb, 2);
          }
        }
        MLDF_OWNER(slot) = param_1;
        result = MLDF_SP_PTR(x);
      }
    }
    break;
  default:
    result = 0;
    break;
  }
  return result;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

extern void padUpdate(void);
extern void checkReset(void);
extern void waitNextFrame(void);
extern void dvdCheckError(void);
extern void mmFreeTick(int a);
extern void gameTextRun(void);
extern u8 lbl_803DC950;
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern u8 framesThisStep;
extern char sZlbBlockTag[];
extern int return0_8002A5B8(int p);
extern int OSDisableInterrupts(void);
extern void OSRestoreInterrupts(int s);
extern char sDirBlockTag;
extern int strncmp(const char *a, const char *b, u32 n);
extern void *memcpy(void *dst, const void *src, u32 n);
extern char *sResourceFileNameTable[];
extern void zlbDecompress(void *dst, int size, int out, void *src);
extern void DCStoreRange(void *p, u32 n);
extern u32 ObjModel_GetUnpackedResourceSize(int p, u32 size);
extern void ObjModel_UnpackResourcePayload(int p, u32 size, int dst, u32 unpacked);
void loadDataFiles(void);
int GXFlush_(u8 visible, int unused);

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void loadAndDecompressDataFile(int param_1,int param_2,u32 param_3,u32 param_4,u32 *param_5,int param_6,u32 param_7)
{
  struct MldfTables *t = (struct MldfTables *)lbl_80345E10;
  u32 b = 0;
  u32 a = 0;
  u8 frame = 0;
  u32 hi;
  int flags;
  u32 off;
  u32 moff;
  int s;
  int i;
  int j;
  int k;
  int r;
  int ok;
  u32 asize;
  int tmp;
  u32 local_78;
  char buf[0x3c];

  switch (param_1) {
  case 0xd:
    s = OSDisableInterrupts();
    flags = lbl_803DCC80;
    OSRestoreInterrupts(s);
    if ((flags & 0x20000000) == 0 && (flags & 0x10000000) == 0) {
      b = MLDF_PTR(0xe);
    }
    if ((flags & 0x80000000) == 0 && (flags & 0x40000000) == 0) {
      a = MLDF_PTR(0x56);
    }
    hi = param_3 & 0x80000000;
    if (hi != 0 && b == 0) {
      while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0) {
        if ((flags & 0x20000000) == 0 && (flags & 0x10000000) == 0) {
          b = *(u32 *)((char *)t + 0x800195d8);
          break;
        }
      padUpdate();
      checkReset();
      if (frame != 0) {
        waitNextFrame();
      }
      loadDataFiles();
      dvdCheckError();
      if (frame != 0) {
        mmFreeTick(0);
        gameTextRun();
        GXFlush_(1, 0);
      }
      if (lbl_803DC950 != 0) {
        frame = 1;
      }
      }
    }
    else if ((param_3 & 0x20000000) != 0 && a == 0) {
      while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0) {
        if ((flags & 0x80000000) == 0 && (flags & 0x40000000) == 0) {
          a = MLDF_PTR(0);
          break;
        }
      padUpdate();
      checkReset();
      if (frame != 0) {
        waitNextFrame();
      }
      loadDataFiles();
      dvdCheckError();
      if (frame != 0) {
        mmFreeTick(0);
        gameTextRun();
        GXFlush_(1, 0);
      }
      if (lbl_803DC950 != 0) {
        frame = 1;
      }
      }
    }
    if ((param_3 & 0x20000000) != 0 && a != 0) {
      param_1 = 0x55;
    } else if (hi != 0 && b != 0) {
      param_1 = 0xd;
    } else if (b != 0) {
      param_1 = 0xd;
    } else if (a != 0) {
      param_1 = 0x55;
    }
    param_3 = param_3 & 0xfffffff;
    break;
  case 0x1b:
    s = OSDisableInterrupts();
    flags = lbl_803DCC80;
    OSRestoreInterrupts(s);
    if ((flags & 0x2000000) == 0 && (flags & 0x1000000) == 0) {
      b = MLDF_PTR(0x1a);
    }
    if ((flags & 0x8000000) == 0 && (flags & 0x4000000) == 0) {
      a = MLDF_PTR(0x53);
    }
    hi = param_3 & 0x80000000;
    if (hi != 0 && b == 0) {
      while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0) {
        if ((flags & 0x2000000) == 0 && (flags & 0x1000000) == 0) {
          b = MLDF_PTR(0x1a);
          break;
        }
      padUpdate();
      checkReset();
      if (frame != 0) {
        waitNextFrame();
      }
      loadDataFiles();
      dvdCheckError();
      if (frame != 0) {
        mmFreeTick(0);
        gameTextRun();
        GXFlush_(1, 0);
      }
      if (lbl_803DC950 != 0) {
        frame = 1;
      }
      }
    }
    else if ((param_3 & 0x20000000) != 0 && a == 0) {
      while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0) {
        if ((flags & 0x8000000) == 0 && (flags & 0x4000000) == 0) {
          a = MLDF_PTR(0x53);
          break;
        }
      padUpdate();
      checkReset();
      if (frame != 0) {
        waitNextFrame();
      }
      loadDataFiles();
      dvdCheckError();
      if (frame != 0) {
        mmFreeTick(0);
        gameTextRun();
        GXFlush_(1, 0);
      }
      if (lbl_803DC950 != 0) {
        frame = 1;
      }
      }
    }
    if ((param_3 & 0x20000000) != 0 && a != 0) {
      param_1 = 0x54;
    } else if (hi != 0 && b != 0) {
      param_1 = 0x1b;
    } else if (b != 0) {
      param_1 = 0x1b;
    } else if (a != 0) {
      param_1 = 0x54;
    }
    param_3 = param_3 & 0xfffffff;
    break;
  case 0x25:
    s = OSDisableInterrupts();
    flags = lbl_803DCC80;
    OSRestoreInterrupts(s);
    if ((flags & 0x20000) == 0 && (flags & 0x10000) == 0) {
      b = MLDF_PTR(0x26);
    }
    if ((flags & 0x80000) == 0 && (flags & 0x40000) == 0) {
      a = MLDF_PTR(0x48);
    }
    if ((param_3 & 0x20000000) != 0 && a != 0) {
      param_1 = 0x47;
    } else if ((param_3 & 0x10000000) != 0 && b != 0) {
      param_1 = 0x25;
    } else if (b != 0) {
      param_1 = 0x25;
    } else if (a != 0) {
      param_1 = 0x47;
    }
    param_3 = param_3 & 0xfffffff;
    break;
  case 0x2b:
    s = OSDisableInterrupts();
    flags = lbl_803DCC80;
    OSRestoreInterrupts(s);
    if ((flags & 4) == 0 && (flags & 1) == 0) {
      b = MLDF_PTR(0x2a);
    }
    if ((flags & 8) == 0 && (flags & 2) == 0) {
      a = MLDF_PTR(0x45);
    }
    if ((param_3 & 0x10000000) != 0 && b == 0) {
      while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0) {
        if ((flags & 4) == 0 && (flags & 1) == 0) {
          b = MLDF_PTR(0x2a);
          break;
        }
      padUpdate();
      checkReset();
      if (frame != 0) {
        waitNextFrame();
      }
      loadDataFiles();
      dvdCheckError();
      if (frame != 0) {
        mmFreeTick(0);
        gameTextRun();
        GXFlush_(1, 0);
      }
      if (lbl_803DC950 != 0) {
        frame = 1;
      }
      }
    }
    else if ((param_3 & 0x20000000) != 0 && a == 0) {
      while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0) {
        if ((flags & 8) == 0 && (flags & 2) == 0) {
          a = MLDF_PTR(0x45);
          break;
        }
      padUpdate();
      checkReset();
      if (frame != 0) {
        waitNextFrame();
      }
      loadDataFiles();
      dvdCheckError();
      if (frame != 0) {
        mmFreeTick(0);
        gameTextRun();
        GXFlush_(1, 0);
      }
      if (lbl_803DC950 != 0) {
        frame = 1;
      }
      }
    }
    if (a != 0 && (param_3 & 0x20000000) != 0) {
      param_1 = 0x46;
      if (param_5 != NULL) {
        moff = *(u32 *)(a + param_6 * 4) & 0xffffff;
        i = 0;
        if (moff == 0) {
          do {
            j = i + 1;
            k = i * 4;
            i = j;
          } while ((*(u32 *)(a + k) & 0xffffff) == 0);
          *param_5 = *(u32 *)(a + j * 4 - 4) & 0xffffff;
        } else if (moff < (*(u32 *)(a + param_6 * 4 - 4) & 0xffffff)) {
          do {
            k = i * 4;
            j = i + 1;
            i = i + 1;
          } while (moff != (*(u32 *)(a + k) & 0xffffff));
          do {
            i = j + 1;
            k = j * 4;
            j = i;
          } while ((*(u32 *)(a + k) & 0xffffff) <= moff);
          *param_5 = (*(u32 *)(a + i * 4 - 4) & 0xffffff) - moff;
        } else {
          do {
            j = param_6 + 1;
            k = param_6 * 4;
            param_6 = j;
          } while ((*(u32 *)(a + k) & 0xffffff) <= moff);
          *param_5 = (*(u32 *)(a + j * 4 - 4) & 0xffffff) - moff;
        }
      }
    } else if (b != 0 && (param_3 & 0x10000000) != 0) {
      param_1 = 0x2b;
      if (param_5 != NULL) {
        moff = *(u32 *)(b + param_6 * 4) & 0xffffff;
        i = 0;
        if (moff == 0) {
          do {
            j = i + 1;
            k = i * 4;
            i = j;
          } while ((*(u32 *)(b + k) & 0xffffff) == 0);
          *param_5 = *(u32 *)(b + j * 4 - 4) & 0xffffff;
        } else if (moff < (*(u32 *)(b + param_6 * 4 - 4) & 0xffffff)) {
          do {
            k = i * 4;
            j = i + 1;
            i = i + 1;
          } while (moff != (*(u32 *)(b + k) & 0xffffff));
          do {
            i = j + 1;
            k = j * 4;
            j = i;
          } while ((*(u32 *)(b + k) & 0xffffff) <= moff);
          *param_5 = (*(u32 *)(b + i * 4 - 4) & 0xffffff) - moff;
        } else {
          do {
            j = param_6 + 1;
            k = param_6 * 4;
            param_6 = j;
          } while ((*(u32 *)(b + k) & 0xffffff) <= moff);
          *param_5 = (*(u32 *)(b + j * 4 - 4) & 0xffffff) - moff;
        }
      }
    } else if (b != 0) {
      param_1 = 0x2b;
      if (param_5 != NULL) {
        moff = *(u32 *)(b + param_6 * 4) & 0xffffff;
        i = 0;
        if (moff == 0) {
          do {
            j = i + 1;
            k = i * 4;
            i = j;
          } while ((*(u32 *)(b + k) & 0xffffff) == 0);
          *param_5 = *(u32 *)(b + j * 4 - 4) & 0xffffff;
        } else if (moff < (*(u32 *)(b + param_6 * 4 - 4) & 0xffffff)) {
          do {
            k = i * 4;
            j = i + 1;
            i = i + 1;
          } while (moff != (*(u32 *)(b + k) & 0xffffff));
          do {
            i = j + 1;
            k = j * 4;
            j = i;
          } while ((*(u32 *)(b + k) & 0xffffff) <= moff);
          *param_5 = (*(u32 *)(b + i * 4 - 4) & 0xffffff) - moff;
        } else {
          do {
            j = param_6 + 1;
            k = param_6 * 4;
            param_6 = j;
          } while ((*(u32 *)(b + k) & 0xffffff) <= moff);
          *param_5 = (*(u32 *)(b + j * 4 - 4) & 0xffffff) - moff;
        }
      }
    } else if (a != 0) {
      param_1 = 0x46;
      if (param_5 != NULL) {
        moff = *(u32 *)(a + param_6 * 4) & 0xffffff;
        i = 0;
        if (moff == 0) {
          do {
            j = i + 1;
            k = i * 4;
            i = j;
          } while ((*(u32 *)(a + k) & 0xffffff) == 0);
          *param_5 = *(u32 *)(a + j * 4 - 4) & 0xffffff;
        } else if (moff < (*(u32 *)(a + param_6 * 4 - 4) & 0xffffff)) {
          do {
            k = i * 4;
            j = i + 1;
            i = i + 1;
          } while (moff != (*(u32 *)(a + k) & 0xffffff));
          do {
            i = j + 1;
            k = j * 4;
            j = i;
          } while ((*(u32 *)(a + k) & 0xffffff) <= moff);
          *param_5 = (*(u32 *)(a + i * 4 - 4) & 0xffffff) - moff;
        } else {
          do {
            j = param_6 + 1;
            k = param_6 * 4;
            param_6 = j;
          } while ((*(u32 *)(a + k) & 0xffffff) <= moff);
          *param_5 = (*(u32 *)(a + j * 4 - 4) & 0xffffff) - moff;
        }
      }
    }
    param_3 = param_3 & 0xfffffff;
    break;
  case 0x30:
    s = OSDisableInterrupts();
    flags = lbl_803DCC80;
    OSRestoreInterrupts(s);
    if ((flags & 0x40) == 0 && (flags & 0x10) == 0) {
      b = MLDF_PTR(0x2f);
    }
    if ((flags & 0x80) == 0 && (flags & 0x20) == 0) {
      a = MLDF_PTR(0x49);
    }
    if ((param_3 & 0x10000000) != 0 && b == 0) {
      while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0) {
        if ((flags & 0x40) == 0 && (flags & 0x10) == 0) {
          b = MLDF_PTR(0x2f);
          break;
        }
      padUpdate();
      checkReset();
      if (frame != 0) {
        waitNextFrame();
      }
      loadDataFiles();
      dvdCheckError();
      if (frame != 0) {
        mmFreeTick(0);
        gameTextRun();
        GXFlush_(1, 0);
      }
      if (lbl_803DC950 != 0) {
        frame = 1;
      }
      }
    }
    else if ((param_3 & 0x20000000) != 0 && a == 0) {
      while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0) {
        if ((flags & 0x80) == 0 && (flags & 0x20) == 0) {
          a = MLDF_PTR(0x49);
          break;
        }
      padUpdate();
      checkReset();
      if (frame != 0) {
        waitNextFrame();
      }
      loadDataFiles();
      dvdCheckError();
      if (frame != 0) {
        mmFreeTick(0);
        gameTextRun();
        GXFlush_(1, 0);
      }
      if (lbl_803DC950 != 0) {
        frame = 1;
      }
      }
    }
    if ((param_3 & 0x20000000) != 0) {
      param_1 = 0x4a;
      if (param_5 != NULL) {
        *param_5 = (*(u32 *)(a + param_6 * 4 + 4) & 0xfffffff) - (*(u32 *)(a + param_6 * 4) & 0xfffffff);
      }
    } else if ((param_3 & 0x10000000) != 0) {
      param_1 = 0x30;
      if (param_5 != NULL) {
        *param_5 = (*(u32 *)(b + param_6 * 4 + 4) & 0xfffffff) - (*(u32 *)(b + param_6 * 4) & 0xfffffff);
      }
    } else if (b != 0) {
      param_1 = 0x30;
      if (param_5 != NULL) {
        *param_5 = (*(u32 *)(b + param_6 * 4 + 4) & 0xfffffff) - (*(u32 *)(b + param_6 * 4) & 0xfffffff);
      }
    } else if (a != 0) {
      param_1 = 0x4a;
      if (param_5 != NULL) {
        *param_5 = (*(u32 *)(a + param_6 * 4 + 4) & 0xfffffff) - (*(u32 *)(a + param_6 * 4) & 0xfffffff);
      }
    }
    param_3 = param_3 & 0xfffffff;
    if ((param_7 & 1) != 0) {
      r = MLDF_PTR(param_1);
      tmp = return0_8002A5B8(r + param_3);
      if (tmp != 0) {
        *param_5 = ObjModel_GetUnpackedResourceSize(r + param_3, *param_5);
      }
    }
    break;
  case 0x51:
    if (MLDF_PTR(0x52) != 0) {
      param_1 = 0x51;
      if (param_5 != NULL) {
        *param_5 = (*(u32 *)(MLDF_PTR(0x52) + param_6 * 4 + 4) & 0xfffffff) - (*(u32 *)(MLDF_PTR(0x52) + param_6 * 4) & 0xfffffff);
      }
    }
    param_3 = param_3 & 0xfffffff;
    if ((param_7 & 1) != 0) {
      r = MLDF_PTR(param_1);
      tmp = return0_8002A5B8(r + param_3);
      if (tmp != 0) {
        *param_5 = ObjModel_GetUnpackedResourceSize(r + param_3, *param_5);
      }
    }
    break;
  case 0x23:
    s = OSDisableInterrupts();
    flags = lbl_803DCC80;
    OSRestoreInterrupts(s);
    if ((flags & 0x400) == 0 && (flags & 0x100) == 0) {
      b = MLDF_PTR(0x24);
    }
    if ((flags & 0x800) == 0 && (flags & 0x200) == 0) {
      a = MLDF_PTR(0x4e);
    }
    if ((param_3 & 0x40000000) != 0 && b == 0) {
      while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0) {
        if ((flags & 0x400) == 0 && (flags & 0x100) == 0) {
          b = MLDF_PTR(0x24);
          break;
        }
      padUpdate();
      checkReset();
      if (frame != 0) {
        waitNextFrame();
      }
      loadDataFiles();
      dvdCheckError();
      if (frame != 0) {
        mmFreeTick(0);
        gameTextRun();
        GXFlush_(1, 0);
      }
      if (lbl_803DC950 != 0) {
        frame = 1;
      }
      }
    }
    else if ((param_3 & 0x80000000) != 0 && a == 0) {
      while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0) {
        if ((flags & 0x800) == 0 && (flags & 0x200) == 0) {
          a = MLDF_PTR(0x4e);
          break;
        }
      padUpdate();
      checkReset();
      if (frame != 0) {
        waitNextFrame();
      }
      loadDataFiles();
      dvdCheckError();
      if (frame != 0) {
        mmFreeTick(0);
        gameTextRun();
        GXFlush_(1, 0);
      }
      if (lbl_803DC950 != 0) {
        frame = 1;
      }
      }
    }
    if (a != 0 && (((u32 *)t->mergeTex0)[param_6] & 0x80000000) != 0) {
      param_1 = 0x4d;
      if (param_5 != NULL) {
        off = *(u32 *)(a + param_6 * 4) & 0xffffff;
        if (off == 0) {
          i = 0;
          do {
            j = i + 1;
            k = i * 4;
            i = j;
          } while ((*(u32 *)(a + k) & 0xffffff) == 0);
          *param_5 = *(u32 *)(a + j * 4 - 4) & 0xffffff;
        } else {
          do {
            j = param_6 + 1;
            k = param_6 * 4;
            param_6 = j;
          } while ((*(u32 *)(a + k) & 0xffffff) <= off);
          *param_5 = (*(u32 *)(a + j * 4 - 4) & 0xffffff) - off;
        }
      }
    } else if (b != 0 && (((u32 *)t->mergeTex0)[param_6] & 0x40000000) != 0) {
      param_1 = 0x23;
      if (param_5 != NULL) {
        off = *(u32 *)(b + param_6 * 4) & 0xffffff;
        if (off == 0) {
          i = 0;
          do {
            j = i + 1;
            k = i * 4;
            i = j;
          } while ((*(u32 *)(b + k) & 0xffffff) == 0);
          *param_5 = *(u32 *)(b + j * 4 - 4) & 0xffffff;
        } else {
          do {
            j = param_6 + 1;
            k = param_6 * 4;
            param_6 = j;
          } while ((*(u32 *)(b + k) & 0xffffff) <= off);
          *param_5 = (*(u32 *)(b + j * 4 - 4) & 0xffffff) - off;
        }
      }
    } else if (b != 0) {
      param_1 = 0x23;
      if (param_5 != NULL) {
        off = *(u32 *)(b + param_6 * 4) & 0xffffff;
        if (off == 0) {
          i = 0;
          do {
            j = i + 1;
            k = i * 4;
            i = j;
          } while ((*(u32 *)(b + k) & 0xffffff) == 0);
          *param_5 = *(u32 *)(b + j * 4 - 4) & 0xffffff;
        } else {
          do {
            j = param_6 + 1;
            k = param_6 * 4;
            param_6 = j;
          } while ((*(u32 *)(b + k) & 0xffffff) <= off);
          *param_5 = (*(u32 *)(b + j * 4 - 4) & 0xffffff) - off;
        }
      }
    } else if (a != 0) {
      param_1 = 0x4d;
      if (param_5 != NULL) {
        off = *(u32 *)(a + param_6 * 4) & 0xffffff;
        if (off == 0) {
          i = 0;
          do {
            j = i + 1;
            k = i * 4;
            i = j;
          } while ((*(u32 *)(a + k) & 0xffffff) == 0);
          *param_5 = *(u32 *)(a + j * 4 - 4) & 0xffffff;
        } else {
          do {
            j = param_6 + 1;
            k = param_6 * 4;
            param_6 = j;
          } while ((*(u32 *)(a + k) & 0xffffff) <= off);
          *param_5 = (*(u32 *)(a + j * 4 - 4) & 0xffffff) - off;
        }
      }
    }
    param_3 = param_3 & 0xfffffff;
    break;
  case 0x20:
    s = OSDisableInterrupts();
    flags = lbl_803DCC80;
    OSRestoreInterrupts(s);
    if ((flags & 0x4000) == 0 && (flags & 0x1000) == 0) {
      b = MLDF_PTR(0x21);
    }
    if ((flags & 0x8000) == 0 && (flags & 0x2000) == 0) {
      a = MLDF_PTR(0x4c);
    }
    if ((param_3 & 0x40000000) != 0 && b == 0) {
      while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0) {
        if ((flags & 0x4000) == 0 && (flags & 0x1000) == 0) {
          b = MLDF_PTR(0x21);
          break;
        }
      padUpdate();
      checkReset();
      if (frame != 0) {
        waitNextFrame();
      }
      loadDataFiles();
      dvdCheckError();
      if (frame != 0) {
        mmFreeTick(0);
        gameTextRun();
        GXFlush_(1, 0);
      }
      if (lbl_803DC950 != 0) {
        frame = 1;
      }
      }
    }
    else if ((param_3 & 0x80000000) != 0 && a == 0) {
      while (s = OSDisableInterrupts(), flags = lbl_803DCC80, OSRestoreInterrupts(s), flags != 0) {
        if ((flags & 0x8000) == 0 && (flags & 0x2000) == 0) {
          a = MLDF_PTR(0x4c);
          break;
        }
      padUpdate();
      checkReset();
      if (frame != 0) {
        waitNextFrame();
      }
      loadDataFiles();
      dvdCheckError();
      if (frame != 0) {
        mmFreeTick(0);
        gameTextRun();
        GXFlush_(1, 0);
      }
      if (lbl_803DC950 != 0) {
        frame = 1;
      }
      }
    }
    if (a != 0 && (((u32 *)t->mergeTex1)[param_6] & 0x80000000) != 0) {
      param_1 = 0x4b;
      if (param_5 != NULL) {
        off = *(u32 *)(a + param_6 * 4) & 0xffffff;
        if (off == 0) {
          i = 0;
          do {
            j = i + 1;
            k = i * 4;
            i = j;
          } while ((*(u32 *)(a + k) & 0xffffff) == 0);
          *param_5 = *(u32 *)(a + j * 4 - 4) & 0xffffff;
        } else {
          do {
            j = param_6 + 1;
            k = param_6 * 4;
            param_6 = j;
          } while ((*(u32 *)(a + k) & 0xffffff) <= off);
          *param_5 = (*(u32 *)(a + j * 4 - 4) & 0xffffff) - off;
        }
      }
    } else if (b != 0 && (((u32 *)t->mergeTex1)[param_6] & 0x40000000) != 0) {
      param_1 = 0x20;
      if (param_5 != NULL) {
        off = *(u32 *)(b + param_6 * 4) & 0xffffff;
        if (off == 0) {
          i = 0;
          do {
            j = i + 1;
            k = i * 4;
            i = j;
          } while ((*(u32 *)(b + k) & 0xffffff) == 0);
          *param_5 = *(u32 *)(b + j * 4 - 4) & 0xffffff;
        } else {
          do {
            j = param_6 + 1;
            k = param_6 * 4;
            param_6 = j;
          } while ((*(u32 *)(b + k) & 0xffffff) <= off);
          *param_5 = (*(u32 *)(b + j * 4 - 4) & 0xffffff) - off;
        }
      }
    } else if (b != 0) {
      param_1 = 0x20;
      if (param_5 != NULL) {
        off = *(u32 *)(b + param_6 * 4) & 0xffffff;
        if (off == 0) {
          i = 0;
          do {
            j = i + 1;
            k = i * 4;
            i = j;
          } while ((*(u32 *)(b + k) & 0xffffff) == 0);
          *param_5 = *(u32 *)(b + j * 4 - 4) & 0xffffff;
        } else {
          do {
            j = param_6 + 1;
            k = param_6 * 4;
            param_6 = j;
          } while ((*(u32 *)(b + k) & 0xffffff) <= off);
          *param_5 = (*(u32 *)(b + j * 4 - 4) & 0xffffff) - off;
        }
      }
    } else if (a != 0) {
      param_1 = 0x4b;
      if (param_5 != NULL) {
        off = *(u32 *)(a + param_6 * 4) & 0xffffff;
        if (off == 0) {
          i = 0;
          do {
            j = i + 1;
            k = i * 4;
            i = j;
          } while ((*(u32 *)(a + k) & 0xffffff) == 0);
          *param_5 = *(u32 *)(a + j * 4 - 4) & 0xffffff;
        } else {
          do {
            j = param_6 + 1;
            k = param_6 * 4;
            param_6 = j;
          } while ((*(u32 *)(a + k) & 0xffffff) <= off);
          *param_5 = (*(u32 *)(a + j * 4 - 4) & 0xffffff) - off;
        }
      }
    }
    param_3 = param_3 & 0xfffffff;
    break;
  case 0x4f:
    if (MLDF_PTR(0x50) != 0) {
      param_1 = 0x4f;
      if (param_5 != NULL) {
        off = *(u32 *)(MLDF_PTR(0x50) + param_6 * 4) & 0xffffff;
        if (off == 0) {
          i = 0;
          do {
            j = i + 1;
            k = i * 4;
            i = j;
          } while ((*(u32 *)(MLDF_PTR(0x50) + k) & 0xffffff) == 0);
          *param_5 = *(u32 *)(MLDF_PTR(0x50) + j * 4 - 4) & 0xffffff;
        } else {
          do {
            j = param_6 + 1;
            k = param_6 * 4;
            param_6 = j;
          } while ((*(u32 *)(MLDF_PTR(0x50) + k) & 0xffffff) <= off);
          *param_5 = (*(u32 *)(MLDF_PTR(0x50) + j * 4 - 4) & 0xffffff) - off;
        }
      }
    }
    param_3 = param_3 & 0xfffffff;
    break;
  }
  if ((param_7 & 1) != 0) {
    return;
  }
  r = MLDF_PTR(param_1);
  if (r == 0) {
    if (param_1 == 0x20 || param_1 == 0x4b) {
      DVDOpen(sResourceFileNameTable[param_1], buf);
      asize = (param_4 + 0x1f) & 0xffffffe0;
      r = (int)mmAlloc(asize, 0x7f7f7fff, 0);
      DVDRead(buf, (void *)r, asize, param_3 & 0xffffff);
      DVDClose(buf);
      DCStoreRange((void *)r, param_4);
      if (strncmp(&sDirBlockTag, (char *)r, 3) == 0) {
        for (;;) {
        }
      }
      if (strncmp((char *)r, sZlbBlockTag, 3) == 0) {
        local_78 = *(u32 *)(r + 8);
        zlbDecompress((void *)(r + 0x10), *(int *)(r + 0xc), param_2, &local_78);
      }
      mm_free((void *)r);
    } else {
      DVDOpen(sResourceFileNameTable[param_1], buf);
      if (((u32)param_2 & 0x1f) == 0 && (param_4 & 0x1f) == 0) {
        DVDRead(buf, (void *)param_2, param_4, param_3);
      } else {
        asize = (param_4 + 0x1f) & 0xffffffe0;
        tmp = (int)mmAlloc(asize, 0x7f7f7fff, 0);
        DVDRead(buf, (void *)tmp, asize, param_3);
        memcpy((void *)param_2, (void *)tmp, param_4);
        mm_free((void *)tmp);
      }
      DCStoreRange((void *)param_2, param_4);
      DVDClose(buf);
    }
  } else if (param_1 == 0xd || param_1 == 0x55) {
    if (r == 0) {
      return;
    }
    memcpy((void *)param_2, (void *)(r + param_3), param_4);
  } else if (param_1 == 0x1b || param_1 == 0x54) {
    if (r == 0) {
      return;
    }
    r = r + param_3;
    if (strncmp((char *)r, sZlbBlockTag, 3) != 0) {
      return;
    }
    local_78 = *(u32 *)(r + 8);
    zlbDecompress((void *)(MLDF_PTR(param_1) + param_3 + 0x10), *(int *)(r + 0xc), param_2, &local_78);
    DCStoreRange((void *)param_2, local_78);
  } else if (param_1 == 0x25 || param_1 == 0x47) {
    if (r == 0) {
      return;
    }
    r = r + param_3;
    if (strncmp((char *)r, sZlbBlockTag, 3) != 0) {
      return;
    }
    local_78 = *(u32 *)(r + 8);
    zlbDecompress((void *)(MLDF_PTR(param_1) + param_3 + 0x10), *(int *)(r + 0xc), param_2, &local_78);
    DCStoreRange((void *)param_2, local_78);
  } else if (param_1 == 0x2b || param_1 == 0x46) {
    int *p = (int *)(r + param_3);
    if (*p == 0xe0e0e0e0) {
      memcpy((void *)param_2, (void *)((int)p + p[2] + 0x18), p[1]);
    } else if (*p == 0xfacefeed) {
      zlbDecompress((void *)((int)p + p[2] + 0x28), p[3] - 0x10, param_2, p + 1);
      DCStoreRange((void *)param_2, p[1]);
    }
  } else if (param_1 == 0x23 || param_1 == 0x4d) {
    r = r + (param_3 & 0xffffff);
    local_78 = *(u32 *)(r + 8);
    zlbDecompress((void *)(r + 0x10), *(int *)(r + 0xc), param_2, &local_78);
    DCStoreRange((void *)param_2, local_78);
  } else if (param_1 == 0x20 || param_1 == 0x4b) {
    param_3 = param_3 & 0xffffff;
    r = r + param_3;
    if (strncmp(&sDirBlockTag, (char *)r, 3) == 0) {
      return;
    }
    if (strncmp((char *)r, sZlbBlockTag, 3) == 0) {
      local_78 = *(u32 *)(r + 8);
      zlbDecompress((void *)(MLDF_PTR(param_1) + param_3 + 0x10), *(int *)(r + 0xc), param_2, &local_78);
      DCStoreRange((void *)param_2, local_78);
    }
  } else if (param_1 == 0x4f) {
    param_3 = param_3 & 0xffffff;
    r = r + param_3;
    if (strncmp(&sDirBlockTag, (char *)r, 3) == 0) {
      return;
    }
    if (strncmp((char *)r, sZlbBlockTag, 3) == 0) {
      local_78 = *(u32 *)(r + 8);
      zlbDecompress((void *)(MLDF_PTR(0x4f) + param_3 + 0x10), *(int *)(r + 0xc), param_2, &local_78);
      DCStoreRange((void *)param_2, local_78);
    }
  } else if (param_1 == 0x30 || param_1 == 0x51 || param_1 == 0x4a) {
    r = r + param_3;
    tmp = return0_8002A5B8(r);
    if (tmp == 0) {
      memcpy((void *)param_2, (void *)(MLDF_PTR(param_1) + param_3), param_4);
    } else {
      asize = ObjModel_GetUnpackedResourceSize(r, *param_5);
      ObjModel_UnpackResourcePayload(r, *param_5, param_2, asize);
    }
  } else {
    memcpy((void *)param_2, (void *)(r + param_3), param_4);
  }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800443fc
 * EN v1.0 Address: 0x800443FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80044548
 * EN v1.1 Size: 8444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800443fc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80044400
 * EN v1.0 Address: 0x80044400
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80046644
 * EN v1.1 Size: 7400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80044400(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint *param_13,
                 int param_14,uint param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80044404
 * EN v1.0 Address: 0x80044404
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8004832C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80044404(int param_1)
{
  if (0x4a < param_1) {
    return 5;
  }
  return (&DAT_802cc8a8)[param_1];
}

/*
 * --INFO--
 *
 * Function: FUN_80044424
 * EN v1.0 Address: 0x80044424
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80048350
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80044424(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: piRomLoadSection
 * EN v1.0 Address: 0x80044428
 * EN v1.0 Size: 1048b
 * EN v1.1 Address: 0x800484A4
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int lbl_8035F208[];
extern u32 lbl_8035F3E8[];
extern char *sMapFileNameTable[];
extern char sRomlistZlbPathFormat[];
extern int lbl_803DCC74;
extern void romListReadCb();
extern void zlbDecompress(void *dst, int size, int out, void *src);
extern void DCStoreRange(void *p, u32 n);
#pragma scheduling off
#pragma peephole off
void piRomLoadSection(int param_1,int param_2,int param_3)
{
  char buf[1048];
  int fi;
  int ok;
  int *p;

  if ((param_3 == 0) && (lbl_8035F208[param_2] == 0)) {
    sprintf(buf, sRomlistZlbPathFormat, sMapFileNameTable[param_2]);
    fi = AtomicSList_Pop(lbl_803DCC8C);
    ok = DVDOpen(buf, (void *)fi);
    if (ok != 0) {
      lbl_8035F208[param_2] = (int)mmAlloc(*(int *)(fi + 0x34), 0x7d7d7d7d, 0);
      lbl_803DCC74 = 1;
      DVDReadAsyncPrio((void *)fi, (void *)lbl_8035F208[param_2], *(int *)(fi + 0x34), 0, romListReadCb, 2);
    }
  } else {
    if (lbl_8035F208[param_2] == 0) {
      sprintf(buf, sRomlistZlbPathFormat, sMapFileNameTable[param_2]);
      fi = AtomicSList_Pop(lbl_803DCC8C);
      ok = DVDOpen(buf, (void *)fi);
      if (ok == 0) {
        return;
      }
      lbl_8035F208[param_2] = (int)mmAlloc(*(int *)(fi + 0x34), 0x7d7d7d7d, 0);
      DVDRead((void *)fi, (void *)lbl_8035F208[param_2], *(int *)(fi + 0x34), 0);
      DVDClose((void *)fi);
      AtomicSList_Push(lbl_803DCC8C, fi);
    }
    p = (int *)(lbl_8035F3E8[0x1d] + param_1);
    if (*p == 0xfacefeed) {
      zlbDecompress((void *)(lbl_8035F208[param_2] + 0x10), p[3], param_3, p + 1);
      DCStoreRange((void *)param_3, p[1]);
    }
  }
}
#pragma peephole reset
#pragma scheduling reset
/*
 * --INFO--
 *
 * Function: FUN_80044840
 * EN v1.0 Address: 0x80044840
 * EN v1.0 Size: 900b
 * EN v1.1 Address: 0x80048658
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80044840(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 *param_11,undefined4 *param_12,
                 int param_13,uint param_14,int param_15,undefined4 param_16)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  undefined8 extraout_f1;
  undefined8 uVar9;
  int aiStack_68 [26];
  
  uVar1 = FUN_80286830();
  iVar8 = -1;
  if ((DAT_803600c8 != 0) || (DAT_80360174 != 0)) {
    iVar5 = param_13;
    uVar6 = param_14;
    iVar7 = param_15;
    uVar9 = extraout_f1;
    FUN_80243e74();
    uVar2 = DAT_803dd900;
    FUN_80243e9c();
    if (((uVar1 & 0x80000000) == 0) || ((uVar2 & 0x2000) != 0)) {
      if (((uVar1 & 0x40000000) == 0) || ((uVar2 & 0x1000) != 0)) {
        if ((DAT_803600cc == 0) || (((uVar2 & 0x1000) != 0 || (DAT_803600c8 == 0)))) {
          if ((DAT_80360178 != 0) && (((uVar2 & 0x2000) == 0 && (DAT_80360174 != 0)))) {
            iVar8 = 0x4b;
          }
        }
        else {
          iVar8 = 0x20;
        }
      }
      else {
        iVar8 = 0x20;
      }
    }
    else {
      iVar8 = 0x4b;
    }
    iVar3 = (&DAT_80360048)[iVar8];
    if (iVar3 == 0) {
      FUN_80249300(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   sResourceFileNameTable[iVar8],(int)aiStack_68);
      uVar2 = FUN_80017830(0x400,0x7f7f7fff);
      FUN_80006c30(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_68,uVar2,
                   0x400,(uVar1 & 0xffffff) << 1,iVar5,uVar6,iVar7,param_16);
      FUN_802493c8(aiStack_68);
      FUN_80242114(uVar2,0x400);
      if ((param_15 == 1) && (param_14 != 0)) {
        iVar8 = uVar2 + *(int *)(param_14 + param_13 * 4) + 4;
        uVar4 = *(undefined4 *)(iVar8 + 4);
        *param_12 = *(undefined4 *)(iVar8 + 8);
        *param_11 = uVar4;
      }
      else if ((param_15 == 2) && (param_14 != 0)) {
        FUN_80003494(param_14,uVar2,(param_13 + 1) * 4);
      }
      else {
        uVar4 = *(undefined4 *)(uVar2 + 0xc);
        *param_11 = *(undefined4 *)(uVar2 + 8);
        iVar8 = FUN_80291d74(-0x7fc23ddc,uVar2,3);
        if (iVar8 == 0) {
          *param_12 = 0xffffffff;
        }
        else {
          *param_12 = uVar4;
        }
      }
      FUN_80017814(uVar2);
    }
    else if ((param_15 == 1) && (param_14 != 0)) {
      iVar3 = iVar3 + (uVar1 & 0xffffff) * 2 + *(int *)(param_14 + param_13 * 4) + 4;
      uVar4 = *(undefined4 *)(iVar3 + 4);
      *param_12 = *(undefined4 *)(iVar3 + 8);
      *param_11 = uVar4;
    }
    else if ((param_15 == 2) && (param_14 != 0)) {
      FUN_80003494(param_14,iVar3 + (uVar1 & 0xffffff) * 2,(param_13 + 1) * 4);
    }
    else {
      iVar3 = iVar3 + (uVar1 & 0xffffff) * 2;
      uVar4 = *(undefined4 *)(iVar3 + 0xc);
      *param_11 = *(undefined4 *)(iVar3 + 8);
      iVar8 = FUN_80291d74(-0x7fc23ddc,iVar3,3);
      if (iVar8 == 0) {
        *param_12 = 0xffffffff;
      }
      else {
        *param_12 = uVar4;
      }
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80044bc4
 * EN v1.0 Address: 0x80044BC4
 * EN v1.0 Size: 384b
 * EN v1.1 Address: 0x80048928
 * EN v1.1 Size: 440b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80044bc4(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,
                 int param_5,uint param_6,int param_7)
{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  
  uVar2 = FUN_80286834();
  iVar4 = -1;
  if ((DAT_803600d4 != 0) || (DAT_8036017c != 0)) {
    FUN_80243e74();
    uVar1 = DAT_803dd900;
    FUN_80243e9c();
    if (((uVar2 & 0x80000000) == 0) || ((uVar1 & 0x200) != 0)) {
      if (((uVar2 & 0x40000000) == 0) || ((uVar1 & 0x100) != 0)) {
        if ((DAT_803600d8 == 0) || ((uVar1 & 0x100) != 0)) {
          if ((DAT_80360180 != 0) && ((uVar1 & 0x200) == 0)) {
            iVar4 = 0x4d;
          }
        }
        else {
          iVar4 = 0x23;
        }
      }
      else {
        iVar4 = 0x23;
      }
    }
    else {
      iVar4 = 0x4d;
    }
    if ((param_7 == 1) && (param_6 != 0)) {
      iVar4 = (&DAT_80360048)[iVar4] + (uVar2 & 0xffffff) * 2 + *(int *)(param_6 + param_5 * 4) + 4;
      uVar3 = *(undefined4 *)(iVar4 + 8);
      *param_3 = *(undefined4 *)(iVar4 + 4);
      *param_4 = uVar3;
    }
    else if ((param_7 == 2) && (param_6 != 0)) {
      FUN_80003494(param_6,(&DAT_80360048)[iVar4] + (uVar2 & 0xffffff) * 2,(param_5 + 1) * 4);
    }
    else {
      iVar4 = (&DAT_80360048)[iVar4] + (uVar2 & 0xffffff) * 2 + 4;
      uVar3 = *(undefined4 *)(iVar4 + 8);
      *param_3 = *(undefined4 *)(iVar4 + 4);
      *param_4 = uVar3;
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80044d44
 * EN v1.0 Address: 0x80044D44
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x80048AE0
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80044d44(uint param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,
                 int param_5,uint param_6,int param_7)
{
  int iVar1;
  undefined4 uVar2;
  
  if (DAT_80360184 != 0) {
    if ((param_7 == 1) && (param_6 != 0)) {
      iVar1 = DAT_80360184 + (param_1 & 0xffffff) * 2 + *(int *)(param_6 + param_5 * 4) + 4;
      uVar2 = *(undefined4 *)(iVar1 + 8);
      *param_3 = *(undefined4 *)(iVar1 + 4);
      *param_4 = uVar2;
    }
    else if ((param_7 == 2) && (param_6 != 0)) {
      FUN_80003494(param_6,DAT_80360184 + (param_1 & 0xffffff) * 2,(param_5 + 1) * 4);
    }
    else {
      iVar1 = DAT_80360184 + (param_1 & 0xffffff) * 2;
      uVar2 = *(undefined4 *)(iVar1 + 0xc);
      *param_3 = *(undefined4 *)(iVar1 + 8);
      iVar1 = FUN_80291d74(-0x7fc23ddc,iVar1,3);
      if (iVar1 == 0) {
        *param_4 = 0xffffffff;
      }
      else {
        *param_4 = uVar2;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80044e24
 * EN v1.0 Address: 0x80044E24
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x80048BD4
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80044e24(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,
                 undefined4 *param_5)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  ulonglong uVar5;
  
  uVar5 = FUN_80286830();
  iVar2 = -1;
  if ((DAT_803600f4 != 0) || (DAT_80360160 != 0)) {
    FUN_80243e74();
    uVar1 = DAT_803dd900;
    FUN_80243e9c();
    iVar4 = 0;
    if (((uVar1 & 4) == 0) && ((uVar1 & 1) == 0)) {
      iVar4 = DAT_803600f0;
    }
    iVar3 = 0;
    if (((uVar1 & 8) == 0) && ((uVar1 & 2) == 0)) {
      iVar3 = DAT_8036015c;
    }
    if ((iVar3 == 0) || ((uVar5 & 0x2000000000000000) == 0)) {
      if ((iVar4 == 0) || ((uVar5 & 0x1000000000000000) == 0)) {
        if (iVar4 == 0) {
          if (iVar3 != 0) {
            iVar2 = 0x46;
          }
        }
        else {
          iVar2 = 0x2b;
        }
      }
      else {
        iVar2 = 0x2b;
      }
    }
    else {
      iVar2 = 0x46;
    }
    iVar2 = (&DAT_80360048)[iVar2] + ((uint)(uVar5 >> 0x20) & 0xfffffff);
    *param_4 = *(undefined4 *)(iVar2 + 0x18);
    *(undefined4 *)uVar5 = *(undefined4 *)(iVar2 + 0x1c);
    *param_3 = *(undefined4 *)(iVar2 + 0x20);
    *param_5 = *(undefined4 *)(iVar2 + 4);
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80044f74
 * EN v1.0 Address: 0x80044F74
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x80048D20
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80044f74(int param_1,int *param_2,int *param_3,undefined4 *param_4,int param_5)
{
  int iVar1;
  
  if (DAT_803600bc == 0) {
    return;
  }
  if (DAT_803600c0 == 0) {
    return;
  }
  iVar1 = DAT_803600bc + param_1;
  *param_2 = (int)*(short *)(iVar1 + 0x1c);
  *param_3 = (int)*(short *)(iVar1 + 0x1e);
  *param_4 = *(undefined4 *)(DAT_803600bc + *(int *)(DAT_803600c0 + param_5 * 4 + 0x18) + 4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80044fc4
 * EN v1.0 Address: 0x80044FC4
 * EN v1.0 Size: 388b
 * EN v1.1 Address: 0x80048D78
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80044fc4(undefined4 param_1,undefined4 param_2,undefined4 *param_3)
{
  uint uVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  ulonglong uVar6;
  
  uVar6 = FUN_80286840();
  puVar3 = (undefined4 *)uVar6;
  iVar5 = -1;
  if (((DAT_803600e0 == 0) || (DAT_803600dc == 0)) && ((DAT_80360168 == 0 || (DAT_80360164 == 0))))
  {
    *param_3 = 0;
    *puVar3 = 0;
  }
  else {
    FUN_80243e74();
    uVar1 = DAT_803dd900;
    FUN_80243e9c();
    if (((DAT_803600dc == 0) || ((uVar6 & 0x1000000000000000) == 0)) || ((uVar1 & 0x10000) != 0)) {
      if (((DAT_80360164 == 0) || ((uVar6 & 0x2000000000000000) == 0)) || ((uVar1 & 0x40000) != 0))
      {
        if ((DAT_803600dc == 0) || ((uVar1 & 0x10000) != 0)) {
          if ((DAT_80360164 != 0) && ((uVar1 & 0x40000) == 0)) {
            iVar5 = 0x47;
          }
        }
        else {
          iVar5 = 0x25;
        }
      }
      else {
        iVar5 = 0x47;
      }
    }
    else {
      iVar5 = 0x25;
    }
    iVar4 = (&DAT_80360048)[iVar5] + ((uint)(uVar6 >> 0x20) & 0xffffff);
    iVar5 = FUN_80291d74(iVar4,-0x7fc23de0,3);
    if (iVar5 == 0) {
      uVar2 = *(undefined4 *)(iVar4 + 0xc);
      *param_3 = *(undefined4 *)(iVar4 + 8);
      *puVar3 = uVar2;
    }
    else {
      *param_3 = 0;
      *puVar3 = 0;
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80045148
 * EN v1.0 Address: 0x80045148
 * EN v1.0 Size: 432b
 * EN v1.1 Address: 0x80048EF4
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80045148(undefined4 param_1,undefined4 param_2,undefined4 *param_3)
{
  uint uVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  ulonglong uVar6;
  
  uVar6 = FUN_80286840();
  puVar3 = (undefined4 *)uVar6;
  iVar5 = -1;
  if (((DAT_803600b0 == 0) || (DAT_803600b4 == 0)) && ((DAT_80360194 == 0 || (DAT_80360198 == 0))))
  {
    *param_3 = 0;
    *puVar3 = 0;
  }
  else {
    FUN_80243e74();
    uVar1 = DAT_803dd900;
    FUN_80243e9c();
    if (((DAT_803600b4 == 0) || ((uVar6 & 0x8000000000000000) == 0)) || ((uVar1 & 0x1000000) != 0))
    {
      if (((DAT_80360198 == 0) || ((uVar6 & 0x2000000000000000) == 0)) || ((uVar1 & 0x4000000) != 0)
         ) {
        if ((DAT_803600b4 == 0) || ((uVar1 & 0x1000000) != 0)) {
          if ((DAT_80360198 != 0) && ((uVar1 & 0x4000000) == 0)) {
            iVar5 = 0x54;
          }
        }
        else {
          iVar5 = 0x1b;
        }
      }
      else {
        iVar5 = 0x54;
      }
    }
    else {
      iVar5 = 0x1b;
    }
    if ((uVar6 & 0xf000000000000000) == 0) {
      *param_3 = 0;
      *puVar3 = 0;
    }
    else {
      iVar4 = (&DAT_80360048)[iVar5] + ((uint)(uVar6 >> 0x20) & 0xffffff);
      iVar5 = FUN_80291d74(iVar4,-0x7fc23de0,3);
      if (iVar5 == 0) {
        uVar2 = *(undefined4 *)(iVar4 + 0xc);
        *param_3 = *(undefined4 *)(iVar4 + 8);
        *puVar3 = uVar2;
      }
      else {
        *param_3 = 0;
        *puVar3 = 0;
      }
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800452f8
 * EN v1.0 Address: 0x800452F8
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x8004908C
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800452f8(int param_1)
{
  if ((&DAT_80360048)[param_1] != 0) {
    return (&DAT_8035fd08)[param_1];
  }
  uRam00000000 = 0;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80045328
 * EN v1.0 Address: 0x80045328
 * EN v1.0 Size: 656b
 * EN v1.1 Address: 0x800490C4
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80045328(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  ulonglong uVar6;
  int aiStack_58 [22];
  
  uVar6 = FUN_80286840();
  iVar2 = (int)(uVar6 >> 0x20);
  uVar4 = (uint)uVar6;
  if (param_12 != 0) {
    if ((&DAT_80360048)[iVar2] == 0) {
      uVar5 = extraout_f1;
      FUN_80249300(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   sResourceFileNameTable[iVar2],(int)aiStack_58);
      if (((uVar6 & 0x1f) == 0) && ((param_12 & 0x1f) == 0)) {
        FUN_802420b0(uVar4,param_12);
        FUN_80006c30(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_58,uVar4,
                     param_12,param_11,param_13,param_14,param_15,param_16);
      }
      else {
        uVar1 = param_12 + 0x1f & ~0x1f;
        uVar3 = FUN_80017830(uVar1,0x7d7d7d7d);
        FUN_802420b0(uVar3,uVar1);
        FUN_80006c30(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_58,uVar3,
                     uVar1,param_11,param_13,param_14,param_15,param_16);
        FUN_80003494(uVar4,uVar3,param_12);
        FUN_80017814(uVar3);
      }
      FUN_802493c8(aiStack_58);
      FUN_80242114(uVar4,param_12);
    }
    else {
      FUN_80003494(uVar4,(&DAT_80360048)[iVar2] + param_11,param_12);
      FUN_80242114(uVar4,param_12);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800455b8
 * EN v1.0 Address: 0x800455B8
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x80049208
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800455b8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,uint param_10,undefined4 param_11,undefined4 param_12,
                undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int aiStack_58 [13];
  int local_24;
  
  if ((&DAT_80360048)[param_9] == 0) {
    FUN_80249300(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 sResourceFileNameTable[param_9],(int)aiStack_58);
    FUN_802420b0(param_10,local_24);
    FUN_80006c30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_58,param_10
                 ,local_24,0,param_13,param_14,param_15,param_16);
    FUN_802493c8(aiStack_58);
  }
  else {
    FUN_80003494(param_10,(&DAT_80360048)[param_9],(&DAT_8035fd08)[param_9]);
    FUN_80242114(param_10,(&DAT_8035fd08)[param_9]);
    local_24 = (&DAT_8035fd08)[param_9];
  }
  return local_24;
}

/*
 * --INFO--
 *
 * Function: FUN_80045734
 * EN v1.0 Address: 0x80045734
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x800492C0
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80045734(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9)
{
  int iVar1;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int aiStack_58 [13];
  undefined4 local_24;
  
  iVar1 = (&DAT_80360048)[param_9];
  if (iVar1 == 0) {
    FUN_80249300(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 sResourceFileNameTable[param_9],(int)aiStack_58);
    (&DAT_8035fd08)[param_9] = local_24;
    iVar1 = FUN_80017830((&DAT_8035fd08)[param_9] + 0x20,0x7d7d7d7d);
    (&DAT_80360048)[param_9] = iVar1;
    FUN_802420b0((&DAT_80360048)[param_9],(&DAT_8035fd08)[param_9]);
    FUN_80006c30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_58,
                 (&DAT_80360048)[param_9],(&DAT_8035fd08)[param_9],0,in_r7,in_r8,in_r9,in_r10);
    FUN_802493c8(aiStack_58);
    iVar1 = (&DAT_80360048)[param_9];
  }
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_800458ac
 * EN v1.0 Address: 0x800458AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8004937C
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800458ac(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800458b0
 * EN v1.0 Address: 0x800458B0
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x80049680
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800458b0(void)
{
  *(undefined2 *)((int)DAT_803dd970 + 0xe) = 0x294;
  *(short *)((int)DAT_803dd970 + 10) = *(short *)((int)DAT_803dd970 + 10) + -10;
  FUN_8024d51c(DAT_803dd970);
  FUN_8024dcb8();
  FUN_8024d054();
  FUN_8024d054();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800458fc
 * EN v1.0 Address: 0x800458FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800496CC
 * EN v1.1 Size: 836b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800458fc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80045900
 * EN v1.0 Address: 0x80045900
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x80049A10
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80045900(void)
{
  bool bVar1;
  short sVar3;
  uint uVar2;
  undefined4 local_98 [3];
  uint auStack_8c [35];
  
  DAT_803dd920 = DAT_803dd920 + 1;
  sVar3 = FUN_80258c18();
  if (sVar3 == (short)(DAT_803dd92a + 1)) {
    bVar1 = DAT_803dd94c == DAT_803dd96c;
    DAT_803dd94c = DAT_803dd96c;
    if (bVar1) {
      DAT_803dd94c = DAT_803dd968;
    }
    DAT_803dd92a = sVar3;
    FUN_8024ddd4(DAT_803dd94c);
    FUN_8024dcb8();
    DAT_803dd929 = 1;
    DAT_803dc228 = DAT_803dd920;
    DAT_803dd920 = 0;
  }
  DAT_803dd92c = DAT_803dd92c + 1;
  if ((DAT_803dd930 != '\0') && (18000 < DAT_803dd92c)) {
    FUN_80045da4();
    FUN_80060650();
    FUN_800179a0();
    FUN_80258a94();
    FUN_8025665c((int *)auStack_8c,DAT_803dd950,0x10000);
    FUN_80256744(auStack_8c);
    FUN_80256854(auStack_8c);
    DAT_803dd954 = FUN_802554d0(DAT_803dd958,DAT_803dd964);
    uVar2 = FUN_80006a98((short *)&DAT_80360390);
    if (uVar2 == 0) {
      FUN_80006aa4((short *)&DAT_80360390,(uint)local_98);
    }
    FUN_802472b0((int *)&DAT_803dd944);
    uVar2 = FUN_80006a98((short *)&DAT_80360390);
    if (uVar2 == 0) {
      FUN_80006aa0(-0x7fc9fc70,(uint)local_98);
      FUN_80256c08(local_98[0]);
    }
    else {
      FUN_80256ca0();
      DAT_803dd927 = 0;
    }
    fn_8004A8F8('\x01');
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80045a58
 * EN v1.0 Address: 0x80045A58
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x80049B64
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80045a58(void)
{
  uint uVar1;
  int iVar2;
  ushort *puVar3;
  ushort *puVar4;
  undefined4 local_28 [3];
  undefined auStack_1c [8];
  int local_14;
  
  if ((DAT_803de288 == 2) || (DAT_803de288 == 3)) {
    FUN_8011810c();
  }
  FUN_80006aa0(-0x7fc9fc70,(uint)auStack_1c);
  puVar4 = &DAT_80397330;
  puVar3 = &DAT_80397240;
  for (iVar2 = 0; iVar2 < (int)(uint)DAT_803ddc80; iVar2 = iVar2 + 1) {
    *puVar3 = *puVar4;
    puVar3[1] = puVar4[1];
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(puVar4 + 4);
    FUN_80258dac((uint)*puVar3,(uint)puVar3[1],(undefined4 *)(puVar3 + 2));
    puVar4 = puVar4 + 6;
    puVar3 = puVar3 + 6;
  }
  DAT_803ddc82 = DAT_803ddc80;
  DAT_803ddc80 = 0;
  if (local_14 == DAT_803dd94c) {
    DAT_803dd928 = 1;
    DAT_803dd929 = 0;
  }
  else {
    FUN_80006aa4((short *)&DAT_80360390,(uint)local_28);
    DAT_803dd92c = 0;
    FUN_802472b0((int *)&DAT_803dd944);
    uVar1 = FUN_80006a98((short *)&DAT_80360390);
    if (uVar1 == 0) {
      FUN_80006aa0(-0x7fc9fc70,(uint)local_28);
      FUN_80256c08(local_28[0]);
      DAT_803dd927 = 1;
    }
    else {
      FUN_80256ca0();
      DAT_803dd927 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80045b94
 * EN v1.0 Address: 0x80045B94
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x80049CA8
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80045b94(void)
{
  FUN_80247dfc((double)lbl_803DF6F0,(double)lbl_803DF708,(double)lbl_803DF6F0,
               (double)lbl_803DF70C,(double)lbl_803DF6F8,(double)lbl_803DF710,
               (float *)&DAT_803974e0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80045bd0
 * EN v1.0 Address: 0x80045BD0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80049CE8
 * EN v1.1 Size: 2132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80045bd0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80045bd4
 * EN v1.0 Address: 0x80045BD4
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x8004A53C
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80045bd4(undefined param_1,undefined param_2,undefined param_3)
{
  *(undefined *)&DAT_803dc230 = param_1;
  *(undefined *)((int)&DAT_803dc230 + 1) = param_2;
  *(undefined *)((int)&DAT_803dc230 + 2) = param_3;
}

/*
 * --INFO--
 *
 * Function: FUN_80045be8
 * EN v1.0 Address: 0x80045BE8
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x8004A550
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80045be8(void)
{
  if ((DAT_803dd970 == &DAT_8032f2b4) || (DAT_803dd970[0x18] != '\0')) {
    FUN_80259858(DAT_803dd970[0x19],DAT_803dd970 + 0x1a,'\0',DAT_803dd970 + 0x32);
  }
  else {
    FUN_80259858(DAT_803dd970[0x19],DAT_803dd970 + 0x1a,'\x01',&DAT_803dc234);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80045c4c
 * EN v1.0 Address: 0x80045C4C
 * EN v1.0 Size: 284b
 * EN v1.1 Address: 0x8004A5B8
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80045c4c(char param_1)
{
  bool bVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  undefined4 local_28;
  undefined4 uStack_24;
  undefined4 local_20;
  undefined4 local_1c;
  uint local_18;
  
  uVar2 = 1;
  gxSetZMode_(1,3,1);
  uVar4 = FUN_8025ce2c(1);
  FUN_80258a04((int)((ulonglong)uVar4 >> 0x20),(int)uVar4,uVar2);
  puVar3 = &local_28;
  FUN_80256b2c(DAT_803dd954,&uStack_24,puVar3);
  local_20 = local_28;
  local_1c = 0;
  local_18 = DAT_803dd950;
  FUN_80243e74();
  FUN_80006aa8((short *)&DAT_80360390,(uint)&local_20);
  if (DAT_803dd927 == '\0') {
    FUN_80256c08(local_28);
    DAT_803dd927 = '\x01';
  }
  FUN_80243e9c();
  FUN_80258b60((uint)DAT_803dc22e);
  uVar4 = FUN_80259a9c(DAT_803dd950,1);
  FUN_80258a04((int)((ulonglong)uVar4 >> 0x20),(int)uVar4,(uint)puVar3);
  DAT_803dc22e = DAT_803dc22e + 1;
  bVar1 = DAT_803dd950 == DAT_803dd96c;
  DAT_803dd950 = DAT_803dd96c;
  if (bVar1) {
    DAT_803dd950 = DAT_803dd968;
  }
  if (((param_1 != '\0') && (DAT_803dc22c != '\0')) &&
     (DAT_803dc22c = DAT_803dc22c + -1, DAT_803dc22c == '\0')) {
    FUN_8024de40(0);
    DAT_803dc22c = '\0';
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80045d68
 * EN v1.0 Address: 0x80045D68
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x8004A6E8
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80045d68(undefined param_1)
{
  FUN_8024de40(1);
  FUN_8024dcb8();
  DAT_803dc22c = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80045da4
 * EN v1.0 Address: 0x80045DA4
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x8004A724
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80045da4(void)
{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  byte bStack_48;
  byte local_47;
  byte local_46 [2];
  int local_44;
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  int local_30;
  int local_2c;
  int local_28 [10];
  
  FUN_80286840();
  FUN_8025e520(&local_2c,local_28,&local_34,&local_30);
  FUN_8025e520(&local_3c,&local_38,&local_44,&local_40);
  uVar1 = countLeadingZeros(local_38 - local_28[0]);
  uVar1 = uVar1 >> 5;
  uVar2 = countLeadingZeros(local_3c - local_2c);
  uVar2 = uVar2 >> 5;
  uVar3 = -(local_40 - local_30) | local_40 - local_30;
  FUN_80256ac8(&bStack_48,&bStack_48,local_46,&local_47,&bStack_48);
  FUN_800723a0();
  if ((uVar2 == 0) && ((int)uVar3 < 0)) {
    FUN_800723a0();
  }
  else if ((uVar1 == 0) && ((uVar2 != 0 && ((int)uVar3 < 0)))) {
    FUN_800723a0();
  }
  else if ((local_47 == 0) && (((uVar1 != 0 && (uVar2 != 0)) && ((int)uVar3 < 0)))) {
    FUN_800723a0();
  }
  else if ((((local_46[0] == 0) || (local_47 == 0)) ||
           ((uVar1 == 0 || ((uVar2 == 0 || (-1 < (int)uVar3)))))) ||
          (-1 < (-(local_44 - local_34) | local_44 - local_34))) {
    FUN_800723a0();
  }
  else {
    FUN_800723a0();
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8004A8F8
 * EN v1.0 Address: 0x80045F18
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x8004A8F8
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8004A8F8(char param_1)
{
  if (param_1 == '\0') {
    *(undefined *)&DAT_cc008000 = 0x61;
    DAT_cc008000 = 0x24000000;
    *(undefined *)&DAT_cc008000 = 0x61;
    DAT_cc008000 = 0x23000000;
    *(undefined *)&DAT_cc008000 = 0x10;
    *(undefined2 *)&DAT_cc008000 = 0;
    *(undefined2 *)&DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0;
  }
  else {
    FUN_8025dc78(0x23,0x16);
    *(undefined *)&DAT_cc008000 = 0x61;
    DAT_cc008000 = 0x2402c004;
    *(undefined *)&DAT_cc008000 = 0x61;
    DAT_cc008000 = 0x23000020;
    *(undefined *)&DAT_cc008000 = 0x10;
    *(undefined2 *)&DAT_cc008000 = 0;
    *(undefined2 *)&DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0x84400;
  }
}

/*
 * --INFO--
 *
 * Function: FUN_80045fcc
 * EN v1.0 Address: 0x80045FCC
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x8004A9B8
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80045fcc(void)
{
  DAT_803dd930 = 0;
  fn_8004A8F8('\0');
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004600c
 * EN v1.0 Address: 0x8004600C
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x8004A9E4
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004600c(void)
{
  uint uVar1;
  uint uVar2;
  double dVar3;
  undefined8 uVar4;
  
  FUN_802461cc(-0x7fc9fd20);
  uVar4 = FUN_80246298(-0x7fc9fd20);
  dVar3 = FUN_80286cd0((uint)((ulonglong)uVar4 >> 0x20),(uint)uVar4);
  lbl_803DD940 =
       (float)(dVar3 / (double)(float)((double)CONCAT44(0x43300000,DAT_800000f8 / 4000) -
                                      DOUBLE_803df700));
  FUN_80246308(-0x7fc9fd20);
  FUN_80246190(-0x7fc9fd20);
  lbl_803DC074 = lbl_803DF71C * lbl_803DF720 * lbl_803DD940;
  if (DAT_803dd5d0 != '\0') {
    lbl_803DC074 = lbl_803DF6F0;
  }
  if (lbl_803DF6F4 < lbl_803DC074) {
    lbl_803DC074 = lbl_803DF6F4;
  }
  lbl_803DC078 = lbl_803DF6F8;
  if (lbl_803DF6FC < lbl_803DC074) {
    lbl_803DC078 = lbl_803DF6F8 / lbl_803DC074;
  }
  uVar2 = (uint)(lbl_803DC074 + lbl_803DD934);
  uVar1 = uVar2 & 0xff;
  DAT_803dc071 = (undefined)uVar2;
  lbl_803DD934 =
       (lbl_803DC074 + lbl_803DD934) -
       (float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803df700);
  DAT_803dc070 = DAT_803dc071;
  if (uVar1 == 0) {
    DAT_803dc070 = 1;
  }
  FUN_80243e74();
  DAT_803dd95c = FUN_802464ec();
  if (*(short *)(DAT_803dd95c + 0x2c8) != 2) {
    FUN_800723a0();
  }
  uVar2 = FUN_80006a90((short *)&DAT_80360390);
  if (1 < uVar2) {
    DAT_803dd92c = 0;
    FUN_802471c4((int *)&DAT_803dd944);
  }
  FUN_80243e9c();
  FUN_80006988();
  FUN_80258664();
  FUN_8025b210();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800461b4
 * EN v1.0 Address: 0x800461B4
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x8004ABA0
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800461b4(int *param_1,int *param_2)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar4 = param_1[4];
  iVar3 = *param_2;
  if (*(char *)(iVar3 + 0x19) != '$') {
    uVar1 = countLeadingZeros(iVar3 - iVar4);
    return uVar1 >> 5;
  }
  if ((*(byte *)(param_2 + 3) & 0x80) == 0) {
    if (*(byte *)(iVar3 + 3) != 0) {
      uVar1 = countLeadingZeros((uint)*(byte *)(iVar3 + 3) - iVar4);
      return uVar1 >> 5;
    }
    iVar5 = *(int *)(*param_1 + (uint)*(byte *)(param_2 + 3) * 0x10);
    iVar6 = 0;
    iVar7 = 4;
    iVar2 = iVar5;
    do {
      if (*(int *)(iVar3 + 0x14) == *(int *)(iVar2 + 0x1c)) {
        uVar1 = countLeadingZeros((uint)*(byte *)(iVar6 + iVar5 + 4) - iVar4);
        return uVar1 >> 5;
      }
      iVar2 = iVar2 + 4;
      iVar6 = iVar6 + 1;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80046270
 * EN v1.0 Address: 0x80046270
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x8004AC50
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80046270(int param_1,int param_2,int param_3)
{
  undefined2 uVar1;
  uint *puVar2;
  uint uVar3;
  uint *puVar4;
  uint uVar5;
  int iVar6;
  
  uVar5 = *(uint *)(param_1 + param_3 * 8);
  uVar1 = *(undefined2 *)(param_1 + param_3 * 8 + 4);
  while (param_3 <= param_2 >> 1) {
    iVar6 = param_3 * 2;
    if ((iVar6 < param_2) && (puVar4 = (uint *)(param_1 + param_3 * 0x10), *puVar4 < puVar4[2])) {
      iVar6 = iVar6 + 1;
    }
    puVar4 = (uint *)(param_1 + iVar6 * 8);
    uVar3 = *puVar4;
    if (uVar3 <= uVar5) break;
    puVar2 = (uint *)(param_1 + param_3 * 8);
    *puVar2 = uVar3;
    *(undefined2 *)(puVar2 + 1) = *(undefined2 *)(puVar4 + 1);
    param_3 = iVar6;
  }
  *(uint *)(param_1 + param_3 * 8) = uVar5;
  *(undefined2 *)(param_1 + param_3 * 8 + 4) = uVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800462f8
 * EN v1.0 Address: 0x800462F8
 * EN v1.0 Size: 1348b
 * EN v1.1 Address: 0x8004ACD8
 * EN v1.1 Size: 1092b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800462f8(undefined4 param_1,undefined4 param_2,undefined param_3,uint param_4,int param_5)
{
  short sVar1;
  undefined2 uVar2;
  short sVar3;
  int *piVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  uint *puVar9;
  uint uVar10;
  uint unaff_r29;
  int *piVar11;
  int iVar12;
  int unaff_r31;
  double dVar13;
  undefined8 uVar14;
  
  uVar14 = FUN_80286834();
  piVar4 = (int *)((ulonglong)uVar14 >> 0x20);
  uVar5 = FUN_800461b4(piVar4,(int *)uVar14);
  if (uVar5 != 0) {
    sVar1 = *(short *)(piVar4 + 8);
    if (sVar1 != 0xfe) {
      *(short *)(piVar4 + 8) = sVar1 + 1;
      piVar11 = (int *)(*piVar4 + sVar1 * 0x10);
      *piVar11 = param_5;
      piVar11[2] = param_4;
      *(undefined *)(piVar11 + 3) = param_3;
      dVar13 = FUN_80017714((float *)(*piVar11 + 8),(float *)piVar4[3]);
      iVar6 = FUN_80286718(dVar13);
      piVar11[1] = iVar6;
    }
    puVar8 = (undefined4 *)piVar4[1];
    sVar3 = *(short *)((int)piVar4 + 0x22) + 1;
    *(short *)((int)piVar4 + 0x22) = sVar3;
    *(short *)(puVar8 + sVar3 * 2 + 1) = sVar1;
    puVar8[*(short *)((int)piVar4 + 0x22) * 2] = 0xfffffffe;
    iVar6 = (int)*(short *)((int)piVar4 + 0x22);
    uVar5 = puVar8[iVar6 * 2];
    uVar2 = *(undefined2 *)(puVar8 + iVar6 * 2 + 1);
    *puVar8 = 0xffffffff;
    while (iVar7 = iVar6 >> 1, (uint)puVar8[iVar7 * 2] < uVar5) {
      *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = *(undefined2 *)(puVar8 + iVar7 * 2 + 1);
      puVar8[iVar6 * 2] = puVar8[iVar7 * 2];
      iVar6 = iVar7;
    }
    puVar8[iVar6 * 2] = uVar5;
    *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = uVar2;
  }
  uVar5 = 0;
  iVar7 = 0;
  sVar1 = *(short *)(piVar4 + 8);
  iVar12 = (int)sVar1;
  iVar6 = iVar12;
  if (0 < iVar12) {
    do {
      if (*(int *)(*piVar4 + iVar7) == param_5) {
        unaff_r29 = (uint)*(byte *)(*piVar4 + iVar7 + 0xe);
        goto LAB_8004ae34;
      }
      iVar7 = iVar7 + 0x10;
      uVar5 = uVar5 + 1;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
  }
  uVar5 = 0xffffffff;
LAB_8004ae34:
  if (((int)uVar5 < 0) || (unaff_r29 != 0)) {
    if ((int)uVar5 < 0) {
      if (iVar12 == 0xfe) {
        piVar11 = (int *)0x0;
      }
      else {
        sVar3 = *(short *)(piVar4 + 8);
        *(short *)(piVar4 + 8) = sVar3 + 1;
        piVar11 = (int *)(*piVar4 + sVar3 * 0x10);
        *piVar11 = param_5;
        piVar11[2] = param_4;
        *(undefined *)(piVar11 + 3) = param_3;
        dVar13 = FUN_80017714((float *)(*piVar11 + 8),(float *)piVar4[3]);
        iVar6 = FUN_80286718(dVar13);
        piVar11[1] = iVar6;
      }
      if (piVar11 != (int *)0x0) {
        uVar5 = piVar11[1];
        if ((uint)piVar4[9] < uVar5) {
          iVar6 = piVar11[2];
          puVar8 = (undefined4 *)piVar4[1];
          sVar3 = *(short *)((int)piVar4 + 0x22) + 1;
          *(short *)((int)piVar4 + 0x22) = sVar3;
          *(short *)(puVar8 + sVar3 * 2 + 1) = sVar1;
          puVar8[*(short *)((int)piVar4 + 0x22) * 2] = -1 - (uVar5 + iVar6);
          iVar6 = (int)*(short *)((int)piVar4 + 0x22);
          uVar5 = puVar8[iVar6 * 2];
          uVar2 = *(undefined2 *)(puVar8 + iVar6 * 2 + 1);
          *puVar8 = 0xffffffff;
          while (iVar7 = iVar6 >> 1, (uint)puVar8[iVar7 * 2] < uVar5) {
            *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = *(undefined2 *)(puVar8 + iVar7 * 2 + 1);
            puVar8[iVar6 * 2] = puVar8[iVar7 * 2];
            iVar6 = iVar7;
          }
          puVar8[iVar6 * 2] = uVar5;
          *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = uVar2;
        }
        else {
          if (uVar5 < (uint)piVar4[9]) {
            piVar4[9] = uVar5;
          }
          iVar7 = piVar11[1];
          iVar6 = piVar11[2];
          puVar8 = (undefined4 *)piVar4[1];
          sVar3 = *(short *)((int)piVar4 + 0x22) + 1;
          *(short *)((int)piVar4 + 0x22) = sVar3;
          *(short *)(puVar8 + sVar3 * 2 + 1) = sVar1;
          puVar8[*(short *)((int)piVar4 + 0x22) * 2] = -1 - (iVar7 + iVar6);
          iVar6 = (int)*(short *)((int)piVar4 + 0x22);
          uVar5 = puVar8[iVar6 * 2];
          uVar2 = *(undefined2 *)(puVar8 + iVar6 * 2 + 1);
          *puVar8 = 0xffffffff;
          while (iVar7 = iVar6 >> 1, (uint)puVar8[iVar7 * 2] < uVar5) {
            *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = *(undefined2 *)(puVar8 + iVar7 * 2 + 1);
            puVar8[iVar6 * 2] = puVar8[iVar7 * 2];
            iVar6 = iVar7;
          }
          puVar8[iVar6 * 2] = uVar5;
          *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = uVar2;
        }
      }
    }
  }
  else {
    iVar6 = *piVar4 + uVar5 * 0x10;
    if (param_4 < *(uint *)(iVar6 + 8)) {
      *(undefined *)(iVar6 + 0xc) = param_3;
      *(uint *)(iVar6 + 8) = param_4;
      uVar10 = *(int *)(iVar6 + 4) + *(int *)(iVar6 + 8);
      iVar6 = (int)*(short *)((int)piVar4 + 0x22);
      puVar8 = (undefined4 *)piVar4[1];
      iVar7 = 0;
      while (iVar7 <= iVar6) {
        iVar12 = iVar7;
        if ((uVar5 & 0xffff) == (uint)*(ushort *)(puVar8 + iVar7 * 2 + 1)) {
          iVar12 = iVar6 + 1;
          unaff_r31 = iVar7;
        }
        iVar7 = iVar12 + 1;
      }
      puVar9 = puVar8 + unaff_r31 * 2;
      uVar5 = *puVar9;
      *puVar9 = uVar10;
      if (uVar10 < uVar5) {
        FUN_80046270((int)puVar8,iVar6,unaff_r31);
      }
      else if (uVar5 < uVar10) {
        uVar5 = *puVar9;
        uVar2 = *(undefined2 *)(puVar9 + 1);
        *puVar8 = 0xffffffff;
        while (iVar6 = unaff_r31 >> 1, (uint)puVar8[iVar6 * 2] < uVar5) {
          *(undefined2 *)(puVar8 + unaff_r31 * 2 + 1) = *(undefined2 *)(puVar8 + iVar6 * 2 + 1);
          puVar8[unaff_r31 * 2] = puVar8[iVar6 * 2];
          unaff_r31 = iVar6;
        }
        puVar8[unaff_r31 * 2] = uVar5;
        *(undefined2 *)(puVar8 + unaff_r31 * 2 + 1) = uVar2;
      }
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8004B11C
 * EN v1.0 Address: 0x8004683C
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x8004B11C
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8004B11C(undefined4 param_1,undefined4 param_2,undefined param_3)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  undefined8 uVar11;
  
  uVar11 = FUN_80286834();
  iVar3 = (int)((ulonglong)uVar11 >> 0x20);
  piVar6 = (int *)uVar11;
  iVar8 = *piVar6;
  if (*(char *)(iVar3 + 0x28) == '\0') {
    uVar2 = ~(int)*(char *)(iVar8 + 0x1b);
  }
  else {
    uVar2 = (uint)*(char *)(iVar8 + 0x1b);
  }
  iVar7 = 0;
  iVar9 = iVar8;
  do {
    iVar1 = DAT_803dd988;
    if ((((-1 < *(int *)(iVar9 + 0x1c)) && ((uVar2 & 0xff & 1 << iVar7) != 0)) &&
        (iVar4 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar1 = DAT_803dd988, iVar4 != 0)) &&
       (iVar1 = iVar4, *(char *)(iVar4 + 0x19) == '$')) {
      FUN_80017690(0x4e2);
      if (((((int)*(short *)(iVar4 + 0x30) == -1) ||
           (uVar5 = FUN_80017690((int)*(short *)(iVar4 + 0x30)), iVar1 = DAT_803dd988, uVar5 != 0))
          && (((int)*(short *)(iVar4 + 0x32) == -1 ||
              (uVar5 = FUN_80017690((int)*(short *)(iVar4 + 0x32)), iVar1 = DAT_803dd988,
              uVar5 == 0)))) &&
         ((*(char *)(iVar4 + 0x1a) != '\b' || (*(char *)(iVar8 + 0x1a) != '\t')))) {
        dVar10 = FUN_80017714((float *)(iVar8 + 8),(float *)(iVar4 + 8));
        uVar5 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,piVar6[2]) -
                                                        DOUBLE_803df728) + dVar10));
        FUN_800462f8((undefined4)iVar3,(undefined4)(u32)piVar6,param_3,uVar5,iVar4);
        iVar1 = DAT_803dd988;
      }
    }
    DAT_803dd988 = iVar1;
    iVar9 = iVar9 + 4;
    iVar7 = iVar7 + 1;
  } while (iVar7 < 4);
  FUN_80286880();
}

/*
 * --INFO--
 *
 * Function: FUN_800469d0
 * EN v1.0 Address: 0x800469D0
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x8004B294
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800469d0(int param_1)
{
  short sVar1;
  
  sVar1 = *(short *)(param_1 + 0x2c);
  if ((int)sVar1 < (int)*(short *)(param_1 + 0x2a)) {
    *(short *)(param_1 + 0x2c) = sVar1 + 1;
    return *(undefined4 *)(*(int *)(param_1 + 8) + sVar1 * 4);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80046a00
 * EN v1.0 Address: 0x80046A00
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x8004B2C4
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80046a00(int *param_1)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined4 *puVar5;
  
  uVar3 = param_1[7];
  iVar1 = *param_1 + uVar3 * 0x10;
  *(undefined *)(iVar1 + 0xd) = 0xff;
  while (uVar2 = (uint)*(byte *)(iVar1 + 0xc), uVar2 != 0xff) {
    iVar1 = *param_1 + uVar2 * 0x10;
    *(char *)(iVar1 + 0xd) = (char)uVar3;
    uVar3 = uVar2;
  }
  if (*(byte *)(iVar1 + 0xd) == 0xff) {
    puVar5 = (undefined4 *)0x0;
  }
  else {
    puVar5 = (undefined4 *)(*param_1 + (uint)*(byte *)(iVar1 + 0xd) * 0x10);
  }
  iVar4 = 0;
  iVar1 = 0;
  while (puVar5 != (undefined4 *)0x0) {
    *(undefined4 *)(param_1[2] + iVar1) = *puVar5;
    iVar1 = iVar1 + 4;
    iVar4 = iVar4 + 1;
    if (iVar4 < 100) {
      if (*(byte *)((int)puVar5 + 0xd) == 0xff) {
        puVar5 = (undefined4 *)0x0;
      }
      else {
        puVar5 = (undefined4 *)(*param_1 + (uint)*(byte *)((int)puVar5 + 0xd) * 0x10);
      }
    }
    else {
      puVar5 = (undefined4 *)0x0;
    }
  }
  *(short *)((int)param_1 + 0x2a) = (short)iVar4;
  *(undefined2 *)(param_1 + 0xb) = 0;
  return iVar4;
}

/*
 * --INFO--
 *
 * Function: fn_8004B394
 * EN v1.0 Address: 0x80046AC8
 * EN v1.0 Size: 520b
 * EN v1.1 Address: 0x8004B394
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8004B394(void)
{
  short sVar1;
  bool bVar2;
  int *piVar3;
  int iVar4;
  uint uVar5;
  int *piVar6;
  uint uVar7;
  int iVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_8028683c();
  piVar3 = (int *)((ulonglong)uVar9 >> 0x20);
  bVar2 = false;
  for (iVar8 = (int)uVar9; (!bVar2 && (iVar8 != 0)); iVar8 = iVar8 + -1) {
    iVar4 = piVar3[1];
    if (*(short *)((int)piVar3 + 0x22) == 0) {
      uVar7 = 0xffffffff;
    }
    else {
      uVar7 = (uint)*(ushort *)(iVar4 + 0xc);
      *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(iVar4 + *(short *)((int)piVar3 + 0x22) * 8);
      sVar1 = *(short *)((int)piVar3 + 0x22);
      *(short *)((int)piVar3 + 0x22) = sVar1 + -1;
      *(undefined2 *)(iVar4 + 0xc) = *(undefined2 *)(iVar4 + sVar1 * 8 + 4);
      FUN_80046270(iVar4,(int)*(short *)((int)piVar3 + 0x22),1);
    }
    if ((int)uVar7 < 0) {
      bVar2 = true;
    }
    else {
      piVar6 = (int *)(*piVar3 + uVar7 * 0x10);
      piVar3[7] = uVar7;
      uVar5 = FUN_800461b4(piVar3,piVar6);
      if (uVar5 == 0) {
        *(undefined *)((int)piVar6 + 0xe) = 1;
        fn_8004B11C((undefined4)piVar3,(undefined4)piVar6,(char)uVar7);
      }
      else {
        bVar2 = true;
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80046cd0
 * EN v1.0 Address: 0x80046CD0
 * EN v1.0 Size: 628b
 * EN v1.1 Address: 0x8004B498
 * EN v1.1 Size: 632b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80046cd0(int *param_1,int param_2,int param_3,int param_4,byte param_5)
{
  undefined2 uVar1;
  short sVar2;
  int iVar3;
  undefined4 *puVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  int iVar9;
  double dVar10;
  
  iVar3 = 0;
  *(undefined2 *)((int)param_1 + 0x22) = 0;
  *(undefined2 *)(param_1 + 8) = 0;
  iVar6 = 0;
  iVar7 = 0;
  iVar9 = 0x1f;
  do {
    *(undefined4 *)(param_1[1] + iVar6) = 0;
    *(undefined *)(*param_1 + iVar7 + 0xe) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 8) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x1e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x10) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x2e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x18) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x3e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x20) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x4e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x28) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x5e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x30) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x6e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x38) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x7e) = 0;
    iVar6 = iVar6 + 0x40;
    iVar7 = iVar7 + 0x80;
    iVar3 = iVar3 + 8;
    iVar9 = iVar9 + -1;
  } while (iVar9 != 0);
  iVar6 = iVar3 * 8;
  iVar7 = iVar3 * 0x10;
  iVar9 = 0xfe - iVar3;
  if (iVar3 < 0xfe) {
    do {
      *(undefined4 *)(param_1[1] + iVar6) = 0;
      *(undefined *)(*param_1 + iVar7 + 0xe) = 0;
      iVar6 = iVar6 + 8;
      iVar7 = iVar7 + 0x10;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
  }
  param_1[6] = param_2;
  param_1[3] = param_3;
  param_1[4] = param_4;
  *(byte *)(param_1 + 10) = param_5 & 1;
  param_1[9] = 10000;
  sVar2 = *(short *)(param_1 + 8);
  if (sVar2 == 0xfe) {
    piVar8 = (int *)0x0;
  }
  else {
    *(short *)(param_1 + 8) = sVar2 + 1;
    piVar8 = (int *)(*param_1 + sVar2 * 0x10);
    *piVar8 = param_2;
    piVar8[2] = 0;
    *(undefined *)(piVar8 + 3) = 0xff;
    dVar10 = FUN_80017714((float *)(*piVar8 + 8),(float *)param_1[3]);
    iVar3 = FUN_80286718(dVar10);
    piVar8[1] = iVar3;
  }
  iVar6 = piVar8[1];
  iVar3 = piVar8[2];
  puVar4 = (undefined4 *)param_1[1];
  sVar2 = *(short *)((int)param_1 + 0x22) + 1;
  *(short *)((int)param_1 + 0x22) = sVar2;
  *(short *)(puVar4 + sVar2 * 2 + 1) = *(short *)(param_1 + 8) + -1;
  puVar4[*(short *)((int)param_1 + 0x22) * 2] = -1 - (iVar6 + iVar3);
  iVar3 = (int)*(short *)((int)param_1 + 0x22);
  uVar5 = puVar4[iVar3 * 2];
  uVar1 = *(undefined2 *)(puVar4 + iVar3 * 2 + 1);
  *puVar4 = 0xffffffff;
  while (iVar6 = iVar3 >> 1, (uint)puVar4[iVar6 * 2] < uVar5) {
    *(undefined2 *)(puVar4 + iVar3 * 2 + 1) = *(undefined2 *)(puVar4 + iVar6 * 2 + 1);
    puVar4[iVar3 * 2] = puVar4[iVar6 * 2];
    iVar3 = iVar6;
  }
  puVar4[iVar3 * 2] = uVar5;
  *(undefined2 *)(puVar4 + iVar3 * 2 + 1) = uVar1;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80046f44
 * EN v1.0 Address: 0x80046F44
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x8004B710
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80046f44(uint *param_1)
{
  if (*param_1 != 0) {
    FUN_80017814(*param_1);
    *param_1 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80046f84
 * EN v1.0 Address: 0x80046F84
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x8004B750
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80046f84(int *param_1)
{
  int iVar1;
  
  iVar1 = FUN_80017830(0x1960,0x10);
  *param_1 = iVar1;
  param_1[1] = *param_1 + 0xfe0;
  param_1[2] = param_1[1] + 0x7f0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80046fd4
 * EN v1.0 Address: 0x80046FD4
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8004B7A4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80046fd4(void)
{
  DAT_803dd990 = FUN_80017830(0x20,0xff);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80047000
 * EN v1.0 Address: 0x80047000
 * EN v1.0 Size: 3464b
 * EN v1.1 Address: 0x8004B7D4
 * EN v1.1 Size: 2352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80047000(int param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  ushort uVar4;
  uint uVar5;
  ushort *puVar6;
  byte *pbVar7;
  ushort *puVar8;
  byte *pbVar9;
  uint uVar10;
  undefined *puVar11;
  int iVar12;
  int iVar13;
  undefined *puVar14;
  undefined *puVar15;
  int iVar16;
  uint uVar17;
  uint uVar18;
  undefined *puVar19;
  undefined2 *puVar20;
  short *psVar21;
  int iVar22;
  int iVar23;
  uint uVar24;
  int iVar25;
  uint uVar26;
  undefined1 *puVar27;
  undefined1 *puVar28;
  uint uVar29;
  uint uVar30;
  bool bVar31;
  
  pbVar9 = (byte *)(param_3 + -1);
  uVar10 = 0;
  uVar17 = 0;
  puVar6 = (ushort *)(param_1 + 2);
  do {
    bVar1 = *(byte *)puVar6;
    uVar5 = uVar17 & 0x1f;
    pbVar7 = (byte *)((int)puVar6 + ((int)(uVar10 + 1) >> 3));
    uVar10 = uVar10 + 1 & 7;
    uVar17 = 0x20 - uVar10 & 0x1f;
    uVar18 = ((uint)*pbVar7 << uVar17 & 0xff | (uint)(*pbVar7 >> 0x20 - uVar17) |
             (uint)pbVar7[1] << 8 - uVar10) & 3;
    puVar6 = (ushort *)(pbVar7 + ((int)(uVar10 + 2) >> 3));
    uVar10 = uVar10 + 2 & 7;
    bVar31 = uVar10 < 0x21;
    uVar17 = 0x20 - uVar10;
    if (uVar18 == 0) {
      if (uVar10 != 0) {
        puVar6 = (ushort *)((int)puVar6 + 1);
        uVar10 = 0;
      }
      uVar4 = *puVar6;
      puVar8 = (ushort *)((int)puVar6 + 1);
      puVar6 = puVar6 + 2;
      uVar18 = (uint)uVar4 | (uint)*puVar8 << 8;
      do {
        bVar2 = *(byte *)puVar6;
        puVar6 = (ushort *)((int)puVar6 + 1);
        pbVar9 = pbVar9 + 1;
        *pbVar9 = bVar2;
        uVar24 = (uint)bVar31;
        bVar31 = CARRY4(uVar18,uVar24 - 1);
        uVar18 = uVar18 + (uVar24 - 1);
      } while (uVar18 != 0);
    }
    else {
      if (uVar18 == 1) {
        puVar11 = &DAT_8030d440;
        iVar12 = -0x7fcf2aa0;
        iVar13 = 9;
        puVar14 = &DAT_8030d960;
        puVar15 = &DAT_8030d980;
        iVar16 = 5;
      }
      else {
        puVar11 = &DAT_803603a0;
        iVar12 = -0x7fc9fb40;
        puVar14 = &DAT_803704c0;
        puVar15 = &DAT_803704e0;
        iVar13 = 8;
        puVar19 = &DAT_803dd9a0;
        do {
          *puVar19 = 0;
          puVar19 = puVar19 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x13;
        puVar19 = &DAT_803784e0;
        do {
          *puVar19 = 0;
          puVar19 = puVar19 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x10;
        puVar20 = &DAT_803784f4;
        do {
          *puVar20 = 0;
          puVar20 = puVar20 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x120;
        puVar19 = puVar11;
        do {
          *puVar19 = 0;
          puVar19 = puVar19 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x10;
        puVar20 = &DAT_80378514;
        do {
          *puVar20 = 0;
          puVar20 = puVar20 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x20;
        puVar19 = puVar14;
        do {
          *puVar19 = 0;
          puVar19 = puVar19 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar16 = (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                   (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                  (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 0x1f) + 0x101;
        pbVar7 = (byte *)((int)puVar6 + ((int)(uVar10 + 5) >> 3));
        uVar10 = uVar10 + 5 & 7;
        uVar17 = 0x20 - uVar10 & 0x1f;
        iVar23 = (((uint)*pbVar7 << uVar17 & 0xff | (uint)(*pbVar7 >> 0x20 - uVar17) |
                  (uint)pbVar7[1] << 8 - uVar10) & 0x1f) + 1;
        pbVar7 = pbVar7 + ((int)(uVar10 + 5) >> 3);
        uVar24 = uVar10 + 5 & 7;
        bVar2 = pbVar7[1];
        bVar3 = *pbVar7;
        uVar18 = 0x20 - uVar24 & 0x1f;
        uVar10 = uVar24 + 4;
        puVar6 = (ushort *)(pbVar7 + ((int)uVar10 >> 3));
        puVar28 = &DAT_802c23d0;
        iVar13 = 0;
        while( true ) {
          uVar10 = uVar10 & 7;
          uVar17 = 0x20 - uVar10;
          if (iVar13 == (((uint)bVar3 << uVar18 & 0xff | (uint)(bVar3 >> 0x20 - uVar18) |
                         (uint)bVar2 << 8 - uVar24) & 0xf) + 4) break;
          uVar17 = ((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                    (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                   (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 7;
          (&DAT_803784e0)[(byte)(&DAT_802c23d0)[iVar13]] = (char)uVar17;
          uVar10 = uVar10 + 3;
          (&DAT_803dd9a0)[uVar17] = (&DAT_803dd9a0)[uVar17] + '\x01';
          puVar6 = (ushort *)((int)puVar6 + ((int)uVar10 >> 3));
          iVar13 = iVar13 + 1;
        }
        for (iVar13 = 7; (&DAT_803dd9a0)[iVar13] == '\0'; iVar13 = iVar13 + -1) {
        }
        iVar22 = 0;
        for (iVar25 = 1; iVar25 <= iVar13; iVar25 = iVar25 + 1) {
          if ((byte)(&DAT_803dd9a0)[iVar25] != 0) {
            (&DAT_803dd998)[iVar25] = (char)iVar22;
            iVar22 = iVar22 + ((uint)(byte)(&DAT_803dd9a0)[iVar25] << iVar13 - iVar25);
          }
        }
        for (iVar22 = 0; iVar22 < 0x13; iVar22 = iVar22 + 1) {
          puVar28 = &DAT_803dd998;
          uVar18 = (uint)(byte)(&DAT_803784e0)[iVar22];
          if (uVar18 != 0) {
            for (iVar25 = 0; iVar25 < 1 << iVar13 - uVar18; iVar25 = iVar25 + 1) {
              bVar2 = (&DAT_803dd998)[uVar18];
              (&DAT_803dd998)[uVar18] = bVar2 + 1;
              (&DAT_80378534)[bVar2] = (char)iVar22;
            }
          }
        }
        puVar20 = &DAT_803784f4;
        iVar22 = 0;
        puVar19 = puVar11;
        do {
          uVar18 = 0;
          if (8 - iVar13 < (int)uVar10) {
            uVar18 = (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10;
          }
          uVar24 = iVar13 + 0x18U & 0x1f;
          puVar27 = (undefined1 *)
                    (uint)(byte)(&DAT_80378534)
                                [(uint)(byte)(&DAT_8030d9a0)
                                             [((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                                               (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                                              uVar18) & (1 << iVar13) - 1U] << uVar24 & 0xff |
                                 (uint)((byte)(&DAT_8030d9a0)
                                              [((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                                                (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                                               uVar18) & (1 << iVar13) - 1U] >> 0x20 - uVar24)];
          puVar6 = (ushort *)
                   ((int)puVar6 + ((int)(uVar10 + (byte)(&DAT_803784e0)[(int)puVar27]) >> 3));
          uVar10 = uVar10 + (byte)(&DAT_803784e0)[(int)puVar27] & 7;
          bVar31 = uVar10 < 0x21;
          uVar17 = 0x20 - uVar10;
          if (puVar27 == (undefined1 *)0x10) {
            uVar18 = (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                       (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                      (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 3) + 3;
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + 2) >> 3));
            uVar10 = uVar10 + 2 & 7;
            bVar31 = uVar10 < 0x21;
            uVar17 = 0x20 - uVar10;
            puVar27 = puVar28;
          }
          else if (puVar27 == (undefined1 *)0x11) {
            puVar27 = (undefined1 *)0x0;
            uVar18 = (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                       (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                      (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 7) + 3;
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + 3) >> 3));
            uVar10 = uVar10 + 3 & 7;
            bVar31 = uVar10 < 0x21;
            uVar17 = 0x20 - uVar10;
          }
          else if (puVar27 == (undefined1 *)0x12) {
            puVar27 = (undefined1 *)0x0;
            uVar18 = (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                       (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                      (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 0x7f) + 0xb;
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + 7) >> 3));
            uVar10 = uVar10 + 7 & 7;
            bVar31 = uVar10 < 0x21;
            uVar17 = 0x20 - uVar10;
          }
          else {
            uVar18 = 1;
          }
          do {
            puVar19[iVar22] = (char)puVar27;
            iVar22 = iVar22 + 1;
            puVar20[(int)puVar27] = puVar20[(int)puVar27] + 1;
            if ((puVar19 == &DAT_803603a0) && (iVar22 == iVar16)) {
              puVar20 = &DAT_80378514;
              iVar22 = 0;
              puVar19 = puVar14;
            }
            uVar24 = (uint)bVar31;
            bVar31 = CARRY4(uVar18,uVar24 - 1);
            uVar18 = uVar18 + (uVar24 - 1);
          } while (uVar18 != 0);
          puVar28 = puVar27;
        } while ((puVar19 == &DAT_803603a0) || (iVar22 < iVar23));
        iVar13 = 0xf;
        for (psVar21 = &DAT_80378512; *psVar21 == 0; psVar21 = psVar21 + -1) {
          iVar13 = iVar13 + -1;
        }
        iVar22 = 0;
        for (iVar25 = 1; iVar25 <= iVar13; iVar25 = iVar25 + 1) {
          uVar4 = (&DAT_803784f4)[iVar25];
          if (uVar4 != 0) {
            *(short *)(iVar25 * 2 + -0x7fc87a4c) = (short)iVar22;
            iVar22 = iVar22 + ((uint)uVar4 << iVar13 - iVar25);
          }
        }
        for (iVar22 = 0; iVar22 < iVar16; iVar22 = iVar22 + 1) {
          uVar18 = (uint)(byte)(&DAT_803603a0)[iVar22];
          if (uVar18 != 0) {
            for (iVar25 = 0; iVar25 < 1 << iVar13 - uVar18; iVar25 = iVar25 + 1) {
              puVar8 = (ushort *)(uVar18 * 2 + -0x7fc87a4c);
              uVar4 = *puVar8;
              *puVar8 = uVar4 + 1;
              *(short *)((uint)uVar4 * 2 + -0x7fc9fb40) = (short)iVar22;
            }
          }
        }
        for (iVar16 = 0xf; (&DAT_80378514)[iVar16] == 0; iVar16 = iVar16 + -1) {
        }
        iVar22 = 0;
        for (iVar25 = 1; iVar25 <= iVar16; iVar25 = iVar25 + 1) {
          if ((ushort)(&DAT_80378514)[iVar25] != 0) {
            (&DAT_803785d4)[iVar25] = (short)iVar22;
            iVar22 = iVar22 + ((uint)(ushort)(&DAT_80378514)[iVar25] << iVar16 - iVar25);
          }
        }
        for (iVar22 = 0; iVar22 < iVar23; iVar22 = iVar22 + 1) {
          uVar18 = (uint)(byte)(&DAT_803704c0)[iVar22];
          if (uVar18 != 0) {
            for (iVar25 = 0; iVar25 < 1 << iVar16 - uVar18; iVar25 = iVar25 + 1) {
              uVar4 = (&DAT_803785d4)[uVar18];
              (&DAT_803785d4)[uVar18] = uVar4 + 1;
              (&DAT_803704e0)[uVar4] = (char)iVar22;
            }
          }
        }
      }
      do {
        uVar24 = ((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                  (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                  (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10 |
                 (uint)*(byte *)(puVar6 + 1) << 0x10 - uVar10) & (1 << iVar13) - 1U;
        uVar17 = iVar13 - 8U & 0x1f;
        uVar18 = iVar13 + 0x10U & 0x1f;
        uVar4 = *(ushort *)
                 (iVar12 + ((uint)(byte)(&DAT_8030d9a0)[uVar24 & 0xff] << uVar17 & 0xffff |
                            (uint)((byte)(&DAT_8030d9a0)[uVar24 & 0xff] >> 0x20 - uVar17) |
                           (uint)(byte)(&DAT_8030d9a0)[uVar24 >> 8] << uVar18 & 0xff |
                           (uint)((byte)(&DAT_8030d9a0)[uVar24 >> 8] >> 0x20 - uVar18)) * 2);
        uVar18 = (uint)uVar4;
        puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + (byte)puVar11[uVar18]) >> 3));
        uVar10 = uVar10 + (byte)puVar11[uVar18] & 7;
        uVar17 = 0x20 - uVar10;
        if (uVar18 < 0x100) {
          pbVar9 = pbVar9 + 1;
          *pbVar9 = (byte)uVar4;
        }
        else {
          if (uVar18 == 0x100) break;
          iVar23 = (uVar18 - 0x101) * 4;
          uVar29 = (uint)*(ushort *)(&DAT_802c23e4 + iVar23);
          uVar24 = (uint)*(ushort *)(&DAT_802c23e6 + iVar23);
          if (uVar24 != 0) {
            uVar29 = uVar29 + (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                                (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                               (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & (1 << uVar24) - 1U)
            ;
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + uVar24) >> 3));
            uVar10 = uVar10 + uVar24 & 7;
            uVar17 = 0x20 - uVar10;
          }
          uVar26 = ((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                    (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                    (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10 |
                   (uint)*(byte *)(puVar6 + 1) << 0x10 - uVar10) & (1 << iVar16) - 1U;
          uVar24 = iVar16 - 8U & 0x1f;
          uVar30 = iVar16 + 0x10U & 0x1f;
          puVar6 = (ushort *)
                   ((int)puVar6 +
                   ((int)(uVar10 + (byte)puVar14[(byte)puVar15[(uint)(byte)(&DAT_8030d9a0)
                                                                           [uVar26 & 0xff] << uVar24
                                                               & 0xffff |
                                                               (uint)((byte)(&DAT_8030d9a0)
                                                                            [uVar26 & 0xff] >>
                                                                     0x20 - uVar24) |
                                                               (uint)(byte)(&DAT_8030d9a0)
                                                                           [uVar26 >> 8] << uVar30 &
                                                               0xff | (uint)((byte)(&DAT_8030d9a0)
                                                                                   [uVar26 >> 8] >>
                                                                            0x20 - uVar30)]]) >> 3))
          ;
          uVar10 = uVar10 + (byte)puVar14[(byte)puVar15[(uint)(byte)(&DAT_8030d9a0)[uVar26 & 0xff]
                                                        << uVar24 & 0xffff |
                                                        (uint)((byte)(&DAT_8030d9a0)[uVar26 & 0xff]
                                                              >> 0x20 - uVar24) |
                                                        (uint)(byte)(&DAT_8030d9a0)[uVar26 >> 8] <<
                                                        uVar30 & 0xff |
                                                        (uint)((byte)(&DAT_8030d9a0)[uVar26 >> 8] >>
                                                              0x20 - uVar30)]] & 7;
          uVar17 = 0x20 - uVar10;
          iVar23 = (uint)(byte)puVar15[(uint)(byte)(&DAT_8030d9a0)[uVar26 & 0xff] << uVar24 & 0xffff
                                       | (uint)((byte)(&DAT_8030d9a0)[uVar26 & 0xff] >>
                                               0x20 - uVar24) |
                                       (uint)(byte)(&DAT_8030d9a0)[uVar26 >> 8] << uVar30 & 0xff |
                                       (uint)((byte)(&DAT_8030d9a0)[uVar26 >> 8] >> 0x20 - uVar30)]
                   * 4;
          uVar30 = (uint)*(ushort *)(&DAT_802c2458 + iVar23);
          uVar24 = (uint)*(ushort *)(&DAT_802c245a + iVar23);
          if (uVar24 != 0) {
            uVar30 = uVar30 + (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                                (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                                (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10 |
                               (uint)*(byte *)(puVar6 + 1) << 0x10 - uVar10) & (1 << uVar24) - 1U);
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + uVar24) >> 3));
            uVar10 = uVar10 + uVar24 & 7;
            uVar17 = 0x20 - uVar10;
          }
          pbVar7 = pbVar9 + -uVar30;
          do {
            pbVar7 = pbVar7 + 1;
            pbVar9 = pbVar9 + 1;
            *pbVar9 = *pbVar7;
            uVar29 = uVar29 - 1;
          } while (uVar29 != 0);
        }
      } while (uVar18 != 0x100);
    }
    if ((((uint)bVar1 << uVar5 | (uint)(bVar1 >> 0x20 - uVar5)) & 1) != 0) {
      return 0;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_80047d88
 * EN v1.0 Address: 0x80047D88
 * EN v1.0 Size: 596b
 * EN v1.1 Address: 0x8004C104
 * EN v1.1 Size: 604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80047d88(char *param_1,char param_2,char param_3,undefined4 *param_4,undefined4 *param_5)
{
  char cVar1;
  bool bVar2;
  bool bVar3;
  undefined4 local_8 [2];
  
  bVar2 = false;
  bVar3 = false;
  if (param_2 == '\0') {
    bVar2 = true;
  }
  else {
    cVar1 = *param_1;
    if ((cVar1 == param_1[1]) && (cVar1 == param_1[2])) {
      if (cVar1 == -1) {
        *param_4 = 0;
        bVar2 = true;
      }
      else if (cVar1 == -0x20) {
        *param_4 = 1;
        bVar2 = true;
      }
      else if (cVar1 == -0x40) {
        *param_4 = 2;
        bVar2 = true;
      }
      else if (cVar1 == -0x60) {
        *param_4 = 3;
        bVar2 = true;
      }
      else if (cVar1 == -0x80) {
        *param_4 = 4;
        bVar2 = true;
      }
      else if (cVar1 == '`') {
        *param_4 = 5;
        bVar2 = true;
      }
      else if (cVar1 == '@') {
        *param_4 = 6;
        bVar2 = true;
      }
      else if (cVar1 == ' ') {
        *param_4 = 7;
        bVar2 = true;
      }
    }
    if (!bVar2) {
      *param_4 = DAT_803dd9f0;
    }
  }
  if (param_3 == '\0') {
    bVar3 = true;
  }
  else {
    cVar1 = param_1[3];
    if (cVar1 == -1) {
      *param_5 = 0;
      bVar3 = true;
    }
    else if (cVar1 == -0x20) {
      *param_5 = 1;
      bVar3 = true;
    }
    else if (cVar1 == -0x40) {
      *param_5 = 2;
      bVar3 = true;
    }
    else if (cVar1 == -0x60) {
      *param_5 = 3;
      bVar3 = true;
    }
    else if (cVar1 == -0x80) {
      *param_5 = 4;
      bVar3 = true;
    }
    else if (cVar1 == '`') {
      *param_5 = 5;
      bVar3 = true;
    }
    else if (cVar1 == '@') {
      *param_5 = 6;
      bVar3 = true;
    }
    else if (cVar1 == ' ') {
      *param_5 = 7;
      bVar3 = true;
    }
    if (!bVar3) {
      *param_5 = DAT_803dd9ec;
    }
  }
  if ((!bVar2) || (!bVar3)) {
    local_8[0] = *(undefined4 *)param_1;
    FUN_8025c510(DAT_803dd9f4,(byte *)local_8);
    DAT_803dd9f4 = DAT_803dd9f4 + 1;
    DAT_803dd9f0 = DAT_803dd9f0 + 1;
    DAT_803dd9ec = DAT_803dd9ec + 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80047fdc
 * EN v1.0 Address: 0x80047FDC
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8004C360
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80047fdc(double param_1,undefined param_2)
{
  uRam803dc24f = param_2;
  lbl_803DC250 = (float)param_1;
  if (param_1 <= (double)lbl_803DF748) {
    return;
  }
  lbl_803DC250 = lbl_803DF748;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80048000
 * EN v1.0 Address: 0x80048000
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8004C380
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80048000(void)
{
  DAT_803dd9a8 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004800c
 * EN v1.0 Address: 0x8004800C
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x8004C38C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004800c(double param_1,double param_2,double param_3,double param_4,double param_5,
                 undefined param_6)
{
  DAT_803dd9a8 = 1;
  lbl_803DD9C4 = (float)param_1;
  lbl_803DD9C0 = (float)param_2;
  lbl_803DD9BC = (float)param_3;
  lbl_803DD9B8 = (float)param_4;
  lbl_803DD9B4 = (float)param_5;
  DAT_803dd9b1 = param_6;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80048048
 * EN v1.0 Address: 0x80048048
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8004C3B0
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80048048(undefined4 *param_1,undefined4 *param_2)
{
  *param_1 = lbl_803DD9C4;
  *param_2 = lbl_803DD9C0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80048094
 * EN v1.0 Address: 0x80048094
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8004C3C4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80048094(void)
{
  return DAT_803dd9a8;
}

/*
 * --INFO--
 *
 * Function: FUN_800480a0
 * EN v1.0 Address: 0x800480A0
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x8004C3CC
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800480a0(int param_1,int param_2)
{
  return param_1 + param_2 * 8 + 0x24;
}

/*
 * --INFO--
 *
 * Function: FUN_800480b4
 * EN v1.0 Address: 0x800480B4
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x8004C3E0
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800480b4(int param_1,int param_2)
{
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),param_2);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),param_2);
    }
    if (*(int *)(param_1 + 0x50) != 0) {
      FUN_800530b8(param_1,(uint *)&DAT_80378600);
      FUN_8025b054((uint *)&DAT_80378600,1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004812c
 * EN v1.0 Address: 0x8004812C
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8004C460
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004812c(int param_1,int param_2)
{
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),param_2);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),param_2);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80048178
 * EN v1.0 Address: 0x80048178
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8004C4AC
 * EN v1.1 Size: 1148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80048178(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8004817c
 * EN v1.0 Address: 0x8004817C
 * EN v1.0 Size: 1636b
 * EN v1.1 Address: 0x8004C928
 * EN v1.1 Size: 1632b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004817c(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5)
{
  uint uVar1;
  uint uVar2;
  double dVar3;
  undefined8 uVar4;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  uint auStack_84 [8];
  uint auStack_64 [8];
  uint auStack_44 [17];
  
  uVar4 = FUN_80286840();
  if ((((DAT_803dd9ea < 0xc) && (DAT_803dd9e9 < 7)) && ((int)DAT_803dda0c < 6)) &&
     (DAT_803dd9f4 < 2)) {
    FUN_80258674(DAT_803dda08,1,4,0x3c,0,0x7d);
    FUN_80258674(DAT_803dda08 + 1,1,4,0x3c,0,0x7d);
    FUN_8025c828(DAT_803dda10,DAT_803dda08 + 1,DAT_803dda0c + 1,0xff);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c1a4(DAT_803dda10,0xf,8,0xe,2);
    FUN_8025c2a8(DAT_803dda10,0,0,0,0,2);
    FUN_8025c224(DAT_803dda10,7,4,6,1);
    FUN_8025c368(DAT_803dda10,1,0,0,0,2);
    GXSetBlendMode(DAT_803dda10,DAT_803dd9f0);
    FUN_8025c5f0(DAT_803dda10,DAT_803dd9ec);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c + 2,0xff);
    FUN_8025be80(DAT_803dda10 + 1);
    FUN_8025c1a4(DAT_803dda10 + 1,0xf,8,0xe,4);
    FUN_8025c2a8(DAT_803dda10 + 1,0,0,1,0,2);
    FUN_8025c224(DAT_803dda10 + 1,7,4,6,2);
    FUN_8025c368(DAT_803dda10 + 1,1,0,0,0,2);
    GXSetBlendMode(DAT_803dda10 + 1,DAT_803dd9f0 + 1);
    FUN_8025c5f0(DAT_803dda10 + 1,DAT_803dd9ec + 1);
    FUN_8025c65c(DAT_803dda10 + 1,0,0);
    FUN_8025c828(DAT_803dda10 + 2,DAT_803dda08,DAT_803dda0c,0xff);
    FUN_8025be80(DAT_803dda10 + 2);
    FUN_8025c1a4(DAT_803dda10 + 2,0xf,8,0xc,4);
    FUN_8025c2a8(DAT_803dda10 + 2,0,0,0,1,2);
    FUN_8025c224(DAT_803dda10 + 2,4,7,7,2);
    FUN_8025c368(DAT_803dda10 + 2,0,0,0,1,2);
    FUN_8025c65c(DAT_803dda10 + 2,0,0);
    FUN_8025c828(DAT_803dda10 + 3,0xff,0xff,0xff);
    FUN_8025be80(DAT_803dda10 + 3);
    FUN_8025c1a4(DAT_803dda10 + 3,5,4,0xe,0xf);
    FUN_8025c2a8(DAT_803dda10 + 3,0,0,0,1,2);
    FUN_8025c224(DAT_803dda10 + 3,7,7,7,7);
    FUN_8025c368(DAT_803dda10 + 3,0,0,0,1,2);
    FUN_8025c65c(DAT_803dda10 + 3,0,0);
    GXSetBlendMode(DAT_803dda10 + 3,DAT_803dd9f0 + 2);
    FUN_8025c828(DAT_803dda10 + 4,0xff,0xff,0xff);
    FUN_8025be80(DAT_803dda10 + 4);
    FUN_8025c1a4(DAT_803dda10 + 4,0,4,0xe,0xf);
    FUN_8025c2a8(DAT_803dda10 + 4,0,0,0,1,0);
    FUN_8025c224(DAT_803dda10 + 4,7,7,7,0);
    FUN_8025c368(DAT_803dda10 + 4,0,0,0,1,0);
    FUN_8025c65c(DAT_803dda10 + 4,0,0);
    GXSetBlendMode(DAT_803dda10 + 4,6);
    DAT_803dd9b0 = 1;
    local_8c = DAT_803df730;
    local_88 = DAT_803df734;
    FUN_8025c49c(1,(short *)&local_8c);
    local_90 = DAT_803df738;
    FUN_8025c510(DAT_803dd9f4,(byte *)&local_90);
    local_94 = DAT_803df73c;
    FUN_8025c510(DAT_803dd9f4 + 1,(byte *)&local_94);
    local_98 = DAT_803df740;
    FUN_8025c510(DAT_803dd9f4 + 2,(byte *)&local_98);
    FUN_8025aa74(auStack_44,(uint)((ulonglong)uVar4 >> 0x20),param_4 & 0xffff,param_5 & 0xffff,1,0,0
                 ,'\0');
    dVar3 = (double)lbl_803DF74C;
    FUN_8025ace8(dVar3,dVar3,dVar3,auStack_44,0,0,0,'\0',0);
    FUN_8025b054(auStack_44,DAT_803dda0c);
    uVar2 = (int)(short)param_4 >> 1;
    uVar1 = (int)(short)param_5 >> 1;
    FUN_8025aa74(auStack_64,(uint)uVar4,uVar2 & 0xffff,uVar1 & 0xffff,1,0,0,'\0');
    dVar3 = (double)lbl_803DF74C;
    FUN_8025ace8(dVar3,dVar3,dVar3,auStack_64,0,0,0,'\0',0);
    FUN_8025b054(auStack_64,DAT_803dda0c + 1);
    FUN_8025aa74(auStack_84,param_3,uVar2 & 0xffff,uVar1 & 0xffff,1,0,0,'\0');
    dVar3 = (double)lbl_803DF74C;
    FUN_8025ace8(dVar3,dVar3,dVar3,auStack_84,0,0,0,'\0',0);
    FUN_8025b054(auStack_84,DAT_803dda0c + 2);
    DAT_803dda10 = DAT_803dda10 + 5;
    DAT_803dda08 = DAT_803dda08 + 2;
    DAT_803dda0c = DAT_803dda0c + 3;
    DAT_803dd9f4 = DAT_803dd9f4 + 3;
    DAT_803dd9f0 = DAT_803dd9f0 + 3;
    DAT_803dd9ec = DAT_803dd9ec + 3;
    DAT_803dd9ea = DAT_803dd9ea + 5;
    DAT_803dd9e9 = DAT_803dd9e9 + 2;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800487e0
 * EN v1.0 Address: 0x800487E0
 * EN v1.0 Size: 996b
 * EN v1.1 Address: 0x8004CF88
 * EN v1.1 Size: 1060b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800487e0(float *param_1)
{
  int local_80;
  int local_7c;
  float local_78;
  float local_74;
  float local_70 [5];
  float local_5c;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  FUN_8025be80(0);
  FUN_8025c828(0,0,0,4);
  FUN_8025c1a4(0,0xf,8,10,0xf);
  FUN_8025c224(0,4,7,5,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  local_40 = lbl_803DF764;
  local_3c = lbl_803DF74C;
  local_38 = lbl_803DF74C;
  local_34 = lbl_803DF74C;
  local_30 = lbl_803DF74C;
  local_2c = lbl_803DF74C;
  local_28 = lbl_803DF764;
  local_24 = lbl_803DF74C;
  FUN_8025d8c4(&local_40,0x1e,1);
  FUN_80258674(1,1,0,0x1e,0,0x7d);
  newshadows_getShadowNoiseTexture(&local_7c);
  if (local_7c != 0) {
    if (*(char *)(local_7c + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_7c + 0x20),2);
    }
    else {
      FUN_8025aeac((uint *)(local_7c + 0x20),*(uint **)(local_7c + 0x40),2);
    }
  }
  newshadows_getShadowNoiseScroll(&local_74,&local_78);
  FUN_80247a48((double)(lbl_803DF760 * local_74),(double)(lbl_803DF760 * local_78),
               (double)lbl_803DF74C,local_70);
  local_70[0] = lbl_803DF768;
  local_5c = lbl_803DF768;
  FUN_8025d8c4(local_70,0x21,1);
  FUN_80258674(2,1,0,0x21,0,0x7d);
  FUN_8025bd1c(0,2,2);
  FUN_8025bb48(0,0,0);
  FUN_8025b94c(1,0,0,7,1,0,0,0,0,0);
  GXSetBlendMode(1,4);
  FUN_8025c828(1,1,1,0xff);
  FUN_8025c1a4(1,8,0xe,0,0);
  FUN_8025c224(1,7,4,0,7);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,1,1,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  newshadows_getShadowRampTexture(&local_80);
  if (local_80 != 0) {
    if (*(char *)(local_80 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_80 + 0x20),3);
    }
    else {
      FUN_8025aeac((uint *)(local_80 + 0x20),*(uint **)(local_80 + 0x40),3);
    }
  }
  local_40 = lbl_803DF74C;
  local_3c = lbl_803DF74C;
  local_38 = lbl_803DF76C;
  local_34 = lbl_803DF770;
  local_30 = lbl_803DF74C;
  local_2c = lbl_803DF74C;
  local_28 = lbl_803DF74C;
  local_24 = lbl_803DF74C;
  FUN_80247618(&local_40,param_1,&local_40);
  FUN_8025d8c4(&local_40,0x24,1);
  FUN_80258674(3,1,0,0x24,0,0x7d);
  FUN_8025be80(2);
  FUN_8025c828(2,3,3,0xff);
  FUN_8025c1a4(2,0xf,0xf,0xf,0);
  FUN_8025c224(2,7,4,0,7);
  FUN_8025c65c(2,0,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,0,0,0,1,0);
  DAT_803dda10 = 3;
  DAT_803dda08 = 4;
  DAT_803dda0c = 4;
  DAT_803dd9fc = 1;
  DAT_803dda04 = 0x27;
  DAT_803dd9ea = 3;
  DAT_803dd9e9 = 4;
  DAT_803dd9e8 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80048bc4
 * EN v1.0 Address: 0x80048BC4
 * EN v1.0 Size: 828b
 * EN v1.1 Address: 0x8004D3AC
 * EN v1.1 Size: 900b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80048bc4(void)
{
  int iVar1;
  double dVar2;
  double dVar3;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float afStack_48 [17];
  
  iVar1 = newshadows_getRadialFalloffTexture();
  dVar3 = (double)lbl_803DF75C;
  FUN_80247b70((double)lbl_803DF774,(double)lbl_803DF778,(double)lbl_803DF778,
               (double)lbl_803DF774,dVar3,dVar3,dVar3,dVar3,afStack_48);
  FUN_8025d8c4(afStack_48,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c6b4(1,0,0,0,1);
  FUN_8025c65c(DAT_803dda10,1,1);
  if (DAT_803dda10 == 0) {
    FUN_8025c1a4(0,0xf,0xf,0xf,0xf);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0);
  }
  FUN_8025c224(DAT_803dda10,7,7,7,4);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,2);
  DAT_803dd9b0 = 1;
  if (iVar1 != 0) {
    if (*(char *)(iVar1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(iVar1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(iVar1 + 0x20),*(uint **)(iVar1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  iVar1 = FUN_80017a98();
  if (iVar1 == 0) {
    dVar3 = (double)lbl_803DF77C;
  }
  else {
    dVar3 = (double)FUN_80006958((double)*(float *)(iVar1 + 0x18),(double)*(float *)(iVar1 + 0x1c),
                                 (double)*(float *)(iVar1 + 0x20));
  }
  dVar2 = -(double)(lbl_803DF748 /
                   (float)(dVar3 - (double)(float)(dVar3 - (double)lbl_803DF780)));
  local_78 = lbl_803DF74C;
  local_74 = lbl_803DF74C;
  local_70 = (float)dVar2;
  local_6c = (float)(dVar2 * (double)(float)(dVar3 - (double)lbl_803DF780));
  local_68 = lbl_803DF74C;
  local_64 = lbl_803DF74C;
  local_60 = lbl_803DF74C;
  local_5c = lbl_803DF74C;
  local_58 = lbl_803DF74C;
  local_54 = lbl_803DF74C;
  local_50 = lbl_803DF74C;
  local_4c = lbl_803DF74C;
  FUN_8025d8c4(&local_78,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c65c(DAT_803dda10,1,1);
  FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0);
  FUN_8025c5f0(DAT_803dda10,0);
  FUN_8025c224(DAT_803dda10,7,2,4,6);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,1,0,0,1,0);
  DAT_803dd9b0 = 1;
  iVar1 = newshadows_getInverseShadowRampTexture();
  if (iVar1 != 0) {
    if (*(char *)(iVar1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(iVar1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(iVar1 + 0x20),*(uint **)(iVar1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9eb = 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x02';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x02';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80048f00
 * EN v1.0 Address: 0x80048F00
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x8004D730
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80048f00(int param_1)
{
  undefined uVar1;
  undefined4 local_8;
  undefined4 local_4;
  
  uVar1 = *(undefined *)(param_1 + 0x43);
  local_4 = CONCAT13(uVar1,CONCAT12(uVar1,CONCAT11(uVar1,(undefined)local_4)));
  local_8 = local_4;
  FUN_8025c510(DAT_803dd9f4,(byte *)&local_8);
  GXSetBlendMode(DAT_803dda10,DAT_803dd9f0);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c1a4(DAT_803dda10,0,2,0xe,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dd9f4 = DAT_803dd9f4 + 1;
  DAT_803dd9f0 = DAT_803dd9f0 + 1;
  DAT_803dd9ec = DAT_803dd9ec + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80049024
 * EN v1.0 Address: 0x80049024
 * EN v1.0 Size: 572b
 * EN v1.1 Address: 0x8004D854
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80049024(void)
{
  double dVar1;
  int local_20;
  float local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  float local_8;
  
  local_1c = DAT_802c2590;
  local_18 = DAT_802c2594;
  local_14 = DAT_802c2598;
  local_10 = DAT_802c259c;
  local_c = DAT_802c25a0;
  local_8 = (float)DAT_802c25a4;
  dVar1 = newshadows_getShadowNoiseScale();
  local_1c = (float)((double)lbl_803DF75C * dVar1);
  local_8 = local_1c;
  if (DAT_803dda08 < 1) {
    FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08,DAT_803dda0c + 1);
  }
  else {
    FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08 + -1,DAT_803dda0c + 1);
  }
  FUN_8025bb48(DAT_803dd9fc,0,0);
  FUN_8025b9e8(2,&local_1c,-3);
  FUN_8025b94c(DAT_803dda10,DAT_803dd9fc,0,3,2,0,0,0,0,0);
  newshadows_getShadowNoiseTexture(&local_20);
  if (local_20 != 0) {
    if (*(char *)(local_20 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_20 + 0x20),DAT_803dda0c + 1);
    }
    else {
      FUN_8025aeac((uint *)(local_20 + 0x20),*(uint **)(local_20 + 0x40),DAT_803dda0c + 1);
    }
  }
  FUN_8025d8c4((float *)&DAT_80397480,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,8);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,1);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  newshadows_bindShadowRenderTexture(DAT_803dda0c);
  DAT_803dd9fc = DAT_803dd9fc + 1;
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 2;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  DAT_803dd9e8 = DAT_803dd9e8 + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80049260
 * EN v1.0 Address: 0x80049260
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x8004DAA4
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80049260(void)
{
  newshadows_bindShadowCaptureTexture(DAT_803dda0c);
  FUN_80258674(DAT_803dda08,0,0,0x24,0,0x7d);
  FUN_8025be80(DAT_803dda10);
  GXSetBlendMode(DAT_803dda10,6);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c1a4(DAT_803dda10,0xf,8,0xe,0);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dda04 = 0x27;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004938c
 * EN v1.0 Address: 0x8004938C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8004DBD0
 * EN v1.1 Size: 1704b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004938c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80049390
 * EN v1.0 Address: 0x80049390
 * EN v1.0 Size: 1408b
 * EN v1.1 Address: 0x8004E278
 * EN v1.1 Size: 1788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80049390(void)
{
  float *pfVar1;
  float local_210;
  float local_20c;
  int local_208;
  int local_204;
  float local_200;
  undefined4 local_1fc;
  undefined4 local_1f8;
  float local_1f4;
  undefined4 local_1f0;
  undefined4 local_1ec;
  float local_1e8;
  undefined4 local_1e4;
  undefined4 local_1e0;
  float local_1dc;
  undefined4 local_1d8;
  undefined4 local_1d4;
  float local_1d0;
  undefined4 local_1cc;
  undefined4 local_1c8;
  undefined4 local_1c4;
  undefined4 local_1c0;
  undefined4 local_1bc;
  float afStack_1b8 [12];
  float afStack_188 [12];
  float afStack_158 [12];
  float afStack_128 [12];
  float afStack_f8 [12];
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  
  local_1dc = DAT_802c2500;
  local_1d8 = DAT_802c2504;
  local_1d4 = DAT_802c2508;
  local_1e8 = DAT_802c250c;
  local_1e4 = DAT_802c2510;
  local_1e0 = DAT_802c2514;
  local_1f4 = DAT_802c2518;
  local_1f0 = DAT_802c251c;
  local_1ec = DAT_802c2520;
  local_200 = DAT_802c2524;
  local_1fc = DAT_802c2528;
  local_1f8 = DAT_802c252c;
  local_1d0 = DAT_802c2530;
  local_1cc = DAT_802c2534;
  local_1c8 = DAT_802c2538;
  local_1c4 = DAT_802c253c;
  local_1c0 = DAT_802c2540;
  local_1bc = DAT_802c2544;
  pfVar1 = (float *)FUN_8000697c();
  FUN_80247944((double)lbl_803DF748,afStack_128,&local_1dc);
  FUN_80247944((double)lbl_803DF748,afStack_158,&local_1e8);
  FUN_80247944((double)lbl_803DF748,afStack_188,&local_1f4);
  FUN_80247944((double)lbl_803DF748,afStack_1b8,&local_200);
  local_38 = lbl_803DF79C;
  local_34 = lbl_803DF74C;
  local_30 = lbl_803DF74C;
  local_2c = lbl_803DF750 * lbl_803DF7A0 * lbl_803DDA58;
  local_28 = lbl_803DF74C;
  local_24 = lbl_803DF79C;
  local_20 = lbl_803DF74C;
  local_1c = lbl_803DF74C;
  local_18 = lbl_803DF74C;
  local_14 = lbl_803DF74C;
  local_10 = lbl_803DF79C;
  local_c = lbl_803DF750 * lbl_803DF7A0 * lbl_803DDA5C;
  local_68 = lbl_803DF7A4;
  local_64 = lbl_803DF74C;
  local_60 = lbl_803DF74C;
  local_5c = lbl_803DF75C * lbl_803DF7A0 * lbl_803DDA58;
  local_58 = lbl_803DF74C;
  local_54 = lbl_803DF7A4;
  local_50 = lbl_803DF74C;
  local_4c = lbl_803DF74C;
  local_48 = lbl_803DF74C;
  local_44 = lbl_803DF74C;
  local_40 = lbl_803DF7A4;
  local_3c = lbl_803DF75C * lbl_803DF7A0 * lbl_803DDA5C;
  FUN_80247618(&local_38,pfVar1,&local_38);
  FUN_80247618(afStack_128,&local_38,&local_38);
  local_18 = lbl_803DF74C;
  local_14 = lbl_803DF74C;
  local_10 = lbl_803DF74C;
  local_c = lbl_803DF748;
  FUN_80247618(&local_68,pfVar1,&local_68);
  FUN_80247618(afStack_158,&local_68,&local_68);
  local_48 = lbl_803DF74C;
  local_44 = lbl_803DF74C;
  local_40 = lbl_803DF74C;
  local_3c = lbl_803DF748;
  FUN_8025d8c4(&local_38,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  FUN_8025d8c4(&local_68,DAT_803dda00 + 3,0);
  FUN_80258674(DAT_803dda08 + 1,0,0,0,0,DAT_803dda00 + 3);
  newshadows_getShadowTexture(&local_204);
  if (local_204 != 0) {
    if (*(char *)(local_204 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_204 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(local_204 + 0x20),*(uint **)(local_204 + 0x40),DAT_803dda0c);
    }
  }
  newshadows_getShadowNoiseScroll(&local_20c,&local_210);
  FUN_8025b9e8(2,&local_1d0,-1);
  FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08 + 2,DAT_803dda0c + 1);
  local_98 = lbl_803DF7A0;
  local_94 = lbl_803DF74C;
  local_90 = lbl_803DF74C;
  local_8c = lbl_803DF7A0 * lbl_803DDA58 + local_20c;
  local_88 = lbl_803DF74C;
  local_84 = lbl_803DF7A0;
  local_80 = lbl_803DF74C;
  local_7c = lbl_803DF74C;
  local_78 = lbl_803DF74C;
  local_74 = lbl_803DF74C;
  local_70 = lbl_803DF7A0;
  local_6c = lbl_803DF7A0 * lbl_803DDA5C;
  PSVECDotProduct((double)lbl_803DF7A8,afStack_f8,0x79);
  FUN_80247618(afStack_f8,&local_98,&local_98);
  FUN_80247618(&local_98,pfVar1,&local_98);
  FUN_80247618(afStack_188,&local_98,&local_98);
  local_78 = lbl_803DF74C;
  local_74 = lbl_803DF74C;
  local_70 = lbl_803DF74C;
  local_6c = lbl_803DF748;
  FUN_8025d8c4(&local_98,DAT_803dda00 + 6,0);
  FUN_80258674(DAT_803dda08 + 2,0,0,0,0,DAT_803dda00 + 6);
  FUN_8025b94c(DAT_803dda10,DAT_803dd9fc,0,2,2,0,0,0,0,0);
  FUN_8025bb48(DAT_803dd9fc,0,0);
  FUN_8025bd1c(DAT_803dd9fc + 1,DAT_803dda08 + 3,DAT_803dda0c + 1);
  local_c8 = lbl_803DF7A0;
  local_c4 = lbl_803DF74C;
  local_c0 = lbl_803DF74C;
  local_bc = lbl_803DF7A0 * lbl_803DDA58;
  local_b8 = lbl_803DF74C;
  local_b4 = lbl_803DF7A0;
  local_b0 = lbl_803DF74C;
  local_ac = lbl_803DF74C;
  local_a8 = lbl_803DF74C;
  local_a4 = lbl_803DF74C;
  local_a0 = lbl_803DF7A0;
  local_9c = lbl_803DF7A0 * lbl_803DDA5C + local_210;
  FUN_80247618(&local_c8,pfVar1,&local_c8);
  FUN_80247618(afStack_1b8,&local_c8,&local_c8);
  local_a8 = lbl_803DF74C;
  local_a4 = lbl_803DF74C;
  local_a0 = lbl_803DF74C;
  local_9c = lbl_803DF748;
  FUN_8025d8c4(&local_c8,DAT_803dda00 + 9,0);
  FUN_80258674(DAT_803dda08 + 3,0,0,0,0,DAT_803dda00 + 9);
  FUN_8025b94c(DAT_803dda10 + 1,DAT_803dd9fc + 1,0,2,2,0,0,1,0,0);
  FUN_8025bb48(DAT_803dd9fc + 1,0,0);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
  FUN_8025c1a4(DAT_803dda10,0xf,0xb,9,0);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c,4);
  FUN_8025c1a4(DAT_803dda10 + 1,0xf,0xb,9,0);
  FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 1,0,0);
  FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
  newshadows_getShadowNoiseTexture(&local_208);
  if (local_208 != 0) {
    if (*(char *)(local_208 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_208 + 0x20),DAT_803dda0c + 1);
    }
    else {
      FUN_8025aeac((uint *)(local_208 + 0x20),*(uint **)(local_208 + 0x40),DAT_803dda0c + 1);
    }
  }
  DAT_803dda08 = DAT_803dda08 + 4;
  DAT_803dda10 = DAT_803dda10 + 2;
  DAT_803dda0c = DAT_803dda0c + 2;
  DAT_803dda00 = DAT_803dda00 + 0xc;
  DAT_803dd9fc = DAT_803dd9fc + 2;
  DAT_803dd9ea = DAT_803dd9ea + '\x02';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x04';
  DAT_803dd9e8 = DAT_803dd9e8 + '\x02';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80049910
 * EN v1.0 Address: 0x80049910
 * EN v1.0 Size: 1488b
 * EN v1.1 Address: 0x8004E974
 * EN v1.1 Size: 1748b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80049910(undefined4 *param_1)
{
  float fVar1;
  float *pfVar2;
  undefined4 local_100;
  float local_fc;
  float local_f8;
  int local_f4;
  int local_f0;
  float local_ec;
  undefined4 local_e8;
  undefined4 local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  undefined4 local_d8;
  float afStack_d4 [12];
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  local_ec = DAT_802c24e8;
  local_e8 = DAT_802c24ec;
  local_e4 = DAT_802c24f0;
  local_e0 = DAT_802c24f4;
  local_dc = DAT_802c24f8;
  local_d8 = DAT_802c24fc;
  pfVar2 = (float *)FUN_8000697c();
  local_44 = lbl_803DF74C;
  local_40 = lbl_803DF74C;
  local_3c = lbl_803DF744 / lbl_803DD9BC;
  local_38 = lbl_803DD9B8;
  fVar1 = lbl_803DF744 / (lbl_803DD9C4 - lbl_803DD9C0);
  local_34 = fVar1 * pfVar2[4];
  local_30 = fVar1 * pfVar2[5];
  local_2c = fVar1 * pfVar2[6];
  local_28 = fVar1 * pfVar2[7] + -lbl_803DD9C4 * fVar1;
  local_24 = lbl_803DF74C;
  local_20 = lbl_803DF74C;
  local_1c = lbl_803DF74C;
  local_18 = lbl_803DF748;
  FUN_8025d8c4(&local_44,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  local_100 = *param_1;
  FUN_8025c510(DAT_803dd9f4,(byte *)&local_100);
  newshadows_getBlankShadowTexture(&local_f0);
  if (local_f0 != 0) {
    if (*(char *)(local_f0 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_f0 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(local_f0 + 0x20),*(uint **)(local_f0 + 0x40),DAT_803dda0c);
    }
  }
  if (DAT_803dd9b1 == '\0') {
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
    FUN_8025c1a4(DAT_803dda10,0,0xe,9,0xf);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    DAT_803dd9b0 = 1;
    GXSetBlendMode(DAT_803dda10,DAT_803dd9f0);
    DAT_803dda08 = DAT_803dda08 + 1;
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dda00 = DAT_803dda00 + 3;
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  }
  else {
    newshadows_getShadowNoiseScroll(&local_f8,&local_fc);
    local_fc = local_fc * lbl_803DF760;
    local_f8 = local_f8 * lbl_803DF788;
    FUN_8025b9e8(2,&local_ec,-2);
    FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08 + 1,DAT_803dda0c + 1);
    local_74 = lbl_803DD9B4;
    local_70 = lbl_803DF74C;
    local_6c = lbl_803DF74C;
    local_68 = lbl_803DDA58 * lbl_803DD9B4 + local_f8;
    local_64 = lbl_803DF74C;
    local_60 = lbl_803DD9B4;
    local_5c = lbl_803DF74C;
    local_58 = lbl_803DF74C;
    local_54 = lbl_803DF74C;
    local_50 = lbl_803DF74C;
    local_4c = lbl_803DF74C;
    local_48 = lbl_803DF748;
    PSVECDotProduct((double)lbl_803DF7A8,afStack_d4,0x7a);
    FUN_80247618(afStack_d4,&local_74,&local_74);
    FUN_80247618(&local_74,pfVar2,&local_74);
    FUN_8025d8c4(&local_74,DAT_803dda00 + 3,0);
    FUN_80258674(DAT_803dda08 + 1,0,0,0,0,DAT_803dda00 + 3);
    FUN_8025b94c(DAT_803dda10,DAT_803dd9fc,0,2,2,6,6,0,0,0);
    FUN_8025bb48(DAT_803dd9fc,0,0);
    FUN_8025bd1c(DAT_803dd9fc + 1,DAT_803dda08 + 2,DAT_803dda0c + 1);
    local_a4 = lbl_803DF74C;
    local_a0 = lbl_803DF74C;
    local_9c = lbl_803DD9B4;
    local_98 = lbl_803DDA5C * lbl_803DD9B4 + local_fc;
    local_94 = lbl_803DF74C;
    local_90 = lbl_803DD9B4;
    local_8c = lbl_803DF74C;
    local_88 = lbl_803DF74C;
    local_84 = lbl_803DF74C;
    local_80 = lbl_803DF74C;
    local_7c = lbl_803DF74C;
    local_78 = lbl_803DF748;
    PSVECDotProduct((double)lbl_803DF7AC,afStack_d4,0x78);
    FUN_80247618(afStack_d4,&local_a4,&local_a4);
    FUN_80247618(&local_a4,pfVar2,&local_a4);
    FUN_8025d8c4(&local_a4,DAT_803dda00 + 6,0);
    FUN_80258674(DAT_803dda08 + 2,0,0,0,0,DAT_803dda00 + 6);
    FUN_8025b94c(DAT_803dda10 + 1,DAT_803dd9fc + 1,0,2,2,0,0,1,0,0);
    FUN_8025bb48(DAT_803dd9fc + 1,0,0);
    FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    DAT_803dd9b0 = 1;
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08,DAT_803dda0c,0xff);
    FUN_8025c1a4(DAT_803dda10 + 1,0,0xe,9,0xf);
    FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
    FUN_8025c65c(DAT_803dda10 + 1,0,0);
    FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
    newshadows_getShadowNoiseTexture(&local_f4);
    if (local_f4 != 0) {
      if (*(char *)(local_f4 + 0x48) == '\0') {
        FUN_8025b054((uint *)(local_f4 + 0x20),DAT_803dda0c + 1);
      }
      else {
        FUN_8025aeac((uint *)(local_f4 + 0x20),*(uint **)(local_f4 + 0x40),DAT_803dda0c + 1);
      }
    }
    GXSetBlendMode(DAT_803dda10 + 1,DAT_803dd9f0);
    DAT_803dda08 = DAT_803dda08 + 3;
    DAT_803dda10 = DAT_803dda10 + 2;
    DAT_803dda0c = DAT_803dda0c + 2;
    DAT_803dda00 = DAT_803dda00 + 9;
    DAT_803dd9fc = DAT_803dd9fc + 2;
    DAT_803dd9ea = DAT_803dd9ea + '\x02';
    DAT_803dd9e9 = DAT_803dd9e9 + '\x03';
    DAT_803dd9e8 = DAT_803dd9e8 + '\x02';
  }
  DAT_803dd9f4 = DAT_803dd9f4 + 1;
  DAT_803dd9f0 = DAT_803dd9f0 + 1;
  DAT_803dd9ec = DAT_803dd9ec + 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80049ee0
 * EN v1.0 Address: 0x80049EE0
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x8004F048
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80049ee0(void)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,4);
  FUN_8025c1a4(DAT_803dda10,0,0xf,0xb,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80049fb0
 * EN v1.0 Address: 0x80049FB0
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x8004F118
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80049fb0(undefined4 *param_1)
{
  undefined4 local_8 [2];
  
  local_8[0] = *param_1;
  FUN_8025c428(2,(byte *)local_8);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
  FUN_8025c1a4(DAT_803dda10,0xf,0,4,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004a094
 * EN v1.0 Address: 0x8004A094
 * EN v1.0 Size: 560b
 * EN v1.1 Address: 0x8004F1FC
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004a094(void)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
  FUN_8025c1a4(DAT_803dda10,0xf,0,4,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  FUN_8025be80(DAT_803dda10 + 1);
  FUN_8025c828(DAT_803dda10 + 1,0xff,0xff,0xff);
  FUN_8025c1a4(DAT_803dda10 + 1,4,0xf,0xf,0);
  FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 1,0,0);
  FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8025be80(DAT_803dda10 + 2);
  FUN_8025c828(DAT_803dda10 + 2,0xff,0xff,4);
  FUN_8025c1a4(DAT_803dda10 + 2,0,6,0xb,0xf);
  FUN_8025c224(DAT_803dda10 + 2,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 2,0,0);
  FUN_8025c2a8(DAT_803dda10 + 2,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10 + 2,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 3;
  DAT_803dd9ea = DAT_803dd9ea + '\x03';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004a2c4
 * EN v1.0 Address: 0x8004A2C4
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x8004F42C
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004a2c4(void)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
  FUN_8025c1a4(DAT_803dda10,0xf,0,4,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004a394
 * EN v1.0 Address: 0x8004A394
 * EN v1.0 Size: 732b
 * EN v1.1 Address: 0x8004F4FC
 * EN v1.1 Size: 856b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004a394(double param_1,undefined4 *param_2,float *param_3)
{
  double dVar1;
  double dVar2;
  undefined4 local_78;
  int local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  if (((DAT_803dd9f4 < 4) && (DAT_803dd9ea < 0xc)) && (DAT_803dd9e9 < 7)) {
    dVar1 = (double)lbl_803DF75C;
    local_6c = (float)(dVar1 / param_1);
    dVar2 = (double)local_6c;
    local_3c = lbl_803DF74C;
    local_38 = lbl_803DF74C;
    local_34 = (float)(-(double)*param_3 * dVar2 + dVar1);
    local_30 = lbl_803DF74C;
    local_2c = lbl_803DF74C;
    local_24 = (float)(-(double)param_3[2] * dVar2 + dVar1);
    local_20 = lbl_803DF74C;
    local_1c = lbl_803DF74C;
    local_18 = lbl_803DF74C;
    local_14 = lbl_803DF748;
    local_70 = lbl_803DF74C;
    local_68 = lbl_803DF74C;
    local_64 = (float)(-(double)param_3[1] * dVar2 + dVar1);
    local_60 = lbl_803DF74C;
    local_5c = lbl_803DF74C;
    local_58 = lbl_803DF74C;
    local_54 = lbl_803DF75C;
    local_50 = lbl_803DF74C;
    local_4c = lbl_803DF74C;
    local_48 = lbl_803DF74C;
    local_44 = lbl_803DF748;
    local_40 = local_6c;
    local_28 = local_6c;
    newshadows_getSoftShadowTexture(&local_74);
    FUN_8025d8c4(&local_40,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
    FUN_8025d8c4(&local_70,DAT_803dda00 + 3,0);
    FUN_80258674(DAT_803dda08 + 1,0,0,0,0,DAT_803dda00 + 3);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
    local_78 = *param_2;
    FUN_8025c510(DAT_803dd9f4,(byte *)&local_78);
    GXSetBlendMode(DAT_803dda10,DAT_803dd9f0);
    FUN_8025c1a4(DAT_803dda10,0xf,0xe,8,0xf);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,1);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    FUN_8025be80(DAT_803dda10 + 1);
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c,0xff);
    FUN_8025c1a4(DAT_803dda10 + 1,0xf,2,8,4);
    FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
    FUN_8025c65c(DAT_803dda10 + 1,0,0);
    FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,2);
    FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
    if (local_74 != 0) {
      if (*(char *)(local_74 + 0x48) == '\0') {
        FUN_8025b054((uint *)(local_74 + 0x20),DAT_803dda0c);
      }
      else {
        FUN_8025aeac((uint *)(local_74 + 0x20),*(uint **)(local_74 + 0x40),DAT_803dda0c);
      }
    }
    DAT_803dda10 = DAT_803dda10 + 2;
    DAT_803dda08 = DAT_803dda08 + 2;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9f4 = DAT_803dd9f4 + 1;
    DAT_803dd9f0 = DAT_803dd9f0 + 1;
    DAT_803dd9ec = DAT_803dd9ec + 1;
    DAT_803dda00 = DAT_803dda00 + 6;
    DAT_803dd9e9 = DAT_803dd9e9 + 2;
    DAT_803dd9ea = DAT_803dd9ea + 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004a670
 * EN v1.0 Address: 0x8004A670
 * EN v1.0 Size: 732b
 * EN v1.1 Address: 0x8004F854
 * EN v1.1 Size: 856b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004a670(double param_1,undefined4 *param_2,float *param_3)
{
  double dVar1;
  double dVar2;
  undefined4 local_78;
  int local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  if (((DAT_803dd9f4 < 4) && (DAT_803dd9ea < 0xc)) && (DAT_803dd9e9 < 7)) {
    dVar1 = (double)lbl_803DF75C;
    local_6c = (float)(dVar1 / param_1);
    dVar2 = (double)local_6c;
    local_3c = lbl_803DF74C;
    local_38 = lbl_803DF74C;
    local_34 = (float)(-(double)*param_3 * dVar2 + dVar1);
    local_30 = lbl_803DF74C;
    local_2c = lbl_803DF74C;
    local_24 = (float)(-(double)param_3[2] * dVar2 + dVar1);
    local_20 = lbl_803DF74C;
    local_1c = lbl_803DF74C;
    local_18 = lbl_803DF74C;
    local_14 = lbl_803DF748;
    local_70 = lbl_803DF74C;
    local_68 = lbl_803DF74C;
    local_64 = (float)(-(double)param_3[1] * dVar2 + dVar1);
    local_60 = lbl_803DF74C;
    local_5c = lbl_803DF74C;
    local_58 = lbl_803DF74C;
    local_54 = lbl_803DF75C;
    local_50 = lbl_803DF74C;
    local_4c = lbl_803DF74C;
    local_48 = lbl_803DF74C;
    local_44 = lbl_803DF748;
    local_40 = local_6c;
    local_28 = local_6c;
    newshadows_getSoftShadowTexture(&local_74);
    FUN_8025d8c4(&local_40,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
    FUN_8025d8c4(&local_70,DAT_803dda00 + 3,0);
    FUN_80258674(DAT_803dda08 + 1,0,0,0,0,DAT_803dda00 + 3);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
    local_78 = *param_2;
    FUN_8025c510(DAT_803dd9f4,(byte *)&local_78);
    GXSetBlendMode(DAT_803dda10,DAT_803dd9f0);
    FUN_8025c1a4(DAT_803dda10,0xf,0xe,8,0xf);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,1);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    FUN_8025be80(DAT_803dda10 + 1);
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c,0xff);
    FUN_8025c1a4(DAT_803dda10 + 1,0xf,2,8,0xf);
    FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
    FUN_8025c65c(DAT_803dda10 + 1,0,0);
    FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,2);
    FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
    if (local_74 != 0) {
      if (*(char *)(local_74 + 0x48) == '\0') {
        FUN_8025b054((uint *)(local_74 + 0x20),DAT_803dda0c);
      }
      else {
        FUN_8025aeac((uint *)(local_74 + 0x20),*(uint **)(local_74 + 0x40),DAT_803dda0c);
      }
    }
    DAT_803dda10 = DAT_803dda10 + 2;
    DAT_803dda08 = DAT_803dda08 + 2;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9f4 = DAT_803dd9f4 + 1;
    DAT_803dd9f0 = DAT_803dd9f0 + 1;
    DAT_803dd9ec = DAT_803dd9ec + 1;
    DAT_803dda00 = DAT_803dda00 + 6;
    DAT_803dd9e9 = DAT_803dd9e9 + 2;
    DAT_803dd9ea = DAT_803dd9ea + 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004a94c
 * EN v1.0 Address: 0x8004A94C
 * EN v1.0 Size: 756b
 * EN v1.1 Address: 0x8004FBAC
 * EN v1.1 Size: 880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004a94c(double param_1,undefined4 *param_2,float *param_3)
{
  double dVar1;
  double dVar2;
  undefined4 local_78;
  int local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  if (((DAT_803dd9f4 < 4) && (DAT_803dd9ea < 0x10)) && (DAT_803dd9e9 < 7)) {
    if (param_1 < (double)lbl_803DF764) {
      param_1 = (double)lbl_803DF764;
    }
    dVar1 = (double)lbl_803DF75C;
    local_6c = (float)(dVar1 / param_1);
    dVar2 = (double)local_6c;
    local_3c = lbl_803DF74C;
    local_38 = lbl_803DF74C;
    local_34 = (float)(-(double)*param_3 * dVar2 + dVar1);
    local_30 = lbl_803DF74C;
    local_2c = lbl_803DF74C;
    local_24 = (float)(-(double)param_3[2] * dVar2 + dVar1);
    local_20 = lbl_803DF74C;
    local_1c = lbl_803DF74C;
    local_18 = lbl_803DF74C;
    local_14 = lbl_803DF748;
    local_70 = lbl_803DF74C;
    local_68 = lbl_803DF74C;
    local_64 = (float)(-(double)param_3[1] * dVar2 + dVar1);
    local_60 = lbl_803DF74C;
    local_5c = lbl_803DF74C;
    local_58 = lbl_803DF74C;
    local_54 = lbl_803DF75C;
    local_50 = lbl_803DF74C;
    local_4c = lbl_803DF74C;
    local_48 = lbl_803DF74C;
    local_44 = lbl_803DF748;
    local_40 = local_6c;
    local_28 = local_6c;
    newshadows_getSoftShadowTexture(&local_74);
    FUN_8025d8c4(&local_40,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
    FUN_8025d8c4(&local_70,DAT_803dda00 + 3,0);
    FUN_80258674(DAT_803dda08 + 1,0,0,0,0,DAT_803dda00 + 3);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
    local_78 = *param_2;
    FUN_8025c510(DAT_803dd9f4,(byte *)&local_78);
    GXSetBlendMode(DAT_803dda10,DAT_803dd9f0);
    FUN_8025c1a4(DAT_803dda10,0xf,0xe,8,0xf);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,1);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    FUN_8025be80(DAT_803dda10 + 1);
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c,0xff);
    FUN_8025c1a4(DAT_803dda10 + 1,0xf,2,8,0);
    FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
    FUN_8025c65c(DAT_803dda10 + 1,0,0);
    FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
    DAT_803dd9b0 = 1;
    if (local_74 != 0) {
      if (*(char *)(local_74 + 0x48) == '\0') {
        FUN_8025b054((uint *)(local_74 + 0x20),DAT_803dda0c);
      }
      else {
        FUN_8025aeac((uint *)(local_74 + 0x20),*(uint **)(local_74 + 0x40),DAT_803dda0c);
      }
    }
    DAT_803dda10 = DAT_803dda10 + 2;
    DAT_803dda08 = DAT_803dda08 + 2;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9f4 = DAT_803dd9f4 + 1;
    DAT_803dd9f0 = DAT_803dd9f0 + 1;
    DAT_803dd9ec = DAT_803dd9ec + 1;
    DAT_803dda00 = DAT_803dda00 + 6;
    DAT_803dd9e9 = DAT_803dd9e9 + 2;
    DAT_803dd9ea = DAT_803dd9ea + 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004ac40
 * EN v1.0 Address: 0x8004AC40
 * EN v1.0 Size: 388b
 * EN v1.1 Address: 0x8004FF1C
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004ac40(int param_1,float *param_2)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025d8c4(param_2,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  GXSetBlendMode(DAT_803dda10,4);
  FUN_8025c1a4(DAT_803dda10,0xe,9,0,0);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,1,1,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004adc4
 * EN v1.0 Address: 0x8004ADC4
 * EN v1.0 Size: 508b
 * EN v1.1 Address: 0x8005009C
 * EN v1.1 Size: 508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004adc4(int param_1)
{
  if (param_1 != 0) {
    FUN_80258674(DAT_803dda08,1,1,0x1e,0,0x7d);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
    FUN_8025c1a4(DAT_803dda10,0xf,10,0xb,8);
    FUN_8025c224(DAT_803dda10,7,7,7,7);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    DAT_803dd9b0 = 1;
    if (param_1 != 0) {
      if (*(char *)(param_1 + 0x48) == '\0') {
        FUN_8025b054((uint *)(param_1 + 0x20),DAT_803dda0c);
      }
      else {
        FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),DAT_803dda0c);
      }
    }
    DAT_803dda08 = DAT_803dda08 + 1;
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,0xff,0xff,5);
    FUN_8025c1a4(DAT_803dda10,0xf,10,0xb,0);
    FUN_8025c224(DAT_803dda10,7,7,7,7);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004afc0
 * EN v1.0 Address: 0x8004AFC0
 * EN v1.0 Size: 1116b
 * EN v1.1 Address: 0x80050298
 * EN v1.1 Size: 1084b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004afc0(float *param_1)
{
  float *pfVar1;
  float fVar2;
  int local_48;
  float afStack_44 [16];
  
  FUN_8025be80(DAT_803dda10);
  FUN_8025be80(DAT_803dda10 + 1);
  FUN_8025be80(DAT_803dda10 + 2);
  FUN_8025be80(DAT_803dda10 + 3);
  pfVar1 = (float *)FUN_8000697c();
  FUN_80247618(param_1 + 0xc,pfVar1,afStack_44);
  FUN_8025d8c4(afStack_44,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0x3c,0,DAT_803dda00);
  pfVar1 = (float *)FUN_8000697c();
  FUN_80247618(param_1,pfVar1,afStack_44);
  FUN_8025d8c4(afStack_44,DAT_803dda00 + 3,0);
  FUN_80258674(DAT_803dda08 + 1,0,0,0x3c,0,DAT_803dda00 + 3);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c + 1,0xff);
  FUN_8025c828(DAT_803dda10 + 2,DAT_803dda08 + 1,DAT_803dda0c + 1,0xff);
  FUN_8025c828(DAT_803dda10 + 3,DAT_803dda08 + 1,DAT_803dda0c + 1,0xff);
  GXSetBlendMode(DAT_803dda10 + 2,6);
  FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,8);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,1);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  FUN_8025c1a4(DAT_803dda10 + 1,2,8,0xc,0xf);
  FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 1,0,0);
  FUN_8025c2a8(DAT_803dda10 + 1,8,0,0,1,1);
  FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8025c1a4(DAT_803dda10 + 2,4,0xe,2,0xf);
  FUN_8025c224(DAT_803dda10 + 2,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 2,0,0);
  FUN_8025c2a8(DAT_803dda10 + 2,0,0,0,1,2);
  FUN_8025c368(DAT_803dda10 + 2,0,0,0,1,0);
  FUN_8025c1a4(DAT_803dda10 + 3,6,0xf,2,0xf);
  FUN_8025c224(DAT_803dda10 + 3,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 3,0,0);
  FUN_8025c2a8(DAT_803dda10 + 3,0,0,0,1,3);
  FUN_8025c368(DAT_803dda10 + 3,0,0,0,1,0);
  newshadows_getShadowRampTexture(&local_48);
  if (local_48 != 0) {
    if (*(char *)(local_48 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_48 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(local_48 + 0x20),*(uint **)(local_48 + 0x40),DAT_803dda0c);
    }
  }
  fVar2 = param_1[0x18];
  if (fVar2 != 0.0) {
    if (*(char *)((int)fVar2 + 0x48) == '\0') {
      FUN_8025b054((uint *)((int)fVar2 + 0x20),DAT_803dda0c + 1);
    }
    else {
      FUN_8025aeac((uint *)((int)fVar2 + 0x20),*(uint **)((int)fVar2 + 0x40),DAT_803dda0c + 1);
    }
  }
  DAT_803dda00 = DAT_803dda00 + 6;
  DAT_803dda08 = DAT_803dda08 + 2;
  DAT_803dda0c = DAT_803dda0c + 2;
  DAT_803dd9e9 = DAT_803dd9e9 + '\x02';
  DAT_803dd9ea = DAT_803dd9ea + '\x04';
  DAT_803dda10 = DAT_803dda10 + 4;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004b41c
 * EN v1.0 Address: 0x8004B41C
 * EN v1.0 Size: 1200b
 * EN v1.1 Address: 0x800506D4
 * EN v1.1 Size: 1232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004b41c(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)
{
  int iVar1;
  uint uVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  FUN_8025be80(DAT_803dda10);
  FUN_8025d8c4((float *)uVar3,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  if ((param_5 == 0) || (param_5 == 2)) {
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
  }
  else {
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,5);
  }
  if (DAT_803dda10 == 0) {
    uVar2 = 0xc;
  }
  else {
    uVar2 = 4;
  }
  if (param_3 == 0) {
    if (param_4 == 2) {
      FUN_8025c1a4(DAT_803dda10,0xf,uVar2,8,0xf);
    }
    else if (param_4 == 3) {
      FUN_8025c1a4(DAT_803dda10,uVar2,0xf,8,0xf);
    }
    else if (param_4 == 1) {
      FUN_8025c1a4(DAT_803dda10,0xf,0xf,8,uVar2);
    }
    else if ((param_5 == 0) || (param_5 == 1)) {
      FUN_8025c1a4(DAT_803dda10,0xf,10,8,uVar2);
    }
    else {
      FUN_8025c1a4(DAT_803dda10,0xf,0xb,8,uVar2);
    }
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c224(DAT_803dda10,7,7,7,7);
    if (param_4 == 1) {
      FUN_8025c2a8(DAT_803dda10,1,0,0,1,2);
      FUN_8025c368(DAT_803dda10,1,0,0,1,2);
    }
    else {
      FUN_8025c2a8(DAT_803dda10,0,0,0,1,2);
      FUN_8025c368(DAT_803dda10,0,0,0,1,2);
    }
  }
  else if (param_3 == 1) {
    if (param_4 == 2) {
      FUN_8025c1a4(DAT_803dda10,0xf,6,8,0xf);
    }
    else if (param_4 == 3) {
      FUN_8025c1a4(DAT_803dda10,6,0xf,8,0xf);
    }
    else if (param_4 == 1) {
      FUN_8025c1a4(DAT_803dda10,0xf,0xf,8,6);
    }
    else if ((param_5 == 0) || (param_5 == 1)) {
      FUN_8025c1a4(DAT_803dda10,0xf,10,8,6);
    }
    else {
      FUN_8025c1a4(DAT_803dda10,0xf,0xb,8,6);
    }
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c224(DAT_803dda10,7,7,7,7);
    if (param_4 == 1) {
      FUN_8025c2a8(DAT_803dda10,1,0,0,1,3);
      FUN_8025c368(DAT_803dda10,1,0,0,1,3);
    }
    else {
      FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
      FUN_8025c368(DAT_803dda10,0,0,0,1,3);
    }
  }
  else {
    DAT_803dd9eb = 1;
    DAT_803dd9b0 = 1;
    FUN_8025c6b4(1,0,0,0,1);
    FUN_8025c65c(DAT_803dda10,1,1);
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0xc);
    if (param_4 == 3) {
      FUN_8025c224(DAT_803dda10,7,5,4,6);
      FUN_8025c368(DAT_803dda10,1,0,0,1,0);
    }
    else {
      FUN_8025c224(DAT_803dda10,7,5,4,7);
      FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    }
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  }
  if (iVar1 != 0) {
    if (*(char *)(iVar1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(iVar1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(iVar1 + 0x20),*(uint **)(iVar1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004b8cc
 * EN v1.0 Address: 0x8004B8CC
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x80050BA4
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004b8cc(uint param_1)
{
  float afStack_48 [11];
  float local_1c;
  undefined4 local_18;
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;
  
  uStack_14 = param_1 ^ 0x80000000;
  local_18 = 0x43300000;
  local_10 = 0x43300000;
  uStack_c = uStack_14;
  FUN_80247a7c((double)(f32)(s32)uStack_14,
               (double)(f32)(s32)uStack_14,
               (double)lbl_803DF74C,afStack_48);
  local_1c = lbl_803DF748;
  FUN_8025d8c4(afStack_48,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,1,4,0x3c,0,DAT_803dda00);
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004b960
 * EN v1.0 Address: 0x8004B960
 * EN v1.0 Size: 776b
 * EN v1.1 Address: 0x80050C54
 * EN v1.1 Size: 848b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004b960(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4)
{
  int iVar1;
  uint uVar2;
  double dVar3;
  undefined8 uVar4;
  float local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  float afStack_58 [11];
  float local_2c;
  undefined4 local_28;
  uint uStack_24;
  
  uVar4 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  local_70 = DAT_802c24d0;
  local_6c = DAT_802c24d4;
  local_68 = DAT_802c24d8;
  local_64 = DAT_802c24dc;
  local_60 = DAT_802c24e0;
  local_5c = DAT_802c24e4;
  if ((DAT_803dc248 & 1) != 0) {
    FUN_8025b9e8(1,&local_70,'\0');
    FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08 + (int)uVar4,DAT_803dda0c);
    if (param_4 != 0) {
      uVar2 = FUN_80053078(param_4);
      uVar2 = (uint)*(ushort *)(uVar2 + 10) /
              ((uint)*(ushort *)(iVar1 + 10) * ((param_3 & 0xf) * 4 + 1));
      if (uVar2 != 0) {
        FUN_8025bb48(DAT_803dd9fc,*(uint *)(&DAT_8030da9c + uVar2 * 4),
                     *(uint *)(&DAT_8030da9c + uVar2 * 4));
      }
    }
    uStack_24 = (int)(param_3 & 0xf0) >> 4 ^ 0x80000000;
    local_28 = 0x43300000;
    dVar3 = (double)(lbl_803DF75C *
                    lbl_803DF7B8 *
                    ((f32)(s32)uStack_24 /
                     lbl_803DF7BC - lbl_803DF748));
    FUN_80247a7c(dVar3,dVar3,(double)lbl_803DF74C,afStack_58);
    local_2c = lbl_803DF748;
    FUN_8025d8c4(afStack_58,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,1,2,0x1e,0,DAT_803dda00);
    FUN_80258674(DAT_803dda08 + 1,1,3,0x1e,0,DAT_803dda00);
    FUN_8025b94c(DAT_803dda10,DAT_803dd9fc,0,3,5,6,6,0,0,0);
    FUN_8025b94c(DAT_803dda10 + 1,DAT_803dd9fc,0,3,9,6,6,1,0,0);
    FUN_8025b94c(DAT_803dda10 + 2,DAT_803dd9fc,0,0,0,0,0,1,0,0);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c + 1 | 0x100,0xff);
    FUN_8025c000(DAT_803dda10,4);
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c + 1 | 0x100,0xff);
    FUN_8025c000(DAT_803dda10 + 1,4);
    if (iVar1 != 0) {
      if (*(char *)(iVar1 + 0x48) == '\0') {
        FUN_8025b054((uint *)(iVar1 + 0x20),DAT_803dda0c);
      }
      else {
        FUN_8025aeac((uint *)(iVar1 + 0x20),*(uint **)(iVar1 + 0x40),DAT_803dda0c);
      }
    }
    DAT_803dda00 = DAT_803dda00 + 3;
    DAT_803dd9fc = DAT_803dd9fc + 1;
    DAT_803dda08 = DAT_803dda08 + 2;
    DAT_803dda10 = DAT_803dda10 + 2;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9ea = DAT_803dd9ea + '\x02';
    DAT_803dd9e8 = DAT_803dd9e8 + '\x01';
    DAT_803dd9e9 = DAT_803dd9e9 + '\x02';
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004bc68
 * EN v1.0 Address: 0x8004BC68
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x80050FA4
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004bc68(char param_1)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  if (param_1 == '\0') {
    FUN_8025c1a4(DAT_803dda10,0xf,0,10,6);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,0,4,6);
  }
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004bd68
 * EN v1.0 Address: 0x8004BD68
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x800510A8
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004bd68(void)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c1a4(DAT_803dda10,0xf,6,8,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,7);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004be30
 * EN v1.0 Address: 0x8004BE30
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x80051170
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004be30(char param_1)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  if (param_1 == '\0') {
    FUN_8025c1a4(DAT_803dda10,0xf,1,10,6);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,1,4,6);
  }
  FUN_8025c224(DAT_803dda10,7,7,7,7);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004bf28
 * EN v1.0 Address: 0x8004BF28
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x8005126C
 * EN v1.1 Size: 600b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004bf28(int param_1,char param_2,uint param_3)
{
  float afStack_78 [12];
  float afStack_48 [15];
  
  if (DAT_803dd9e8 == '\0') {
    FUN_8025be80(DAT_803dda10);
  }
  if (param_2 == '\0') {
    FUN_80247a7c((double)lbl_803DF7C0,(double)lbl_803DF7C0,(double)lbl_803DF74C,afStack_78);
    FUN_80247a48((double)lbl_803DF75C,(double)lbl_803DF75C,(double)lbl_803DF748,afStack_48);
    FUN_80247618(afStack_48,afStack_78,afStack_78);
    FUN_8025d8c4(afStack_78,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,1,1,0x1e,0,DAT_803dda00);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
    DAT_803dda00 = DAT_803dda00 + 3;
    DAT_803dda08 = DAT_803dda08 + 1;
    DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  }
  else {
    FUN_8025bec8(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08 + -1,DAT_803dda0c,0xff);
  }
  FUN_8025c224(DAT_803dda10,7,4,3,7);
  if (param_2 == '\0') {
    FUN_8025c1a4(DAT_803dda10,0xf,8,10,0xf);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,8,4,0xf);
  }
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
  if ((param_3 & 1) == 0) {
    FUN_8025c6b4(3,0,0,0,1);
  }
  else {
    FUN_8025c6b4(3,2,2,2,1);
  }
  FUN_8025c65c(DAT_803dda10,0,3);
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004c174
 * EN v1.0 Address: 0x8004C174
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800514C4
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004c174(int param_1,char param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8004c178
 * EN v1.0 Address: 0x8004C178
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800516A4
 * EN v1.1 Size: 832b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004c178(int param_1,float *param_2)
{
}

/* sda21 accessors. */
extern u8 lbl_803DCD28;
u8 isHeavyFogEnabled(void) { return lbl_803DCD28; }

/* lbl = N (byte) */
void disableHeavyFog(void) { lbl_803DCD28 = 0x0; }

/* *p1 = lbl1; *p2 = lbl2; (f32) */
extern f32 lbl_803DCD44;
extern f32 lbl_803DCD40;
void fn_8004C234(f32 *p1, f32 *p2) { *p1 = lbl_803DCD44; *p2 = lbl_803DCD40; }

extern u32 lbl_803DB5EC;
extern f32 lbl_803DB5F0;
extern f32 lbl_803DEAC8;
#pragma scheduling off
#pragma peephole off
void fn_8004C1E4(u8 b, f32 scale) {
    ((u8*)&lbl_803DB5EC)[3] = b;
    lbl_803DB5F0 = scale;
    if (scale > lbl_803DEAC8) {
        lbl_803DB5F0 = lbl_803DEAC8;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void *fn_8004B118(int *p) {
    void **arr;
    int idx = *(s16*)((char*)p + 0x2c);
    if (idx < *(s16*)((char*)p + 0x2a)) {
        arr = *(void***)((char*)p + 8);
        (*(s16*)((char*)p + 0x2c))++;
        return arr[idx];
    }
    return NULL;
}

int fn_8004B148(int *p) {
    int node;
    u32 cur;
    u32 prev;
    int i;
    int count;
    int *entry;

    prev = p[7];
    node = *p + prev * 0x10;
    *(u8 *)(node + 0xd) = 0xff;
    while ((cur = *(u8 *)(node + 0xc)) != 0xff) {
        node = *p + cur * 0x10;
        *(u8 *)(node + 0xd) = (u8)prev;
        prev = cur;
    }
    if (*(u8 *)(node + 0xd) == 0xff) {
        entry = NULL;
    } else {
        entry = (int *)(*p + (u32)*(u8 *)(node + 0xd) * 0x10);
    }
    count = 0;
    i = 0;
    while (entry != NULL) {
        *(int *)(p[2] + i) = *entry;
        i += 4;
        count++;
        if (count >= 100) {
            entry = NULL;
        } else if (*(u8 *)((int)entry + 0xd) == 0xff) {
            entry = NULL;
        } else {
            entry = (int *)(*p + (u32)*(u8 *)((int)entry + 0xd) * 0x10);
        }
    }
    *(s16 *)((int)p + 0x2a) = (s16)count;
    *(u16 *)(p + 0xb) = 0;
    return count;
}

extern f32 vec3f_distanceSquared(f32 *a, f32 *b);
int fn_8004B31C(int *param_1, int param_2, int param_3, int param_4, u8 param_5) {
    int i = 0;
    int o4;
    int o8;
    int n;
    int *node;
    u32 *heap;
    short s;
    u32 pri;
    u16 idx;
    int parent;

    *(s16 *)((char *)param_1 + 0x22) = 0;
    *(s16 *)((char *)param_1 + 0x20) = 0;
    o4 = 0;
    o8 = 0;
    for (i = 0; i < 0xf8; i += 8) {
        *(int *)(param_1[1] + o4) = 0;
        *(u8 *)(*param_1 + o8 + 0xe) = 0;
        *(int *)(param_1[1] + o4 + 8) = 0;
        *(u8 *)(*param_1 + o8 + 0x1e) = 0;
        *(int *)(param_1[1] + o4 + 0x10) = 0;
        *(u8 *)(*param_1 + o8 + 0x2e) = 0;
        *(int *)(param_1[1] + o4 + 0x18) = 0;
        *(u8 *)(*param_1 + o8 + 0x3e) = 0;
        *(int *)(param_1[1] + o4 + 0x20) = 0;
        *(u8 *)(*param_1 + o8 + 0x4e) = 0;
        *(int *)(param_1[1] + o4 + 0x28) = 0;
        *(u8 *)(*param_1 + o8 + 0x5e) = 0;
        *(int *)(param_1[1] + o4 + 0x30) = 0;
        *(u8 *)(*param_1 + o8 + 0x6e) = 0;
        *(int *)(param_1[1] + o4 + 0x38) = 0;
        *(u8 *)(*param_1 + o8 + 0x7e) = 0;
        o4 += 0x40;
        o8 += 0x80;
    }
    o4 = i * 8;
    o8 = i * 0x10;
    n = 0xfe - i;
    if (i < 0xfe) {
        do {
            *(int *)(param_1[1] + o4) = 0;
            *(u8 *)(*param_1 + o8 + 0xe) = 0;
            o4 += 8;
            o8 += 0x10;
            n += -1;
        } while (n != 0);
    }
    param_1[6] = param_2;
    param_1[3] = param_3;
    param_1[4] = param_4;
    *(u8 *)((char *)param_1 + 0x28) = param_5 & 1;
    param_1[9] = 10000;
    s = *(s16 *)((char *)param_1 + 0x20);
    if (s == 0xfe) {
        node = NULL;
    } else {
        *(s16 *)((char *)param_1 + 0x20) = s + 1;
        node = (int *)(*param_1 + s * 0x10);
        *node = param_2;
        node[2] = 0;
        *(u8 *)(node + 3) = 0xff;
        node[1] = (u32)vec3f_distanceSquared((f32 *)(*node + 8), (f32 *)param_1[3]);
    }
    i = node[1] + node[2];
    heap = (u32 *)param_1[1];
    s = *(s16 *)((char *)param_1 + 0x22) + 1;
    *(s16 *)((char *)param_1 + 0x22) = s;
    *(u16 *)(heap + s * 2 + 1) = *(s16 *)((char *)param_1 + 0x20) - 1;
    heap[*(s16 *)((char *)param_1 + 0x22) * 2] = -1 - i;
    i = *(s16 *)((char *)param_1 + 0x22);
    pri = heap[i * 2];
    idx = *(u16 *)(heap + i * 2 + 1);
    *heap = 0xffffffff;
    while (parent = i >> 1, heap[parent * 2] < pri) {
        *(u16 *)(heap + i * 2 + 1) = *(u16 *)(heap + parent * 2 + 1);
        heap[i * 2] = heap[parent * 2];
        i = parent;
    }
    heap[i * 2] = pri;
    *(u16 *)(heap + i * 2 + 1) = idx;
    return 0;
}

extern char sDirBlockTag;
extern u32 lbl_8035F3E8[];
extern void *memcpy(void *dst, const void *src, u32 n);
extern int strncmp(const char *a, const char *b, u32 n);
void texPreGetMipmap(u32 param_1, int param_2, int *param_3, int *param_4, int param_5, u8 *param_6, int param_7) {
    u32 base = lbl_8035F3E8[0x4f];
    if (base != 0) {
        if (param_7 == 1 && param_6 != 0) {
            int e = base + (param_1 & 0xffffff) * 2 + *(int *)(param_6 + param_5 * 4) + 4;
            int v = *(int *)(e + 8);
            *param_3 = *(int *)(e + 4);
            *param_4 = v;
        } else if (param_7 == 2 && param_6 != 0) {
            memcpy(param_6, (void *)(base + (param_1 & 0xffffff) * 2), (param_5 + 1) * 4);
        } else {
            int e = base + (param_1 & 0xffffff) * 2;
            int v = *(int *)(e + 0xc);
            *param_3 = *(int *)(e + 8);
            if (strncmp(&sDirBlockTag, (char *)e, 3) == 0) {
                *param_4 = 0xffffffff;
            } else {
                *param_4 = v;
            }
        }
    }
}

extern int OSDisableInterrupts(void);
extern void OSRestoreInterrupts(int s);
extern int lbl_803DCC80;
void tex0GetFrame(int param_1, int param_2, int *param_3, int *param_4, int param_5, u8 *param_6, int param_7) {
    int idx = -1;
    if (lbl_8035F3E8[0x23] != 0 || lbl_8035F3E8[0x4d] != 0) {
        int s = OSDisableInterrupts();
        int flags = lbl_803DCC80;
        u32 f478;
        u32 f520;
        OSRestoreInterrupts(s);
        f478 = lbl_8035F3E8[0x24];
        f520 = lbl_8035F3E8[0x4e];
        if ((param_1 & 0x80000000) != 0 && (flags & 0x200) == 0) {
            idx = 0x4d;
        } else if ((param_1 & 0x40000000) != 0 && (flags & 0x100) == 0) {
            idx = 0x23;
        } else if (f478 != 0 && (flags & 0x100) == 0) {
            idx = 0x23;
        } else if (f520 != 0 && (flags & 0x200) == 0) {
            idx = 0x4d;
        }
        if (param_7 == 1 && param_6 != 0) {
            int base = lbl_8035F3E8[idx];
            int e = base + (param_1 & 0xffffff) * 2 + *(int *)(param_6 + param_5 * 4) + 4;
            int v = *(int *)(e + 8);
            *param_3 = *(int *)(e + 4);
            *param_4 = v;
        } else if (param_7 == 2 && param_6 != 0) {
            memcpy(param_6, (void *)(lbl_8035F3E8[idx] + (param_1 & 0xffffff) * 2), (param_5 + 1) * 4);
        } else {
            int e = lbl_8035F3E8[idx] + (param_1 & 0xffffff) * 2 + 4;
            int v = *(int *)(e + 8);
            *param_3 = *(int *)(e + 4);
            *param_4 = v;
        }
    }
}

extern char *sResourceFileNameTable[];
extern void *mmAlloc(int size, int align, int zone);
extern void mm_free(void *p);
extern int DVDOpen(char *fileName, void *fileInfo);
extern int DVDRead(void *fileInfo, void *addr, int length, int offset);
extern int DVDClose(void *fileInfo);
extern void DCStoreRange(void *p, u32 n);
void tex1GetFrame(u32 param_1, int param_2, int *param_3, int *param_4, int param_5, u8 *param_6, int param_7) {
    int idx = -1;
    if (lbl_8035F3E8[0x20] != 0 || lbl_8035F3E8[0x4b] != 0) {
        int s = OSDisableInterrupts();
        int flags = lbl_803DCC80;
        u32 f46c;
        u32 f518;
        OSRestoreInterrupts(s);
        f46c = lbl_8035F3E8[0x21];
        f518 = lbl_8035F3E8[0x4c];
        if ((param_1 & 0x80000000) != 0 && (flags & 0x2000) == 0) {
            idx = 0x4b;
        } else if ((param_1 & 0x40000000) != 0 && (flags & 0x1000) == 0) {
            idx = 0x20;
        } else if (f46c != 0 && (flags & 0x1000) == 0 && lbl_8035F3E8[0x20] != 0) {
            idx = 0x20;
        } else if (f518 != 0 && (flags & 0x2000) == 0 && lbl_8035F3E8[0x4b] != 0) {
            idx = 0x4b;
        }
        {
            u32 base = lbl_8035F3E8[idx];
            if (base != 0) {
                if (param_7 == 1 && param_6 != 0) {
                    int e = (param_1 & 0xffffff) * 2 + *(int *)(param_6 + param_5 * 4) + 4;
                    int v;
                    e = base + e;
                    v = *(int *)(e + 4);
                    *param_4 = *(int *)(e + 8);
                    *param_3 = v;
                } else if (param_7 == 2 && param_6 != 0) {
                    memcpy(param_6, (void *)(base + (param_1 & 0xffffff) * 2), (param_5 + 1) * 4);
                } else {
                    int e = base + (param_1 & 0xffffff) * 2;
                    int v = *(int *)(e + 0xc);
                    *param_3 = *(int *)(e + 8);
                    if (strncmp(&sDirBlockTag, (char *)e, 3) == 0) {
                        *param_4 = 0xffffffff;
                    } else {
                        *param_4 = v;
                    }
                }
            } else {
                char fileInfo[0x3c];
                char *buf;
                DVDOpen(sResourceFileNameTable[idx], fileInfo);
                buf = mmAlloc(0x400, 0x7f7f7fff, 0);
                DVDRead(fileInfo, buf, 0x400, (param_1 & 0xffffff) * 2);
                DVDClose(fileInfo);
                DCStoreRange(buf, 0x400);
                if (param_7 == 1 && param_6 != 0) {
                    int e = *(int *)(param_6 + param_5 * 4) + 4;
                    int v;
                    e = (int)buf + e;
                    v = *(int *)(e + 4);
                    *param_4 = *(int *)(e + 8);
                    *param_3 = v;
                } else if (param_7 == 2 && param_6 != 0) {
                    memcpy(param_6, buf, (param_5 + 1) * 4);
                } else {
                    int v = *(int *)(buf + 0xc);
                    *param_3 = *(int *)(buf + 8);
                    if (strncmp(&sDirBlockTag, (char *)buf, 3) == 0) {
                        *param_4 = 0xffffffff;
                    } else {
                        *param_4 = v;
                    }
                }
                mm_free(buf);
            }
        }
    }
}

extern u32 sMapFileNameIndexRemapTable[];
extern u8 lbl_803DB5D0;
extern u8 lbl_803DCD28;
extern u8 lbl_803DCD31;
extern f32 lbl_803DCD34;
extern f32 lbl_803DCD38;
extern f32 lbl_803DCD3C;
extern f32 lbl_803DCD40;
extern f32 lbl_803DCD44;

int mapGetDirIdx(int idx) {
    if (idx >= 0x4b) return 5;
    return sMapFileNameIndexRemapTable[idx];
}

void setColor_803db5d0(u8 r, u8 g, u8 b) {
    (&lbl_803DB5D0)[0] = r;
    (&lbl_803DB5D0)[1] = g;
    (&lbl_803DB5D0)[2] = b;
}

void enableHeavyFog(u8 mode, f32 a, f32 b, f32 c, f32 d, f32 e) {
    lbl_803DCD28 = 1;
    lbl_803DCD44 = a;
    lbl_803DCD40 = b;
    lbl_803DCD3C = c;
    lbl_803DCD38 = d;
    lbl_803DCD34 = e;
    lbl_803DCD31 = mode;
}

void *Shader_getLayer(char *base, int idx) { return base + idx * 8 + 0x24; }

extern u8 lbl_803DCCB0;
extern void gxPerfFn_8004a77c(int);
void gxTransformFn_8004a83c(void) {
    lbl_803DCCB0 = 0;
    gxPerfFn_8004a77c(0);
}

typedef union { u8 u8; u16 u16; u32 u32; s16 s16; s32 s32; f32 f32; } PiWGPipe;
extern volatile PiWGPipe GXWGFifo : (0xCC008000);
extern void GXSetGPMetric(int perf0, int perf1);
void gxPerfFn_8004a77c(int param_1) {
    if ((u8)param_1 != 0) {
        GXSetGPMetric(0x23, 0x16);
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x2402c004;
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x23000020;
        GXWGFifo.u8 = 0x10;
        GXWGFifo.u16 = 0;
        GXWGFifo.u16 = 0x1006;
        GXWGFifo.u32 = 0x84400;
    } else {
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x24000000;
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x23000000;
        GXWGFifo.u8 = 0x10;
        GXWGFifo.u16 = 0;
        GXWGFifo.u16 = 0x1006;
        GXWGFifo.u32 = 0;
    }
}

extern void *mmAlloc(int size, int align, int zone);
extern void *lbl_803DCD10;
void allocSomething32bytes(void) {
    lbl_803DCD10 = mmAlloc(0x20, 0xff, 0);
}

extern u32 lbl_8035F0A8[];
extern u32 lbl_8035F3E8[];
u32 getDataFileSize(int idx) {
    if (lbl_8035F3E8[idx] != 0) {
        return lbl_8035F0A8[idx];
    }
    *(u8 *)0 = 0;
    return 0;
}

extern void VISetBlack(int);
extern void VIFlush(void);
extern u8 lbl_803DB5CC;
#pragma peephole off
void viFn_8004a56c(int val) {
    int v = val;
    VISetBlack(1);
    VIFlush();
    lbl_803DB5CC = (u8)v;
}
#pragma peephole reset

extern void mm_free(void *p);
void freeAndNull(void **p) {
    if (*p != NULL) {
        mm_free(*p);
        *p = NULL;
    }
}

extern f32 lbl_803DEA70;
extern f32 lbl_803DEA78;
extern f32 lbl_803DEA88;
extern f32 lbl_803DEA8C;
extern f32 lbl_803DEA90;
extern f32 hudMatrix[];
extern void C_MTXOrtho(f32 *mtx, f32 t, f32 b, f32 l, f32 r, f32 n, f32 f);
void initViewport(void) {
    C_MTXOrtho(hudMatrix, lbl_803DEA70, lbl_803DEA88, lbl_803DEA70, lbl_803DEA8C, lbl_803DEA78, lbl_803DEA90);
}
#pragma scheduling reset

extern int lbl_803DCD88;
extern int lbl_803DCD8C;
extern int lbl_803DCD90;
extern u8 lbl_803DCD6A;
extern void GXSetTevDirect(int);
extern void GXSetTevOrder(int, int, int, int);
extern void GXSetTevSwapMode(int, int, int);
extern void GXSetTevColorIn(int, int, int, int, int);
extern void GXSetTevAlphaIn(int, int, int, int, int);
extern void GXSetTevColorOp(int, int, int, int, int, int);
extern void GXSetTevAlphaOp(int, int, int, int, int, int);

#pragma scheduling off
#pragma peephole off
void fn_80050F2C(void) {
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 255);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorIn(lbl_803DCD90, 15, 6, 8, 15);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 3);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int fn_8004AA24(int *ctx, int *ref) {
    int target = ctx[4];
    int *node = (int *)ref[0];
    if (((s8 *)node)[0x19] == 0x24) {
        u8 idx = ((u8 *)ref)[0xc];
        if ((idx & 0x80) == 0) {
            if (((u8 *)node)[3] != 0) {
                return ((u8 *)node)[3] == target;
            } else {
                int *arr = (int *)*(int *)((char *)ctx[0] + (idx << 4));
                int *p = arr;
                int i;
                for (i = 0; i < 4; i++) {
                    if ((u32)node[5] == *(u32 *)((char *)p + 0x1c)) {
                        return ((u8 *)arr)[i + 4] == target;
                    }
                    p++;
                }
                return 0;
            }
        }
        return 0;
    }
    return (int)node == target;
}
void fn_8004AAD4(u8* arr, int size, int idx) {
    u32 key = *(u32*)(arr + idx * 8);
    u16 val = *(u16*)(arr + idx * 8 + 4);
    int half = size >> 1;
    int child;
    u8* cp;
    u8* childptr;
    while (idx <= half) {
        child = idx + idx;
        if (child < size) {
            cp = arr + child * 8;
            if (*(u32*)cp < *(u32*)(cp + 8)) {
                child++;
            }
        }
        childptr = arr + child * 8;
        if (key >= *(u32*)childptr) break;
        *(u32*)(arr + idx * 8) = *(u32*)childptr;
        *(u16*)(arr + idx * 8 + 4) = *(u16*)(childptr + 4);
        idx = child;
    }
    *(u32*)(arr + idx * 8) = key;
    *(u16*)(arr + idx * 8 + 4) = val;
}
#pragma dont_inline reset
extern void fn_8004AFA0(int *q, int *elem, int idx);
int fn_8004B218(int *q, int n) {
    int done = 0;
    int result = 0;
    int idx;
    int *elem;
    int *heap;
    int count;
    while (done == 0 && n != 0) {
        heap = *(int **)((char *)q + 0x4);
        count = *(s16 *)((char *)q + 0x22);
        if (count == 0) {
            idx = -1;
        } else {
            idx = *(u16 *)((char *)heap + 0xc);
            *(int *)((char *)heap + 0x8) = *(int *)((char *)heap + count * 8);
            *(s16 *)((char *)q + 0x22) = count - 1;
            *(u16 *)((char *)heap + 0xc) = *(u16 *)((char *)heap + count * 8 + 4);
            fn_8004AAD4((u8 *)heap, *(s16 *)((char *)q + 0x22), 1);
        }
        if (idx < 0) {
            done = 1;
            result = -1;
        } else {
            elem = (int *)(*(int *)((char *)q + 0) + idx * 16);
            *(int *)((char *)q + 0x1c) = idx;
            if (fn_8004AA24(q, elem) != 0) {
                done = 1;
                result = 1;
            } else {
                *((u8 *)elem + 0xe) = 1;
                fn_8004AFA0(q, elem, idx);
            }
        }
        n--;
    }
    return result;
}
extern int *gRomCurveInterface;
extern u32 GameBit_Get(int eventId);
extern char *lbl_803DCD08;
extern void fn_8004AB5C(int *q, int *elem, int idx, u32 d, char *obj);
void fn_8004AFA0(int *q, int *elem, int idx) {
    u8 mask;
    char *p;
    char *node;
    char *obj;
    int bit;
    int t;
    node = (char *)elem[0];
    if (*(u8 *)((char *)q + 0x28) != 0) {
        t = *(s8 *)(node + 0x1b);
    } else {
        t = ~*(s8 *)(node + 0x1b);
    }
    bit = 0;
    p = node;
    mask = t;
    for (; bit < 4; bit++) {
        int nodeId = *(int *)(p + 0x1c);
        if (nodeId > -1 && (mask & (1 << bit)) != 0) {
            obj = (char *)(*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(nodeId);
            if (obj != 0) {
                switch (*(s8 *)(obj + 0x19)) {
                case 0x24: {
                    s16 ev1;
                    s16 ev2;
                    GameBit_Get(0x4e2);
                    ev1 = *(s16 *)(obj + 0x30);
                    if (ev1 == -1 || GameBit_Get(ev1) != 0) {
                        ev2 = *(s16 *)(obj + 0x32);
                        if (ev2 == -1 || GameBit_Get(ev2) == 0) {
                            if (!(*(s8 *)(obj + 0x1a) == 8 && *(s8 *)(node + 0x1a) == 9)) {
                                f32 d = vec3f_distanceSquared((f32 *)(node + 8), (f32 *)(obj + 8));
                                fn_8004AB5C(q, elem, idx, (u32)((f32)(u32)elem[2] + d), obj);
                            }
                        }
                    }
                    break;
                }
                default:
                    lbl_803DCD08 = obj;
                    break;
                }
            }
        }
        p += 4;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void gxSetZMode_(int a, int b, int c);
extern void GXSetAlphaUpdate(u8 v);
extern void GXFlush(void);
extern void GXGetFifoPtrs(void *fifo, void **out_g, void **out_p);
extern int OSDisableInterrupts(void);
extern void OSRestoreInterrupts(int s);
extern void Queue_Push(void *q, void *item);
extern void GXEnableBreakPt(void *p);
extern void GXSetDrawSync(u16 v);
extern void GXCopyDisp(void *fb, u8 clear);
extern void VISetBlack(int black);
extern void *lbl_803DCCD4;
extern void *lbl_803DCCD0;
extern void *lbl_803DCCEC;
extern void *lbl_803DCCE8;
extern u8 lbl_803DCCA7;
extern u16 lbl_803DB5CE;
extern u8 lbl_803DB5CC;
extern char lbl_8035F730[];
#pragma scheduling off
int GXFlush_(u8 visible, int unused) {
    void *fifo_get;
    void *fifo_put;
    void *item[3];
    int s;
    void *next;
    gxSetZMode_(1, 3, 1);
    GXSetAlphaUpdate(1);
    GXFlush();
    GXGetFifoPtrs(lbl_803DCCD4, &fifo_get, &fifo_put);
    item[0] = fifo_put;
    item[1] = (void *)0;
    item[2] = lbl_803DCCD0;
    s = OSDisableInterrupts();
    Queue_Push(&lbl_8035F730[0], item);
    if (lbl_803DCCA7 == 0) {
        GXEnableBreakPt(fifo_put);
        lbl_803DCCA7 = 1;
    }
    OSRestoreInterrupts(s);
    GXSetDrawSync(lbl_803DB5CE);
    GXCopyDisp(lbl_803DCCD0, 1);
    GXFlush();
    lbl_803DB5CE = (u16)(lbl_803DB5CE + 1);
    next = lbl_803DCCEC;
    if (lbl_803DCCD0 == next) next = lbl_803DCCE8;
    lbl_803DCCD0 = next;
    if (visible != 0 && lbl_803DB5CC != 0) {
        lbl_803DB5CC = lbl_803DB5CC - 1;
        if (lbl_803DB5CC == 0) {
            VISetBlack(0);
            lbl_803DB5CC = 0;
        }
    }
    return 0;
}
#pragma scheduling reset

extern u8 GXNtsc480Prog[];
extern u8 lbl_803DB5D4;
extern u8 *lbl_803DCCF0;
extern void GXSetCopyFilter(u8 aa, u8 *pat, u8 vf_en, u8 *vfilter);
#pragma scheduling off
void setDisplayCopyFilter(void) {
    u8 *p = lbl_803DCCF0;
    if (p == GXNtsc480Prog || p[0x18] != 0) {
        GXSetCopyFilter(p[0x19], p + 0x1a, 0, p + 0x32);
    } else {
        GXSetCopyFilter(p[0x19], p + 0x1a, 1, &lbl_803DB5D4);
    }
}
#pragma scheduling reset

extern void GXLoadTexObj(void *obj, int id);
extern void GXLoadTexObjPreLoaded(void *obj, void *region, int id);
extern void fn_80053C40(u8 *tex, void *out);
extern u8 lbl_803779A0[];
#pragma scheduling off
void textureFn_8004c264(u8 *tex, int mapId) {
    void *base;
    if (tex == NULL) return;
    base = &tex[32];
    if (tex[72] != 0) {
        GXLoadTexObjPreLoaded(base, *(void **)(tex + 64), mapId);
    } else {
        GXLoadTexObj(base, mapId);
    }
    if (*(void **)(tex + 80) != NULL) {
        fn_80053C40(tex, lbl_803779A0);
        GXLoadTexObj(lbl_803779A0, 1);
    }
}
#pragma scheduling reset

#pragma scheduling off
void selectTexture(u8 *tex, int mapId) {
    void *base;
    if (tex == NULL) return;
    base = &tex[0x20];
    if (tex[0x48] != 0) {
        GXLoadTexObjPreLoaded(base, *(void **)(tex + 0x40), mapId);
    } else {
        GXLoadTexObj(base, mapId);
    }
}
extern int lbl_803DCC80;
#pragma scheduling off
#pragma peephole off
void loadModelsBin(int a, int *p1c, int *p20, int *p18, int *p4) {
    u32 v31 = 0;
    u32 v30 = 0;
    int idx = -1;
    int flags;
    int saved;
    char *p;
    if (lbl_8035F3E8[0x2b] != 0 || lbl_8035F3E8[0x46] != 0) {
        saved = OSDisableInterrupts();
        flags = lbl_803DCC80;
        OSRestoreInterrupts(saved);
        if ((flags & 4) == 0 && (flags & 1) == 0) {
            v31 = lbl_8035F3E8[0x2a];
        }
        if ((flags & 8) == 0 && (flags & 2) == 0) {
            v30 = lbl_8035F3E8[0x45];
        }
        if (v30 != 0 && (a & 0x20000000) != 0) {
            idx = 0x46;
        } else if (v31 != 0 && (a & 0x10000000) != 0) {
            idx = 0x2b;
        } else if (v31 != 0) {
            idx = 0x2b;
        } else if (v30 != 0) {
            idx = 0x46;
        }
        p = (char *)lbl_8035F3E8[idx] + (a & 0x0fffffff);
        *p18 = *(int *)(p + 0x18);
        *p1c = *(int *)(p + 0x1c);
        *p20 = *(int *)(p + 0x20);
        *p4 = *(int *)(p + 0x4);
    }
}
#pragma peephole reset
#pragma scheduling reset
extern char sZlbBlockTag[];
extern int strncmp(const char *a, const char *b, u32 n);
#pragma scheduling off
#pragma peephole off
void checkLoadBlock(int a, int *pc, int *p8) {
    int idx = -1;
    int flags;
    int saved;
    char *blk;
    u32 t25, t47;
    if ((lbl_8035F3E8[0x26] != 0 && lbl_8035F3E8[0x25] != 0) ||
        (lbl_8035F3E8[0x48] != 0 && lbl_8035F3E8[0x47] != 0)) {
        saved = OSDisableInterrupts();
        flags = lbl_803DCC80;
        OSRestoreInterrupts(saved);
        t25 = lbl_8035F3E8[0x25];
        t47 = lbl_8035F3E8[0x47];
        if (t25 != 0 && (a & 0x10000000) != 0 && (flags & 0x10000) == 0) {
            idx = 0x25;
        } else if (t47 != 0 && (a & 0x20000000) != 0 && (flags & 0x40000) == 0) {
            idx = 0x47;
        } else if (t25 != 0 && (flags & 0x10000) == 0) {
            idx = 0x25;
        } else if (t47 != 0 && (flags & 0x40000) == 0) {
            idx = 0x47;
        }
        blk = (char *)lbl_8035F3E8[idx] + (a & 0x00ffffff);
        if (strncmp(blk, sZlbBlockTag, 3) != 0) {
            *p8 = 0;
            *pc = 0;
        } else {
            *p8 = *(int *)(blk + 0x8);
            *pc = *(int *)(blk + 0xc);
        }
    } else {
        *p8 = 0;
        *pc = 0;
    }
}
void loadVoxMaps(int a, int *pc, int *p8) {
    int idx = -1;
    int flags;
    int saved;
    char *blk;
    u32 t1b, t54;
    if ((lbl_8035F3E8[0x1a] != 0 && lbl_8035F3E8[0x1b] != 0) ||
        (lbl_8035F3E8[0x53] != 0 && lbl_8035F3E8[0x54] != 0)) {
        saved = OSDisableInterrupts();
        flags = lbl_803DCC80;
        OSRestoreInterrupts(saved);
        t1b = lbl_8035F3E8[0x1b];
        t54 = lbl_8035F3E8[0x54];
        if (t1b != 0 && (a & 0x80000000) != 0 && (flags & 0x1000000) == 0) {
            idx = 0x1b;
        } else if (t54 != 0 && (a & 0x20000000) != 0 && (flags & 0x4000000) == 0) {
            idx = 0x54;
        } else if (t1b != 0 && (flags & 0x1000000) == 0) {
            idx = 0x1b;
        } else if (t54 != 0 && (flags & 0x4000000) == 0) {
            idx = 0x54;
        }
        if ((a & 0xf0000000) != 0) {
            blk = (char *)lbl_8035F3E8[idx] + (a & 0x00ffffff);
            if (strncmp(blk, sZlbBlockTag, 3) != 0) {
                *p8 = 0;
                *pc = 0;
            } else {
                *p8 = *(int *)(blk + 0x8);
                *pc = *(int *)(blk + 0xc);
            }
        } else {
            *p8 = 0;
            *pc = 0;
        }
    } else {
        *p8 = 0;
        *pc = 0;
    }
}
void fn_80050FF4(u8 mode) {
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (mode != 0) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 1, 4, 6);
    } else {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 1, 0xa, 6);
    }
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 3);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A = lbl_803DCD6A + 1;
}
extern u8 lbl_803DCD30;
void gxTextureFn_80050e28(u8 mode) {
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (mode != 0) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 4, 6);
    } else {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 0xa, 6);
    }
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A = lbl_803DCD6A + 1;
}
extern void GXSetTevIndRepeat(int stage);
extern void PSMTXScale(f32 m[3][4], f32 x, f32 y, f32 z);
extern void PSMTXTrans(f32 m[3][4], f32 x, f32 y, f32 z);
extern void PSMTXConcat(f32 dst[3][4], f32 a[3][4], f32 b[3][4]);
extern void GXLoadTexMtxImm(void *m, int id, int type);
extern void GXSetTexCoordGen2(int dst, int func, int src, int mtx, int normalize, int pttexmtx);
extern void GXSetTevSwapModeTable(int table, int r, int g, int b, int a);
extern u8 lbl_803DCD68;
extern int lbl_803DCD80;
extern u8 lbl_803DCD69;
extern f32 lbl_803DEACC;
extern f32 Breaking_803DEB40;
extern f32 lbl_803DEADC;
void fn_800510F0(void *p1, u8 flag2, u8 flag3) {
    f32 mtxB[3][4];
    f32 mtxA[3][4];
    if (lbl_803DCD68 == 0) {
        GXSetTevDirect(lbl_803DCD90);
    }
    if (flag2 != 0) {
        GXSetTevIndRepeat(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88 - 1, lbl_803DCD8C, 0xff);
    } else {
        PSMTXScale(mtxA, Breaking_803DEB40, Breaking_803DEB40, lbl_803DEACC);
        PSMTXTrans(mtxB, lbl_803DEADC, lbl_803DEADC, lbl_803DEAC8);
        PSMTXConcat(mtxB, mtxA, mtxA);
        GXLoadTexMtxImm(mtxA, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 1, 1, 0x1e, 0, lbl_803DCD80);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
        lbl_803DCD80 = lbl_803DCD80 + 3;
        lbl_803DCD88 = lbl_803DCD88 + 1;
        lbl_803DCD69 = lbl_803DCD69 + 1;
    }
    GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 3, 7);
    if (flag2 != 0) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 4, 0xf);
    } else {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xa, 0xf);
    }
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 3);
    if ((flag3 & 1) != 0) {
        GXSetTevSwapModeTable(3, 2, 2, 2, 1);
    } else {
        GXSetTevSwapModeTable(3, 0, 0, 0, 1);
    }
    GXSetTevSwapMode(lbl_803DCD90, 0, 3);
    if (p1 != 0) {
        if (*(u8 *)((char *)p1 + 0x48) != 0) {
            GXLoadTexObjPreLoaded((char *)p1 + 0x20, *(void **)((char *)p1 + 0x40), lbl_803DCD8C);
        } else {
            GXLoadTexObj((char *)p1 + 0x20, lbl_803DCD8C);
        }
    }
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A = lbl_803DCD6A + 1;
}
extern void gxTextureFn_8004bf88(void *buf, u8 a, u8 b, int *out1, int *out2);
extern void GXSetTevKColorSel(int stage, int sel);
void textureFn_80051348(void *p1, u8 p2) {
    f32 mtxB[3][4];
    f32 mtxA[3][4];
    u8 buf[3];
    int out_c;
    int out_8;
    PSMTXScale(mtxA, Breaking_803DEB40, Breaking_803DEB40, lbl_803DEACC);
    PSMTXTrans(mtxB, lbl_803DEADC, lbl_803DEADC, lbl_803DEAC8);
    PSMTXConcat(mtxB, mtxA, mtxA);
    GXLoadTexMtxImm(mtxA, lbl_803DCD80, 0);
    buf[0] = p2;
    buf[1] = p2;
    buf[2] = p2;
    gxTextureFn_8004bf88(buf, 1, 0, &out_c, &out_8);
    GXSetTevKColorSel(lbl_803DCD90, out_c);
    GXSetTexCoordGen2(lbl_803DCD88, 1, 1, 0x1e, 0, lbl_803DCD80);
    if (lbl_803DCD68 == 0) {
        GXSetTevDirect(lbl_803DCD90);
    }
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xe, 0xa);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 2);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    if (p1 != 0) {
        if (*(u8 *)((char *)p1 + 0x48) != 0) {
            GXLoadTexObjPreLoaded((char *)p1 + 0x20, *(void **)((char *)p1 + 0x40), lbl_803DCD8C);
        } else {
            GXLoadTexObj((char *)p1 + 0x20, lbl_803DCD8C);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A = lbl_803DCD6A + 1;
    lbl_803DCD69 = lbl_803DCD69 + 1;
}
extern void objGetColor(int slot, u8 *red, u8 *green, u8 *blue);
extern int lbl_803DCD78;
void fn_80051528(void *p1, void *mtx) {
    u8 buf[3];
    int out_c;
    int out_8;
    objGetColor(0, &buf[0], &buf[1], &buf[2]);
    if (mtx != 0) {
        GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, lbl_803DCD80);
        lbl_803DCD80 = lbl_803DCD80 + 3;
    } else {
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, 0x7d);
    }
    gxTextureFn_8004bf88(buf, 1, 0, &out_c, &out_8);
    GXSetTevKColorSel(lbl_803DCD90, out_c);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0xe, 0xa, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    GXSetTevDirect(lbl_803DCD90 + 1);
    GXSetTevOrder(lbl_803DCD90 + 1, 0xff, 0xff, 4);
    GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
    GXSetTevColorIn(lbl_803DCD90 + 1, 0, 0xa, 0xb, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 7);
    GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    GXSetTevDirect(lbl_803DCD90 + 2);
    GXSetTevOrder(lbl_803DCD90 + 2, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevSwapMode(lbl_803DCD90 + 2, 0, 0);
    GXSetTevColorIn(lbl_803DCD90 + 2, 0xf, 0, 8, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90 + 2, 7, 7, 7, 4);
    GXSetTevColorOp(lbl_803DCD90 + 2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90 + 2, 0, 0, 0, 1, 0);
    {
        int id = lbl_803DCD8C;
        if (p1 != 0) {
            if (*(u8 *)((char *)p1 + 0x48) != 0) {
                GXLoadTexObjPreLoaded((char *)p1 + 0x20, *(void **)((char *)p1 + 0x40), id);
            } else {
                GXLoadTexObj((char *)p1 + 0x20, id);
            }
        }
    }
    lbl_803DCD78 = lbl_803DCD78 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 3;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A += 3;
    lbl_803DCD69 += 1;
}
typedef struct { f32 v[2][3]; } IndTexMtx23;
extern IndTexMtx23 lbl_802C1E28;
extern u8 *lbl_803DCD2C;
extern int lbl_803DB5F4;
extern u8 lbl_803DB5F8;
extern u8 lbl_803DCD68;
extern f32 Prepared_803DEAD8;
extern f32 lbl_803DEAE0;
extern f32 lbl_803DEADC;
extern int lbl_803DCD7C;
extern u8 *textureAlloc(int w, int h, int fmt, int a, int b, int c, int d, int e, int f);
extern u32 randomGetRange(int min, int max);
extern void DCFlushRange(void *p, u32 n);
extern void newshadows_getReflectionScrollOffsets(f32 *x, f32 *y);
extern f32 fn_80293E80(f32 x);
extern void GXSetIndTexMtx(int id, f32 offset[2][3], int scale_exp);
extern void GXSetIndTexOrder(int ind_stage, int tex_coord, int tex_map);
extern void GXSetTevIndirect(int tev, int ind, int fmt, int bias, int mtx, int ws, int wt, int addprev, int utclod, int alpha);
void textureFn_8004c330(void *p1, void *mtx) {
    IndTexMtx23 m;
    f32 sx;
    f32 sy;
    int out_c;
    int out_8;
    int y;
    int x;
    int v1;
    u8 *dst;
    int v2;
    int v3;
    m = lbl_802C1E28;
    if (lbl_803DCD2C == 0) {
        lbl_803DCD2C = textureAlloc(0x20, 0x20, 4, 0, 0, 1, 1, 1, 1);
        for (y = 0; y < 0x20; y++) {
            for (x = 0; x < 0x20; x++) {
                u8 *row = lbl_803DCD2C + (y & 3) * 2;
                dst = row + (y >> 2) * 0x20 + (x & 3) * 8 + (x >> 2) * 0x100;
                v1 = randomGetRange(0x80, 0xff);
                v2 = v1 - randomGetRange(0, 0x40);
                v3 = v1 - randomGetRange(0x40, 0x80);
                *(u16 *)(dst + 0x60) =
                    ((v1 & 0xf8) >> 3) | ((v2 & 0xf8) << 8 | (v3 & 0xfc) << 3);
            }
        }
        DCFlushRange(lbl_803DCD2C + 0x60, *(u32 *)(lbl_803DCD2C + 0x44));
    }
    newshadows_getReflectionScrollOffsets(&sx, &sy);
    m.v[0][1] = lbl_803DEAE0 * fn_80293E80(Prepared_803DEAD8 * sx) + lbl_803DEADC;
    m.v[1][2] = lbl_803DEAE0 * fn_80293E80(Prepared_803DEAD8 * sy) + lbl_803DEADC;
    GXSetTevOrder(lbl_803DCD90, 0, lbl_803DCD8C + 1, 8);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (mtx != 0) {
        GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, lbl_803DCD80);
        lbl_803DCD80 = lbl_803DCD80 + 3;
    } else {
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, 0x7d);
    }
    GXSetIndTexMtx(1, m.v, (s8)lbl_803DB5F4);
    GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88, lbl_803DCD8C);
    GXSetTevIndirect(lbl_803DCD90, lbl_803DCD7C, 0, 7, 1, 0, 0, 0, 0, 3);
    gxTextureFn_8004bf88(&lbl_803DB5F8, 1, 0, &out_c, &out_8);
    GXSetTevKColorSel(lbl_803DCD90, out_c);
    GXSetTevColorIn(lbl_803DCD90, 0xe, 8, 0xb, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 1);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevOrder(lbl_803DCD90 + 1, 0xff, 0xff, 0xff);
    GXSetTevDirect(lbl_803DCD90 + 1);
    GXSetTevColorIn(lbl_803DCD90 + 1, 2, 0, 1, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 0);
    GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    {
        int id = lbl_803DCD8C;
        if (p1 != 0) {
            void *obj = (char *)p1 + 0x20;
            if (*(u8 *)((char *)p1 + 0x48) != 0) {
                GXLoadTexObjPreLoaded(obj, *(void **)((char *)p1 + 0x40), id);
            } else {
                GXLoadTexObj(obj, id);
            }
        }
    }
    {
        int id2 = lbl_803DCD8C + 1;
        u8 *tex = lbl_803DCD2C;
        if (tex != 0) {
            void *obj = tex + 0x20;
            if (*(u8 *)(tex + 0x48) != 0) {
                GXLoadTexObjPreLoaded(obj, *(void **)(tex + 0x40), id2);
            } else {
                GXLoadTexObj(obj, id2);
            }
        }
    }
    lbl_803DCD78 = lbl_803DCD78 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 2;
    lbl_803DCD8C = lbl_803DCD8C + 2;
    lbl_803DCD6A += 2;
    lbl_803DCD69 += 1;
    lbl_803DCD68 += 1;
}
void textureFn_8004ff20(void *p1) {
    if (p1 != 0) {
        GXSetTexCoordGen2(lbl_803DCD88, 1, 1, 0x1e, 0, 0x7d);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xa, 0xb, 8);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        lbl_803DCD30 = 1;
        {
            int id = lbl_803DCD8C;
            if (p1 != 0) {
                if (*(u8 *)((char *)p1 + 0x48) != 0) {
                    GXLoadTexObjPreLoaded((char *)p1 + 0x20, *(void **)((char *)p1 + 0x40), id);
                } else {
                    GXLoadTexObj((char *)p1 + 0x20, id);
                }
            }
        }
        lbl_803DCD88 = lbl_803DCD88 + 1;
        lbl_803DCD90 = lbl_803DCD90 + 1;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        lbl_803DCD69 = lbl_803DCD69 + 1;
        lbl_803DCD6A = lbl_803DCD6A + 1;
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 5);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xa, 0xb, 0);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        lbl_803DCD90 = lbl_803DCD90 + 1;
        lbl_803DCD6A = lbl_803DCD6A + 1;
    }
}
extern int lbl_803DCD70;
extern int lbl_803DCD6C;
extern int lbl_803DCD74;
extern void GXSetTevKColor(int id, void *color);
void gxTextureFn_8004bf88(void *bufp, u8 flag1, u8 flag2, int *out1, int *out2) {
    u8 *buf = bufp;
    u8 found1 = 0;
    u8 found2 = 0;
    if (flag1 != 0) {
        if (buf[0] == buf[1] && buf[0] == buf[2]) {
            if (buf[0] == 0xff) {
                *out1 = 0;
                found1 = 1;
            } else if (buf[0] == 0xe0) {
                *out1 = 1;
                found1 = 1;
            } else if (buf[0] == 0xc0) {
                *out1 = 2;
                found1 = 1;
            } else if (buf[0] == 0xa0) {
                *out1 = 3;
                found1 = 1;
            } else if (buf[0] == 0x80) {
                *out1 = 4;
                found1 = 1;
            } else if (buf[0] == 0x60) {
                *out1 = 5;
                found1 = 1;
            } else if (buf[0] == 0x40) {
                *out1 = 6;
                found1 = 1;
            } else if (buf[0] == 0x20) {
                *out1 = 7;
                found1 = 1;
            }
        }
        if (found1 == 0) {
            *out1 = lbl_803DCD70;
        }
    } else {
        found1 = 1;
    }
    if (flag2 != 0) {
        if (buf[3] == 0xff) {
            *out2 = 0;
            found2 = 1;
        } else if (buf[3] == 0xe0) {
            *out2 = 1;
            found2 = 1;
        } else if (buf[3] == 0xc0) {
            *out2 = 2;
            found2 = 1;
        } else if (buf[3] == 0xa0) {
            *out2 = 3;
            found2 = 1;
        } else if (buf[3] == 0x80) {
            *out2 = 4;
            found2 = 1;
        } else if (buf[3] == 0x60) {
            *out2 = 5;
            found2 = 1;
        } else if (buf[3] == 0x40) {
            *out2 = 6;
            found2 = 1;
        } else if (buf[3] == 0x20) {
            *out2 = 7;
            found2 = 1;
        }
        if (found2 == 0) {
            *out2 = lbl_803DCD6C;
        }
    } else {
        found2 = 1;
    }
    if (found1 == 0 || found2 == 0) {
        int color = *(int *)bufp;
        GXSetTevKColor(lbl_803DCD74, &color);
        lbl_803DCD74 = lbl_803DCD74 + 1;
        lbl_803DCD70 = lbl_803DCD70 + 1;
        lbl_803DCD6C = lbl_803DCD6C + 1;
    }
}
void gxTextureFn_8004d5b4(void *p1) {
    u8 buf[3];
    int color;
    u8 b = *(u8 *)((char *)p1 + 0x43);
    buf[2] = b;
    buf[1] = b;
    buf[0] = b;
    color = *(int *)buf;
    GXSetTevKColor(lbl_803DCD74, &color);
    GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 0xff);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorIn(lbl_803DCD90, 0, 2, 0xe, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD74 = lbl_803DCD74 + 1;
    lbl_803DCD70 = lbl_803DCD70 + 1;
    lbl_803DCD6C = lbl_803DCD6C + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A = lbl_803DCD6A + 1;
}
struct piIndMtx { f32 m[2][3]; };
extern struct piIndMtx lbl_802C1D50;
extern u8 lbl_803DB5E8;
extern int lbl_803DCD7C;
extern int lbl_8030CEE0[];
extern f32 lbl_803DEB38;
extern f32 lbl_803DEB3C;
extern void *textureIdxToPtr(int idx);
extern void GXSetIndTexMtx(int id, f32 offset[2][3], int scale_exp);
extern void GXSetIndTexOrder(int ind_stage, int tex_coord, int tex_map);
extern void GXSetIndTexCoordScale(int ind_stage, int scale_s, int scale_t);
extern void GXSetTevIndirect(int tev, int ind, int fmt, int bias, int mtx, int ws, int wt, int addprev, int utclod, int alpha);
extern void GXSetTevOp(int stage, int mode);
int textureFn_80050ad8(void *p1, int p2, u8 p3, u32 p4) {
    struct piIndMtx indmtx;
    f32 mtx[3][4];
    f32 v;
    int result = 0;
    indmtx = lbl_802C1D50;
    if ((lbl_803DB5E8 & 1) == 0) {
        return 0;
    }
    GXSetIndTexMtx(1, indmtx.m, 0);
    GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88 + p2, lbl_803DCD8C);
    if (p4 != 0) {
        void *texptr;
        u32 div;
        p2 = (p3 & 0xf) * 4 + 1;
        texptr = textureIdxToPtr(p4);
        div = (u32)*(u16 *)((char *)texptr + 0xa) / (u32)(*(u16 *)((char *)p1 + 0xa) * p2);
        if (div != 0) {
            GXSetIndTexCoordScale(lbl_803DCD7C, lbl_8030CEE0[div - 1], lbl_8030CEE0[div - 1]);
        } else {
            result = (u8)p2;
        }
    } else {
        result = 1;
    }
    v = (f32)(s32)((p3 & 0xf0) >> 4);
    v = v / lbl_803DEB3C;
    v = v - lbl_803DEAC8;
    v = lbl_803DEB38 * v;
    v = lbl_803DEADC * v;
    PSMTXScale(mtx, v, v, lbl_803DEACC);
    mtx[2][3] = lbl_803DEAC8;
    GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 1, 2, 0x1e, 0, lbl_803DCD80);
    GXSetTexCoordGen2(lbl_803DCD88 + 1, 1, 3, 0x1e, 0, lbl_803DCD80);
    GXSetTevIndirect(lbl_803DCD90, lbl_803DCD7C, 0, 3, 5, 6, 6, 0, 0, 0);
    GXSetTevIndirect(lbl_803DCD90 + 1, lbl_803DCD7C, 0, 3, 9, 6, 6, 1, 0, 0);
    GXSetTevIndirect(lbl_803DCD90 + 2, lbl_803DCD7C, 0, 0, 0, 0, 0, 1, 0, 0);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, (lbl_803DCD8C + 1) | 0x100, 0xff);
    GXSetTevOp(lbl_803DCD90, 4);
    GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, (lbl_803DCD8C + 1) | 0x100, 0xff);
    GXSetTevOp(lbl_803DCD90 + 1, 4);
    if (p1 != 0) {
        if (*(u8 *)((char *)p1 + 0x48) != 0) {
            GXLoadTexObjPreLoaded((char *)p1 + 0x20, *(void **)((char *)p1 + 0x40), lbl_803DCD8C);
        } else {
            GXLoadTexObj((char *)p1 + 0x20, lbl_803DCD8C);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD7C = lbl_803DCD7C + 1;
    lbl_803DCD88 = lbl_803DCD88 + 2;
    lbl_803DCD90 = lbl_803DCD90 + 2;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A = lbl_803DCD6A + 2;
    lbl_803DCD68 = lbl_803DCD68 + 1;
    lbl_803DCD69 = lbl_803DCD69 + 2;
    return result;
}
extern f32 fn_8006C670(void);
extern f32 lbl_803DEADC;
extern struct piIndMtx lbl_802C1E10;
extern f32 lbl_80396820[3][4];
extern void getTextureFn_8006c5e4(void *out);
extern void selectReflectionTexture(int id);
void fn_8004D6D8(void) {
    struct piIndMtx indmtx;
    void *tex;
    int id;
    f32 v;
    indmtx = lbl_802C1E10;
    v = lbl_803DEADC * fn_8006C670();
    indmtx.m[0][0] = v;
    indmtx.m[1][2] = v;
    if (lbl_803DCD88 > 0) {
        GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88 - 1, lbl_803DCD8C + 1);
    } else {
        GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88, lbl_803DCD8C + 1);
    }
    GXSetIndTexCoordScale(lbl_803DCD7C, 0, 0);
    GXSetIndTexMtx(2, indmtx.m, -3);
    GXSetTevIndirect(lbl_803DCD90, lbl_803DCD7C, 0, 3, 2, 0, 0, 0, 0, 0);
    getTextureFn_8006c5e4(&tex);
    id = lbl_803DCD8C + 1;
    if (tex != NULL) {
        void *obj = (char *)tex + 0x20;
        if (*(u8 *)((char *)tex + 0x48) != 0) {
            GXLoadTexObjPreLoaded(obj, *(void **)((char *)tex + 0x40), id);
        } else {
            GXLoadTexObj(obj, id);
        }
    }
    GXLoadTexMtxImm(lbl_80396820, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 8);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 1);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    selectReflectionTexture(lbl_803DCD8C);
    lbl_803DCD7C = lbl_803DCD7C + 1;
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 2;
    lbl_803DCD6A++;
    lbl_803DCD69++;
    lbl_803DCD68++;
}
extern void fn_8006C540(u8 **out);
extern int lbl_803DCD6C;
void fn_8004F380(f32 param_1, int *param_2, f32 *param_3) {
    f32 matA[3][4];
    f32 matB[3][4];
    u8 *src;
    int color;
    int id;
    f32 c8, cc, d1, f;
    if (lbl_803DCD74 <= 3 && lbl_803DCD6A < 0xc && lbl_803DCD69 < 7) {
        d1 = lbl_803DEADC;
        f = d1 / param_1;
        cc = lbl_803DEACC;
        c8 = lbl_803DEAC8;
        matA[0][0] = f;
        matA[0][1] = cc;
        matA[0][2] = cc;
        matA[0][3] = -param_3[0] * f + d1;
        matA[1][0] = cc;
        matA[1][1] = cc;
        matA[1][2] = f;
        matA[1][3] = -param_3[2] * f + d1;
        matA[2][0] = cc;
        matA[2][1] = cc;
        matA[2][2] = cc;
        matA[2][3] = c8;
        matB[0][0] = cc;
        matB[0][1] = f;
        matB[0][2] = cc;
        matB[0][3] = -param_3[1] * f + d1;
        matB[1][0] = cc;
        matB[1][1] = cc;
        matB[1][2] = cc;
        matB[1][3] = d1;
        matB[2][0] = cc;
        matB[2][1] = cc;
        matB[2][2] = cc;
        matB[2][3] = c8;
        fn_8006C540(&src);
        GXLoadTexMtxImm(matA, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
        GXLoadTexMtxImm(matB, lbl_803DCD80 + 3, 0);
        GXSetTexCoordGen2(lbl_803DCD88 + 1, 0, 0, 0, 0, lbl_803DCD80 + 3);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
        color = *param_2;
        GXSetTevKColor(lbl_803DCD74, &color);
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xe, 8, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 1);
        GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        GXSetTevDirect(lbl_803DCD90 + 1);
        GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C, 0xff);
        GXSetTevColorIn(lbl_803DCD90 + 1, 0xf, 2, 8, 4);
        GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
        GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 2);
        GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
        id = lbl_803DCD8C;
        if (src != NULL) {
            u8 *obj = src + 0x20;
            if (src[0x48] != 0) {
                GXLoadTexObjPreLoaded(obj, *(void **)(src + 0x40), id);
            } else {
                GXLoadTexObj(obj, id);
            }
        }
        lbl_803DCD90 = lbl_803DCD90 + 2;
        lbl_803DCD88 = lbl_803DCD88 + 2;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        lbl_803DCD74 = lbl_803DCD74 + 1;
        lbl_803DCD70 = lbl_803DCD70 + 1;
        lbl_803DCD6C = lbl_803DCD6C + 1;
        lbl_803DCD80 = lbl_803DCD80 + 6;
        lbl_803DCD69 = lbl_803DCD69 + 2;
        lbl_803DCD6A = lbl_803DCD6A + 2;
    }
}
void fn_8004F6D8(f32 param_1, int *param_2, f32 *param_3) {
    f32 matA[3][4];
    f32 matB[3][4];
    u8 *src;
    int color;
    int id;
    f32 c8, cc, d1, f;
    if (lbl_803DCD74 <= 3 && lbl_803DCD6A < 0xc && lbl_803DCD69 < 7) {
        d1 = lbl_803DEADC;
        f = d1 / param_1;
        cc = lbl_803DEACC;
        c8 = lbl_803DEAC8;
        matA[0][0] = f;
        matA[0][1] = cc;
        matA[0][2] = cc;
        matA[0][3] = -param_3[0] * f + d1;
        matA[1][0] = cc;
        matA[1][1] = cc;
        matA[1][2] = f;
        matA[1][3] = -param_3[2] * f + d1;
        matA[2][0] = cc;
        matA[2][1] = cc;
        matA[2][2] = cc;
        matA[2][3] = c8;
        matB[0][0] = cc;
        matB[0][1] = f;
        matB[0][2] = cc;
        matB[0][3] = -param_3[1] * f + d1;
        matB[1][0] = cc;
        matB[1][1] = cc;
        matB[1][2] = cc;
        matB[1][3] = d1;
        matB[2][0] = cc;
        matB[2][1] = cc;
        matB[2][2] = cc;
        matB[2][3] = c8;
        fn_8006C540(&src);
        GXLoadTexMtxImm(matA, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
        GXLoadTexMtxImm(matB, lbl_803DCD80 + 3, 0);
        GXSetTexCoordGen2(lbl_803DCD88 + 1, 0, 0, 0, 0, lbl_803DCD80 + 3);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
        color = *param_2;
        GXSetTevKColor(lbl_803DCD74, &color);
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xe, 8, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 1);
        GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        GXSetTevDirect(lbl_803DCD90 + 1);
        GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C, 0xff);
        GXSetTevColorIn(lbl_803DCD90 + 1, 0xf, 2, 8, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
        GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 2);
        GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
        id = lbl_803DCD8C;
        if (src != NULL) {
            u8 *obj = src + 0x20;
            if (src[0x48] != 0) {
                GXLoadTexObjPreLoaded(obj, *(void **)(src + 0x40), id);
            } else {
                GXLoadTexObj(obj, id);
            }
        }
        lbl_803DCD90 = lbl_803DCD90 + 2;
        lbl_803DCD88 = lbl_803DCD88 + 2;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        lbl_803DCD74 = lbl_803DCD74 + 1;
        lbl_803DCD70 = lbl_803DCD70 + 1;
        lbl_803DCD6C = lbl_803DCD6C + 1;
        lbl_803DCD80 = lbl_803DCD80 + 6;
        lbl_803DCD69 = lbl_803DCD69 + 2;
        lbl_803DCD6A = lbl_803DCD6A + 2;
    }
}
extern f32 lbl_803DEAE4;
void fn_8004FA30(f32 param_1, int *param_2, f32 *param_3) {
    f32 matA[3][4];
    f32 matB[3][4];
    u8 *src;
    int color;
    int id;
    f32 c8, cc, d1, f;
    if (lbl_803DCD74 <= 3 && lbl_803DCD6A < 0x10 && lbl_803DCD69 < 7) {
        if (param_1 < lbl_803DEAE4) {
            param_1 = lbl_803DEAE4;
        }
        d1 = lbl_803DEADC;
        f = d1 / param_1;
        cc = lbl_803DEACC;
        c8 = lbl_803DEAC8;
        matA[0][0] = f;
        matA[0][1] = cc;
        matA[0][2] = cc;
        matA[0][3] = -param_3[0] * f + d1;
        matA[1][0] = cc;
        matA[1][1] = cc;
        matA[1][2] = f;
        matA[1][3] = -param_3[2] * f + d1;
        matA[2][0] = cc;
        matA[2][1] = cc;
        matA[2][2] = cc;
        matA[2][3] = c8;
        matB[0][0] = cc;
        matB[0][1] = f;
        matB[0][2] = cc;
        matB[0][3] = -param_3[1] * f + d1;
        matB[1][0] = cc;
        matB[1][1] = cc;
        matB[1][2] = cc;
        matB[1][3] = d1;
        matB[2][0] = cc;
        matB[2][1] = cc;
        matB[2][2] = cc;
        matB[2][3] = c8;
        fn_8006C540(&src);
        GXLoadTexMtxImm(matA, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
        GXLoadTexMtxImm(matB, lbl_803DCD80 + 3, 0);
        GXSetTexCoordGen2(lbl_803DCD88 + 1, 0, 0, 0, 0, lbl_803DCD80 + 3);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
        color = *param_2;
        GXSetTevKColor(lbl_803DCD74, &color);
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xe, 8, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 1);
        GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        GXSetTevDirect(lbl_803DCD90 + 1);
        GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C, 0xff);
        GXSetTevColorIn(lbl_803DCD90 + 1, 0xf, 2, 8, 0);
        GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 0);
        GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
        GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
        lbl_803DCD30 = 1;
        id = lbl_803DCD8C;
        if (src != NULL) {
            u8 *obj = src + 0x20;
            if (src[0x48] != 0) {
                GXLoadTexObjPreLoaded(obj, *(void **)(src + 0x40), id);
            } else {
                GXLoadTexObj(obj, id);
            }
        }
        lbl_803DCD90 = lbl_803DCD90 + 2;
        lbl_803DCD88 = lbl_803DCD88 + 2;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        lbl_803DCD74 = lbl_803DCD74 + 1;
        lbl_803DCD70 = lbl_803DCD70 + 1;
        lbl_803DCD6C = lbl_803DCD6C + 1;
        lbl_803DCD80 = lbl_803DCD80 + 6;
        lbl_803DCD69 = lbl_803DCD69 + 2;
        lbl_803DCD6A = lbl_803DCD6A + 2;
    }
}
extern void *Camera_GetInverseViewMatrix(void);
extern void fn_8006C5B8(void *out);
void fn_8005011C(int param_1) {
    u8 *local_48;
    f32 mtx[3][4];
    u8 *obj2;
    int id;
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevDirect(lbl_803DCD90 + 1);
    GXSetTevDirect(lbl_803DCD90 + 2);
    GXSetTevDirect(lbl_803DCD90 + 3);
    PSMTXConcat((f32 (*)[4])(param_1 + 0x30), Camera_GetInverseViewMatrix(), mtx);
    GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0x3c, 0, lbl_803DCD80);
    PSMTXConcat((f32 (*)[4])param_1, Camera_GetInverseViewMatrix(), mtx);
    GXLoadTexMtxImm(mtx, lbl_803DCD80 + 3, 0);
    GXSetTexCoordGen2(lbl_803DCD88 + 1, 0, 0, 0x3c, 0, lbl_803DCD80 + 3);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C + 1, 0xff);
    GXSetTevOrder(lbl_803DCD90 + 2, lbl_803DCD88 + 1, lbl_803DCD8C + 1, 0xff);
    GXSetTevOrder(lbl_803DCD90 + 3, lbl_803DCD88 + 1, lbl_803DCD8C + 1, 0xff);
    GXSetTevKColorSel(lbl_803DCD90 + 2, 6);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 8);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 1);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevColorIn(lbl_803DCD90 + 1, 2, 8, 0xc, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
    GXSetTevColorOp(lbl_803DCD90 + 1, 8, 0, 0, 1, 1);
    GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    GXSetTevColorIn(lbl_803DCD90 + 2, 4, 0xe, 2, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90 + 2, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90 + 2, 0, 0);
    GXSetTevColorOp(lbl_803DCD90 + 2, 0, 0, 0, 1, 2);
    GXSetTevAlphaOp(lbl_803DCD90 + 2, 0, 0, 0, 1, 0);
    GXSetTevColorIn(lbl_803DCD90 + 3, 6, 0xf, 2, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90 + 3, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90 + 3, 0, 0);
    GXSetTevColorOp(lbl_803DCD90 + 3, 0, 0, 0, 1, 3);
    GXSetTevAlphaOp(lbl_803DCD90 + 3, 0, 0, 0, 1, 0);
    fn_8006C5B8(&local_48);
    id = lbl_803DCD8C;
    if (local_48 != NULL) {
        void *obj = local_48 + 0x20;
        if (local_48[0x48] != 0) {
            GXLoadTexObjPreLoaded(obj, *(void **)(local_48 + 0x40), id);
        } else {
            GXLoadTexObj(obj, id);
        }
    }
    id = lbl_803DCD8C + 1;
    obj2 = *(u8 **)(param_1 + 0x60);
    if (obj2 != NULL) {
        void *obj = obj2 + 0x20;
        if (obj2[0x48] != 0) {
            GXLoadTexObjPreLoaded(obj, *(void **)(obj2 + 0x40), id);
        } else {
            GXLoadTexObj(obj, id);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 6;
    lbl_803DCD88 = lbl_803DCD88 + 2;
    lbl_803DCD8C = lbl_803DCD8C + 2;
    lbl_803DCD69 += 2;
    lbl_803DCD6A += 4;
    lbl_803DCD90 = lbl_803DCD90 + 4;
}
extern u8 lbl_803DCD6B;
void fn_80050558(u8 *param_1, void *param_2, int param_3, int param_4, int param_5) {
    int uVar2;
    GXSetTevDirect(lbl_803DCD90);
    GXLoadTexMtxImm(param_2, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
    if (param_5 == 0 || param_5 == 2) {
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
    } else {
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 5);
    }
    if (lbl_803DCD90 == 0) {
        uVar2 = 0xc;
    } else {
        uVar2 = 4;
    }
    if (param_3 == 0) {
        if (param_4 == 2) {
            GXSetTevColorIn(lbl_803DCD90, 0xf, uVar2, 8, 0xf);
        } else if (param_4 == 3) {
            GXSetTevColorIn(lbl_803DCD90, uVar2, 0xf, 8, 0xf);
        } else if (param_4 == 1) {
            GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 8, uVar2);
        } else if (param_5 == 0 || param_5 == 1) {
            GXSetTevColorIn(lbl_803DCD90, 0xf, 0xa, 8, uVar2);
        } else {
            GXSetTevColorIn(lbl_803DCD90, 0xf, 0xb, 8, uVar2);
        }
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
        if (param_4 == 1) {
            GXSetTevColorOp(lbl_803DCD90, 1, 0, 0, 1, 2);
            GXSetTevAlphaOp(lbl_803DCD90, 1, 0, 0, 1, 2);
        } else {
            GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 2);
            GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 2);
        }
    } else if (param_3 == 1) {
        if (param_4 == 2) {
            GXSetTevColorIn(lbl_803DCD90, 0xf, 6, 8, 0xf);
        } else if (param_4 == 3) {
            GXSetTevColorIn(lbl_803DCD90, 6, 0xf, 8, 0xf);
        } else if (param_4 == 1) {
            GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 8, 6);
        } else if (param_5 == 0 || param_5 == 1) {
            GXSetTevColorIn(lbl_803DCD90, 0xf, 0xa, 8, 6);
        } else {
            GXSetTevColorIn(lbl_803DCD90, 0xf, 0xb, 8, 6);
        }
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 7);
        if (param_4 == 1) {
            GXSetTevColorOp(lbl_803DCD90, 1, 0, 0, 1, 3);
            GXSetTevAlphaOp(lbl_803DCD90, 1, 0, 0, 1, 3);
        } else {
            GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 3);
            GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 3);
        }
    } else {
        lbl_803DCD6B = 1;
        lbl_803DCD30 = 1;
        GXSetTevSwapModeTable(1, 0, 0, 0, 1);
        GXSetTevSwapMode(lbl_803DCD90, 1, 1);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0xc);
        if (param_4 == 3) {
            GXSetTevAlphaIn(lbl_803DCD90, 7, 5, 4, 6);
            GXSetTevAlphaOp(lbl_803DCD90, 1, 0, 0, 1, 0);
        } else {
            GXSetTevAlphaIn(lbl_803DCD90, 7, 5, 4, 7);
            GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        }
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    }
    if (param_1 != NULL) {
        if (param_1[0x48] != 0) {
            GXLoadTexObjPreLoaded(param_1 + 0x20, *(void **)(param_1 + 0x40), lbl_803DCD8C);
        } else {
            GXLoadTexObj(param_1 + 0x20, lbl_803DCD8C);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}
extern void C_MTXLightOrtho(f32 m[3][4], f32 t, f32 b, f32 l, f32 r, f32 sS, f32 sT, f32 tS, f32 tT);
extern int fn_8006C754(void);
extern int fn_8006C74C(void);
extern u8 *Obj_GetPlayerObject(void);
extern f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
extern void GXSetTevKAlphaSel(int tev, int sel);
extern f32 lbl_803DEAF4;
extern f32 lbl_803DEAF8;
extern f32 lbl_803DEAFC;
extern f32 lbl_803DEB00;
void fn_8004D230(void) {
    f32 mtx1[4][4];
    f32 mtx2[3][4];
    u8 *obj1;
    u8 *player;
    u8 *obj2;
    int id;
    f32 dist;
    f32 tmp;
    f32 t;

    obj1 = (u8 *)fn_8006C754();
    C_MTXLightOrtho(mtx1, lbl_803DEAF4, lbl_803DEAF8, lbl_803DEAF8, lbl_803DEAF4,
                    lbl_803DEADC, lbl_803DEADC, lbl_803DEADC, lbl_803DEADC);
    GXLoadTexMtxImm(mtx1, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevSwapModeTable(1, 0, 0, 0, 1);
    GXSetTevSwapMode(lbl_803DCD90, 1, 1);
    if (lbl_803DCD90 == 0) {
        GXSetTevColorIn(0, 0xf, 0xf, 0xf, 0xf);
    } else {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0);
    }
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 4);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 2);
    lbl_803DCD30 = 1;
    id = lbl_803DCD8C;
    if (obj1 != NULL) {
        void *obj = obj1 + 0x20;
        if (obj1[0x48] != 0) {
            GXLoadTexObjPreLoaded(obj, *(void **)(obj1 + 0x40), id);
        } else {
            GXLoadTexObj(obj, id);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    player = Obj_GetPlayerObject();
    if (player != NULL) {
        dist = Camera_DistanceToCurrentViewPosition(*(f32 *)(player + 0x18), *(f32 *)(player + 0x1c), *(f32 *)(player + 0x20));
    } else {
        dist = lbl_803DEAFC;
    }
    tmp = dist - lbl_803DEB00;
    t = -(lbl_803DEAC8 / (dist - tmp));
    mtx2[0][0] = lbl_803DEACC;
    mtx2[0][1] = lbl_803DEACC;
    mtx2[0][2] = t;
    mtx2[0][3] = t * tmp;
    mtx2[1][0] = lbl_803DEACC;
    mtx2[1][1] = lbl_803DEACC;
    mtx2[1][2] = lbl_803DEACC;
    mtx2[1][3] = lbl_803DEACC;
    mtx2[2][0] = lbl_803DEACC;
    mtx2[2][1] = lbl_803DEACC;
    mtx2[2][2] = lbl_803DEACC;
    mtx2[2][3] = lbl_803DEACC;
    GXLoadTexMtxImm(mtx2, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevSwapMode(lbl_803DCD90, 1, 1);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0);
    GXSetTevKAlphaSel(lbl_803DCD90, 0);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 2, 4, 6);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 1, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    obj2 = (u8 *)fn_8006C74C();
    id = lbl_803DCD8C;
    if (obj2 != NULL) {
        void *obj = obj2 + 0x20;
        if (obj2[0x48] != 0) {
            GXLoadTexObjPreLoaded(obj, *(void **)(obj2 + 0x40), id);
        } else {
            GXLoadTexObj(obj, id);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6B = 1;
    lbl_803DCD6A += 2;
    lbl_803DCD69 += 2;
}
extern void newshadows_getReflectionScrollOffsets(f32 *x, f32 *y);
extern int lbl_803DCD84;
extern f32 lbl_803DEAE0;
extern f32 bootThisDol;
extern f32 lbl_803DEAEC;
extern f32 lbl_803DEAF0;
void fn_8004CE0C(void *param_1) {
    f32 mtx40[3][4];
    f32 mtx70[3][4];
    f32 sx;
    f32 sy;
    u8 *obj7c;
    u8 *obj80;

    GXSetTexCoordGen2(0, 1, 4, 0x3c, 0, 0x7d);
    GXSetTevDirect(0);
    GXSetTevOrder(0, 0, 0, 4);
    GXSetTevColorIn(0, 0xf, 8, 10, 0xf);
    GXSetTevAlphaIn(0, 4, 7, 5, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    mtx40[0][0] = lbl_803DEAE4;
    mtx40[0][1] = lbl_803DEACC;
    mtx40[0][2] = lbl_803DEACC;
    mtx40[0][3] = lbl_803DEACC;
    mtx40[1][0] = lbl_803DEACC;
    mtx40[1][1] = lbl_803DEACC;
    mtx40[1][2] = lbl_803DEAE4;
    mtx40[1][3] = lbl_803DEACC;
    GXLoadTexMtxImm(mtx40, 0x1e, 1);
    GXSetTexCoordGen2(1, 1, 0, 0x1e, 0, 0x7d);
    getTextureFn_8006c5e4(&obj7c);
    if (obj7c != NULL) {
        void *obj = obj7c + 0x20;
        if (obj7c[0x48] != 0) {
            GXLoadTexObjPreLoaded(obj, *(void **)(obj7c + 0x40), 2);
        } else {
            GXLoadTexObj(obj, 2);
        }
    }
    newshadows_getReflectionScrollOffsets(&sx, &sy);
    PSMTXTrans(mtx70, lbl_803DEAE0 * sx, lbl_803DEAE0 * sy, lbl_803DEACC);
    mtx70[0][0] = bootThisDol;
    mtx70[1][1] = bootThisDol;
    GXLoadTexMtxImm(mtx70, 0x21, 1);
    GXSetTexCoordGen2(2, 1, 0, 0x21, 0, 0x7d);
    GXSetIndTexOrder(0, 2, 2);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetTevIndirect(1, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevKColorSel(1, 4);
    GXSetTevOrder(1, 1, 1, 0xff);
    GXSetTevColorIn(1, 8, 0xe, 0, 0);
    GXSetTevAlphaIn(1, 7, 4, 0, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 1, 1, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
    fn_8006C5B8(&obj80);
    if (obj80 != NULL) {
        void *obj = obj80 + 0x20;
        if (obj80[0x48] != 0) {
            GXLoadTexObjPreLoaded(obj, *(void **)(obj80 + 0x40), 3);
        } else {
            GXLoadTexObj(obj, 3);
        }
    }
    mtx40[0][0] = lbl_803DEACC;
    mtx40[0][1] = lbl_803DEACC;
    mtx40[0][2] = lbl_803DEAEC;
    mtx40[0][3] = lbl_803DEAF0;
    mtx40[1][0] = lbl_803DEACC;
    mtx40[1][1] = lbl_803DEACC;
    mtx40[1][2] = lbl_803DEACC;
    mtx40[1][3] = lbl_803DEACC;
    PSMTXConcat(mtx40, param_1, mtx40);
    GXLoadTexMtxImm(mtx40, 0x24, 1);
    GXSetTexCoordGen2(3, 1, 0, 0x24, 0, 0x7d);
    GXSetTevDirect(2);
    GXSetTevOrder(2, 3, 3, 0xff);
    GXSetTevColorIn(2, 0xf, 0xf, 0xf, 0);
    GXSetTevAlphaIn(2, 7, 4, 0, 7);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);
    lbl_803DCD90 = 3;
    lbl_803DCD88 = 4;
    lbl_803DCD8C = 4;
    lbl_803DCD7C = 1;
    lbl_803DCD84 = 0x27;
    lbl_803DCD6A = 3;
    lbl_803DCD69 = 4;
    lbl_803DCD68 = 1;
}
extern u32 getButtonsJustPressed(int set);
extern void printHeapStats(int a);
extern void defragMemory(int a);
extern void debugPrintSetColor(int r, int g, int b, int a);
extern void fn_80137948(char *fmt, ...);
extern char sAssetHaltFormat[];
extern int lbl_8035EF48[];
extern s16 lbl_803DCC78;
extern int lbl_803DCC70;
extern void loadTableFiles(void);
void loadDataFiles(void) {
    int *ids;
    char **names;
    int i;
    if (getButtonsJustPressed(2) & 0x100) {
        for (i = 0x50; i < 0x57; i++) {
        }
        printHeapStats(1);
    }
    if (getButtonsJustPressed(2) & 0x200) {
        defragMemory(0);
    }
    if (lbl_803DCC78 != 0) {
        if (lbl_803DCC78 == 1) {
            defragMemory(0);
        }
        lbl_803DCC78--;
    }
    i = 0;
    ids = lbl_8035EF48;
    names = sResourceFileNameTable;
    do {
        if (*ids != -1) {
            debugPrintSetColor(0, 0xff, 0, 0xff);
            fn_80137948(sAssetHaltFormat, *names);
            debugPrintSetColor(0xff, 0xff, 0xff, 0xff);
            lbl_803DCC70 = 1;
            if (mapLoadDataFile(*ids, i) != 0) {
                *ids = -1;
                printHeapStats(1);
            }
            lbl_803DCC70 = 0;
        }
        ids++;
        names++;
        i++;
    } while (i <= 0x57);
    loadTableFiles();
}
#pragma peephole reset
#pragma scheduling reset
extern void VIConfigure(void *mode);
void tvInit(void) {
    *(s16 *)((char *)lbl_803DCCF0 + 0xe) = 0x294;
    *(u16 *)((char *)lbl_803DCCF0 + 0xa) = *(u16 *)((char *)lbl_803DCCF0 + 0xa) - 0xa;
    VIConfigure(lbl_803DCCF0);
    VIFlush();
    VIWaitForRetrace();
    VIWaitForRetrace();
}
void mapsBinGetRomlistSize(int idx, int *out1, int *out2, int *out3, int p5) {
    char *base = (char *)lbl_8035F3E8;
    char *e;
    if (*(int *)(base + 0x74) == 0) return;
    if (*(int *)(base + 0x78) == 0) return;
    e = (char *)*(int *)(base + 0x74) + idx;
    *out1 = *(s16 *)(e + 0x1c);
    *out2 = *(s16 *)(e + 0x1e);
    *out3 = *(int *)((char *)*(int *)(base + 0x74) +
            *(int *)((char *)*(int *)(base + 0x78) + p5 * 4 + 0x18) + 4);
}
void trickyVoxAllocFn_8004b5d4(int *out) {
    out[0] = (int)mmAlloc(0x1960, 0x10, 0);
    out[1] = out[0] + 0xfe0;
    out[2] = out[1] + 0x7f0;
}
extern int DVDOpen(char *fileName, void *fileInfo);
extern int DVDRead(void *fileInfo, void *addr, int length, int offset);
extern void *memcpy(void *dst, const void *src, u32 n);
void *fileLoad(int id) {
    u8 fileInfo[0x3c];
    if (lbl_8035F3E8[id] != 0) {
        return (void *)lbl_8035F3E8[id];
    }
    DVDOpen(sResourceFileNameTable[id], fileInfo);
    lbl_8035F0A8[id] = *(s32 *)(fileInfo + 0x34);
    lbl_8035F3E8[id] = (u32)mmAlloc(lbl_8035F0A8[id] + 0x20, 0x7d7d7d7d, 0);
    DCInvalidateRange((void *)lbl_8035F3E8[id], lbl_8035F0A8[id]);
    DVDRead(fileInfo, (void *)lbl_8035F3E8[id], lbl_8035F0A8[id], 0);
    DVDClose(fileInfo);
    return (void *)lbl_8035F3E8[id];
}
int fileLoadToBuffer(int id, void *buffer) {
    u8 fileInfo[0x3c];
    if (lbl_8035F3E8[id] != 0) {
        memcpy(buffer, (void *)lbl_8035F3E8[id], lbl_8035F0A8[id]);
        DCStoreRange(buffer, lbl_8035F0A8[id]);
        return lbl_8035F0A8[id];
    }
    DVDOpen(sResourceFileNameTable[id], fileInfo);
    DCInvalidateRange(buffer, *(s32 *)(fileInfo + 0x34));
    DVDRead(fileInfo, buffer, *(s32 *)(fileInfo + 0x34), 0);
    DVDClose(fileInfo);
    return *(s32 *)(fileInfo + 0x34);
}
int fileLoadToBufferOffset(int id, void *buffer, int offset, int size) {
    u8 fileInfo[0x3c];
    void *tmp;
    int asize;
    if (size == 0) return 0;
    if (lbl_8035F3E8[id] != 0) {
        memcpy(buffer, (void *)(lbl_8035F3E8[id] + offset), size);
        DCStoreRange(buffer, size);
        return size;
    }
    DVDOpen(sResourceFileNameTable[id], fileInfo);
    if (((int)buffer & 0x1f) != 0 || (size & 0x1f) != 0) {
        asize = (size + 0x1f) & ~0x1f;
        tmp = mmAlloc(asize, 0x7d7d7d7d, 0);
        DCInvalidateRange(tmp, asize);
        DVDRead(fileInfo, tmp, asize, offset);
        memcpy(buffer, tmp, size);
        mm_free(tmp);
    } else {
        DCInvalidateRange(buffer, size);
        DVDRead(fileInfo, buffer, size, offset);
    }
    DVDClose(fileInfo);
    DCStoreRange(buffer, size);
    return size;
}
extern u8 lbl_803DCD30;
void fn_8004EECC(void) {
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 4);
    GXSetTevColorIn(lbl_803DCD90, 0, 0xf, 0xb, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A = lbl_803DCD6A + 1;
}
void fn_8004F080(void) {
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 0xff);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 4, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 3);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevDirect(lbl_803DCD90 + 1);
    GXSetTevOrder(lbl_803DCD90 + 1, 0xff, 0xff, 0xff);
    GXSetTevColorIn(lbl_803DCD90 + 1, 4, 0xf, 0xf, 0);
    GXSetTevAlphaIn(lbl_803DCD90 + 1, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90 + 1, 0, 0);
    GXSetTevColorOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90 + 1, 0, 0, 0, 1, 0);
    GXSetTevDirect(lbl_803DCD90 + 2);
    GXSetTevOrder(lbl_803DCD90 + 2, 0xff, 0xff, 4);
    GXSetTevColorIn(lbl_803DCD90 + 2, 0, 6, 0xb, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90 + 2, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90 + 2, 0, 0);
    GXSetTevColorOp(lbl_803DCD90 + 2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90 + 2, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 3;
    lbl_803DCD6A = lbl_803DCD6A + 3;
}
extern void textureFn_8006c75c(int a);
extern void GXSetTevKColorSel(int tev, int sel);
extern int lbl_803DCD84;
void fn_8004D928(void) {
    textureFn_8006c75c(lbl_803DCD8C);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0x24, 0, 0x7d);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevKColorSel(lbl_803DCD90, 6);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xe, 0);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD88++;
    lbl_803DCD90++;
    lbl_803DCD8C++;
    lbl_803DCD84 = 0x27;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}
void fn_8004FDA0(u8 *param_1, void *param_2) {
    GXSetTevDirect(lbl_803DCD90);
    GXLoadTexMtxImm(param_2, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 0, 0, 0, 0, lbl_803DCD80);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevKColorSel(lbl_803DCD90, 4);
    GXSetTevColorIn(lbl_803DCD90, 0xe, 9, 0, 0);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 1, 1, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    {
        int id = lbl_803DCD8C;
        if (param_1 != NULL) {
            void *obj = param_1 + 0x20;
            if (param_1[0x48] != 0) {
                GXLoadTexObjPreLoaded(obj, *(void **)(param_1 + 0x40), id);
            } else {
                GXLoadTexObj(obj, id);
            }
        }
    }
    lbl_803DCD88++;
    lbl_803DCD90++;
    lbl_803DCD8C++;
    lbl_803DCD80 += 3;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}
void fn_80050A28(int param_1) {
    f32 m[3][4];
    PSMTXScale(m, (f32)param_1, (f32)param_1, lbl_803DEACC);
    m[2][3] = lbl_803DEAC8;
    GXLoadTexMtxImm(m, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, 1, 4, 0x3c, 0, lbl_803DCD80);
    lbl_803DCD80 += 3;
    lbl_803DCD88++;
    lbl_803DCD69++;
}
void fn_8004F2B0(void) {
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 0xff);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 4, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A = lbl_803DCD6A + 1;
}
extern void GXSetTevColor(int id, void *color);
void fn_8004EF9C(int *param) {
    int color = param[0];
    GXSetTevColor(2, &color);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 0xff);
    GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 4, 0xf);
    GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A = lbl_803DCD6A + 1;
}
#pragma scheduling reset

extern u8 lbl_802CC6A0[];
extern char lbl_8035F680[];
extern void OSStopStopwatch(void *sw);
extern u64 OSCheckStopwatch(void *sw);
extern void OSResetStopwatch(void *sw);
extern void OSStartStopwatch(void *sw);
extern int OSGetCurrentThread(void);
extern int Queue_GetCount(void *q);
extern void OSSleepThread(void *q);
extern void OSRestoreInterrupts(int lvl);
extern void Camera_ApplyFullViewport(void);
extern void GXInvalidateVtxCache(void);
extern void GXInvalidateTexAll(void);
extern void OSReport(const char *fmt, ...);
extern int GXReadDrawSync(void);
extern void VISetNextFrameBuffer(void *fb);
extern void GXReadXfRasMetric(int *a, int *b, int *c, int *d);
extern void GXGetGPStatus(u8 *a, u8 *b, u8 *c, u8 *d, u8 *e);
extern void gxErrorFn_80060b40(void);
extern void modelFn_800292e0(void);
extern void __GXAbortWaitPECopyDone(void);
extern void GXInitFifoBase(void *fifo, void *base, u32 size);
extern void GXSetCPUFifo(void *fifo);
extern void GXSetGPFifo(void *fifo);
extern int GXInit(void *base, u32 size);
extern void Queue_Push(void *q, void *e);
extern void OSWakeupThread(void *q);
extern int Queue_Peek(void *q, void *out);
extern void Queue_Pop(void *q, void *out);
extern void GXDisableBreakPt(void);
extern void gxPerfFn_8004a77c(int v);
extern void THPPlayerPostDrawDone(void);
extern void GXPeekZ(int x, int y, void *out);
extern f32 lbl_803DCCC0;
extern f64 lbl_803DEA80;
extern u8 lbl_803DC950;
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern u8 framesThisStep;
extern f32 lbl_803DEA9C;
extern f32 lbl_803DEAA0;
extern f32 lbl_803DEA70;
extern f32 lbl_803DEA74;
extern f32 lbl_803DEA78;
extern f32 lbl_803DEA7C;
extern f32 lbl_803DCCB4;
extern u8 lbl_803DB411;
extern int lbl_803DCCDC;
extern char lbl_8035F730[];
extern int lbl_803DCCAC;
extern char lbl_803DCCC4[];
extern int lbl_803DCCA0;
extern u16 lbl_803DCCAA;
extern u8 lbl_803DCCA9;
extern int lbl_803DB5C8;
extern int lbl_803DD610;
extern s16 lbl_803966D0[];
extern s16 lbl_803965E0[];
extern u8 lbl_803DD000;
extern u8 lbl_803DD002;
extern u8 lbl_803DCCA8;
#pragma scheduling off
#pragma peephole off
void waitNextFrame(void)
{
    int lvl;
    u32 frames;

    OSStopStopwatch(lbl_8035F680);
    lbl_803DCCC0 = (f32)OSCheckStopwatch(lbl_8035F680) /
                   (f32)(u32)((*(u32 *)0x800000f8 >> 2) / 1000);
    OSResetStopwatch(lbl_8035F680);
    OSStartStopwatch(lbl_8035F680);
    timeDelta = lbl_803DEA9C * lbl_803DEAA0 * lbl_803DCCC0;
    if (lbl_803DC950 != 0) {
        timeDelta = lbl_803DEA70;
    }
    if (lbl_803DEA74 < timeDelta) {
        timeDelta = lbl_803DEA74;
    }
    oneOverTimeDelta = lbl_803DEA78;
    if (lbl_803DEA7C < timeDelta) {
        oneOverTimeDelta = lbl_803DEA78 / timeDelta;
    }
    frames = (int)(timeDelta + lbl_803DCCB4) & 0xff;
    lbl_803DB411 = frames;
    lbl_803DCCB4 = (timeDelta + lbl_803DCCB4) - (f32)(u32)frames;
    framesThisStep = lbl_803DB411;
    if (frames == 0) {
        framesThisStep = 1;
    }
    lvl = OSDisableInterrupts();
    lbl_803DCCDC = OSGetCurrentThread();
    if (*(s16 *)(lbl_803DCCDC + 0x2c8) != 2) {
        OSReport((char *)lbl_802CC6A0 + 0x401b8, *(s16 *)(lbl_803DCCDC + 0x2c8),
                 *(u16 *)(lbl_803DCCDC + 0x2ca), *(int *)(lbl_803DCCDC + 0x2cc));
    }
    if (Queue_GetCount(lbl_8035F730) > 1) {
        lbl_803DCCAC = 0;
        OSSleepThread(lbl_803DCCC4);
    }
    OSRestoreInterrupts(lvl);
    Camera_ApplyFullViewport();
    GXInvalidateVtxCache();
    GXInvalidateTexAll();
}
#pragma peephole reset
#pragma scheduling reset

void logGpuHang(void);
extern u8 lbl_803DCCB0;
extern void *lbl_803DCCD0;
extern void *lbl_803DCCD4;
extern void *lbl_803DCCD8;
extern void *lbl_803DCCE4;
extern u8 lbl_803DCCA7;
extern void *lbl_803DCCCC;
extern void *lbl_803DCCEC;
extern void *lbl_803DCCE8;
#pragma scheduling off
#pragma peephole off
void videoSwapFrameBuffers(void)
{
    u16 sync;
    int tok[3];
    char fifo[140];

    lbl_803DCCA0 = lbl_803DCCA0 + 1;
    sync = GXReadDrawSync();
    if (sync == (u16)(lbl_803DCCAA + 1)) {
        if (lbl_803DCCCC == lbl_803DCCEC) {
            lbl_803DCCCC = lbl_803DCCE8;
        } else {
            lbl_803DCCCC = lbl_803DCCEC;
        }
        lbl_803DCCAA = sync;
        VISetNextFrameBuffer(lbl_803DCCCC);
        VIFlush();
        lbl_803DCCA9 = 1;
        lbl_803DB5C8 = lbl_803DCCA0;
        lbl_803DCCA0 = 0;
    }
    lbl_803DCCAC = lbl_803DCCAC + 1;
    if (lbl_803DCCB0 != 0 && lbl_803DCCAC > 18000) {
        logGpuHang();
        gxErrorFn_80060b40();
        modelFn_800292e0();
        __GXAbortWaitPECopyDone();
        GXInitFifoBase(fifo, lbl_803DCCD0, 0x10000);
        GXSetCPUFifo(fifo);
        GXSetGPFifo(fifo);
        lbl_803DCCD4 = (void *)GXInit(lbl_803DCCD8, (u32)lbl_803DCCE4);
        if (Queue_IsEmpty(lbl_8035F730) == 0) {
            Queue_Pop(lbl_8035F730, tok);
        }
        OSWakeupThread(lbl_803DCCC4);
        if (Queue_IsEmpty(lbl_8035F730) == 0) {
            Queue_Peek(lbl_8035F730, tok);
            GXEnableBreakPt((void *)tok[0]);
        } else {
            GXDisableBreakPt();
            lbl_803DCCA7 = 0;
        }
        gxPerfFn_8004a77c(1);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void videoFn_800499e8(void)
{
    int i;
    u16 *src;
    u16 *dst;
    int tok[3];
    char peek[8];

    if (lbl_803DD610 == 2 || lbl_803DD610 == 3) {
        THPPlayerPostDrawDone();
    }
    Queue_Peek(lbl_8035F730, &peek);
    i = 0;
    src = (u16 *)lbl_803966D0;
    dst = (u16 *)lbl_803965E0;
    for (; i < (int)(u32)lbl_803DD000; i++) {
        dst[0] = src[0];
        dst[1] = src[1];
        *(int *)(dst + 4) = *(int *)(src + 4);
        GXPeekZ(dst[0], dst[1], dst + 2);
        src += 6;
        dst += 6;
    }
    lbl_803DD002 = lbl_803DD000;
    lbl_803DD000 = 0;
    if (*(int *)(peek + 4) == (int)lbl_803DCCCC) {
        lbl_803DCCA8 = 1;
        lbl_803DCCA9 = 0;
    } else {
        Queue_Pop(lbl_8035F730, tok);
        lbl_803DCCAC = 0;
        OSWakeupThread(lbl_803DCCC4);
        if (Queue_IsEmpty(lbl_8035F730) == 0) {
            Queue_Peek(lbl_8035F730, tok);
            GXEnableBreakPt((void *)tok[0]);
            lbl_803DCCA7 = 1;
        } else {
            GXDisableBreakPt();
            lbl_803DCCA7 = 0;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void logGpuHang(void)
{
    char *strs = (char *)lbl_802CC6A0;
    int topPerf0, topPerf1, topClks, topClks2;
    int botPerf0, botPerf1, botClks, botClks2;
    u32 xfStuck;
    u32 cmdStuck;
    int rdIdle;
    int cmdIdle;
    u8 fifoErr;
    char readIdle;
    char cmdRdy[2];

    GXReadXfRasMetric(&botPerf0, &botClks, &botPerf1, &botClks2);
    GXReadXfRasMetric(&topPerf0, &topClks, &topPerf1, &topClks2);
    xfStuck = (topClks - botClks) == 0;
    cmdStuck = (topPerf0 - botPerf0) == 0;
    rdIdle = (topClks2 - botClks2) != 0;
    cmdIdle = (topPerf1 - botPerf1) != 0;
    GXGetGPStatus(&fifoErr, &fifoErr, (u8 *)cmdRdy, (u8 *)&readIdle, &fifoErr);
    OSReport(strs + 0x4002c, cmdRdy[0], readIdle, xfStuck, cmdStuck, rdIdle, cmdIdle);
    if (cmdStuck == 0 && rdIdle != 0) {
        OSReport(strs + 0x400fc);
    } else if (xfStuck == 0 && cmdStuck != 0 && rdIdle != 0) {
        OSReport(strs + 0x4011c);
    } else if (readIdle == 0 && xfStuck != 0 && cmdStuck != 0 && rdIdle != 0) {
        OSReport(strs + 0x40144);
    } else if (cmdRdy[0] == 0 || readIdle == 0 || xfStuck == 0 || cmdStuck == 0 || rdIdle == 0 ||
               cmdIdle == 0) {
        OSReport(strs + 0x4019c);
    } else {
        OSReport(strs + 0x4016c);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void debugPrintfxy(int x, int y, const char *fmt, ...);
extern int OSGetResetButtonState(void);
extern void setShouldResetNextFrame(int v);
extern u8 lbl_803DCCA5;
extern u8 lbl_803DCCA6;
extern s8 lbl_803DCCA4;
extern u8 lbl_803DDA28;
extern char lbl_803DB5DC;
#pragma scheduling off
#pragma peephole off
void gpuErrorHandler(void)
{
    char *strs = (char *)lbl_802CC6A0;
    int r;
    int rdIdle;
    int cmdIdle;
    u32 xfStuck;
    u32 cmdStuck;
    int topPerf0, topPerf1, topClks, topClks2;
    int botPerf0, botPerf1, botClks, botClks2;
    u8 fifoErr;
    char readIdle;
    char cmdRdy[2];
    int tok[11];

    if (lbl_803DCCA8 != 0 && lbl_803DCCA9 != 0) {
        Queue_Pop(lbl_8035F730, tok);
        lbl_803DCCAC = 0;
        OSWakeupThread(lbl_803DCCC4);
        r = Queue_IsEmpty(lbl_8035F730);
        if (r == 0) {
            Queue_Peek(lbl_8035F730, tok);
            GXEnableBreakPt((void *)tok[0]);
        } else {
            GXDisableBreakPt();
        }
        lbl_803DCCA8 = 0;
        lbl_803DCCA9 = 0;
        lbl_803DCCA7 = r == 0;
    }
    lbl_803DCCA5 = 1;
    lbl_803DCCA6 = 1;
    if (lbl_803DCCA4 == 1) {
        if (OSGetResetButtonState() == 0) {
            lbl_803DCCA4 = lbl_803DCCA4 + 1;
            setShouldResetNextFrame(1);
        }
    } else if (lbl_803DCCA4 == 0 && OSGetResetButtonState() != 0) {
        lbl_803DCCA4 = lbl_803DCCA4 + 1;
    }
    if (lbl_803DDA28 != 0 && lbl_803DCCDC != 0 && lbl_803DCCAC > 600) {
        debugPrintfxy(0x32, 100, strs + 0x40000);
        GXReadXfRasMetric(&botPerf0, &botClks, &botPerf1, &botClks2);
        GXReadXfRasMetric(&topPerf0, &topClks, &topPerf1, &topClks2);
        xfStuck = (topClks - botClks) == 0;
        cmdStuck = (topPerf0 - botPerf0) == 0;
        rdIdle = (topClks2 - botClks2) != 0;
        cmdIdle = (topPerf1 - botPerf1) != 0;
        GXGetGPStatus(&fifoErr, &fifoErr, (u8 *)cmdRdy, (u8 *)&readIdle, &fifoErr);
        debugPrintfxy(0x32, 0x78, strs + 0x4002c, cmdRdy[0], readIdle, xfStuck, cmdStuck, rdIdle, cmdIdle);
        if (cmdStuck == 0 && rdIdle != 0) {
            debugPrintfxy(0x32, 0x8c, strs + 0x40048);
        } else if (xfStuck == 0 && cmdStuck != 0 && rdIdle != 0) {
            debugPrintfxy(0x32, 0x8c, strs + 0x40068);
        } else if (readIdle == 0 && xfStuck != 0 && cmdStuck != 0 && rdIdle != 0) {
            debugPrintfxy(0x32, 0x8c, strs + 0x40090);
        } else if (cmdRdy[0] == 0 || readIdle == 0 || xfStuck == 0 || cmdStuck == 0 ||
                   rdIdle == 0 || cmdIdle == 0) {
            debugPrintfxy(0x32, 0x8c, strs + 0x400e4);
        } else {
            debugPrintfxy(0x32, 0x8c, strs + 0x400b4);
        }
        debugPrintfxy(0x32, 0xa0, &lbl_803DB5DC, *(int *)(lbl_803DCCDC + 0x198));
    }
}
#pragma peephole reset
#pragma scheduling reset
