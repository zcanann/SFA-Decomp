#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8001746C.h"

typedef struct {
    int x, y, z;
} IVec3;

extern undefined4 FUN_800033a8();
extern undefined8 FUN_80003494();
extern int FUN_800066e8();
extern undefined4 FUN_800066f0();
extern undefined4 FUN_80006708();
extern undefined4 FUN_80006774();
extern uint FUN_80006780();
extern undefined4 FUN_80006784();
extern uint FUN_80006788();
extern undefined4 FUN_800067c0();
extern undefined8 FUN_80006808();
extern undefined8 FUN_8000680c();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006864();
extern undefined4 FUN_800068bc();
extern undefined4 FUN_800068c8();
extern undefined4 FUN_800068f8();
extern undefined4 FUN_800068fc();
extern int FUN_80006908();
extern undefined4 FUN_80006910();
extern undefined4 FUN_80006948();
extern undefined4 FUN_80006974();
extern undefined4 FUN_8000697c();
extern void* FUN_800069a8();
extern undefined4 FUN_80006a04();
extern undefined8 FUN_80006a84();
extern undefined4 FUN_80006adc();
extern undefined8 FUN_80006ae0();
extern undefined4 FUN_80006ae4();
extern undefined4 FUN_80006ae8();
extern undefined4 FUN_80006aec();
extern int FUN_80006af4();
extern undefined4 FUN_80006afc();
extern undefined8 FUN_80006b00();
extern undefined4 FUN_80006b04();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined8 FUN_80006b18();
extern undefined8 FUN_80006b58();
extern undefined8 FUN_80006b5c();
extern undefined4 FUN_80006b60();
extern int FUN_80006b7c();
extern undefined4 FUN_80006b84();
extern undefined4 FUN_80006b88();
extern undefined4 FUN_80006b8c();
extern undefined4 FUN_80006ba8();
extern char FUN_80006bc0();
extern char FUN_80006bd0();
extern uint FUN_80006c00();
extern uint FUN_80006c08();
extern uint FUN_80006c10();
extern undefined4 FUN_80006c18();
extern undefined4 FUN_80006c1c();
extern undefined4 FUN_80006c24();
extern undefined4 FUN_80006c28();
extern undefined8 FUN_80006c34();
extern undefined4 FUN_80006c38();
extern uint FUN_80006c54();
extern int FUN_80006c5c();
extern undefined8 FUN_80006c64();
extern undefined4 FUN_80006c68();
extern undefined4 FUN_80006c74();
extern undefined4 FUN_80006c7c();
extern undefined4 FUN_80006c80();
extern undefined4 FUN_80006c84();
extern undefined8 FUN_80006c88();
extern undefined4 FUN_80006c8c();
extern int FUN_80006c98();
extern void* FUN_80006c9c();
extern int FUN_80006ca4();
extern undefined4 ObjHits_TickPriorityHitCooldowns();
extern undefined4 ObjHits_Update();
extern undefined8 FUN_800356f0();
extern uint ObjHitbox_AllocRotatedBounds();
extern uint ObjHitReact_InitState();
extern uint ObjHits_AllocObjectState();
extern undefined8 ObjHitReact_UpdateResetObjects();
extern undefined4 ObjHits_ResetWorkBuffers();
extern undefined4 ObjHits_InitWorkBuffers();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern int ObjGroup_GetObjectGroup();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjGroup_ClearAll();
extern undefined4 ObjContact_RemoveObjectCallbacks();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800404cc();
extern undefined8 FUN_80040d88();
extern undefined8 FUN_80040d94();
extern undefined4 FUN_80041c10();
extern undefined4 FUN_80041ff8();
extern uint FUN_80042838();
extern int FUN_80042c18();
extern undefined4 FUN_80042f88();
extern undefined4 FUN_80043030();
extern undefined8 FUN_80044400();
extern undefined4 FUN_80044424();
extern undefined8 FUN_80044e24();
extern int FUN_800452f8();
extern undefined8 FUN_80045328();
extern undefined4 FUN_800455b8();
extern int FUN_80045734();
extern char FUN_800458ac();
extern undefined4 FUN_800458b0();
extern undefined4 FUN_80045b94();
extern undefined4 FUN_80045bd0();
extern undefined8 FUN_80045bd4();
extern undefined4 FUN_80045be8();
extern undefined4 FUN_80045c4c();
extern undefined4 FUN_80045d68();
extern undefined4 FUN_80045fcc();
extern undefined8 FUN_8004600c();
extern undefined8 FUN_80046fd4();
extern undefined4 FUN_8004812c();
extern undefined4 FUN_80052f20();
extern undefined4 FUN_80052fdc();
extern undefined8 FUN_80053074();
extern undefined4 FUN_80053078();
extern undefined8 FUN_80053754();
extern undefined4 FUN_80053758();
extern int FUN_800537a0();
extern int FUN_8005398c();
extern undefined8 FUN_80053aa0();
extern undefined4 FUN_80053c34();
extern undefined8 FUN_80055d10();
extern undefined8 FUN_800565fc();
extern undefined4 FUN_800566c8();
extern undefined4 FUN_800566cc();
extern int FUN_800566e0();
extern undefined4 FUN_800566e8();
extern undefined4 FUN_80056a4c();
extern undefined4 FUN_80056c88();
extern undefined4 FUN_80056cf8();
extern undefined8 FUN_80057048();
extern void fn_8005C8CC();
extern undefined8 FUN_8005c8ac();
extern undefined4 FUN_8005c8b0();
extern undefined4 FUN_8005cc24();
extern undefined4 FUN_8005d17c();
extern undefined4 FUN_8005d340();
extern undefined4 FUN_8005d370();
extern undefined8 FUN_800614d0();
extern uint FUN_800614dc();
extern undefined8 FUN_80061918();
extern undefined4 FUN_800620ec();
extern undefined4 FUN_800627a0();
extern undefined4 FUN_8006325c();
extern void trackDolphin_initIntersectionBuffers(void);
extern int newshadows_getSmallShadowTexture(void);
extern undefined8 FUN_8006bce4();
extern undefined4 FUN_8006efb4();
extern undefined4 FUN_8006f564();
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern void trackIntersect_invalidateCachedRenderState(void);
extern undefined4 FUN_8006fb14();
extern undefined4 FUN_8006fd74();
extern undefined4 FUN_8006fd84();
extern undefined4 FUN_8006fd88();
extern undefined4 FUN_8006fd90();
extern undefined4 FUN_8007089c();
extern undefined4 FUN_800709d8();
extern undefined4 FUN_800709dc();
extern undefined4 FUN_800709e0();
extern undefined4 FUN_800709e8();
extern undefined4 FUN_80071204();
extern undefined4 FUN_8007172c();
extern undefined4 FUN_80071d70();
extern undefined4 FUN_80071f8c();
extern undefined4 FUN_80071f90();
extern uint FUN_800723a0();
extern undefined4 FUN_800723d4();
extern int FUN_800723e0();
extern undefined4 FUN_800723e8();
extern undefined4 FUN_80072930();
extern undefined8 FUN_80081078();
extern int saveFileStruct_isCheatActive();
extern uint FUN_800e8b6c();
extern undefined4 FUN_800e99f8();
extern undefined4 FUN_800ea9b8();
extern undefined4 FUN_800eab50();
extern undefined8 camcontrol_playTargetTypeSfx();
extern undefined8 runLoadingScreens();
extern undefined4 n_rareware_frameStart();
extern undefined4 FUN_8012c9e8();
extern undefined4 FUN_801357e8();
extern undefined4 FUN_8013580c();
extern undefined8 FUN_80135810();
extern undefined4 FUN_80135818();
extern undefined8 FUN_80135b7c();
extern undefined4 FUN_80135c40();
extern undefined4 FUN_8016e834();
extern uint FUN_80240a7c();
extern undefined4 __OSEVSetNumber();
extern void* FUN_80241b84();
extern int FUN_80241de8();
extern int FUN_80241df0();
extern undefined4 FUN_802420b0();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_80242114();
extern undefined4 FUN_80242300();
extern undefined4 FUN_80242338();
extern undefined4 FUN_80242360();
extern undefined4 FUN_80242384();
extern undefined4 FUN_80242454();
extern ushort FUN_80243618();
extern undefined4 FUN_802436fc();
extern undefined4 FUN_80243a30();
extern undefined4 FUN_80243d34();
extern undefined4 FUN_80243e74();
extern undefined4 FUN_80243e9c();
extern undefined4 FUN_80244e58();
extern bool FUN_80244fa0();
extern uint FUN_80245218();
extern undefined4 FUN_80245ee0();
extern undefined4 FUN_80245f50();
extern undefined4 FUN_802473cc();
extern undefined4 FUN_802475b8();
extern undefined4 FUN_802475e4();
extern undefined4 FUN_80247618();
extern undefined4 FUN_802476e4();
extern undefined4 FUN_80247944();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247aa4();
extern undefined4 FUN_80247b70();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_80247cd8();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double SeekTwiceBeforeRead();
extern double FUN_80247f90();
extern undefined4 FUN_80247fb0();
extern undefined4 FUN_80248134();
extern undefined4 FUN_80249958();
extern undefined4 FUN_8024bad0();
extern undefined4 FUN_8024bb7c();
extern undefined4 FUN_8024bb8c();
extern undefined4 FUN_8024cbdc();
extern undefined8 FUN_8024d054();
extern undefined4 FUN_8024d51c();
extern undefined4 FUN_8024dcb8();
extern undefined4 FUN_8024de40();
extern ushort FUN_8024e0e0();
extern undefined4 FUN_8024edb8();
extern undefined4 FUN_8024ff34();
extern undefined4 FUN_802501f4();
extern undefined4 FUN_80250220();
extern undefined4 FUN_80259858();
extern undefined4 FUN_80259dd4();
extern undefined4 FUN_80259df0();
extern undefined4 FUN_80259e00();
extern undefined4 FUN_80259e10();
extern undefined4 FUN_80259e2c();
extern undefined4 FUN_80259fac();
extern undefined4 FUN_8025a07c();
extern undefined4 FUN_8025a08c();
extern undefined4 FUN_8025a0a8();
extern undefined4 FUN_8025a17c();
extern undefined4 FUN_8025a1a4();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025a608();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025da88();
extern undefined4 FUN_8025db38();
extern int FUN_8028680c();
extern undefined8 FUN_80286814();
extern undefined8 FUN_8028681c();
extern undefined8 FUN_80286824();
extern int FUN_80286828();
extern undefined8 FUN_8028682c();
extern ulonglong FUN_80286830();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern uint FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286858();
extern undefined4 FUN_80286860();
extern undefined4 FUN_80286868();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286874();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_8028fde8();
extern undefined4 FUN_802924c8();
extern undefined4 FUN_80292804();
extern undefined4 FUN_80292b24();
extern f32 powfBitEstimate(f32 x, f32 y);
extern undefined4 FUN_80293130();
extern undefined4 FUN_80293134();
extern undefined4 FUN_80293520();
extern undefined4 FUN_80293470();
extern double FUN_80293900();
extern undefined4 fcos16Precise();
extern undefined4 FUN_80293f7c();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_802950c0();
extern undefined4 FUN_802950cc();
extern undefined4 FUN_802950d0();
extern void mm_free(void *ptr);
extern void gxTextureFn_80072dfc(void *obj, void **model, int param_3);
extern void *textureIdxToPtr(int textureId);
extern void GXSetBlendMode(int type, int srcFactor, int dstFactor, int op);
extern void gxSetZMode_(u32 enable, int func, u32 update);
extern void gxSetPeControl_ZCompLoc_(u32 beforeTex);
extern void GXSetAlphaCompare(int comp0, int ref0, int op, int comp1, int ref1);
extern undefined4 FUN_802950d4();
extern undefined4 FUN_802950d8();
extern undefined4 FUN_802950dc();
extern uint countLeadingZeros();
extern longlong ldexpf();

extern undefined4 DAT_802c2204;
extern undefined4 DAT_802c2268;
extern undefined4 DAT_802c226c;
extern undefined4 DAT_802c2270;
extern undefined4 DAT_802c2274;
extern undefined4 DAT_802c2278;
extern undefined4 DAT_802c227c;
extern undefined4 DAT_802c7b54;
extern undefined DAT_802c7b80;
extern undefined4 DAT_802c7b98;
extern undefined4 DAT_802c7b9a;
extern undefined4 DAT_802c7cc2;
extern undefined4 DAT_802c7ccc;
extern undefined4 DAT_802c8b48;
extern undefined4 DAT_802c8b4a;
extern undefined4 DAT_802c8b54;
extern undefined4 DAT_802c8b56;
extern undefined4 DAT_802c8e06;
extern undefined4 DAT_802c8e08;
extern undefined4 DAT_802c8e0a;
extern undefined4 DAT_802c8e60;
extern undefined4 DAT_802c8e64;
extern undefined4 DAT_802c8e65;
extern undefined4 DAT_802c8e68;
extern undefined4 DAT_802c8e6a;
extern uint DAT_802c8e70;
extern undefined4 DAT_802c94c0;
extern undefined4 DAT_802c99a4;
extern undefined4 DAT_802c99f8;
extern undefined4 DAT_802ca2e4;
extern ushort DAT_802ca338;
extern short DAT_802caa68;
extern undefined4 DAT_802caa80;
extern undefined4 DAT_802caaa0;
extern undefined4 DAT_802caac0;
extern undefined4 DAT_802cac80;
extern undefined4 DAT_802caca8;
extern undefined4 DAT_802cacd0;
extern undefined4 DAT_802cacf8;
extern undefined4 DAT_802cb778;
extern undefined4 DAT_802cb77c;
extern undefined4 DAT_802cb780;
extern undefined4 DAT_802cb7b8;
extern undefined4 DAT_802cb7c0;
extern undefined4 DAT_802cb7c4;
extern undefined4 DAT_802cb7c8;
extern undefined4 DAT_8032f278;
extern undefined4 DAT_8032f2b4;
extern undefined4 DAT_8033a5e0;
extern undefined4 DAT_8033a600;
extern undefined2 DAT_8033a620;
extern undefined4* DAT_8033a628;
extern undefined4 DAT_8033a8a0;
extern undefined2 DAT_8033a8a4;
extern undefined4 DAT_8033a9a0;
extern undefined4 DAT_8033b1a0;
extern undefined4 DAT_8033b1a4;
extern undefined4 DAT_8033b1a8;
extern undefined4 DAT_8033b1ac;
extern undefined4 DAT_8033b1b0;
extern uint* DAT_8033bba0;
extern undefined4 DAT_8033bbbc;
extern byte DAT_8033bbc4;
extern byte DAT_8033bbc5;
extern int DAT_8033bbc8;
extern undefined4 DAT_8033bbe4;
extern uint* DAT_8033bbf0;
extern undefined4* DAT_8033bbf4;
extern undefined4 DAT_8033bbf8;
extern undefined4 DAT_8033bbfc;
extern undefined4 DAT_8033bc00;
extern undefined4 DAT_8033bc0c;
extern uint* DAT_8033bc18;
extern undefined DAT_8033bc40;
extern undefined4 DAT_8033bc8a;
extern undefined DAT_8033bc8c;
extern undefined4 DAT_8033bcd6;
extern undefined4 DAT_8033bd22;
extern undefined4 DAT_8033bd6e;
extern undefined4 DAT_8033bdba;
extern undefined4 DAT_8033be06;
extern undefined4 DAT_8033be52;
extern undefined4 DAT_8033be9e;
extern uint DAT_8033bea0;
extern undefined4 DAT_8033c2a0;
extern undefined4 DAT_8033c6a0;
extern undefined4 DAT_8033c6a4;
extern undefined4 DAT_8033caa0;
extern undefined4 DAT_8033caa4;
extern undefined4 DAT_8033caa8;
extern undefined4 DAT_8033caac;
extern undefined4 DAT_8033cab0;
extern undefined4 DAT_8033cab4;
extern undefined4 DAT_8033cab8;
extern undefined4 DAT_8033cabc;
extern char DAT_8033cac0;
extern undefined4 DAT_8033cac4;
extern undefined4 DAT_8033cac8;
extern undefined4 DAT_8033cacc;
extern undefined4 DAT_8033cad0;
extern undefined4 DAT_8033cae0;
extern undefined4 DAT_8033caf0;
extern undefined4 DAT_8033cb00;
extern undefined4 DAT_8033cb10;
extern uint DAT_8033cb20;
extern undefined4 DAT_8033cbe8;
extern undefined4 DAT_8033cbe9;
extern undefined4 DAT_8033cbec;
extern undefined4 DAT_8033cbf0;
extern undefined4 DAT_8033cbf4;
extern undefined4 DAT_8033cbf8;
extern undefined4 DAT_8033cc08;
extern undefined4 DAT_8033cc0c;
extern undefined4 DAT_8033cc18;
extern undefined4 DAT_8033cc1c;
extern undefined4 DAT_8033cc20;
extern undefined4 DAT_8033cc24;
extern undefined4 DAT_8033cfd8;
extern int DAT_8033d400;
extern undefined4 DAT_8033d478;
extern undefined4 DAT_8033d47c;
extern uint DAT_8033d480;
extern undefined4 DAT_8033d484;
extern undefined4 DAT_80341300;
extern int DAT_80341304;
extern int DAT_80341308;
extern undefined4 DAT_8034130c;
extern undefined4 DAT_80341310;
extern undefined4 DAT_8034131c;
extern undefined4 DAT_80341330;
extern undefined4 DAT_80341344;
extern undefined4 DAT_803413a0;
extern undefined4 DAT_803414e0;
extern undefined4 DAT_803414e4;
extern undefined4 DAT_803414e8;
extern undefined4 DAT_803414ec;
extern undefined4 DAT_803414f0;
extern undefined4 DAT_803414f4;
extern undefined4 DAT_803414f8;
extern undefined4 DAT_803414fc;
extern undefined4 DAT_80341500;
extern undefined4 DAT_80341504;
extern int DAT_80341508;
extern undefined4 DAT_803dbfd8;
extern undefined4 DAT_803dc024;
extern undefined4 DAT_803dc028;
extern undefined4 DAT_803dc02c;
extern undefined4 DAT_803dc034;
extern undefined4 DAT_803dc040;
extern undefined4 DAT_803dc04c;
extern undefined4 DAT_803dc050;
extern undefined4 DAT_803dc054;
extern undefined4 DAT_803dc058;
extern undefined4 DAT_803dc05c;
extern undefined4 DAT_803dc060;
extern undefined4 DAT_803dc068;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc07c;
extern undefined4 DAT_803dc084;
extern undefined4 DAT_803dc085;
extern undefined4 DAT_803dc088;
extern undefined4 DAT_803dc08c;
extern undefined4 DAT_803dc090;
extern undefined4 DAT_803dc094;
extern undefined4 DAT_803dc0a0;
extern undefined4 DAT_803dc0a8;
extern undefined4 DAT_803dc0ac;
extern undefined4 DAT_803dd198;
extern undefined4 DAT_803dd424;
extern undefined4 DAT_803dd426;
extern undefined4 DAT_803dd428;
extern undefined4 DAT_803dd4c8;
extern undefined4 DAT_803dd4c9;
extern undefined4 DAT_803dd5d0;
extern undefined4 DAT_803dd5d1;
extern undefined4 DAT_803dd5e0;
extern undefined4 DAT_803dd5e8;
extern undefined4* DAT_803dd5ec;
extern undefined4* DAT_803dd5f0;
extern undefined2* DAT_803dd5f4;
extern undefined4 DAT_803dd5f8;
extern undefined4 DAT_803dd5fc;
extern undefined4 DAT_803dd600;
extern undefined4 DAT_803dd604;
extern undefined4 DAT_803dd608;
extern undefined4 DAT_803dd60c;
extern undefined4 DAT_803dd610;
extern undefined4 DAT_803dd611;
extern undefined4 DAT_803dd612;
extern undefined4 DAT_803dd618;
extern undefined4 DAT_803dd61c;
extern undefined4 DAT_803dd624;
extern undefined4 DAT_803dd625;
extern undefined4 DAT_803dd626;
extern undefined4 DAT_803dd627;
extern undefined4 DAT_803dd628;
extern undefined4 DAT_803dd62a;
extern undefined4 DAT_803dd62c;
extern undefined4 DAT_803dd630;
extern undefined4 DAT_803dd634;
extern undefined4 DAT_803dd638;
extern undefined4 DAT_803dd63c;
extern undefined4* DAT_803dd644;
extern undefined4 DAT_803dd648;
extern undefined* DAT_803dd64c;
extern undefined4 DAT_803dd650;
extern undefined4 DAT_803dd654;
extern undefined4 DAT_803dd658;
extern undefined4 DAT_803dd65c;
extern undefined4 DAT_803dd660;
extern undefined4 DAT_803dd664;
extern undefined4 DAT_803dd668;
extern uint** DAT_803dd66c;
extern undefined4 DAT_803dd670;
extern undefined4 DAT_803dd674;
extern undefined4 DAT_803dd675;
extern undefined4 DAT_803dd676;
extern undefined4 DAT_803dd677;
extern undefined4 DAT_803dd678;
extern undefined4 DAT_803dd67c;
extern undefined4 DAT_803dd680;
extern undefined4 DAT_803dd684;
extern undefined4 DAT_803dd688;
extern undefined4 DAT_803dd690;
extern undefined4 DAT_803dd694;
extern undefined4 DAT_803dd698;
extern undefined4 DAT_803dd6a0;
extern undefined4 DAT_803dd6a4;
extern undefined4 DAT_803dd6a8;
extern undefined4 DAT_803dd6b0;
extern undefined4 DAT_803dd6b1;
extern undefined4 DAT_803dd6b4;
extern undefined4 DAT_803dd6b8;
extern undefined4 DAT_803dd6b9;
extern undefined4 DAT_803dd6ba;
extern undefined4 DAT_803dd6bb;
extern undefined4 DAT_803dd6bc;
extern undefined4 DAT_803dd6bd;
extern undefined4 DAT_803dd6be;
extern undefined4 DAT_803dd6bf;
extern undefined4 DAT_803dd6c0;
extern undefined4 DAT_803dd6c1;
extern undefined4 DAT_803dd6c2;
extern undefined4 DAT_803dd6c4;
extern undefined4 DAT_803dd6c6;
extern undefined4 DAT_803dd6c8;
extern undefined4 DAT_803dd6c9;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4 DAT_803dd6d8;
extern undefined4 DAT_803dd6dc;
extern undefined4 DAT_803dd6e0;
extern undefined4 DAT_803dd6e4;
extern undefined4 DAT_803dd6e8;
extern undefined4* DAT_803dd6ec;
extern undefined4* DAT_803dd6f0;
extern undefined4 DAT_803dd6f4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4 DAT_803dd700;
extern undefined4 DAT_803dd704;
extern undefined4 DAT_803dd708;
extern undefined4 DAT_803dd70c;
extern undefined4* DAT_803dd710;
extern undefined4* DAT_803dd714;
extern undefined4* DAT_803dd718;
extern undefined4 DAT_803dd71c;
extern undefined4 DAT_803dd720;
extern undefined4 DAT_803dd724;
extern undefined4 DAT_803dd728;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd734;
extern undefined4 DAT_803dd738;
extern undefined4* DAT_803dd73c;
extern undefined4 DAT_803dd740;
extern undefined4 DAT_803dd744;
extern undefined4 DAT_803dd745;
extern undefined4 DAT_803dd74c;
extern undefined4 DAT_803dd750;
extern undefined4 DAT_803dd754;
extern undefined4 DAT_803dd758;
extern undefined4 DAT_803dd75c;
extern undefined4 DAT_803dd760;
extern undefined4 DAT_803dd764;
extern undefined4 DAT_803dd768;
extern undefined4 DAT_803dd770;
extern undefined4 DAT_803dd774;
extern undefined4 DAT_803dd778;
extern undefined4* DAT_803dd77c;
extern undefined4 DAT_803dd788;
extern undefined4 DAT_803dd78c;
extern undefined4 DAT_803dd790;
extern undefined4 DAT_803dd794;
extern undefined4 DAT_803dd798;
extern undefined4 DAT_803dd79c;
extern undefined4 DAT_803dd7a0;
extern undefined4 DAT_803dd7a4;
extern undefined4 DAT_803dd7a8;
extern undefined4 DAT_803dd7ac;
extern undefined4 DAT_803dd7b0;
extern undefined4 DAT_803dd7b4;
extern undefined4 DAT_803dd7b8;
extern undefined4 DAT_803dd7bc;
extern undefined4 DAT_803dd7c0;
extern undefined4 DAT_803dd7c2;
extern undefined4 DAT_803dd7cc;
extern undefined4 DAT_803dd7d0;
extern undefined4* DAT_803dd7d4;
extern undefined4 DAT_803dd7d8;
extern short* DAT_803dd7dc;
extern short* DAT_803dd7e0;
extern short* DAT_803dd7e4;
extern undefined4 DAT_803dd7e8;
extern undefined4 DAT_803dd7f0;
extern undefined4 DAT_803dd7f4;
extern undefined4 DAT_803dd7f8;
extern undefined4 DAT_803dd7fc;
extern undefined4 DAT_803dd804;
extern int* DAT_803dd808;
extern undefined4 DAT_803dd80c;
extern int* DAT_803dd810;
extern undefined4 DAT_803dd814;
extern int* DAT_803dd818;
extern undefined4 DAT_803dd81c;
extern undefined4 DAT_803dd820;
extern undefined4 DAT_803dd824;
extern undefined4 DAT_803dd828;
extern undefined4 DAT_803dd82c;
extern int* DAT_803dd830;
extern undefined4 DAT_803dd834;
extern undefined4 DAT_803dd838;
extern int* DAT_803dd83c;
extern undefined4 DAT_803dd840;
extern undefined4 DAT_803dd844;
extern undefined4 DAT_803dd926;
extern undefined4* DAT_803dd970;
extern undefined4 DAT_803de110;
extern undefined4 DAT_803de288;
extern undefined4 DAT_803de29c;
extern undefined4 DAT_803df3c0;
extern f64 DOUBLE_803df370;
extern f64 DOUBLE_803df378;
extern f64 DOUBLE_803df3a8;
extern f64 DOUBLE_803df3b8;
extern f64 DOUBLE_803df3c8;
extern f64 DOUBLE_803df3f0;
extern f64 DOUBLE_803df400;
extern f64 DOUBLE_803df458;
extern f64 DOUBLE_803df460;
extern f64 DOUBLE_803df480;
extern f64 DOUBLE_803df4a0;
extern f64 DOUBLE_803df4b0;
extern f64 DOUBLE_803df528;
extern f64 DOUBLE_803df530;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803dc080;
extern f32 FLOAT_803dd614;
extern f32 FLOAT_803dd620;
extern f32 FLOAT_803dd68c;
extern f32 FLOAT_803dd748;
extern f32 FLOAT_803dd780;
extern f32 FLOAT_803dd7c8;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803ddb4c;
extern f32 FLOAT_803ddb50;
extern f32 FLOAT_803df384;
extern f32 FLOAT_803df388;
extern f32 FLOAT_803df38c;
extern f32 FLOAT_803df390;
extern f32 FLOAT_803df394;
extern f32 FLOAT_803df398;
extern f32 FLOAT_803df39c;
extern f32 FLOAT_803df3a0;
extern f32 FLOAT_803df3b0;
extern f32 FLOAT_803df3b4;
extern f32 FLOAT_803df3d0;
extern f32 FLOAT_803df3d4;
extern f32 FLOAT_803df3d8;
extern f32 FLOAT_803df3dc;
extern f32 FLOAT_803df3e0;
extern f32 FLOAT_803df3e4;
extern f32 FLOAT_803df3e8;
extern f32 FLOAT_803df3ec;
extern f32 FLOAT_803df3f8;
extern f32 FLOAT_803df408;
extern f32 FLOAT_803df40c;
extern f32 FLOAT_803df410;
extern f32 FLOAT_803df414;
extern f32 FLOAT_803df418;
extern f32 FLOAT_803df41c;
extern f32 FLOAT_803df420;
extern f32 FLOAT_803df424;
extern f32 FLOAT_803df428;
extern f32 FLOAT_803df42c;
extern f32 FLOAT_803df430;
extern f32 FLOAT_803df434;
extern f32 FLOAT_803df438;
extern f32 FLOAT_803df440;
extern f32 FLOAT_803df444;
extern f32 FLOAT_803df448;
extern f32 FLOAT_803df44c;
extern f32 FLOAT_803df450;
extern f32 FLOAT_803df454;
extern f32 FLOAT_803df470;
extern f32 FLOAT_803df474;
extern f32 FLOAT_803df478;
extern f32 FLOAT_803df488;
extern f32 FLOAT_803df48c;
extern f32 FLOAT_803df490;
extern f32 FLOAT_803df498;
extern f32 FLOAT_803df4a8;
extern f32 FLOAT_803df4b8;
extern f32 FLOAT_803df4bc;
extern f32 FLOAT_803df4c0;
extern f32 FLOAT_803df4c4;
extern f32 FLOAT_803df4c8;
extern f32 FLOAT_803df4cc;
extern f32 FLOAT_803df4d0;
extern f32 FLOAT_803df4d4;
extern f32 FLOAT_803df4d8;
extern f32 FLOAT_803df4dc;
extern f32 FLOAT_803df4e0;
extern f32 FLOAT_803df4e4;
extern f32 FLOAT_803df4e8;
extern f32 FLOAT_803df4ec;
extern f32 FLOAT_803df4f0;
extern f32 FLOAT_803df4f4;
extern f32 FLOAT_803df4f8;
extern f32 FLOAT_803df4fc;
extern f32 FLOAT_803df500;
extern f32 FLOAT_803df508;
extern f32 FLOAT_803df50c;
extern f32 FLOAT_803df510;
extern f32 FLOAT_803df514;
extern f32 FLOAT_803df518;
extern f32 FLOAT_803df51c;
extern f32 FLOAT_803df520;
extern f32 FLOAT_803df538;
extern f32 FLOAT_803df53c;
extern f32 FLOAT_803df548;
extern f32 FLOAT_803df54c;
extern f32 FLOAT_803df550;
extern f32 FLOAT_803df554;
extern f32 FLOAT_803df558;
extern void* PTR_s_Animtest_802c7a1c;
extern void* PTR_s_English_802c7b50;
extern int iRam803dd800;
extern short* psRam803dd800;
extern short sRam803dd7fe;
extern char s_H_H_H_H_H_H_H_H_802caad1[];
extern char s_Warning__Model_animation_buffer_o_802cb784[];
extern char s_Warning__Unknown_object_type___d_802cb8d8[];
extern char s_gametext_Sequences__d__s_bin_802caa48[];
extern char s_gametext__s__s_bin_802ca9f4[];
extern char s_objFreeObjdef__Error_____d__802cb880[];
extern undefined4* s_urstovwxazbcmdefghtkilnpoq_802ca93c;
extern undefined4 uRam00000000;

/*
 * --INFO--
 *
 * Function: gameTextFn_80017434
 * EN v1.0 Address: 0x80017434
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001746C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* moved below GameTextSlot/global declarations */

/*
 * --INFO--
 *
 * Function: FUN_80017438
 * EN v1.0 Address: 0x80017438
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80017508
 * EN v1.1 Size: 4104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017438(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001743c
 * EN v1.0 Address: 0x8001743C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80018510
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001743c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017440
 * EN v1.0 Address: 0x80017440
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80018644
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017440(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017448
 * EN v1.0 Address: 0x80017448
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80018728
 * EN v1.1 Size: 1236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017448(undefined4 param_1,undefined4 param_2,undefined4 *param_3,float *param_4,
                 float *param_5,uint param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001744c
 * EN v1.0 Address: 0x8001744C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80018BFC
 * EN v1.1 Size: 784b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001744c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017450
 * EN v1.0 Address: 0x80017450
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80018F0C
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80017450(int param_1,uint param_2,uint *param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017458
 * EN v1.0 Address: 0x80017458
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800191A4
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017458(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017460
 * EN v1.0 Address: 0x80017460
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800191FC
 * EN v1.1 Size: 640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 *
FUN_80017460(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017468
 * EN v1.0 Address: 0x80017468
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001947C
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 *
FUN_80017468(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017470
 * EN v1.0 Address: 0x80017470
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800195A8
 * EN v1.1 Size: 660b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
ushort * FUN_80017470(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                     undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                     uint param_9)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017478
 * EN v1.0 Address: 0x80017478
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001983C
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017478(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001747c
 * EN v1.0 Address: 0x8001747C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80019884
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001747c(ushort param_1,ushort param_2,uint param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017480
 * EN v1.0 Address: 0x80017480
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800198DC
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017480(int param_1,undefined4 param_2,undefined4 param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017484
 * EN v1.0 Address: 0x80017484
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80019940
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017484(byte param_1,byte param_2,byte param_3,byte param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017488
 * EN v1.0 Address: 0x80017488
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800199A8
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017488(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001748c
 * EN v1.0 Address: 0x8001748C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80019B4C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8001748c(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017494
 * EN v1.0 Address: 0x80017494
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80019B54
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017494(int param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017498
 * EN v1.0 Address: 0x80017498
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80019C28
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80017498(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800174a0
 * EN v1.0 Address: 0x800174A0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80019C30
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800174a0(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800174a8
 * EN v1.0 Address: 0x800174A8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80019C38
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_800174a8(void)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_800174b0
 * EN v1.0 Address: 0x800174B0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80019C44
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800174b0(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800174b8
 * EN v1.0 Address: 0x800174B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80019C5C
 * EN v1.1 Size: 1504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800174b8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800174bc
 * EN v1.0 Address: 0x800174BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001A23C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800174bc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800174c0
 * EN v1.0 Address: 0x800174C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001A26C
 * EN v1.1 Size: 492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800174c0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800174c4
 * EN v1.0 Address: 0x800174C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001A458
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800174c4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800174c8
 * EN v1.0 Address: 0x800174C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001A6A4
 * EN v1.1 Size: 684b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800174c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800174cc
 * EN v1.0 Address: 0x800174CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001A950
 * EN v1.1 Size: 1224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800174cc(void)
{
}

/*
 * --INFO--
 *
 * Function: textRenderStr
 * EN v1.0 Address: 0x800174D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001AE18
 * EN v1.1 Size: 1760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int curLanguage;
extern u8 *gameTextFonts;
extern void *gameTextDrawFunc;
extern char *sLanguageNameTable[][2];
extern u8 lbl_802C7400[];
extern u8 lbl_802C8680[];
extern f32 lbl_803DE704;
extern f32 lbl_803DE708;
extern f32 lbl_803DE70C;
extern f32 lbl_803DE710;
extern f32 lbl_803DE714;
extern f32 lbl_803DE718;
extern f32 lbl_803DC9A0;
extern f32 lbl_803DC994;
extern u8 lbl_803DC9A4;
extern u8 lbl_803DC9A5;
extern u8 lbl_803DC9A6;
extern u8 lbl_803DC9A7;
extern int lbl_803DC9BC;
extern int lbl_803DC9B0;
extern int lbl_803DC9AC;
extern int lbl_803DC9B8;
extern int lbl_803DC9B4;
extern int lbl_803DC998;
extern int lbl_803DC98C;
extern int lbl_803DC988;
extern int lbl_803DC99C;
extern int lbl_803DC9E8;
extern int lbl_803DB3CC;
typedef struct {
    u32 key;
    int len;
} CtrlCharEntry;
extern CtrlCharEntry lbl_802C86F0[];

#pragma push
#pragma scheduling off
#pragma peephole off
int getControlCharLen(u32 c) {
    CtrlCharEntry *p = lbl_802C86F0;
    int i;
    for (i = 45; i >= 0; i--) {
        if (p->key == c) {
            return p->len;
        }
        p++;
    }
    return 0;
}
#pragma pop

extern int utf8GetNextChar(u8 *p, int *outLen);
void gameTextMeasureString(u8 *str, f32 *outW, f32 *outZero, f32 scale, f32 *outMaxAdv, f32 *outMaxH, int glyphLang);
extern void translateToDinoLanguage(u8 *str);
extern void setTextColor(int a, int r, int g, int b, int al);
extern void _textSetColor(int a, int r, int g, int b, int al);
extern void textureSetupFn_800799c0(void);
extern void textRenderSetup(void);
extern void textRenderSetupFn_80079804(void);
extern void textRenderSetupFn_800795e8(void);
extern void textBlendSetupFn_80078a7c(void);
extern void selectTexture(void *tex, int a);
extern void GXGetScissor(u32 *a, u32 *b, u32 *c, u32 *d);
extern void GXSetScissor(u32 a, u32 b, u32 c, u32 d);
extern void gxSetScissorRect(int a, int b, int c, int d, int e, int f);
extern void textRenderChar(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1);

#pragma push
#pragma scheduling off
#pragma peephole off
void textRenderStr(u8 *str, u8 *win, int mode, f32 x, f32 y, f32 lineH) {
    int byteOff;
    int glyphLang;
    int curTexPage;
    int realign;
    int ch;
    int charLen;
    int n2;
    int i;
    int cnt;
    int skipGlyph;
    u8 *p;
    u8 *g;
    u8 *winBase;
    void *tex;
    f32 spaceExtra;
    f32 measW;
    f32 measN;
    f32 fx0, fy0, fx1, fy1;
    f32 u0, v0;
    int params[8];
    u32 scisX, scisY, scisW, scisH;

    byteOff = 0;
    spaceExtra = lbl_803DE704;
    if (lbl_803DC9E8 == 2) {
        glyphLang = 6;
    } else {
        glyphLang = ((u8 *)sLanguageNameTable)[curLanguage * 8 + 4];
    }
    curTexPage = -1;
    realign = 1;
    if (str == NULL) {
        return;
    }
    if (*(int *)(gameTextFonts + 0x1c) != 2) {
        return;
    }

    if (curLanguage != 4 && mode == 1 && saveFileStruct_isCheatActive(3) &&
        win == lbl_802C7400 + 0x140) {
        translateToDinoLanguage(str);
    }

    gameTextMeasureString(str, &measW, &measN, lbl_803DC9A0, 0, 0, -1);
    if (lbl_803DC9BC == 0) {
        setTextColor(0, lbl_803DC9A7, lbl_803DC9A6, lbl_803DC9A5, lbl_803DC9A4);
        _textSetColor(0, lbl_803DC9A7, lbl_803DC9A6, lbl_803DC9A5, lbl_803DC9A4);
        textureSetupFn_800799c0();
        textRenderSetup();
        textRenderSetupFn_80079804();
        textBlendSetupFn_80078a7c();
    }

    x = x + (f32)*(s16 *)(win + 0x14);
    y = y + (f32)*(s16 *)(win + 0x16);
    winBase = lbl_802C7400;

    while (p = str + byteOff, (ch = utf8GetNextChar(p, &charLen)) != 0) {
        byteOff += charLen;
        skipGlyph = 0;
        if (ch >= 0xe000 && ch <= 0xf8ff) {
            n2 = getControlCharLen(ch);
            for (i = 0; i < n2; i++) {
                int hi = str[byteOff++];
                int lo = str[byteOff++];
                params[i] = (hi << 8) | lo;
            }
            if ((u32)(ch - 0xf8f4) <= 0xb) {
                switch (ch) {
                case 0xf8f4:
                    lbl_803DC9A0 = (f32)params[0] * lbl_803DE708;
                    break;
                case 0xf8f7:
                    glyphLang = params[0];
                    break;
                case 0xf8f8:
                    win[0x12] = 0;
                    realign = 1;
                    break;
                case 0xf8f9:
                    win[0x12] = 1;
                    realign = 1;
                    break;
                case 0xf8fa:
                    win[0x12] = 2;
                    realign = 1;
                    break;
                case 0xf8fb:
                    win[0x12] = 3;
                    realign = 1;
                    break;
                case 0xf8ff:
                    if (mode == 0) {
                        lbl_803DC9A4 = params[3] * (lbl_803DC9A4 + 1) >> 8;
                        lbl_803DC9A7 = params[0];
                        lbl_803DC9A6 = params[1];
                        lbl_803DC9A5 = params[2];
                        if (lbl_803DC9BC == 0) {
                            setTextColor(0, lbl_803DC9A7, lbl_803DC9A6, lbl_803DC9A5, lbl_803DC9A4);
                            _textSetColor(0, lbl_803DC9A7, lbl_803DC9A6, lbl_803DC9A5, lbl_803DC9A4);
                            textureSetupFn_800799c0();
                            textRenderSetup();
                            textRenderSetupFn_80079804();
                            textBlendSetupFn_80078a7c();
                        }
                    }
                    skipGlyph = 1;
                    break;
                }
            }
            if (skipGlyph) {
                continue;
            }
        } else {
            if (mode == 0) {
                lbl_803DC998++;
            }
        }

        if (realign != 0) {
            switch (win[0x12]) {
            case 0:
                spaceExtra = lbl_803DE704;
                break;
            case 1:
                spaceExtra = lbl_803DE704;
                gameTextMeasureString(p, &measW, NULL, lbl_803DC9A0, 0, 0, -1);
                x = (f32)*(s16 *)(win + 0x14) +
                    ((f32)(u32)*(u16 *)(win + 8) - measW);
                break;
            case 2:
                spaceExtra = lbl_803DE704;
                gameTextMeasureString(p, &measW, NULL, lbl_803DC9A0, 0, 0, -1);
                x = ((f32)(u32)*(u16 *)(win + 8) - measW) * lbl_803DE70C +
                    (f32)*(s16 *)(win + 0x14);
                break;
            case 3: {
                int acc = 0;
                int spaceCount = 0;
                int innerCh;
                int innerLen;
                gameTextMeasureString(p, &measW, NULL, lbl_803DC9A0, 0, 0, -1);
                while ((innerCh = utf8GetNextChar(p + acc, &innerLen)) != 0) {
                    acc += innerLen;
                    if (innerCh == 0x20) {
                        spaceCount++;
                    }
                    if (innerCh >= 0xe000 && innerCh <= 0xf8ff) {
                        acc += getControlCharLen(innerCh) * 2;
                    }
                }
                spaceExtra = ((f32)(u32)*(u16 *)(win + 8) - measW) / (f32)spaceCount;
                break;
            }
            }
            realign = 0;
        }

        g = *(u8 **)gameTextFonts;
        cnt = *(int *)(gameTextFonts + 8);
        while (cnt-- != 0) {
            if (*(u32 *)g == (u32)ch && g[0xe] == glyphLang) {
                goto matched;
            }
            g += 0x10;
        }
        g = NULL;
    matched:
        if (g == NULL) {
            continue;
        }

        if (ch == 0xa) {
            x = lbl_803DE704;
            y = y + lineH;
            continue;
        }
        if (ch == 0x20) {
            x = lbl_803DC9A0 * (f32)(g[0xc] + (*(s8 *)(g + 8) + *(s8 *)(g + 9))) + x;
            x = x + spaceExtra;
            continue;
        }

        u0 = (f32)(*(u16 *)(g + 4) << 5);
        v0 = (f32)(*(u16 *)(g + 6) << 5);
        fx0 = lbl_803DE710 * (x + (f32)*(s8 *)(g + 8) * lbl_803DC9A0);
        fy0 = lbl_803DE710 * (y + (f32)*(s8 *)(g + 0xa) * lbl_803DC9A0);
        fx1 = lbl_803DE710 * ((f32)(u32)g[0xc] * lbl_803DC9A0) + fx0;
        fy1 = lbl_803DE710 * ((f32)(u32)g[0xd] * lbl_803DC9A0) + fy0;
        if (fx0 < lbl_803DE704 && fx1 > lbl_803DE704) {
            u0 = lbl_803DE714 * -fx0 + u0;
            fx0 = lbl_803DE704;
        }
        if (fy0 < lbl_803DE704 && fy1 > lbl_803DE704) {
            v0 = lbl_803DE714 * -fy0 + v0;
            fy0 = lbl_803DE704;
        }

        if (lbl_803DC9BC != 0) {
            if (fx0 < (f32)lbl_803DC9B0) {
                lbl_803DC9B0 = (int)fx0;
            }
            if (fx1 > (f32)lbl_803DC9AC) {
                lbl_803DC9AC = (int)fx1;
            }
            if (fy0 < (f32)lbl_803DC9B8) {
                lbl_803DC9B8 = (int)fy0;
            }
            if (fy1 > (f32)lbl_803DC9B4) {
                lbl_803DC9B4 = (int)fy1;
            }
        } else {
            if (g[0xe] == 3) {
                f32 shift = (f32)(lbl_803DB3CC << 2);
                fy0 = fy0 - shift;
                fy1 = fy1 - shift;
                GXGetScissor(&scisX, &scisY, &scisW, &scisH);
                if (scisY < lbl_803DB3CC) {
                    GXSetScissor(scisX, 0, scisW, scisH);
                } else {
                    GXSetScissor(scisX, scisY - lbl_803DB3CC, scisW, scisH);
                }
            }
            if (g[0xe] == 5) {
                int iw = g[0xc] + (*(s8 *)(g + 8) + *(s8 *)(g + 9));
                int ih = g[0xd] + (*(s8 *)(g + 0xa) + *(s8 *)(g + 0xb));
                GXGetScissor(&scisX, &scisY, &scisW, &scisH);
                gxSetScissorRect(0, 0, *(s16 *)(winBase + 0xfd4), *(s16 *)(winBase + 0xfd6),
                                 *(s16 *)(winBase + 0xfd4) + *(u16 *)(winBase + 0xfc8),
                                 *(s16 *)(winBase + 0xfd6) + *(u16 *)(winBase + 0xfca));
                fx0 = (f32)(*(s16 *)(winBase + 0xfd4) + ((*(u16 *)(winBase + 0xfc8) - iw) >> 1));
                fx1 = fx0 + (f32)iw;
                fy0 = (f32)(*(s16 *)(winBase + 0xfd6) + ((*(u16 *)(winBase + 0xfca) - ih) >> 1));
                fy1 = fy0 + (f32)ih;
                fx0 = fx0 * lbl_803DE710;
                fx1 = fx1 * lbl_803DE710;
                fy0 = fy0 * lbl_803DE710;
                fy1 = fy1 * lbl_803DE710;
            }

            if (mode != 0) {
                f32 ox = (f32)lbl_803DC98C;
                f32 oy = (f32)lbl_803DC988;
                fx0 = fx0 + ox;
                fx1 = fx1 + ox;
                fy0 = fy0 + oy;
                fy1 = fy1 + oy;
            }

            if (lbl_803DC9BC == 0) {
                if (curTexPage != g[0xf]) {
                    curTexPage = g[0xf];
                    tex = *(void **)(gameTextFonts + 0x10 + g[0xf] * 4);
                    selectTexture(tex, 0);
                    if (lbl_802C8680[g[0xe] * 16 + 6] == 1) {
                        if (mode != 0) {
                            setTextColor(0, 0, 0, 0, lbl_803DC9A4);
                        } else {
                            setTextColor(0, 0xff, 0xff, 0xff, lbl_803DC9A4);
                            textureSetupFn_800799c0();
                            textRenderSetupFn_800795e8();
                            textRenderSetupFn_80079804();
                        }
                    } else {
                        setTextColor(0, lbl_803DC9A7, lbl_803DC9A6, lbl_803DC9A5, lbl_803DC9A4);
                        _textSetColor(0, lbl_803DC9A7, lbl_803DC9A6, lbl_803DC9A5, lbl_803DC9A4);
                        textureSetupFn_800799c0();
                        textRenderSetup();
                        textRenderSetupFn_80079804();
                    }
                }
            }

            if (lbl_803DC99C != 0 && mode == 0 && g[0xe] != 5 &&
                (f32)lbl_803DC998 >= lbl_803DC994) {
                setTextColor(0, 0, 0, 0, 0);
            }

            if (gameTextDrawFunc != NULL) {
                f32 sW = lbl_803DE718 * (f32)(u32)*(u16 *)((u8 *)tex + 0xa);
                f32 sH = lbl_803DE718 * (f32)(u32)*(u16 *)((u8 *)tex + 0xc);
                ((void (*)(int, int, int, int, f32, f32, f32, f32))gameTextDrawFunc)(
                    (int)fx0, (int)fy0, (int)fx1, (int)fy1,
                    u0 / sW, v0 / sH,
                    (u0 + (f32)(g[0xc] << 5)) / sW,
                    (v0 + (f32)(g[0xd] << 5)) / sH);
            } else {
                f32 sW = lbl_803DE718 * (f32)(u32)*(u16 *)((u8 *)tex + 0xa);
                f32 sH = lbl_803DE718 * (f32)(u32)*(u16 *)((u8 *)tex + 0xc);
                textRenderChar((int)fx0, (int)fy0, (int)fx1, (int)fy1,
                               u0 / sW, v0 / sH,
                               (u0 + (f32)(g[0xc] << 5)) / sW,
                               (v0 + (f32)(g[0xd] << 5)) / sH);
            }

            if (g[0xe] == 3 || g[0xe] == 5) {
                GXSetScissor(scisX, scisY, scisW, scisH);
            }
        }

        if (g[0xe] != 5) {
            x = lbl_803DC9A0 * (f32)(g[0xc] + (*(s8 *)(g + 8) + *(s8 *)(g + 9))) + x;
        }
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void gameTextMeasureString(u8 *str, f32 *outW, f32 *outZero, f32 scale, f32 *outMaxAdv, f32 *outMaxH, int glyphLang) {
    int byteOff;
    u32 ch;
    int charLen;
    int n2;
    int i;
    int cnt;
    u8 *p;
    u8 *g;
    u8 *tbl;
    f32 width;
    f32 mAdv;
    f32 mH;
    int params[8];

    byteOff = 0;
    width = lbl_803DE704;
    if (str == NULL) {
        return;
    }
    if (glyphLang == -1) {
        if (lbl_803DC9E8 == 2) {
            glyphLang = 6;
        } else {
            glyphLang = ((u8 *)sLanguageNameTable)[curLanguage * 8 + 4];
        }
    }
    tbl = &lbl_802C8680[glyphLang * 16];
    if (glyphLang != 5) {
        if (outMaxAdv != NULL) {
            *outMaxAdv = (f32)(u32)*(u16 *)(tbl + 8) * scale;
        }
        if (outMaxH != NULL) {
            *outMaxH = (f32)(u32)*(u16 *)(tbl + 0xa) * scale;
        }
    }

    while (p = str + byteOff, (ch = utf8GetNextChar(p, &charLen)) != 0) {
        byteOff += charLen;
        if (ch >= 0xe000 && ch <= 0xf8ff) {
            n2 = getControlCharLen(ch);
            for (i = 0; i < n2; i++) {
                int hi = str[byteOff++];
                int lo = str[byteOff++];
                params[i] = (hi << 8) | lo;
            }
            switch (ch) {
            case 0xf8f7:
                glyphLang = params[0];
                tbl = &lbl_802C8680[glyphLang * 16];
                if (glyphLang != 5) {
                    mAdv = (f32)(u32)*(u16 *)(tbl + 8) * scale;
                    if (outMaxAdv != NULL && mAdv > *outMaxAdv) {
                        *outMaxAdv = mAdv;
                    }
                    mH = (f32)(u32)*(u16 *)(tbl + 0xa) * scale;
                    if (outMaxH != NULL && mH > *outMaxH) {
                        *outMaxH = mH;
                    }
                }
                break;
            case 0xf8f4:
                scale = (f32)params[0] * lbl_803DE708;
                break;
            }
            continue;
        }

        g = *(u8 **)gameTextFonts;
        cnt = *(int *)(gameTextFonts + 8);
        while (cnt-- != 0) {
            if (*(u32 *)g == (u32)ch && g[0xe] == glyphLang) {
                goto matched;
            }
            g += 0x10;
        }
        g = NULL;
    matched:
        if (g == NULL) {
            continue;
        }
        if (glyphLang == 5) {
            continue;
        }
        width = scale * (f32)(g[0xc] + (*(s8 *)(g + 8) + *(s8 *)(g + 9))) + width;
    }

    if (outW != NULL) {
        *outW = width;
    }
    if (outZero != NULL) {
        *outZero = lbl_803DE704;
    }
}
#pragma pop

extern u8 sGameTextGlyphOrder[];

#pragma push
#pragma scheduling off
#pragma peephole off
void translateToDinoLanguage(u8 *str) {
    int byteOff = 0;
    u32 ch;
    int charLen;
    u8 *p;

    if (str == NULL) {
        return;
    }
    while (p = str + byteOff, (ch = utf8GetNextChar(p, &charLen)) != 0) {
        if (ch >= 0xe000 && ch <= 0xf8ff) {
            byteOff += getControlCharLen(ch) * 2;
        } else {
            int base;
            if (ch >= 0x61 && ch <= 0x7a) {
                base = 0x61;
            } else if (ch >= 0x41 && ch <= 0x5a) {
                base = 0x41;
            } else {
                base = 0;
            }
            if (base != 0) {
                *p = sGameTextGlyphOrder[ch - base] + base - 0x61;
            }
        }
        byteOff += charLen;
    }
}
#pragma pop

extern char lbl_802C8F40[];
extern u8 lbl_80339980[];
extern u8 lbl_803399A0[];
extern u8 lbl_803399C0[];
extern int lbl_803DC970;
extern u8 *lbl_803DC974;
extern int lbl_803DC978;
extern int lbl_803DC97C;
extern f32 timeDelta;
extern f32 lbl_803DE704;
extern f32 lbl_803DE71C;
extern char lbl_803DB3D4[];
extern char *sMapDirectoryNameTable[];
extern void *curGameTextDir;
extern void *gameTextGet();
extern int sprintf(char *dst, const char *fmt, ...);

#pragma push
#pragma scheduling off
void *gameTextGetPhrase(int textId, int phraseIndex) {
    char *strings;
    u16 *entry;

    strings = lbl_802C8F40;
    if (*(int *)(gameTextFonts + 0x1c) != 2) {
        lbl_803DC97C = lbl_803DC97C + 1;
        if (lbl_803DC97C >= 8) {
            lbl_803DC97C = 0;
        }
        entry = (u16 *)(lbl_803399C0 + lbl_803DC97C * 0xc);
        lbl_803DC974 = (u8 *)entry;
        lbl_803DC978 = *(int *)*(int **)((u8 *)entry + 8);
        *entry = 0xffff;
        lbl_803DC970 = (int)(lbl_803399A0 + lbl_803DC97C * 4);
        switch (*(int *)(gameTextFonts + 0x1c)) {
        case 0:
            sprintf((char *)lbl_803DC978, strings + 0xec4);
            break;
        case 1:
            sprintf((char *)lbl_803DC978, strings + 0xed4);
            break;
        case 3:
            sprintf((char *)lbl_803DC978, strings + 0xee0);
            break;
        case 4:
            sprintf((char *)lbl_803DC978, strings + 0xef0);
            break;
        }
        return lbl_803DC974;
    }

    entry = gameTextGet();
    if (*entry == 0xffff) {
        lbl_803DC97C = lbl_803DC97C + 1;
        if (lbl_803DC97C >= 8) {
            lbl_803DC97C = 0;
        }
        entry = (u16 *)(lbl_803399C0 + lbl_803DC97C * 0xc);
        lbl_803DC974 = (u8 *)entry;
        lbl_803DC978 = *(int *)*(int **)((u8 *)entry + 8);
        *entry = 0xffff;
        lbl_803DC970 = (int)(lbl_803399A0 + lbl_803DC97C * 4);
        sprintf((char *)lbl_803DC978, strings + 0xefc, textId,
                sMapDirectoryNameTable[(int)curGameTextDir]);
        return lbl_803DC974;
    }

    if (phraseIndex >= entry[1]) {
        lbl_803DC97C = lbl_803DC97C + 1;
        if (lbl_803DC97C >= 8) {
            lbl_803DC97C = 0;
        }
        entry = (u16 *)(lbl_803399C0 + lbl_803DC97C * 0xc);
        lbl_803DC974 = (u8 *)entry;
        lbl_803DC978 = *(int *)*(int **)((u8 *)entry + 8);
        *entry = 0xffff;
        lbl_803DC970 = (int)(lbl_803399A0 + lbl_803DC97C * 4);
        sprintf((char *)lbl_803DC978, strings + 0xf10, textId, phraseIndex);
        return lbl_803DC974;
    }

    return *(void **)(*(int *)((u8 *)entry + 8) + phraseIndex * 4);
}

void *gameTextGetStr(void) {
    u8 *entry;
    void *t;

    if (*(int *)(gameTextFonts + 0x1c) == 2) {
        t = gameTextGet();
        return *(void **)*(u8 **)((u8 *)t + 8);
    }
    lbl_803DC97C = lbl_803DC97C + 1;
    if (lbl_803DC97C >= 8) {
        lbl_803DC97C = 0;
    }
    entry = lbl_803399C0 + lbl_803DC97C * 0xc;
    lbl_803DC974 = entry;
    lbl_803DC978 = *(int *)*(int **)(entry + 8);
    *(u16 *)entry = 0xffff;
    lbl_803DC970 = (int)(lbl_803399A0 + lbl_803DC97C * 4);
    switch (*(int *)(gameTextFonts + 0x1c)) {
    case 0:
        sprintf((char *)lbl_803DC978, lbl_802C8F40 + 0xec4);
        break;
    case 1:
        sprintf((char *)lbl_803DC978, lbl_802C8F40 + 0xed4);
        break;
    case 3:
        sprintf((char *)lbl_803DC978, lbl_802C8F40 + 0xee0);
        break;
    case 4:
        sprintf((char *)lbl_803DC978, lbl_802C8F40 + 0xef0);
        break;
    }
    return lbl_803DC974;
}
#pragma pop

#pragma push
#pragma scheduling off
void *gameTextGet(int textId) {
    u8 *gameTextBase;
    char *strings;
    u8 *fonts;
    u16 *entry;
    int count;
    int slotIndex;
    u16 *cachedEntry;
    u16 *prevCachedEntry;
    f32 zero;
    f32 fadeLimit;
    f32 *cachedAlpha;

    gameTextBase = lbl_80339980;
    strings = lbl_802C8F40;
    fonts = gameTextFonts;

    if (*(int *)(fonts + 0x1c) != 2) {
        lbl_803DC97C++;
        if (lbl_803DC97C >= 8) {
            lbl_803DC97C = 0;
        }
        entry = (u16 *)(gameTextBase + 0x40 + lbl_803DC97C * 0xc);
        lbl_803DC974 = (u8 *)entry;
        lbl_803DC978 = *(int *)*(int **)((u8 *)entry + 8);
        *entry = 0xffff;
        lbl_803DC970 = (int)(gameTextBase + 0x20 + lbl_803DC97C * 4);

        switch (*(int *)(gameTextFonts + 0x1c)) {
        case 0:
            sprintf((char *)lbl_803DC978, (char *)strings + 0xec4);
            break;
        case 1:
            sprintf((char *)lbl_803DC978, (char *)strings + 0xed4);
            break;
        case 3:
            sprintf((char *)lbl_803DC978, (char *)strings + 0xee0);
            break;
        case 4:
            sprintf((char *)lbl_803DC978, (char *)strings + 0xef0);
            break;
        }
        return lbl_803DC974;
    }

    entry = *(u16 **)(fonts + 4);
    count = *(int *)(fonts + 0xc);
    while (count != 0) {
        if (*entry == textId) {
            return entry;
        }
        entry += 6;
        count--;
    }

    slotIndex = 8;
    cachedEntry = (u16 *)(gameTextBase + 0xa0);
    while (1) {
        prevCachedEntry = cachedEntry;
        cachedEntry = prevCachedEntry - 6;
        if (slotIndex == 0) {
            break;
        }
        slotIndex--;
        if (*cachedEntry == textId) {
            zero = lbl_803DE704;
            *(f32 *)(gameTextBase + slotIndex * 4) = zero;
            cachedAlpha = (f32 *)(gameTextBase + 0x20 + slotIndex * 4);
            fadeLimit = lbl_803DE71C;
            if (zero < fadeLimit) {
                *cachedAlpha = zero + timeDelta;
                if (*cachedAlpha >= fadeLimit) {
                    sprintf((char *)*(int *)*(int **)((u8 *)cachedEntry + 8), strings + 0xefc, textId,
                            sMapDirectoryNameTable[(int)curGameTextDir]);
                }
            }
            return cachedEntry;
        }
    }

    lbl_803DC97C++;
    if (lbl_803DC97C >= 8) {
        lbl_803DC97C = 0;
    }
    entry = (u16 *)(gameTextBase + 0x40 + lbl_803DC97C * 0xc);
    lbl_803DC974 = (u8 *)entry;
    lbl_803DC978 = *(int *)*(int **)((u8 *)entry + 8);
    *entry = 0xffff;
    lbl_803DC970 = (int)(gameTextBase + 0x20 + lbl_803DC97C * 4);
    sprintf((char *)lbl_803DC978, lbl_803DB3D4, textId,
            sMapDirectoryNameTable[(int)curGameTextDir]);
    *(u16 *)lbl_803DC974 = (u16)textId;
    *(f32 *)lbl_803DC970 = lbl_803DE704;
    return lbl_803DC974;
}
#pragma pop

/*
 * --INFO--
 *
 * Function: FUN_800174d4
 * EN v1.0 Address: 0x800174D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001B4F8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800174d4(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800174d8
 * EN v1.0 Address: 0x800174D8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001B500
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800174d8(undefined4 param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800174e0
 * EN v1.0 Address: 0x800174E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001B520
 * EN v1.1 Size: 536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800174e0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800174e4
 * EN v1.0 Address: 0x800174E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001B738
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800174e4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800174e8
 * EN v1.0 Address: 0x800174E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001B7B4
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800174e8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800174ec
 * EN v1.0 Address: 0x800174EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001B86C
 * EN v1.1 Size: 960b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800174ec(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800174f0
 * EN v1.0 Address: 0x800174F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001BC2C
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800174f0(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800174f4
 * EN v1.0 Address: 0x800174F4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001BC8C
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800174f4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800174f8
 * EN v1.0 Address: 0x800174F8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001BD68
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800174f8(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017500
 * EN v1.0 Address: 0x80017500
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001BD8C
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80017500(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017508
 * EN v1.0 Address: 0x80017508
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001BDC8
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017508(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001750c
 * EN v1.0 Address: 0x8001750C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001BE88
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001750c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017510
 * EN v1.0 Address: 0x80017510
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001BEE0
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017510(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017514
 * EN v1.0 Address: 0x80017514
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001BF44
 * EN v1.1 Size: 1836b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017514(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017518
 * EN v1.0 Address: 0x80017518
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001C670
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017518(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001751c
 * EN v1.0 Address: 0x8001751C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001C858
 * EN v1.1 Size: 936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001751c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017520
 * EN v1.0 Address: 0x80017520
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001CC00
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017520(uint *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017524
 * EN v1.0 Address: 0x80017524
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001CD60
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017524(undefined4 param_1,undefined4 param_2,undefined param_3,undefined param_4,
                 uint param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017528
 * EN v1.0 Address: 0x80017528
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001CE70
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80017528(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017530
 * EN v1.0 Address: 0x80017530
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001D13C
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80017530(int param_1,int param_2)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017538
 * EN v1.0 Address: 0x80017538
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001D22C
 * EN v1.1 Size: 1208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017538(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001753c
 * EN v1.0 Address: 0x8001753C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001D6E4
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001753c(int param_1,int param_2,short param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017540
 * EN v1.0 Address: 0x80017540
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001D774
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017540(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017544
 * EN v1.0 Address: 0x80017544
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001D7D8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017544(double param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017548
 * EN v1.0 Address: 0x80017548
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001D7E0
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017548(int param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001754c
 * EN v1.0 Address: 0x8001754C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001D7F4
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001754c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017550
 * EN v1.0 Address: 0x80017550
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001D8BC
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017550(int param_1,undefined4 *param_2,undefined4 *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017554
 * EN v1.0 Address: 0x80017554
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001D8D0
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017554(int param_1,undefined4 param_2,undefined4 param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017558
 * EN v1.0 Address: 0x80017558
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001D8DC
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017558(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017560
 * EN v1.0 Address: 0x80017560
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001D8E4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017560(double param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017564
 * EN v1.0 Address: 0x80017564
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001D910
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017564(double param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017568
 * EN v1.0 Address: 0x80017568
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001D93C
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017568(double param_1,double param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001756c
 * EN v1.0 Address: 0x8001756C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001D9B4
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001756c(double param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,int param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017570
 * EN v1.0 Address: 0x80017570
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001DA48
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80017570(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017578
 * EN v1.0 Address: 0x80017578
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DA50
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017578(int param_1,undefined4 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001757c
 * EN v1.0 Address: 0x8001757C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DA58
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001757c(double param_1,double param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017580
 * EN v1.0 Address: 0x80017580
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DAA4
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017580(int param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017584
 * EN v1.0 Address: 0x80017584
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DAB8
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017584(int param_1,undefined *param_2,undefined *param_3,undefined *param_4,
                 undefined *param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017588
 * EN v1.0 Address: 0x80017588
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DADC
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017588(int param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001758c
 * EN v1.0 Address: 0x8001758C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DB00
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001758c(double param_1,double param_2,double param_3,int param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017590
 * EN v1.0 Address: 0x80017590
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DB24
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017590(double param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017594
 * EN v1.0 Address: 0x80017594
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DB7C
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017594(int param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017598
 * EN v1.0 Address: 0x80017598
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DB90
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017598(int param_1,undefined *param_2,undefined *param_3,undefined *param_4,
                 undefined *param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001759c
 * EN v1.0 Address: 0x8001759C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DBB4
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001759c(int param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175a0
 * EN v1.0 Address: 0x800175A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DBD8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175a0(int param_1,undefined param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175a4
 * EN v1.0 Address: 0x800175A4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001DBE0
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800175a4(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800175ac
 * EN v1.0 Address: 0x800175AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DBE8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175ac(int param_1,undefined4 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175b0
 * EN v1.0 Address: 0x800175B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DBF0
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175b0(int param_1,undefined4 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175b4
 * EN v1.0 Address: 0x800175B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DBF8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175b4(int param_1,undefined4 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175b8
 * EN v1.0 Address: 0x800175B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DC00
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175b8(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175bc
 * EN v1.0 Address: 0x800175BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DC18
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175bc(int param_1,undefined param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175c0
 * EN v1.0 Address: 0x800175C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DC20
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175c0(int param_1,undefined param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175c4
 * EN v1.0 Address: 0x800175C4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001DC28
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800175c4(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800175cc
 * EN v1.0 Address: 0x800175CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DC30
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175cc(double param_1,int param_2,char param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175d0
 * EN v1.0 Address: 0x800175D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DCFC
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175d0(double param_1,double param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175d4
 * EN v1.0 Address: 0x800175D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DD54
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175d4(double param_1,double param_2,double param_3,int *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175d8
 * EN v1.0 Address: 0x800175D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DE04
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175d8(int param_1,undefined param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175dc
 * EN v1.0 Address: 0x800175DC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001DE0C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_800175dc(int param_1)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_800175e4
 * EN v1.0 Address: 0x800175E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DE14
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175e4(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175e8
 * EN v1.0 Address: 0x800175E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DE30
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175e8(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175ec
 * EN v1.0 Address: 0x800175EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001DE4C
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175ec(double param_1,double param_2,double param_3,int *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175f0
 * EN v1.0 Address: 0x800175F0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001DF10
 * EN v1.1 Size: 812b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int * FUN_800175f0(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800175f8
 * EN v1.0 Address: 0x800175F8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001E23C
 * EN v1.1 Size: 812b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175f8(int param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800175fc
 * EN v1.0 Address: 0x800175FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001E568
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800175fc(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017600
 * EN v1.0 Address: 0x80017600
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001E6CC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017600(int param_1,undefined4 param_2,undefined4 param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017604
 * EN v1.0 Address: 0x80017604
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001E6F8
 * EN v1.1 Size: 704b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017604(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017608
 * EN v1.0 Address: 0x80017608
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001E9B8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017608(undefined param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001760c
 * EN v1.0 Address: 0x8001760C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001E9EC
 * EN v1.1 Size: 876b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001760c(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined4 param_7,undefined4 param_8,int *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017610
 * EN v1.0 Address: 0x80017610
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001ED58
 * EN v1.1 Size: 804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017610(undefined4 param_1,undefined4 param_2,int param_3,int *param_4,uint param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017614
 * EN v1.0 Address: 0x80017614
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001F07C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017614(int param_1,undefined *param_2,undefined *param_3,undefined *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017618
 * EN v1.0 Address: 0x80017618
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001F0A4
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017618(int param_1,undefined param_2,undefined param_3,undefined param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001761c
 * EN v1.0 Address: 0x8001761C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001F0C0
 * EN v1.1 Size: 904b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001761c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017620
 * EN v1.0 Address: 0x80017620
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001F448
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017620(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017624
 * EN v1.0 Address: 0x80017624
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001F58C
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int * FUN_80017624(int param_1,char param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8001762c
 * EN v1.0 Address: 0x8001762C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001F610
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001762c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017630
 * EN v1.0 Address: 0x80017630
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001F73C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017630(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017634
 * EN v1.0 Address: 0x80017634
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001F740
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017634(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017638
 * EN v1.0 Address: 0x80017638
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001F744
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017638(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001763c
 * EN v1.0 Address: 0x8001763C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001F79C
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001763c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017640
 * EN v1.0 Address: 0x80017640
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001F7E0
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017640(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017644
 * EN v1.0 Address: 0x80017644
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001F82C
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017644(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017648
 * EN v1.0 Address: 0x80017648
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001F870
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017648(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001764c
 * EN v1.0 Address: 0x8001764C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001F87C
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001764c(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017650
 * EN v1.0 Address: 0x80017650
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001FA3C
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017650(undefined4 param_1,undefined4 param_2,uint *param_3,uint *param_4,uint param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017654
 * EN v1.0 Address: 0x80017654
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001FB10
 * EN v1.1 Size: 828b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017654(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017658
 * EN v1.0 Address: 0x80017658
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001FE4C
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80017658(int *param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017660
 * EN v1.0 Address: 0x80017660
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001FE5C
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017660(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017664
 * EN v1.0 Address: 0x80017664
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001FF38
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017664(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017668
 * EN v1.0 Address: 0x80017668
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001FF54
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017668(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001766c
 * EN v1.0 Address: 0x8001766C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001FF6C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001766c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017670
 * EN v1.0 Address: 0x80017670
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001FF84
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017670(short param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017674
 * EN v1.0 Address: 0x80017674
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001FFA0
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017674(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8001767c
 * EN v1.0 Address: 0x8001767C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001FFA8
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001767c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017680
 * EN v1.0 Address: 0x80017680
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001FFAC
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80017680(uint param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017688
 * EN v1.0 Address: 0x80017688
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80020000
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80017688(uint param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017690
 * EN v1.0 Address: 0x80017690
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80020078
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80017690(uint param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017698
 * EN v1.0 Address: 0x80017698
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800201AC
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017698(uint param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001769c
 * EN v1.0 Address: 0x8001769C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80020380
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8001769c(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800176a4
 * EN v1.0 Address: 0x800176A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80020388
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176a4(undefined param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800176a8
 * EN v1.0 Address: 0x800176A8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80020390
 * EN v1.1 Size: 828b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800176a8(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800176b0
 * EN v1.0 Address: 0x800176B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800206CC
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176b0(undefined param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800176b4
 * EN v1.0 Address: 0x800176B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800206D8
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176b4(undefined param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800176b8
 * EN v1.0 Address: 0x800176B8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800206E4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_800176b8(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800176c0
 * EN v1.0 Address: 0x800176C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800206EC
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176c0(undefined param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800176c4
 * EN v1.0 Address: 0x800176C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800206F8
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176c4(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800176c8
 * EN v1.0 Address: 0x800176C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800207AC
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176c8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800176cc
 * EN v1.0 Address: 0x800176CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800207D0
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176cc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800176d0
 * EN v1.0 Address: 0x800176D0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80020800
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800176d0(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800176d8
 * EN v1.0 Address: 0x800176D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002080C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176d8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800176dc
 * EN v1.0 Address: 0x800176DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80020834
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176dc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800176e0
 * EN v1.0 Address: 0x800176E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800208B8
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176e0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800176e4
 * EN v1.0 Address: 0x800176E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80020A1C
 * EN v1.1 Size: 724b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176e4(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 int param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800176e8
 * EN v1.0 Address: 0x800176E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80020CF0
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176e8(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 int param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800176ec
 * EN v1.0 Address: 0x800176EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80020E50
 * EN v1.1 Size: 1456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800176f0
 * EN v1.0 Address: 0x800176F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80021400
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176f0(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 int param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800176f4
 * EN v1.0 Address: 0x800176F4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80021434
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_800176f4(double param_1,double param_2,double param_3)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_800176fc
 * EN v1.0 Address: 0x800176FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80021494
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800176fc(undefined4 param_1,undefined4 param_2,undefined2 *param_3,undefined2 *param_4,
                 undefined2 *param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017700
 * EN v1.0 Address: 0x80017700
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80021634
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017700(ushort *param_1,float *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017704
 * EN v1.0 Address: 0x80017704
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800216CC
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017704(undefined4 *param_1,undefined4 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017708
 * EN v1.0 Address: 0x80017708
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80021730
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80017708(float *param_1,float *param_2)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017710
 * EN v1.0 Address: 0x80017710
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80021754
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017710(float *param_1,float *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017714
 * EN v1.0 Address: 0x80017714
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80021794
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80017714(float *param_1,float *param_2)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_8001771c
 * EN v1.0 Address: 0x8001771C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800217C8
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001771c(float *param_1,float *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017720
 * EN v1.0 Address: 0x80017720
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80021818
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017720(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017728
 * EN v1.0 Address: 0x80017728
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80021850
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017728(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017730
 * EN v1.0 Address: 0x80017730
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80021884
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017730(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017738
 * EN v1.0 Address: 0x80017738
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800218B8
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017738(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017740
 * EN v1.0 Address: 0x80017740
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002191C
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017740(double param_1,double param_2,double param_3,float *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017744
 * EN v1.0 Address: 0x80017744
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80021970
 * EN v1.1 Size: 540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017744(undefined4 param_1,float *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017748
 * EN v1.0 Address: 0x80017748
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80021B8C
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017748(ushort *param_1,float *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001774c
 * EN v1.0 Address: 0x8001774C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80021C64
 * EN v1.1 Size: 800b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001774c(float *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017750
 * EN v1.0 Address: 0x80017750
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80021F84
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017750(double param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017754
 * EN v1.0 Address: 0x80017754
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80021FAC
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017754(float *param_1,ushort *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017758
 * EN v1.0 Address: 0x80017758
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80022150
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80017758(double param_1,double param_2,float *param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017760
 * EN v1.0 Address: 0x80017760
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80022264
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80017760(uint param_1,uint param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017768
 * EN v1.0 Address: 0x80017768
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80022324
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017768(undefined4 *param_1,undefined4 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001776c
 * EN v1.0 Address: 0x8001776C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800223A8
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001776c(float *param_1,float *param_2,float *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017770
 * EN v1.0 Address: 0x80017770
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800224C8
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017770(int param_1,int param_2,float *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017774
 * EN v1.0 Address: 0x80017774
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80022714
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017774(float *param_1,float *param_2,float *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017778
 * EN v1.0 Address: 0x80017778
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80022790
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017778(double param_1,double param_2,double param_3,float *param_4,float *param_5,
                 float *param_6,float *param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001777c
 * EN v1.0 Address: 0x8001777C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80022800
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001777c(float *param_1,float *param_2,float *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017780
 * EN v1.0 Address: 0x80017780
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800228BC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017780(double param_1,float *param_2,float *param_3,float *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017784
 * EN v1.0 Address: 0x80017784
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800228F0
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017784(float *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017788
 * EN v1.0 Address: 0x80017788
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80022974
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017788(float *param_1,float *param_2,float *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001778c
 * EN v1.0 Address: 0x8001778C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800229CC
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001778c(float *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017790
 * EN v1.0 Address: 0x80017790
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80022A0C
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017790(uint param_1,uint param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017794
 * EN v1.0 Address: 0x80017794
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80022A88
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017794(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017798
 * EN v1.0 Address: 0x80017798
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80022ABC
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017798(uint param_1,uint param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001779c
 * EN v1.0 Address: 0x8001779C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80022B0C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8001779c(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800177a4
 * EN v1.0 Address: 0x800177A4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80022B30
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800177a4(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800177ac
 * EN v1.0 Address: 0x800177AC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80022C14
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800177ac(uint param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800177b4
 * EN v1.0 Address: 0x800177B4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80022DE4
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800177b4(undefined4 param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800177bc
 * EN v1.0 Address: 0x800177BC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80022E00
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800177bc(undefined4 param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800177c4
 * EN v1.0 Address: 0x800177C4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80022E1C
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800177c4(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800177cc
 * EN v1.0 Address: 0x800177CC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80022ED0
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800177cc(uint param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800177d4
 * EN v1.0 Address: 0x800177D4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80022EE8
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800177d4(uint param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800177dc
 * EN v1.0 Address: 0x800177DC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80022F00
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800177dc(uint param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800177e4
 * EN v1.0 Address: 0x800177E4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80022F18
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800177e4(uint param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800177ec
 * EN v1.0 Address: 0x800177EC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80022F30
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800177ec(uint param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800177f4
 * EN v1.0 Address: 0x800177F4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80022F48
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800177f4(undefined4 param_1,undefined4 param_2,int param_3,undefined2 param_4,
                 undefined2 param_5,undefined4 param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800177f8
 * EN v1.0 Address: 0x800177F8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800230CC
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800177f8(undefined4 param_1,undefined4 param_2,int param_3,undefined2 param_4,
                 undefined2 param_5,undefined4 param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800177fc
 * EN v1.0 Address: 0x800177FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800231F8
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800177fc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017800
 * EN v1.0 Address: 0x80017800
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002337C
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017800(uint param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017808
 * EN v1.0 Address: 0x80017808
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800233D0
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017808(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001780c
 * EN v1.0 Address: 0x8001780C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800234AC
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001780c(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017810
 * EN v1.0 Address: 0x80017810
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800235B0
 * EN v1.1 Size: 788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017810(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017814
 * EN v1.0 Address: 0x80017814
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800238C4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017814(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017818
 * EN v1.0 Address: 0x80017818
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800238F8
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80017818(undefined4 param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017820
 * EN v1.0 Address: 0x80017820
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80023914
 * EN v1.1 Size: 984b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017820(undefined4 param_1,undefined4 param_2,undefined4 param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017824
 * EN v1.0 Address: 0x80017824
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80023CEC
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80017824(uint param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8001782c
 * EN v1.0 Address: 0x8001782C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80023D80
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001782c(undefined param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017830
 * EN v1.0 Address: 0x80017830
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80023D8C
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017830(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017838
 * EN v1.0 Address: 0x80017838
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80023F98
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017838(int param_1,int param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017840
 * EN v1.0 Address: 0x80017840
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80024060
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017840(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017844
 * EN v1.0 Address: 0x80017844
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002419C
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 * FUN_80017844(undefined4 *param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8001784c
 * EN v1.0 Address: 0x8001784C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800241F8
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001784c(undefined4 *param_1,undefined4 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017850
 * EN v1.0 Address: 0x80017850
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80024240
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 * FUN_80017850(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017858
 * EN v1.0 Address: 0x80017858
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800243D0
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017858(short *param_1,undefined4 *param_2,int param_3,undefined4 *param_4,
                 undefined4 *param_5,int param_6,int param_7,int param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001785c
 * EN v1.0 Address: 0x8001785C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800245A0
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001785c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017860
 * EN v1.0 Address: 0x80017860
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800245E8
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017860(int param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017864
 * EN v1.0 Address: 0x80017864
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80024764
 * EN v1.1 Size: 536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017864(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,uint param_5,
                 uint param_6,uint param_7,uint param_8,short param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017868
 * EN v1.0 Address: 0x80017868
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002497C
 * EN v1.1 Size: 1476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017868(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001786c
 * EN v1.0 Address: 0x8001786C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80024F40
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8001786c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,undefined4 param_11,undefined4 param_12)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017874
 * EN v1.0 Address: 0x80017874
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80024F8C
 * EN v1.1 Size: 1368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017874(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9,int param_10,undefined4 param_11,undefined4 param_12,uint *param_13,
                 int param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017878
 * EN v1.0 Address: 0x80017878
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800254E4
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017878(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001787c
 * EN v1.0 Address: 0x8001787C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80025894
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8001787c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,int param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017884
 * EN v1.0 Address: 0x80017884
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80025944
 * EN v1.1 Size: 612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017884(int param_1,uint param_2,int *param_3,int param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017888
 * EN v1.0 Address: 0x80017888
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80025BA8
 * EN v1.1 Size: 1108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017888(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001788c
 * EN v1.0 Address: 0x8001788C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80025FFC
 * EN v1.1 Size: 976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001788c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017890
 * EN v1.0 Address: 0x80017890
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800263CC
 * EN v1.1 Size: 1160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017890(undefined4 param_1,undefined4 param_2,int param_3,int *param_4,undefined *param_5,
                 undefined4 param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017894
 * EN v1.0 Address: 0x80017894
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80026854
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017894(int param_1,undefined4 param_2,int param_3,int *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017898
 * EN v1.0 Address: 0x80017898
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800269EC
 * EN v1.1 Size: 532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017898(int *param_1,int param_2,int *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001789c
 * EN v1.0 Address: 0x8001789C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80026C00
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001789c(undefined4 param_1,undefined4 param_2,int *param_3,undefined *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178a0
 * EN v1.0 Address: 0x800178A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80026CF4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178a0(int param_1,undefined param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178a4
 * EN v1.0 Address: 0x800178A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80026CFC
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178a4(double param_1,double param_2,double param_3,int param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178a8
 * EN v1.0 Address: 0x800178A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80026D0C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178a8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178ac
 * EN v1.0 Address: 0x800178AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80026D18
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178ac(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178b0
 * EN v1.0 Address: 0x800178B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80026D4C
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178b0(uint *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178b4
 * EN v1.0 Address: 0x800178B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80026DC0
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178b4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178b8
 * EN v1.0 Address: 0x800178B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80026EC4
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178b8(int param_1,int param_2,float *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178bc
 * EN v1.0 Address: 0x800178BC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80026FB8
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800178bc(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800178c4
 * EN v1.0 Address: 0x800178C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80027048
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178c4(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,undefined4 param_7,int param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178c8
 * EN v1.0 Address: 0x800178C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800271C8
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178c8(int *param_1,float *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178cc
 * EN v1.0 Address: 0x800178CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80027280
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178cc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178d0
 * EN v1.0 Address: 0x800178D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002736C
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178d0(undefined4 param_1,undefined4 param_2,float *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178d4
 * EN v1.0 Address: 0x800178D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800274C8
 * EN v1.1 Size: 1040b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178d4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178d8
 * EN v1.0 Address: 0x800178D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800278D8
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178d8(double param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178dc
 * EN v1.0 Address: 0x800178DC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800279A8
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800178dc(int *param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800178e4
 * EN v1.0 Address: 0x800178E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80027A44
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178e4(double param_1,int *param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178e8
 * EN v1.0 Address: 0x800178E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80027A90
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178e8(double param_1,int *param_2,int param_3,int param_4,int param_5,byte param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178ec
 * EN v1.0 Address: 0x800178EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80027B7C
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178ec(int *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178f0
 * EN v1.0 Address: 0x800178F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80027C04
 * EN v1.1 Size: 704b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178f0(undefined4 param_1,undefined4 param_2,int param_3,float *param_4,int param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178f4
 * EN v1.0 Address: 0x800178F4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80027EC4
 * EN v1.1 Size: 692b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178f4(double param_1,double param_2,int *param_3,int param_4,int param_5,float *param_6,
                 short *param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178f8
 * EN v1.0 Address: 0x800178F8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80028178
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800178f8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800178fc
 * EN v1.0 Address: 0x800178FC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800282C8
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
char * FUN_800178fc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                   undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                   int param_9,short param_10,short param_11,int param_12,undefined4 param_13,
                   undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017904
 * EN v1.0 Address: 0x80017904
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80028418
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017904(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8001790c
 * EN v1.0 Address: 0x8001790C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80028428
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8001790c(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017914
 * EN v1.0 Address: 0x80017914
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80028438
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017914(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8001791c
 * EN v1.0 Address: 0x8001791C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80028448
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001791c(int *param_1,int param_2,undefined4 *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017920
 * EN v1.0 Address: 0x80017920
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800284AC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017920(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017924
 * EN v1.0 Address: 0x80017924
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800284D8
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017924(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8001792c
 * EN v1.0 Address: 0x8001792C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800284E8
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8001792c(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017934
 * EN v1.0 Address: 0x80017934
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800284F8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 FUN_80017934(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8001793c
 * EN v1.0 Address: 0x8001793C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80028500
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001793c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017940
 * EN v1.0 Address: 0x80017940
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002854C
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017940(undefined4 param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017944
 * EN v1.0 Address: 0x80017944
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80028568
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017944(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8001794c
 * EN v1.0 Address: 0x8001794C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80028588
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8001794c(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017954
 * EN v1.0 Address: 0x80017954
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80028590
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017954(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017958
 * EN v1.0 Address: 0x80017958
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800285F0
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017958(int param_1,undefined4 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001795c
 * EN v1.0 Address: 0x8001795C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800285F8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8001795c(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017964
 * EN v1.0 Address: 0x80017964
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80028600
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017964(int param_1,undefined4 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017968
 * EN v1.0 Address: 0x80017968
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80028608
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017968(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001796c
 * EN v1.0 Address: 0x8001796C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002861C
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001796c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017970
 * EN v1.0 Address: 0x80017970
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80028630
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017970(int *param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017978
 * EN v1.0 Address: 0x80017978
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002867C
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017978(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017980
 * EN v1.0 Address: 0x80017980
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002868C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017980(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017984
 * EN v1.0 Address: 0x80017984
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80028728
 * EN v1.1 Size: 1264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017984(int param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017988
 * EN v1.0 Address: 0x80017988
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80028C18
 * EN v1.1 Size: 540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017988(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8001798c
 * EN v1.0 Address: 0x8001798C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80028E34
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8001798c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017990
 * EN v1.0 Address: 0x80017990
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80028F84
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017990(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017994
 * EN v1.0 Address: 0x80017994
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80029058
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017994(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017998
 * EN v1.0 Address: 0x80017998
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80029260
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined *
FUN_80017998(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            )
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800179a0
 * EN v1.0 Address: 0x800179A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800293B8
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179a0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179a4
 * EN v1.0 Address: 0x800179A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80029440
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179a4(int *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179a8
 * EN v1.0 Address: 0x800179A8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800295BC
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int * FUN_800179a8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                  undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                  byte *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                  uint *param_13,int param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800179b0
 * EN v1.0 Address: 0x800179B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80029648
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179b0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 *param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179b4
 * EN v1.0 Address: 0x800179B4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80029774
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800179b4(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800179bc
 * EN v1.0 Address: 0x800179BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002977C
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179bc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179c0
 * EN v1.0 Address: 0x800179C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002983C
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179c0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179c4
 * EN v1.0 Address: 0x800179C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800298B8
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179c4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179c8
 * EN v1.0 Address: 0x800179C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002990C
 * EN v1.1 Size: 880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179c8(undefined4 param_1,undefined4 param_2,int param_3,uint *param_4,uint param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179cc
 * EN v1.0 Address: 0x800179CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80029C7C
 * EN v1.1 Size: 628b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179cc(undefined4 param_1,undefined4 param_2,int param_3,int *param_4,int param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179d0
 * EN v1.0 Address: 0x800179D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80029EF0
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179d0(float *param_1,float *param_2,float *param_3,float *param_4,int param_5,
                 int param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179d4
 * EN v1.0 Address: 0x800179D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002A074
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179d4(float *param_1,float *param_2,float *param_3,float *param_4,int param_5,
                 int param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179d8
 * EN v1.0 Address: 0x800179D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002A1E8
 * EN v1.1 Size: 692b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179d8(float *param_1,float *param_2,float *param_3,float *param_4,float *param_5,
                 int param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179dc
 * EN v1.0 Address: 0x800179DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002A49C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179dc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179e0
 * EN v1.0 Address: 0x800179E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002A4A4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179e0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179e4
 * EN v1.0 Address: 0x800179E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002A4AC
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179e4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179e8
 * EN v1.0 Address: 0x800179E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002A4E4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179e8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179ec
 * EN v1.0 Address: 0x800179EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002A51C
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800179ec(undefined4 param_1,undefined4 param_2,ushort *param_3,int param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800179f0
 * EN v1.0 Address: 0x800179F0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002A690
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800179f0(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800179f8
 * EN v1.0 Address: 0x800179F8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002A698
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800179f8(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017a00
 * EN v1.0 Address: 0x80017A00
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002A6AC
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a00(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a04
 * EN v1.0 Address: 0x80017A04
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002A6B0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a04(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a08
 * EN v1.0 Address: 0x80017A08
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002A6B4
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a08(ushort *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a0c
 * EN v1.0 Address: 0x80017A0C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002A84C
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a0c(int param_1,undefined param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a10
 * EN v1.0 Address: 0x80017A10
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002A8D4
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a10(int param_1,undefined param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a14
 * EN v1.0 Address: 0x80017A14
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002A8E0
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a14(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a18
 * EN v1.0 Address: 0x80017A18
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002A8EC
 * EN v1.1 Size: 692b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a18(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a1c
 * EN v1.0 Address: 0x80017A1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002ABA0
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a1c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a20
 * EN v1.0 Address: 0x80017A20
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002ACFC
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_80017a20(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017a28
 * EN v1.0 Address: 0x80017A28
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002AD08
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a28(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a2c
 * EN v1.0 Address: 0x80017A2C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002AE08
 * EN v1.1 Size: 616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a2c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a30
 * EN v1.0 Address: 0x80017A30
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002B070
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a30(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a34
 * EN v1.0 Address: 0x80017A34
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002B11C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_80017a34(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017a3c
 * EN v1.0 Address: 0x80017A3C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002B128
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a3c(ushort *param_1,ushort param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a40
 * EN v1.0 Address: 0x80017A40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002B270
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a40(ushort *param_1,float *param_2,float *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a44
 * EN v1.0 Address: 0x80017A44
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002B2C0
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a44(ushort *param_1,float *param_2,float *param_3,char param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a48
 * EN v1.0 Address: 0x80017A48
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002B384
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a48(float *param_1,short *param_2,float *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a4c
 * EN v1.0 Address: 0x80017A4C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002B454
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a4c(short *param_1,undefined4 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a50
 * EN v1.0 Address: 0x80017A50
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002B554
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a50(ushort *param_1,float *param_2,char param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a54
 * EN v1.0 Address: 0x80017A54
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002B660
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80017a54(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017a5c
 * EN v1.0 Address: 0x80017A5C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002B678
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017a5c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,undefined4 param_10)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017a64
 * EN v1.0 Address: 0x80017A64
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002B738
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a64(int param_1,ushort param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a68
 * EN v1.0 Address: 0x80017A68
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002B754
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a68(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a6c
 * EN v1.0 Address: 0x80017A6C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002B7B0
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a6c(int param_1,int param_2,int param_3,int param_4,char param_5,char param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a70
 * EN v1.0 Address: 0x80017A70
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002B830
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a70(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a74
 * EN v1.0 Address: 0x80017A74
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002B938
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a74(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a78
 * EN v1.0 Address: 0x80017A78
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002B95C
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a78(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a7c
 * EN v1.0 Address: 0x80017A7C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002B9A0
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017a7c(int param_1,char param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017a80
 * EN v1.0 Address: 0x80017A80
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002B9C8
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80017a80(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017a88
 * EN v1.0 Address: 0x80017A88
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002BA34
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80017a88(double param_1,double param_2,double param_3,int param_4)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017a90
 * EN v1.0 Address: 0x80017A90
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002BA84
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80017a90(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017a98
 * EN v1.0 Address: 0x80017A98
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002BAC4
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80017a98(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017aa0
 * EN v1.0 Address: 0x80017AA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002BB04
 * EN v1.1 Size: 968b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017aa0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017aa4
 * EN v1.0 Address: 0x80017AA4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002BECC
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 * FUN_80017aa4(uint param_1,undefined2 param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017aac
 * EN v1.0 Address: 0x80017AAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002BF60
 * EN v1.1 Size: 1252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017aac(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017ab0
 * EN v1.0 Address: 0x80017AB0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002C444
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017ab0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017ab4
 * EN v1.0 Address: 0x80017AB4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002C528
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017ab4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017ab8
 * EN v1.0 Address: 0x80017AB8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002C6E4
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017ab8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,uint *param_11,int param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017abc
 * EN v1.0 Address: 0x80017ABC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002C7A0
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017abc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,uint *param_11,int param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017ac0
 * EN v1.0 Address: 0x80017AC0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002C85C
 * EN v1.1 Size: 872b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017ac0(short *param_1,undefined4 param_2,undefined4 param_3,int param_4,
                 undefined4 param_5,int param_6,undefined4 param_7,undefined4 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017ac4
 * EN v1.0 Address: 0x80017AC4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002CBC4
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017ac4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017ac8
 * EN v1.0 Address: 0x80017AC8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002CC9C
 * EN v1.1 Size: 624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017ac8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017acc
 * EN v1.0 Address: 0x80017ACC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002CF0C
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017acc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017ad0
 * EN v1.0 Address: 0x80017AD0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002CF80
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017ad0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017ad4
 * EN v1.0 Address: 0x80017AD4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002CFB8
 * EN v1.1 Size: 600b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017ad4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017ad8
 * EN v1.0 Address: 0x80017AD8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002D210
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017ad8(int param_1,int param_2,undefined4 param_3,uint param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017adc
 * EN v1.0 Address: 0x80017ADC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002D404
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017adc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,uint param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017ae0
 * EN v1.0 Address: 0x80017AE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002D654
 * EN v1.1 Size: 2612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017ae0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined param_11,undefined4 param_12,
                 uint *param_13,int param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017ae4
 * EN v1.0 Address: 0x80017AE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002E088
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017ae4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined param_11,undefined4 param_12,
                 uint *param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017ae8
 * EN v1.0 Address: 0x80017AE8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002E144
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80017ae8(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017af0
 * EN v1.0 Address: 0x80017AF0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002E174
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017af0(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017af8
 * EN v1.0 Address: 0x80017AF8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002E1AC
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80017af8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017b00
 * EN v1.0 Address: 0x80017B00
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8002E1F4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80017b00(undefined4 *param_1,undefined4 *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017b08
 * EN v1.0 Address: 0x80017B08
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002E21C
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017b08(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017b0c
 * EN v1.0 Address: 0x80017B0C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002E288
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017b0c(undefined4 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017b10
 * EN v1.0 Address: 0x80017B10
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002E38C
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017b10(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017b14
 * EN v1.0 Address: 0x80017B14
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002E4F4
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017b14(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017b18
 * EN v1.0 Address: 0x80017B18
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002E574
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017b18(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017b1c
 * EN v1.0 Address: 0x80017B1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002E720
 * EN v1.1 Size: 876b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017b1c(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,int param_12,
                 undefined4 param_13,int param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80017b20
 * EN v1.0 Address: 0x80017B20
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8002EA8C
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80017b20(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/* Pattern wrappers. */
void doNothing_8001F678(void) {}
#pragma dont_inline on
void doNothing_startOfFrame(void) {}
#pragma dont_inline reset
void doNothing_onSaveSelectScreenExit(void) {}
int return1_800202BC(void) { return 0x1; }
int return0_8002969C(void) { return 0x0; }
int return0_8002A5B8(void) { return 0x0; }
void doNothing_afterRenderObject(void) {}
void doNothing_beforeRenderObject(void) {}
void fn_8002B85C(void) {}

/* ObjModel/model-file accessors. */
typedef struct ObjModelRenderOpLite {
    u8 pad00[0x43];
    s8 alpha;
} ObjModelRenderOpLite;

typedef struct ObjModelFileHeaderLite {
    u8 pad00[0x38];
    ObjModelRenderOpLite *renderOps;
    u8 pad3c[0xf3 - 0x3c];
    u8 jointCount;
    u8 extraJointCount;
    u8 padf5[0xf8 - 0xf5];
    u8 renderOpCount;
} ObjModelFileHeaderLite;

typedef struct ObjModelInstanceLite {
    ObjModelFileHeaderLite *file;
    u8 pad04[0x0c - 0x04];
    u8 *jointMatrices[2];
    u8 pad14[0x18 - 0x14];
    u16 bufferFlags;
} ObjModelInstanceLite;

#pragma push
#pragma scheduling off
#pragma peephole off
void *fn_80028354(u8 *modelFile, int index) {
    return *(u8 **)(modelFile + 0x5c) + index * 8;
}

void *fn_80028364(u8 *modelFile, int index) {
    return *(u8 **)(modelFile + 0x60) + index * 0x14;
}

void *modelFileGetDisplayList(u8 *modelFile, int displayListIndex) {
    return *(u8 **)(modelFile + 0xd0) + displayListIndex * 0x1c;
}

void ObjModel_CopyJointTranslation(u8 *modelBytes, int jointIndex, f32 *out) {
    ObjModelInstanceLite *model;
    ObjModelFileHeaderLite *modelFile;
    uint jointCount;
    u8 *jointMtx;

    model = (ObjModelInstanceLite *)modelBytes;
    modelFile = model->file;
    jointCount = modelFile->jointCount;
    if (jointCount != 0) {
        jointCount += modelFile->extraJointCount;
    } else {
        jointCount = 1;
    }

    if (jointIndex >= (int)jointCount) {
        jointIndex = 0;
    }

    jointMtx = model->jointMatrices[model->bufferFlags & 1] + jointIndex * 0x40;
    out[0] = *(f32 *)(jointMtx + 0xc);
    out[1] = *(f32 *)(jointMtx + 0x1c);
    out[2] = *(f32 *)(jointMtx + 0x2c);
}

void *fn_800283E8(u8 *model, int textureIndex) {
    return textureIdxToPtr(*(int *)(*(u8 **)(model + 0x20) + textureIndex * 4));
}

void *ObjModel_GetBaseVertexCoords(u8 *model, int vertexIndex) {
    return *(u8 **)(model + 0x28) + vertexIndex * 6;
}

#pragma dont_inline on
void *ObjModel_GetRenderOp(u8 *model, int renderOpIndex) {
    return *(u8 **)(model + 0x38) + renderOpIndex * 0x44;
}
#pragma dont_inline reset

u16 modelFileHeaderGetCullDistance(u8 *modelFile) {
    return *(u16 *)(modelFile + 0xe0);
}

#pragma dont_inline on
void ObjModel_ClearRenderAttachment(u8 *model) {
    if (*(void **)(model + 0x58) != NULL) {
        mm_free(*(void **)(model + 0x58));
        *(void **)(model + 0x58) = NULL;
    } else {
        *(void **)(model + 0x38) = NULL;
    }
}
#pragma dont_inline reset

#pragma dont_inline on
void ObjModel_EnableDefaultRenderCallback(void *obj, u8 *model, f32 *mtx, int enabled, f32 scale) {
    if (*(void **)(model + 0x58) == NULL) {
        *(void **)(model + 0x38) = gxTextureFn_80072dfc;
    }
}
#pragma dont_inline reset

void *ObjModel_GetCurrentVertexCoords(u8 *model, int vertexIndex) {
    model += (((*(u16 *)(model + 0x18) >> 1) & 1) * 4);
    return *(u8 **)(model + 0x1c) + vertexIndex * 6;
}

void *ObjModel_GetPostRenderCallback(u8 *model) {
    return *(void **)(model + 0x3c);
}

void fn_800284CC(void) {
    GXSetBlendMode(1, 4, 1, 5);
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void ObjModel_SetPostRenderCallback(u8 *model, void *callback) {
    *(void **)(model + 0x3c) = callback;
}

void *ObjModel_GetRenderCallback(u8 *model) {
    return *(void **)(model + 0x38);
}

void ObjModel_SetRenderCallback(u8 *model, void *callback) {
    *(void **)(model + 0x38) = callback;
}

void ObjModel_ToggleVertexBuffer(u8 *model) {
    *(u16 *)(model + 0x18) ^= 2;
}

void ObjModel_ToggleMatrixBuffer(u8 *model) {
    *(u16 *)(model + 0x18) ^= 1;
}

void *ObjModel_GetJointMatrix(u8 *modelBytes, int jointIndex) {
    ObjModelInstanceLite *model;
    ObjModelFileHeaderLite *modelFile;
    uint jointCount;

    model = (ObjModelInstanceLite *)modelBytes;
    modelFile = model->file;
    jointCount = modelFile->jointCount;
    if (jointCount != 0) {
        jointCount += modelFile->extraJointCount;
    } else {
        jointCount = 1;
    }

    if (jointIndex >= (int)jointCount) {
        jointIndex = 0;
    }

    return model->jointMatrices[model->bufferFlags & 1] + jointIndex * 0x40;
}

void *ObjModel_GetRenderOpTextureRefs(u8 *model, int renderOpIndex) {
    return *(u8 **)(model + 0x34) + renderOpIndex * 0xc;
}

int ObjModel_GetUnpackedResourceSize(u8 *resource, int baseSize) {
    return baseSize + resource[8] * resource[7];
}

void Obj_SetModelRenderOpAlpha(u8 *obj, int alpha) {
    int renderOpAlpha;
    int renderOpIndex;
    ObjModelFileHeaderLite *modelFile;
    ObjModelInstanceLite *model;

    renderOpAlpha = alpha;
    model = *(ObjModelInstanceLite **)(*(u8 **)(obj + 0x7c) + (s8)obj[0xad] * 4);
    if (model != NULL) {
        modelFile = model->file;
        if (modelFile != NULL) {
            for (renderOpIndex = 0; renderOpIndex < modelFile->renderOpCount; renderOpIndex++) {
                ((ObjModelRenderOpLite *)ObjModel_GetRenderOp((u8 *)modelFile, renderOpIndex))
                    ->alpha = renderOpAlpha;
            }
        }
    }
}

void Obj_SetModelSlotIndex(u8 *obj, int slotIndex) {
    *(s8 *)(obj + 0xac) = slotIndex;
}

void Obj_ClearModelSlotIndex(u8 *obj) {
    *(s8 *)(obj + 0xac) = -1;
}

void *Obj_GetActiveModel(u8 *obj) {
    return *(void **)(*(u8 **)(obj + 0x7c) + (s8)obj[0xad] * 4);
}

extern int *lbl_803DCAB4;
extern u8 framesThisStep;
extern f32 lbl_803DE88C;
extern f32 lbl_803DE89C;
extern f32 lbl_803DE8A0;
extern void Obj_BuildWorldTransformMatrix(u8 *obj, f32 *mtx, int flags);

void Obj_ClearModelColorFadeRecursive(u8 *obj) {
    int i;
    u8 *childScan;

    *(s16 *)(obj + 0xe6) = 0;
    obj[0xe5] &= ~0x6;
    i = 0;
    childScan = obj;
    while (i < obj[0xeb]) {
        Obj_ClearModelColorFadeRecursive(*(u8 **)(childScan + 0xc8));
        childScan += 4;
        i++;
    }
}

void Obj_TickModelColorFadeRecursive(u8 *obj) {
    f32 alpha;
    int i;
    u8 *childScan;

    if ((obj[0xe5] & 4) != 0) {
        alpha = (f32)obj[0xef] + lbl_803DE89C * timeDelta;
    } else {
        alpha = (f32)obj[0xef] - lbl_803DE89C * timeDelta;
    }

    if (alpha < lbl_803DE88C) {
        alpha = -alpha;
        obj[0xe5] ^= 4;
    } else if (alpha > lbl_803DE8A0) {
        alpha = lbl_803DE8A0 - (alpha - lbl_803DE8A0);
        obj[0xe5] ^= 4;
    }

    *(s8 *)(obj + 0xef) = (int)alpha;
    if ((obj[0xe5] & 8) == 0) {
        *(s16 *)(obj + 0xe6) -= framesThisStep;
        if (*(s16 *)(obj + 0xe6) <= 0 && *(void **)(obj + 0xc4) == NULL) {
            Obj_ClearModelColorFadeRecursive(obj);
        }
    }

    i = 0;
    childScan = obj;
    while (i < obj[0xeb]) {
        Obj_TickModelColorFadeRecursive(*(u8 **)(childScan + 0xc8));
        childScan += 4;
        i++;
    }
}

#pragma dont_inline on
void Obj_SetModelColorFadeRecursive(u8 *obj, int frames, u8 red, u8 green, u8 blue, u8 startAtHalf) {
    int i;
    u8 *childScan;

    *(s16 *)(obj + 0xe6) = (s16)frames;
    obj[0xe5] &= ~4;
    obj[0xe5] |= 2;
    obj[0xec] = red;
    obj[0xed] = green;
    obj[0xee] = blue;
    if (frames == 10000) {
        obj[0xe5] |= 8;
    } else {
        obj[0xe5] &= ~8;
    }
    if (startAtHalf != 0) {
        obj[0xef] = 0x7f;
    } else {
        obj[0xef] = 0;
    }

    i = 0;
    childScan = obj;
    while (i < obj[0xeb]) {
        Obj_SetModelColorFadeRecursive(*(u8 **)(childScan + 0xc8), frames, red, green, blue, startAtHalf);
        childScan += 4;
        i++;
    }
}
#pragma dont_inline reset

void Obj_SetModelColorOverrideRecursive(u8 *obj, u8 red, u8 green, u8 blue, u8 alpha, u8 enabled) {
    int i;
    u8 *childScan;

    if (enabled != 0) {
        obj[0xe5] |= 0x10;
        obj[0xec] = red;
        obj[0xed] = green;
        obj[0xee] = blue;
        obj[0xef] = alpha;
    } else {
        obj[0xe5] &= ~0x10;
    }

    i = 0;
    childScan = obj;
    while (i < obj[0xeb]) {
        Obj_SetModelColorOverrideRecursive(*(u8 **)(childScan + 0xc8), red, green, blue, alpha, enabled);
        childScan += 4;
        i++;
    }
}

void Obj_ResetModelColorState(u8 *obj) {
    *(s16 *)(obj + 0xe6) = 0;
    obj[0xe5] &= ~1;
    obj[0xf0] = 0;
    ObjModel_ClearRenderAttachment((u8 *)Obj_GetActiveModel(obj));
    (*(void (*)(int, int, int, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))((int)obj, 0x7fb, 0, 0x50, 0);
    (*(void (*)(int, int, int, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))((int)obj, 0x7fc, 0, 0x32, 0);
}

#pragma peephole off
void Obj_StartModelFadeIn(u8 *obj, int frames) {
    f32 mtx[16];
    int fadeLimit;
    s16 objType;

    fadeLimit = 10;
    objType = *(s16 *)(obj + 0x44);
    if (objType == 0x1c || objType == 0x6d || objType == 0x2a) {
        fadeLimit = 40;
    }
    if ((*(u8 *)(*(u8 **)(obj + 0x50) + 0x76) & 1) != 0) {
        if (obj[0xf0] < fadeLimit) {
            obj[0xf0]++;
            Obj_SetModelColorFadeRecursive(obj, 0x1e, 0xa0, 0xff, 0xff, 0);
        }
        if (obj[0xf0] == fadeLimit) {
            if ((obj[0xe5] & 2) != 0) {
                Obj_ClearModelColorFadeRecursive(obj);
            }
            *(s16 *)(obj + 0xe6) = (s16)frames;
            obj[0xe5] = (u8)(obj[0xe5] | 1);
            Obj_BuildWorldTransformMatrix(obj, mtx, 0);
            ((void (*)(u8 *, u8 *, f32 *, int, f32))ObjModel_EnableDefaultRenderCallback)(
                obj, *(u8 **)(*(u8 **)(obj + 0x7c) + (s8)obj[0xad] * 4), mtx, 1,
                *(f32 *)(obj + 0xa8) * *(f32 *)(obj + 8));
            (*(void (*)(int, int, int, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))((int)obj, 0x7fc, 0, 0x64, 0);
        }
    }
}
#pragma peephole reset

#pragma pop

/* Global game-state / text accessors. */
extern u8 lbl_803DCA3D;
extern u8 lbl_803DCA3C;
extern u8 lbl_803DCA3E;
extern s8 lbl_803DCA3A;
extern s8 lbl_803DCA3B;
extern s16 lbl_803DCA46;
extern int curLanguage;
extern void *curGameTextDir;

#pragma dont_inline on
int getGameState(void) {
    return lbl_803DCA3D;
}
#pragma dont_inline reset

extern u8 lbl_803DCA49;
extern void init(void);
extern void checkReset(void);
extern void gameLoop(void);

void main(void) {
    lbl_803DCA3D = 0;
    lbl_803DCA49 = 0;
    init();
    lbl_803DCA49 = 1;
    lbl_803DCA3D = 1;
    do {
        checkReset();
        gameLoop();
    } while (1);
}

#pragma peephole off
void setGameState(int state) {
    lbl_803DCA3D = (u8)state;
}

void setTimeStop(int v) {
    lbl_803DCA3C = (u8)v;
}

void setShouldResetNextFrame(int v) {
    lbl_803DCA3E = (u8)v;
}
#pragma peephole reset

void setFrameCountdown_800202c4(u8 v) {
    lbl_803DCA3B = v;
}

#pragma dont_inline on
int getHudHiddenFrameCount(void) {
    return lbl_803DCA3A;
}
#pragma dont_inline reset

s16 getScreenBlankFrameCount(void) {
    return lbl_803DCA46;
}

int getCurLanguage(void) {
    return curLanguage;
}

#pragma dont_inline on
void *getCurGameText(void) {
    return curGameTextDir;
}
#pragma dont_inline reset

int objIsFrozen(u8 *obj) {
    return obj[0xe5] & 1;
}

int objGetFlagsE5_2(u8 *obj) {
    return obj[0xe5] & 2;
}

void objSetEventName(u8 *obj, void *name) {
    *(void **)(obj + 0x60) = name;
}

void crash(void) {
    *(u8 *)0 = 0;
}

void __set_debug_bba(u8 *p) {
    p[0x19] = 0;
}

#pragma peephole off
int roundUpTo4(int x) {
    int r = x & 3;
    if (r > 0) {
        x += 4 - r;
    }
    return x;
}

#pragma dont_inline on
int roundUpTo8(int x) {
    int r = x & 7;
    if (r > 0) {
        x += 8 - r;
    }
    return x;
}

int roundUpTo16(int x) {
    int r = x & 0xf;
    if (r > 0) {
        x += 0x10 - r;
    }
    return x;
}

int roundUpTo32(int x) {
    int r = x & 0x1f;
    if (r > 0) {
        x += 0x20 - r;
    }
    return x;
}
#pragma dont_inline reset
#pragma peephole reset

/* Simple field/global accessors. */
extern int lbl_803DC9E8;
extern void *gameTextDrawFunc;
extern u8 *gameTextFonts;
extern u8 lbl_803DCB10;
extern int lbl_803DCAE8[2];
extern u8 lbl_803DCA48;

void fn_8001D714(u8 *p, f32 v) {
    *(f32 *)(p + 0x2f4) = v;
}

void *fn_8001D818(u8 *p) {
    return p + 0x230;
}

void *fn_8001D984(u8 *p) {
    return *(void **)(p + 0x16c);
}

void fn_8001D98C(u8 *p, void *v) {
    *(void **)(p + 0x16c) = v;
}

void *fn_8001DB1C(u8 *p) {
    return *(void **)(p + 0x54);
}

void fn_8001DB24(u8 *p, void *v) {
    *(void **)(p + 0x54) = v;
}

void fn_8001DB5C(u8 *p, u8 v) {
    p[0x2fc] = v;
}

void *fn_8001DB64(u8 *p) {
    return *(void **)(p + 0x58);
}

f32 fn_8001DD48(u8 *p) {
    return *(f32 *)(p + 0x144);
}

void fn_80026C30(u8 *p, u8 v) {
    p[0x1a] = v;
}

#pragma dont_inline on
int gameTextFn_80019b14(void) {
    return lbl_803DC9E8;
}
#pragma dont_inline reset

#pragma dont_inline on
void gameTextSetDrawFunc(void *fn) {
    gameTextDrawFunc = fn;
}
#pragma dont_inline reset

void lightSetField2FB(u8 *p, u8 v) {
    p[0x2fb] = v;
}

void lightSetField4D(u8 *p, u8 v) {
    p[0x4d] = v;
}

void lightSetFieldBC_8001db14(u8 *p, u8 v) {
    p[0xbc] = v;
}

void modelLightStruct_setField50(u8 *p, void *v) {
    *(void **)(p + 0x50) = v;
}

extern u8 lbl_803DCA30;
extern void *lbl_8033BEC0[];
extern void *objAllocLight(void *owner);
extern void GXInitLightDistAttn(u8 *lt_obj, f32 ref_dist, f32 ref_br, int dist_func);
extern void GXGetLightAttnK(u8 *lt_obj, f32 *k0, f32 *k1, f32 *k2);
extern void GXInitLightAttnA(u8 *lt_obj, f32 a0, f32 a1, f32 a2);
extern void GXInitLightAttn(u8 *lt_obj, f32 a0, f32 a1, f32 a2, f32 k0, f32 k1, f32 k2);
extern void *mmAlloc(int size, int type, int flag);
extern void *memset(void *dst, int val, int n);
extern f32 *Camera_GetViewMatrix(void);
extern void PSMTXMultVec(f32 *mtx, f32 *in, f32 *out);
extern void PSMTXMultVecSR(f32 *mtx, f32 *in, f32 *out);
extern void Vec_normalize(f32 *dst, f32 *src);
extern void Obj_TransformLocalPointByWorldMatrix(u8 *obj, f32 *src, f32 *dst, u8 flag);
extern void Obj_TransformLocalVectorByWorldMatrix(void *obj, f32 *src, f32 *dst);
extern void Obj_BuildInverseWorldTransformMatrix(u8 *obj, f32 *out);
extern void lightFn_8001db6c(u8 *light, u8 enabled, f32 duration);
extern void lightFn_8001d620(u8 *light, int mode, s16 frames);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DE750;
extern f32 lbl_803DE754;
extern f32 lbl_803DE758;
extern f32 lbl_803DE760;
extern f32 lbl_803DE75C;
extern f32 lbl_803DE76C;
extern f32 lbl_803DE790;
extern f32 lbl_803DE79C;
extern f32 lbl_803DE7A0;
extern void textureFree(void *tex);

#pragma peephole off
#pragma scheduling off
void *objCreateLight(int arg, u8 addToList) {
    void *light;
    if (addToList) {
        if (lbl_803DCA30 >= 0x32) {
            return NULL;
        }
        light = objAllocLight((void *)arg);
        if (light == NULL) {
            return NULL;
        }
        {
            int i = lbl_803DCA30++;
            lbl_8033BEC0[i] = light;
        }
        return light;
    }
    light = objAllocLight((void *)arg);
    if (light != NULL) {
        return light;
    }
    return NULL;
}
#pragma scheduling reset
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma peephole off
void fn_8001CB3C(void **lightSlot) {
    u8 *light;
    int i;
    int count;

    light = *lightSlot;
    if (light != NULL) {
        i = 0;
        count = lbl_803DCA30;
        while (i < count) {
            if (lbl_8033BEC0[i] == light) {
                break;
            }
            i++;
        }

        if (i < count) {
            while (i < count - 1) {
                lbl_8033BEC0[i] = lbl_8033BEC0[i + 1];
                i++;
            }
            lbl_803DCA30--;
        }

        if (light[0x2f8] == 2 && *(void **)(light + 0x2e8) != NULL) {
            textureFree(*(void **)(light + 0x2e8));
        }
        mm_free(light);
        *lightSlot = NULL;
    }
}

void ModelLightStruct_free(u8 *light) {
    int count;
    int i;

    i = 0;
    count = lbl_803DCA30;
    while (i < count) {
        if (lbl_8033BEC0[i] == light) {
            break;
        }
        i++;
    }

    if (i < count) {
        while (i < count - 1) {
            lbl_8033BEC0[i] = lbl_8033BEC0[i + 1];
            i++;
        }
        lbl_803DCA30--;
    }

    if (light[0x2f8] == 2 && *(void **)(light + 0x2e8) != NULL) {
        textureFree(*(void **)(light + 0x2e8));
    }
    mm_free(light);
}

void *fn_8001CC9C(int unused, u8 red, u8 green, u8 blue, u8 setFlag) {
    u8 *light;
    u8 *newLight;

    if (lbl_803DCA30 >= 0x32) {
        light = NULL;
    } else {
        newLight = objAllocLight((void *)unused);
        if (newLight == NULL) {
            light = NULL;
        } else {
            int index = lbl_803DCA30++;
            lbl_8033BEC0[index] = newLight;
            light = newLight;
        }
    }

    if (light != NULL) {
        *(int *)(light + 0x50) = 2;
        light[0xac] = red;
        light[0xa8] = red;
        light[0xad] = green;
        light[0xa9] = green;
        light[0xae] = blue;
        light[0xaa] = blue;
        light[0xaf] = 0;
        light[0xab] = 0;
        light[0xbc] = 1;
        *(f32 *)(light + 0x140) = lbl_803DE750;
        *(f32 *)(light + 0x144) = lbl_803DE754;
        GXInitLightDistAttn(light + 0x68, *(f32 *)(light + 0x140), lbl_803DE758, 2);
        GXGetLightAttnK(light + 0x68, (f32 *)(light + 0x124), (f32 *)(light + 0x128),
                        (f32 *)(light + 0x12c));
        if (setFlag != 0) {
            light[0x2fb] = 1;
        }
    }

    return light;
}
#pragma pop

#pragma dont_inline on
#pragma push
#pragma scheduling off
#pragma peephole off
void *objAllocLight(void *owner) {
    u8 *light;
    f32 tmp[3];
    f32 *view;
    f32 zero;
    f32 atten;

    light = mmAlloc(0x300, 0x1a, 0);
    if (light == NULL) {
        return NULL;
    }

    memset(light, 0, 0x300);
    *(void **)light = owner;

    if (*(void **)light != NULL) {
        zero = lbl_803DE75C;
        *(f32 *)(light + 4) = zero;
        *(f32 *)(light + 8) = zero;
        *(f32 *)(light + 0xc) = zero;
        Obj_TransformLocalPointByWorldMatrix(*(u8 **)light, (f32 *)(light + 4), (f32 *)(light + 0x10), 1);
    } else {
        zero = lbl_803DE75C;
        *(f32 *)(light + 0x10) = zero;
        *(f32 *)(light + 0x14) = zero;
        *(f32 *)(light + 0x18) = zero;
    }

    view = Camera_GetViewMatrix();
    if (*(int *)(light + 0x60) == 0) {
        tmp[0] = *(f32 *)(light + 0x10) - playerMapOffsetX;
        tmp[1] = *(f32 *)(light + 0x14);
        tmp[2] = *(f32 *)(light + 0x18) - playerMapOffsetZ;
        PSMTXMultVec(view, tmp, (f32 *)(light + 0x1c));
    } else {
        *(IVec3 *)(light + 0x1c) = *(IVec3 *)(light + 0x10);
    }

    if (*(void **)light != NULL) {
        zero = lbl_803DE75C;
        *(f32 *)(light + 0x28) = zero;
        *(f32 *)(light + 0x2c) = zero;
        *(f32 *)(light + 0x30) = lbl_803DE760;
        Vec_normalize((f32 *)(light + 0x28), (f32 *)(light + 0x28));
        Obj_TransformLocalVectorByWorldMatrix(*(void **)light, (f32 *)(light + 0x28), (f32 *)(light + 0x34));
    } else {
        zero = lbl_803DE75C;
        *(f32 *)(light + 0x34) = zero;
        *(f32 *)(light + 0x38) = zero;
        *(f32 *)(light + 0x3c) = lbl_803DE760;
        Vec_normalize((f32 *)(light + 0x34), (f32 *)(light + 0x34));
    }

    view = Camera_GetViewMatrix();
    if (*(int *)(light + 0x60) == 0) {
        PSMTXMultVecSR(view, (f32 *)(light + 0x34), (f32 *)(light + 0x40));
    } else {
        *(IVec3 *)(light + 0x40) = *(IVec3 *)(light + 0x34);
    }

    lightFn_8001db6c(light, 1, lbl_803DE75C);
    *(int *)(light + 0x50) = 4;
    *(int *)(light + 0x54) = 1;
    *(f32 *)(light + 0x140) = lbl_803DE750;
    *(f32 *)(light + 0x144) = lbl_803DE754;
    GXInitLightDistAttn(light + 0x68, *(f32 *)(light + 0x140), lbl_803DE758, 2);
    GXGetLightAttnK(light + 0x68, (f32 *)(light + 0x124), (f32 *)(light + 0x128), (f32 *)(light + 0x12c));
    zero = lbl_803DE75C;
    *(f32 *)(light + 0x144) = zero;
    light[0x2fc] = 0x7f;
    *(int *)(light + 0x5c) = 0;
    light[0x64] = 1;
    *(int *)(light + 0x60) = 0;
    light[0x4d] = 0;
    light[0xbc] = 0;
    light[0xac] = 0xff;
    light[0xa8] = 0xff;
    light[0xad] = 0xff;
    light[0xa9] = 0xff;
    light[0xae] = 0xff;
    light[0xaa] = 0xff;
    light[0xaf] = 0xff;
    light[0xab] = 0xff;
    *(f32 *)(light + 0xb4) = lbl_803DE79C;
    *(int *)(light + 0xb8) = 0;
    GXInitLightAttnA(light + 0x68, lbl_803DE760, zero, zero);
    light[0x114] = 0;
    light[0x104] = 0xff;
    light[0x100] = 0xff;
    light[0x105] = 0xff;
    light[0x101] = 0xff;
    light[0x106] = 0xff;
    light[0x102] = 0xff;
    light[0x107] = 0xff;
    light[0x103] = 0xff;
    *(f32 *)(light + 0x10c) = lbl_803DE7A0;
    *(f32 *)(light + 0x110) = lbl_803DE76C;
    atten = *(f32 *)(light + 0x10c) * lbl_803DE790;
    zero = lbl_803DE75C;
    GXInitLightAttn(light + 0xc0, zero, zero, lbl_803DE760, atten, zero,
                    lbl_803DE760 - atten);
    lightFn_8001d620(light, 0, 0);
    light[0xb0] = 0xff;
    light[0xb1] = 0xff;
    light[0xb2] = 0xff;
    light[0xb3] = 0xff;
    light[0x108] = 0xff;
    light[0x109] = 0xff;
    light[0x10a] = 0xff;
    light[0x10b] = 0xff;
    if (*(void **)light != NULL) {
        Obj_BuildInverseWorldTransformMatrix(*(u8 **)light, (f32 *)(light + 0x170));
    }
    atten = lbl_803DE760;
    *(f32 *)(light + 0x134) = atten;
    *(f32 *)(light + 0x124) = atten;
    zero = lbl_803DE75C;
    *(f32 *)(light + 0x128) = zero;
    *(f32 *)(light + 0x12c) = zero;
    return light;
}
#pragma pop
#pragma dont_inline reset

void fn_8001D80C(u8 *p, void *a, void *b) {
    *(void **)(p + 0x270) = a;
    *(void **)(p + 0x274) = b;
}

f32 gameTextFn_80019c00(void) {
    return *(f32 *)(gameTextFonts + 0x20);
}

u8 fn_8001FD88(void **p) {
    *p = lbl_803DCAE8;
    return lbl_803DCA48;
}

void tailFn_80026c38(u8 *p, f32 a, f32 b, f32 c) {
    *(f32 *)(p + 8) = a;
    *(f32 *)(p + 0xc) = b;
    *(f32 *)(p + 0x10) = c;
}

#pragma peephole off
void texFlagFn_80023cbc(int v) {
    lbl_803DCB10 = (u8)v;
}
#pragma peephole reset

extern u16 lbl_803DCA42;
extern u8 lbl_803DCAF0;
typedef struct {
    u8 _pad[0x1c];
    int state;
    u8 _pad2[8];
} GameTextStateElem;
extern GameTextStateElem lbl_8033AF40[];
extern u8 lbl_803DB408;
extern int gMmFreeDelay;
extern int lbl_803DCB14;
extern int lbl_803DCB08;
extern int lbl_803DB434;

#pragma push
#pragma scheduling off
#pragma peephole off
void fn_8001D71C(u8 *p, u8 a, u8 b, u8 c, u8 d) {
    p[0x2ec] = a;
    p[0x2ed] = b;
    p[0x2ee] = c;
    p[0x2ef] = d;
}

void fn_8001D7F8(u8 *p, void **a, void **b) {
    *a = *(void **)(p + 0x270);
    *b = *(void **)(p + 0x274);
}

void fn_8001D9E0(u8 *p, u8 a, u8 b, u8 c, u8 d) {
    p[0x108] = a;
    p[0x109] = b;
    p[0x10a] = c;
    p[0x10b] = d;
}

void lightSetFieldB0(u8 *p, u8 a, u8 b, u8 c, u8 d) {
    p[0xb0] = a;
    p[0xb1] = b;
    p[0xb2] = c;
    p[0xb3] = d;
}

void fn_8001FE90(void) {
    lbl_803DCA42++;
    lbl_803DCAF0 = 0xd0;
}

void fn_8001FEA8(void) {
    lbl_803DCA42++;
    lbl_803DCAF0 = 0xc9;
}

#pragma dont_inline on
int gameTextGetState(int i) {
    return lbl_8033AF40[i].state;
}
#pragma dont_inline reset

extern void textFn_8001b7b8(void);
extern int lbl_803DC9F0;
extern int lbl_803DCA04;
extern void *lbl_803DC9F8;

void mainLoopDoGameText(void) {
    if (lbl_803DC9F0 != 0) {
        if (gameTextGetState(1) == 2 && lbl_803DCA04 == 1) {
            textFn_8001b7b8();
        }
    } else {
        if (gameTextGetState(0) == 2 && (int)lbl_803DC9F8 == (int)getCurGameText() &&
            lbl_803DCA04 == 1) {
            textFn_8001b7b8();
        }
    }
}

void blankScreen(int frames) {
    s16 v = frames;
    lbl_803DCA46 = v;
    if (v < 0) {
        lbl_803DCA46 = 0;
    }
}

void fn_8001DD50(u8 *p, f32 *a, f32 *b, f32 *c) {
    *a = *(f32 *)(p + 0x1c);
    *b = *(f32 *)(p + 0x20);
    *c = *(f32 *)(p + 0x24);
}

void fn_8001DD6C(u8 *p, f32 *a, f32 *b, f32 *c) {
    *a = *(f32 *)(p + 0x10);
    *b = *(f32 *)(p + 0x14);
    *c = *(f32 *)(p + 0x18);
}

#pragma peephole on
void fn_8001FE74(void *v) {
    int i = lbl_803DCA48;
    lbl_803DCA48 = i + 1;
    lbl_803DCAE8[i] = (int)v;
}
#pragma peephole reset

#pragma dont_inline on
int mmSetFreeDelay(int v) {
    int old = gMmFreeDelay;
    lbl_803DCB14++;
    gMmFreeDelay = v;
    return old;
}

int testAndSet_onlyUseHeap3(int v) {
    lbl_803DCB14++;
    {
        int old = lbl_803DCB08;
        lbl_803DCB08 = v;
        return old;
    }
}

int testAndSet_onlyUseHeaps1and2(int v) {
    lbl_803DCB14++;
    {
        int old = lbl_803DB434;
        lbl_803DB434 = v;
        return old;
    }
}
#pragma dont_inline reset

void colorFn_8001efe0(int i, u8 a, u8 b, u8 c) {
    u8 *base = &lbl_803DB408;
    base[i * 4] = a;
    base[i * 4 + 1] = b;
    base[i * 4 + 2] = c;
}

int fn_80022E0C(int x) {
    int r = x & 1;
    if (r > 0) {
        x += 2 - r;
    }
    return x;
}

void modelFn_8001db3c(u8 *p, int n) {
    *(int *)(p + 0x5c) = n;
    p[0x64] = (u8)(1 << n);
}

void objSetHintTextIdx(u8 *obj, u16 idx) {
    if (idx > 4) {
        idx = 0;
    }
    obj[0xe8] = (u8)idx;
}
#pragma pop

extern void GXInitLightAttnA(u8 *lt_obj, f32 a0, f32 a1, f32 a2);
extern int getLoadedFileFlags(int);
extern s8 lbl_803DCB74;
extern int lbl_803408A8[];
extern int lbl_803DD610;
extern void *lbl_803DD61C;
extern f32 lbl_803DE760;
extern f32 lbl_803DE75C;
extern f32 lbl_803DE764;
extern f32 lbl_803DE778;
extern f32 lbl_803DE78C;
extern f32 lbl_803DE788;
extern f32 lbl_803DE794;
extern f32 lbl_803DE798;
extern void *textureLoadAsset(int assetId);
extern int randomGetRange(int lo, int hi);

#pragma push
#pragma scheduling off
#pragma peephole off
void fn_8001D9F4(u8 *p, u8 *a, u8 *b, u8 *c, u8 *d) {
    *a = p[0x100];
    *b = p[0x101];
    *c = p[0x102];
    *d = p[0x103];
}

void fn_8001DACC(u8 *p, u8 *a, u8 *b, u8 *c, u8 *d) {
    *a = p[0xa8];
    *b = p[0xa9];
    *c = p[0xaa];
    *d = p[0xab];
}

void fn_8001DA3C(u8 *p, f32 a, f32 b, f32 c) {
    GXInitLightAttnA(p + 0x68, a, b, c);
}

void modelLightStruct_setColors100104(u8 *p, u8 a, u8 b, u8 c, u8 d) {
    p[0x104] = a;
    p[0x100] = a;
    p[0x105] = b;
    p[0x101] = b;
    p[0x106] = c;
    p[0x102] = c;
    p[0x107] = d;
    p[0x103] = d;
}

void modelLightStruct_setColorsA8AC(u8 *p, u8 a, u8 b, u8 c, u8 d) {
    p[0xac] = a;
    p[0xa8] = a;
    p[0xad] = b;
    p[0xa9] = b;
    p[0xae] = c;
    p[0xaa] = c;
    p[0xaf] = d;
    p[0xab] = d;
}

void lightGetColor(int i, u8 *a, u8 *b, u8 *c) {
    u8 *base = &lbl_803DB408;
    *a = base[i * 4];
    *b = base[i * 4 + 1];
    *c = base[i * 4 + 2];
}

#pragma dont_inline on
void *getCache(void) {
    if (lbl_803DD610 != 4 && lbl_803DD610 != 0) {
        return lbl_803DD61C;
    }
    return (void *)0xe0000000;
}
#pragma dont_inline reset

f32 getXZDistance(f32 *a, f32 *b) {
    f32 dx = a[0] - b[0];
    f32 dz = a[2] - b[2];
    return dx * dx + dz * dz;
}

f32 vec3f_distanceSquared(f32 *a, f32 *b) {
    f32 dx = a[0] - b[0];
    f32 dy = a[1] - b[1];
    f32 dz = a[2] - b[2];
    return dx * dx + dy * dy + dz * dz;
}

void Vec3_ScaleAdd(f32 *a, f32 s, f32 *b, f32 *out) {
    out[0] = s * b[0] + a[0];
    out[1] = s * b[1] + a[1];
    out[2] = s * b[2] + a[2];
}

void lightFn_8001d168(u8 *light) {
    f32 progress;
    f32 intensity;
    int mode;

    mode = *(int *)(light + 0x2d8);
    if (mode == 2) {
        *(f32 *)(light + 0x2e0) += *(f32 *)(light + 0x2dc) * timeDelta;
    } else if (mode > 0 && mode < 2) {
        *(f32 *)(light + 0x2e4) += *(f32 *)(light + 0x2dc) * timeDelta;
        if (*(f32 *)(light + 0x2e4) >= lbl_803DE760) {
            *(f32 *)(light + 0x2e0) = (f32)randomGetRange(0, 100) / lbl_803DE778;
            *(f32 *)(light + 0x2e4) = lbl_803DE75C;
        }
    }

    progress = *(f32 *)(light + 0x2e0);
    if (progress > lbl_803DE760) {
        *(f32 *)(light + 0x2e0) = lbl_803DE760 - (progress - lbl_803DE760);
        *(f32 *)(light + 0x2dc) = -*(f32 *)(light + 0x2dc);
    } else if (progress < lbl_803DE75C) {
        *(f32 *)(light + 0x2e0) = -progress;
        *(f32 *)(light + 0x2dc) = -*(f32 *)(light + 0x2dc);
    }

    progress = *(f32 *)(light + 0x2e0);
    light[0xa8] = (u8)(int)(progress * (f32)(light[0xb0] - light[0xac]) + (f32)light[0xac]);
    light[0xa9] = (u8)(int)(progress * (f32)(light[0xb1] - light[0xad]) + (f32)light[0xad]);
    light[0xaa] = (u8)(int)(progress * (f32)(light[0xb2] - light[0xae]) + (f32)light[0xae]);
    light[0xab] = (u8)(int)(progress * (f32)(light[0xb3] - light[0xaf]) + (f32)light[0xaf]);

    intensity = *(f32 *)(light + 0x138);
    light[0xa8] = (u8)(int)((f32)light[0xa8] * intensity);
    light[0xa9] = (u8)(int)((f32)light[0xa9] * intensity);
    light[0xaa] = (u8)(int)((f32)light[0xaa] * intensity);
    light[0xab] = (u8)(int)((f32)light[0xab] * intensity);

    light[0x100] = (u8)(int)(progress * (f32)(light[0x108] - light[0x104]) + (f32)light[0x104]);
    light[0x101] = (u8)(int)(progress * (f32)(light[0x109] - light[0x105]) + (f32)light[0x105]);
    light[0x102] = (u8)(int)(progress * (f32)(light[0x10a] - light[0x106]) + (f32)light[0x106]);
    light[0x103] = (u8)(int)(progress * (f32)(light[0x10b] - light[0x107]) + (f32)light[0x107]);

    light[0x100] = (u8)(int)((f32)light[0x100] * intensity);
    light[0x101] = (u8)(int)((f32)light[0x101] * intensity);
    light[0x102] = (u8)(int)((f32)light[0x102] * intensity);
    light[0x103] = (u8)(int)((f32)light[0x103] * intensity);
}

void lightFn_8001d620(u8 *light, int mode, s16 frames) {
    f32 denom;

    *(int *)(light + 0x2d8) = mode;
    if (mode != 0) {
        if (frames != 0) {
            denom = frames;
        } else {
            denom = lbl_803DE760;
        }
        *(f32 *)(light + 0x2dc) = lbl_803DE760 / denom;
        light[0xac] = light[0xa8];
        light[0xad] = light[0xa9];
        light[0xae] = light[0xaa];
        light[0x104] = light[0x100];
        light[0x105] = light[0x101];
        light[0x106] = light[0x102];
        denom = lbl_803DE75C;
        *(f32 *)(light + 0x2e0) = denom;
        *(f32 *)(light + 0x2e4) = denom;
    }
}

void fn_8001D730(u8 *light, u32 textureId, u8 red, u8 green, u8 blue, u8 alpha, f32 scale) {
    void *texture;

    if (textureId != 0) {
        texture = textureLoadAsset(textureId);
        *(void **)(light + 0x2e8) = texture;
        if (texture != NULL) {
            light[0x2f8] = 2;
        }
    } else {
        texture = textureLoadAsset(0x605);
        *(void **)(light + 0x2e8) = texture;
        if (texture != NULL) {
            light[0x2f8] = 2;
        }
    }
    light[0x2ec] = red;
    light[0x2ed] = green;
    light[0x2ee] = blue;
    light[0x2ef] = alpha;
    *(f32 *)(light + 0x2f0) = scale;
    light[0x2f9] = 0;
    light[0x2fa] = 0;
    *(f32 *)(light + 0x2f4) = lbl_803DE788 * *(f32 *)(light + 0x2f0);
}

void lightFn_8001db6c(u8 *light, u8 enabled, f32 duration) {
    f32 zero;

    zero = lbl_803DE75C;
    if (zero == duration) {
        if (enabled != 0) {
            *(int *)(light + 0x58) = 2;
            *(f32 *)(light + 0x138) = lbl_803DE760;
        } else {
            *(int *)(light + 0x58) = 0;
            *(f32 *)(light + 0x138) = zero;
        }
        light[0x4c] = enabled;
        return;
    }

    if (enabled != 0) {
        if (*(int *)(light + 0x58) == 0 || *(int *)(light + 0x58) == 3) {
            *(int *)(light + 0x58) = 1;
            *(f32 *)(light + 0x13c) = lbl_803DE760 / (lbl_803DE794 * duration);
            *(f32 *)(light + 0x138) = lbl_803DE75C;
        }
        light[0x4c] = 1;
        return;
    }

    if (*(int *)(light + 0x58) != 2 && *(int *)(light + 0x58) != 1) {
        return;
    }
    *(int *)(light + 0x58) = 3;
    *(f32 *)(light + 0x13c) = lbl_803DE798 / (lbl_803DE794 * duration);
    *(f32 *)(light + 0x138) = lbl_803DE760;
}

void fn_8001D820(u8 *p, f32 v) {
    f32 clamped = *(f32 *)(p + 0x160);
    if (v >= clamped) {
        clamped = lbl_803DE764;
        if (v <= clamped) {
            clamped = v;
        }
    }
    *(f32 *)(p + 0x164) = clamped;
}

void fn_8001D84C(u8 *p, f32 v) {
    f32 clamped = lbl_803DE78C;
    if (v >= clamped) {
        clamped = *(f32 *)(p + 0x164);
        if (v <= clamped) {
            clamped = v;
        }
    }
    *(f32 *)(p + 0x160) = clamped;
}

int Obj_IsLoadingLocked(void) {
    return !(getLoadedFileFlags(0) & 0x100000);
}

void objSetSlot(u8 *obj, s8 slot) {
    if (slot == 0x5a) {
        if ((*(u32 *)(*(u8 **)(obj + 0x50) + 0x44) & 0x40) == 0) {
            return;
        }
    }
    *(s8 *)(obj + 0xae) = slot;
}

#pragma peephole on
void fn_8002B758(void *v) {
    int i;
    int count;

    count = lbl_803DCB74;
    for (i = 0; i < count; i++) {
        if ((void *)lbl_803408A8[i] == v) {
            break;
        }
    }
    if (i == count) {
        return;
    }
    for (; i < count - 1; i++) {
        lbl_803408A8[i] = lbl_803408A8[i + 1];
    }
    lbl_803DCB74--;
}

void fn_8002B860(void *v) {
    s8 i = lbl_803DCB74;
    lbl_803DCB74 = i + 1;
    lbl_803408A8[i] = (int)v;
}
#pragma peephole reset
#pragma pop

extern float fn_802924B4(float y, float x);
extern void Sfx_SetObjectSoundsPaused(s32 paused);
extern void gameTextInitFn_8001c794(void);
extern void gameTextLoadDir(int dirId);
extern void LCQueueWait();
extern void mmFree(void *p);
extern void mmFreeDeferred(void *p);
extern void objList_remove(void *list, void *item);
extern double lbl_803DE7D8;
extern u8 lbl_803DCA31;
extern int lbl_803DCA34;
extern u8 lbl_803DC980;
extern f32 lbl_803DE854;
extern int lbl_803DCBAC;
extern int *lbl_803DCBB0;
extern u8 *lbl_803DCBB4;
extern int lbl_803DCB7C;
extern f32 timeDelta;

typedef struct {
    u8 active;
    u8 _1[3];
    int lightMask;
    int mode;
    int matSrc;
} Elem8033BE60;
extern Elem8033BE60 lbl_8033BE60[];

#pragma push
#pragma scheduling off
#pragma peephole off
void cutsceneExit(void) {
    lbl_803DCA3A = 0;
    lbl_803DCA3C = 0;
    Sfx_SetObjectSoundsPaused(0);
}

void gameTextInit(void) {
    gameTextInitFn_8001c794();
    lbl_803DC980 = 1;
    gameTextLoadDir(0x1c);
}

int getAngle(float y, float x) {
    return (int)(lbl_803DE7D8 * fn_802924B4(y, x));
}

int atan2_8002178c(float y, float x) {
    return (int)(lbl_803DE7D8 * fn_802924B4(y, x));
}

#pragma dont_inline on
void cacheFn_800229c4(int sync) {
    if (lbl_803DD610 == 4 || lbl_803DD610 == 0) {
        LCQueueWait();
    }
}
#pragma dont_inline reset

void fn_80026C54(u8 *p) {
    p[0x18] = 0;
    *(f32 *)(p + 0x14) += timeDelta;
    if (*(f32 *)(p + 0x14) > lbl_803DE854) {
        *(f32 *)(p + 0x14) -= lbl_803DE854;
    }
}

#pragma dont_inline on
void mm_free(void *p) {
    if (gMmFreeDelay == 0) {
        mmFree(p);
    } else {
        mmFreeDeferred(p);
    }
}
#pragma dont_inline reset

void *getTablesBinEntry(int i) {
    if (i < 0 || i >= lbl_803DCBAC) {
        return lbl_803DCBB4;
    }
    return lbl_803DCBB4 + lbl_803DCBB0[i] * 4;
}

void fn_8002CE14(u8 *obj) {
    if (*(u16 *)(obj + 0xb0) & 0x10) {
        int *list = &lbl_803DCB7C;
        int prev = 0;
        int cur = list[1];
        s16 linkOff = *(s16 *)((u8 *)list + 2);
        while (cur != 0 && (s8)obj[0xae] < (s8)((u8 *)cur)[0xae]) {
            prev = cur;
            cur = *(int *)((u8 *)cur + linkOff);
        }
        objListAdd(&lbl_803DCB7C, prev, (int)obj);
    }
}

void objRemoveFromListFn_8002ce88(u8 *obj) {
    if (*(u16 *)(obj + 0xb0) & 0x10) {
        objList_remove(&lbl_803DCB7C, obj);
    }
}

void *Obj_GetPlayerObject(void) {
    int count;
    void **objs = ObjGroup_GetObjects(0, &count);
    if (count != 0) {
        return objs[0];
    }
    return NULL;
}

void fn_8001E608(int i, int a, int b) {
    lbl_8033BE60[i].mode = a;
    lbl_8033BE60[i].lightMask = 0;
    lbl_8033BE60[i].matSrc = b;
    lbl_8033BE60[i].active = 1;
}

#pragma peephole off
void fn_8001E8F4(u8 v) {
    lbl_803DCA31 = v;
    lbl_803DCA34 = 1;
    lbl_8033BE60[0].active = 0;
    lbl_8033BE60[1].active = 0;
    lbl_8033BE60[2].active = 0;
    lbl_8033BE60[3].active = 0;
    lbl_8033BE60[4].active = 0;
    lbl_8033BE60[5].active = 0;
}
#pragma peephole reset
#pragma pop

extern void mapReloadWithFadeout(void);
extern f32 fcos16(int angle);
extern f32 sqrtf(f32 x);
extern void *loadAsset(void *req);
extern void setGQR7(u32 v);
extern int lbl_803DCB84;
extern void *lbl_803DCB88;
extern u8 lbl_803DCA39;
extern f32 lbl_803DE7D0;

typedef struct {
    u8 f0;
    u8 f1;
    u8 _2[2];
    int f4;
    int f8;
    int fc;
    int f10;
    u8 _14[0xc];
    int f20;
    int f24;
} AssetReq;
extern AssetReq lbl_8033BF88;
extern void *fileLoad(int id, int heap);
extern void fileLoadToBuffer(int id, void *buf);
extern void fileLoadToBufferOffset(int id, void *buf, int offset, int size);
extern void *Resource_Acquire(u32 id, u32 arg);
extern void *loadCharacter(s16 *data, int flags, int arg2, int arg3, void *parent, int unused);
extern int textureLoad(int id, int flag);
extern void *loadAnimation(int hdr, s16 id, int b, u8 *bufout);

void *loadAsset(void *reqVoid) {
    u8 tmp[0x14];
    AssetReq *req;

    req = reqVoid;
    switch (req->f1) {
        case 0:
            *(void **)req->f8 = fileLoad(req->f4, 0);
            break;
        case 1:
            fileLoadToBuffer(req->f4, (void *)req->f8);
            break;
        case 2:
            fileLoadToBufferOffset(req->f4, (void *)req->f8, req->f10, req->fc);
            break;
        case 4:
            *(void **)req->f8 =
                loadCharacter(*(s16 **)((u8 *)req + 0x18), *(int *)((u8 *)req + 0x1c),
                              *(int *)((u8 *)req + 0x24), *(int *)((u8 *)req + 0x20),
                              *(void **)((u8 *)req + 0x14), *(int *)((u8 *)req + 0x28));
            break;
        case 3:
            *(void **)req->f8 = (void *)textureLoad(req->f4, 0);
            break;
        case 5:
            *(void **)req->f8 = Resource_Acquire(req->f4 & 0xffff, req->fc & 0xffff);
            break;
        case 6:
            *(void **)req->f8 = (void *)((int (*)(int, int, void *))return0_8002969C)(req->f4, req->fc, tmp);
            break;
        case 7:
            *(void **)req->f8 =
                loadAnimation(*(int *)((u8 *)req + 0x24), (s16)req->f4, (s16)req->fc,
                              *(u8 **)((u8 *)req + 0x20));
            break;
    }
}

#pragma push
#pragma scheduling off
#pragma peephole off
void mtxFn_80021ec0(u8 *p, f32 s) {
    *(f32 *)(p + 0x10) *= s;
    *(f32 *)(p + 0x14) *= s;
    *(f32 *)(p + 0x18) *= s;
}

void *ObjList_GetObjects(int *outA, int *outB) {
    if (outA != NULL) {
        *outA = 0;
    }
    if (outB != NULL) {
        *outB = lbl_803DCB84;
    }
    return lbl_803DCB88;
}

void mapReload(void) {
    mapReloadWithFadeout();
    lbl_803DCA39 = 1;
}

int cos16(u16 angle) {
    return (int)(lbl_803DE7D0 * fcos16(angle));
}

asm void setGQR6(register u32 v) {
    nofralloc
    mtspr GQR6, v
    blr
}

asm void setGQR7(register u32 v) {
    nofralloc
    mtspr GQR7, v
    blr
}

#pragma dont_inline on
void fn_8002A3D4(int a, int b, int c, int d) {
    setGQR7((((a << 8) + b) << 16) | ((c << 8) + d));
}
#pragma dont_inline reset

f32 Vec3_Length(f32 *v) {
    return sqrtf(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
}

f32 Vec_xzDistance(f32 *a, f32 *b) {
    f32 dx = a[0] - b[0];
    f32 dz = a[2] - b[2];
    return sqrtf(dx * dx + dz * dz);
}

f32 Vec_distance(f32 *a, f32 *b) {
    f32 dx = a[0] - b[0];
    f32 dy = a[1] - b[1];
    f32 dz = a[2] - b[2];
    return sqrtf(dx * dx + dy * dy + dz * dz);
}

void Vec3_Cross(f32 *a, f32 *b, f32 *out) {
    out[0] = a[1] * b[2] - a[2] * b[1];
    out[1] = a[2] * b[0] - a[0] * b[2];
    out[2] = a[0] * b[1] - a[1] * b[0];
}

extern f32 lbl_803DE808;
extern f32 lbl_803DE80C;

void Vec3_ReflectAgainstNormal(f32 *a, f32 *n, f32 *out) {
    f32 dot = a[1] * n[1] + a[0] * n[0] + a[2] * n[2];
    if (dot > lbl_803DE808) {
        out[0] = n[0];
        out[1] = n[1];
        out[2] = n[2];
    } else {
        f32 s = dot * lbl_803DE80C;
        out[0] = a[0];
        out[1] = a[1];
        out[2] = a[2];
        out[0] *= s;
        out[1] *= s;
        out[2] *= s;
        out[0] += n[0];
        out[1] += n[1];
        out[2] += n[2];
    }
}

#pragma dont_inline on
void *loadAssetFileById(int id, int arg) {
    lbl_8033BF88.f0 = 1;
    lbl_8033BF88.f1 = 0;
    lbl_8033BF88.f4 = arg;
    lbl_8033BF88.f8 = id;
    return loadAsset(&lbl_8033BF88);
}

void *loadTextureFile(int id, int arg) {
    lbl_8033BF88.f0 = 1;
    lbl_8033BF88.f1 = 3;
    lbl_8033BF88.f4 = arg;
    lbl_8033BF88.f8 = id;
    return loadAsset(&lbl_8033BF88);
}
#pragma dont_inline reset

void Obj_SetActiveModelIndex(u8 *obj, int idx) {
    if (idx == (s8)obj[0xad]) {
        return;
    }
    if (idx < 0) {
        idx = 0;
    } else {
        int max = *(s8 *)(*(u8 **)(obj + 0x50) + 0x55);
        if (idx >= max) {
            idx = max - 1;
        }
    }
    *(s8 *)(obj + 0xad) = idx;
}
#pragma pop

extern int OSDisableInterrupts(void);
extern int OSRestoreInterrupts(int level);
extern void subtitleFn_8001b700(void);
extern int lbl_803DCA00;
extern s16 lbl_803DC9AA;
extern s16 lbl_803DC9A8;
extern int lbl_803DC9C8;
typedef struct {
    int v;
    int f4;
    int f8;
    int fc;
    int f10;
} GameTextSlot;
extern GameTextSlot lbl_8033A540[];

typedef struct ObjListObjectDef {
    u8 pad00[0x14];
    u32 objectId;
} ObjListObjectDef;

typedef struct ObjListObject {
    u8 pad00[0x4c];
    ObjListObjectDef *def;
} ObjListObject;

#pragma push
#pragma scheduling off
#pragma peephole off
int setSubtitlesEnabled(int enabled) {
    int old = lbl_803DCA00;
    lbl_803DCA00 = enabled;
    if (enabled == 0) {
        subtitleFn_8001b700();
    }
    return old;
}

void *getTrickyObject(void) {
    int count;
    void **objs = ObjGroup_GetObjects(1, &count);
    if (count != 0) {
        return objs[0];
    }
    return NULL;
}

void AtomicSList_Push(void **list, void *node) {
    int intr = OSDisableInterrupts();
    *(void **)node = *list;
    *list = node;
    OSRestoreInterrupts(intr);
}

ObjListObject *ObjList_FindObjectById(u32 objectId) {
    int i;
    int count = lbl_803DCB84;
    ObjListObject **arr = lbl_803DCB88;
    for (i = 0; i < count; i++) {
        ObjListObject *obj = arr[i];
        ObjListObjectDef *def = obj->def;
        if (def != NULL && def->objectId == objectId) {
            return obj;
        }
    }
    return NULL;
}

extern int lbl_803DB3C8;
extern void hudDrawRect(int x0, int y0, int x1, int y1, void *color);
extern int lbl_803DC9D8;
extern int gameTextFn_8001bcb4(void);
extern int gameTextFn_8001b44c(int x);
extern void gameTextLoadForCurMap(int sourceId);

#pragma dont_inline on
void gameTextSetCharset(int charset, int flags) {
    if (gameTextDrawFunc != NULL || (flags & 1)) {
        gameTextFonts = (u8 *)&lbl_8033AF40[charset];
        lbl_803DC9E8 = charset;
        if (charset == 2) {
            int color = lbl_803DB3C8;
            hudDrawRect(0, 0, 0xa00, 0x780, &color);
            lbl_803DC99C = 0;
        }
    }
    if (gameTextDrawFunc == NULL || (flags & 2)) {
        int i = lbl_803DC9C8;
        GameTextSlot *s;
        lbl_803DC9C8 = i + 1;
        s = &lbl_8033A540[i];
        s->v = 0xf;
        s->f4 = charset;
    }
}

#pragma dont_inline reset

void gameTextLoadDir(int dirId) {
    GameTextSlot *cmd;
    int color;
    int slotIndex;

    lbl_803DC9A7 = 0xff;
    lbl_803DC9A6 = 0xff;
    lbl_803DC9A5 = 0xff;
    lbl_803DC9A4 = 0xff;

    if (dirId == 3) {
        gameTextFonts = (u8 *)&lbl_8033AF40[2];
        lbl_803DC9E8 = 2;
        color = lbl_803DB3C8;
        hudDrawRect(0, 0, 0xa00, 0x780, &color);
        lbl_803DC99C = 0;
        if (gameTextDrawFunc == NULL) {
            slotIndex = lbl_803DC9C8;
            lbl_803DC9C8 = slotIndex + 1;
            cmd = &lbl_8033A540[slotIndex];
            cmd->v = 0xf;
            cmd->f4 = 2;
        }
    } else if (dirId == 0x1c) {
        curGameTextDir = (void *)dirId;
        gameTextFonts = (u8 *)&lbl_8033AF40[3];
        lbl_803DC9E8 = 3;
        if (gameTextDrawFunc == NULL) {
            slotIndex = lbl_803DC9C8;
            lbl_803DC9C8 = slotIndex + 1;
            cmd = &lbl_8033A540[slotIndex];
            cmd->v = 0xf;
            cmd->f4 = 3;
        }
        gameTextLoadForCurMap(3);
    } else {
        gameTextFonts = (u8 *)&lbl_8033AF40[0];
        lbl_803DC9E8 = 0;
        if (gameTextDrawFunc == NULL) {
            slotIndex = lbl_803DC9C8;
            lbl_803DC9C8 = slotIndex + 1;
            cmd = &lbl_8033A540[slotIndex];
            cmd->v = 0xf;
            cmd->f4 = 0;
        }
        curGameTextDir = (void *)dirId;
        if ((gameTextFn_8001bcb4() == 0 || gameTextFn_8001b44c(dirId) == 0) &&
            (int)curGameTextDir != lbl_803DC9D8) {
            gameTextLoadForCurMap(0);
        }
    }
}

void gameTextFn_80019804(int flags) {
    if (flags & 1) {
        lbl_803DC9AA = 0;
        lbl_803DC9A8 = 0;
    }
    if (flags & 2) {
        int i = lbl_803DC9C8;
        lbl_803DC9C8 = i + 1;
        lbl_8033A540[i].v = 0xb;
    }
}

extern u8 lbl_802C7400[];
extern void *lbl_803DC9CC;

void gameTextFn_80017434(u8 *param_1) {
    int i;
    GameTextSlot *s;
    int idx;

    if (param_1 == NULL) {
        i = lbl_803DC9C8;
        lbl_803DC9C8 = i + 1;
        s = &lbl_8033A540[i];
        lbl_803DC9CC = NULL;
        s->v = 8;
        s->f4 = 0xff;
    } else {
        i = lbl_803DC9C8;
        lbl_803DC9C8 = i + 1;
        s = &lbl_8033A540[i];
        idx = (param_1 - lbl_802C7400) / 0x20;
        if (idx == 0xff) {
            lbl_803DC9CC = NULL;
        } else {
            lbl_803DC9CC = lbl_802C7400 + idx * 0x20;
        }
        s->v = 8;
        s->f4 = idx;
    }
}

void gameTextFn_8001984c(s16 x, s16 y, int flags) {
    if (flags & 1) {
        lbl_803DC9AA = x;
        lbl_803DC9A8 = y;
    }
    if (flags & 2) {
        int i = lbl_803DC9C8;
        GameTextSlot *s;
        lbl_803DC9C8 = i + 1;
        s = &lbl_8033A540[i];
        s->v = 0xa;
        s->f4 = (u16)x;
        s->f8 = (u16)y;
    }
}

#pragma dont_inline on
void *getTabEntry(int id, int arg, int e, int d) {
    lbl_8033BF88.f0 = 1;
    lbl_8033BF88.f1 = 2;
    lbl_8033BF88.f4 = arg;
    lbl_8033BF88.f8 = id;
    lbl_8033BF88.f10 = e;
    lbl_8033BF88.fc = d;
    return loadAsset(&lbl_8033BF88);
}
#pragma dont_inline reset

int ObjModel_HasActiveBlendChannels(u8 *model) {
    u8 *ch;

    if (*(void **)(*(u8 **)model + 0xdc) == NULL) {
        return 0;
    }
    ch = *(u8 **)(model + 0x28);
    if (*(f32 *)(ch + 0x0) != *(f32 *)(ch + 0x4) || (ch[0xe] & 0xe)) {
        return 1;
    }
    if (*(f32 *)(ch + 0x10) != *(f32 *)(ch + 0x14) || (ch[0x1e] & 0xe)) {
        return 1;
    }
    if (*(f32 *)(ch + 0x20) != *(f32 *)(ch + 0x24) || (ch[0x2e] & 0xe)) {
        return 1;
    }
    return 0;
}

void ObjModel_SetBlendChannelWeight(u8 *model, int channel, f32 weight) {
    u8 *ch;

    if (channel > 2) {
        return;
    }
    if (*(void **)(*(u8 **)model + 0xdc) == NULL) {
        return;
    }
    ch = *(u8 **)(model + 0x28) + channel * 0x10;
    if (weight != *(f32 *)ch) {
        *(f32 *)ch = weight;
    }
    ch[0xe] |= 4;
}
#pragma pop

typedef f32 Mtx[3][4];
extern void cutsceneEnterExit(int a, int b);
extern void Obj_BuildWorldTransformMatrix(u8 *obj, f32 *mtx, int flags);
extern void PSMTXMultVecSR(f32 *mtx, f32 *in, f32 *out);
extern void PSVECSubtract(f32 *a, f32 *b, f32 *out);
extern void PSVECNormalize(f32 *src, f32 *dst);
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern int lbl_803DC9F0;
extern int lbl_803DB3E0;
extern int lbl_803DCA04;
extern s16 lbl_802C9EE8[];
extern int lbl_803DC9FC;
extern void *lbl_803DC9F8;
extern u8 lbl_803DC9F7;
extern u8 lbl_803DC9F6;
extern u8 lbl_803DC9F5;
extern u8 lbl_803DC9F4;
extern int gameTextGetTaskText(int taskId, int *textId, int *dirId);
extern void *getCurGameText(void);
extern void loadGameTextSequence();
extern f32 lbl_803DE7C0;
extern f32 lbl_803DE7C4;
extern u8 lbl_803DCB42;

typedef struct {
    int numSlots;
    int f4;
    u8 *start;
    int size;
    int f10;
} MmRegion;
extern MmRegion gMmRegionTable[];

#pragma push
#pragma scheduling off
#pragma peephole off
void cutsceneFadeInOut(int a) {
    cutsceneEnterExit(a, 1);
}

int gameTextFn_8001b44c(int x) {
    if (lbl_803DC9F0 == 0) {
        lbl_803DB3E0 = x;
        return 1;
    }
    return 0;
}

#pragma optimize_for_size on
void gameTextLoadTaskText(int taskId) {
    int textId;
    int dirId;
    s16 *taskList;
    int count;
    int allowed;

    if (gameTextGetTaskText(taskId, &textId, &dirId) != 0) {
        if (lbl_803DCA00 == 0) {
            taskList = lbl_802C9EE8;
            count = 0xb;
            do {
                if (taskId == *taskList) {
                    allowed = 1;
                    goto checkAllowed;
                }
                taskList++;
            } while (--count != 0);
            allowed = 0;
checkAllowed:
            if (allowed == 0) {
                return;
            }
        }

        lbl_803DC9FC = textId;
        lbl_803DC9F8 = (void *)dirId;
        if (dirId == 0x29) {
            loadGameTextSequence();
            lbl_803DC9F0 = 1;
        } else {
            lbl_803DB3E0 = (int)getCurGameText();
            gameTextLoadDir((int)lbl_803DC9F8);
            lbl_803DC9F0 = 0;
        }
        lbl_803DCA04 = 1;
        lbl_803DC9F7 = 0xff;
        lbl_803DC9F6 = 0xff;
        lbl_803DC9F5 = 0xff;
        lbl_803DC9F4 = 0xff;
    }
}
#pragma optimize_for_size reset

#pragma optimize_for_size on
int gameTextFn_8001bcb4(void) {
    int ret;

    ret = 0;
    if (lbl_803DCA00 != 0) {
        if (lbl_803DCA04 != 0) {
            ret = 1;
        }
    }
    return ret;
}
#pragma optimize_for_size reset

#pragma dont_inline on
void Obj_TransformLocalVectorByWorldMatrix(void *obj, f32 *src, f32 *dst) {
    f32 mtx[16];
    Obj_BuildWorldTransformMatrix(obj, mtx, 0);
    PSMTXMultVecSR(mtx, src, dst);
}
#pragma dont_inline reset

extern void PSMTXMultVec(f32 *mtx, f32 *in, f32 *out);
extern f32 lbl_803DE890;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

#pragma dont_inline on
void Obj_TransformLocalPointByWorldMatrix(u8 *obj, f32 *src, f32 *dst, u8 flag) {
    f32 savedZ;
    f32 mtx[16];
    if (flag) {
        savedZ = *(f32 *)(obj + 8);
        *(f32 *)(obj + 8) = lbl_803DE890;
    }
    Obj_BuildWorldTransformMatrix(obj, mtx, 0);
    PSMTXMultVec(mtx, src, dst);
    if (flag) {
        *(f32 *)(obj + 8) = savedZ;
    }
    dst[0] += playerMapOffsetX;
    dst[2] += playerMapOffsetZ;
}
#pragma dont_inline reset

extern void Vec_normalize(f32 *dst, f32 *src);
extern f32 *Camera_GetViewMatrix(void);
extern void mtxRotateByVec3s(f32 *mtx, void *transform);
extern void mtx44Transpose(f32 *src, f32 *dst);

void fn_8002B2AC(f32 *out, u8 *transform, f32 *in) {
    f32 rotated[3];
    struct {
        s16 rotX;
        s16 rotY;
        s16 rotZ;
        s16 pad;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } inverse;
    f32 rotMtx[16];
    f32 transposed[16];

    inverse.x = -*(f32 *)(transform + 0xc);
    inverse.y = -*(f32 *)(transform + 0x10);
    inverse.z = -*(f32 *)(transform + 0x14);
    inverse.rotX = -*(s16 *)(transform + 0);
    inverse.rotY = -*(s16 *)(transform + 2);
    inverse.rotZ = -*(s16 *)(transform + 4);
    inverse.scale = lbl_803DE890;
    mtxRotateByVec3s(rotMtx, &inverse);
    mtx44Transpose(rotMtx, transposed);
    PSMTXMultVec(transposed, in, rotated);
    *(u32 *)(out + 0) = *(u32 *)(rotated + 0);
    *(u32 *)(out + 1) = *(u32 *)(rotated + 1);
    *(u32 *)(out + 2) = *(u32 *)(rotated + 2);
}

void modelStruct2_setVectors(u8 *s, f32 x, f32 y, f32 z) {
    f32 *view;
    if (*(void **)s != NULL) {
        *(f32 *)(s + 0x28) = x;
        *(f32 *)(s + 0x2c) = y;
        *(f32 *)(s + 0x30) = z;
        Vec_normalize((f32 *)(s + 0x28), (f32 *)(s + 0x28));
        Obj_TransformLocalVectorByWorldMatrix(*(void **)s, (f32 *)(s + 0x28), (f32 *)(s + 0x34));
    } else {
        *(f32 *)(s + 0x34) = x;
        *(f32 *)(s + 0x38) = y;
        *(f32 *)(s + 0x3c) = z;
        Vec_normalize((f32 *)(s + 0x34), (f32 *)(s + 0x34));
    }
    view = Camera_GetViewMatrix();
    if (*(int *)(s + 0x60) == 0) {
        PSMTXMultVecSR(view, (f32 *)(s + 0x34), (f32 *)(s + 0x40));
    } else {
        *(int *)(s + 0x40) = *(int *)(s + 0x34);
        *(int *)(s + 0x44) = *(int *)(s + 0x38);
        *(int *)(s + 0x48) = *(int *)(s + 0x3c);
    }
}

void lightVecFn_8001dd88(u8 *s, f32 x, f32 y, f32 z) {
    f32 tmp[3];
    f32 *view;
    if (*(void **)s != NULL) {
        *(f32 *)(s + 0x4) = x;
        *(f32 *)(s + 0x8) = y;
        *(f32 *)(s + 0xc) = z;
        Obj_TransformLocalPointByWorldMatrix(*(void **)s, (f32 *)(s + 0x4), (f32 *)(s + 0x10), 1);
    } else {
        *(f32 *)(s + 0x10) = x;
        *(f32 *)(s + 0x14) = y;
        *(f32 *)(s + 0x18) = z;
    }
    view = Camera_GetViewMatrix();
    if (*(int *)(s + 0x60) == 0) {
        tmp[0] = *(f32 *)(s + 0x10) - playerMapOffsetX;
        tmp[1] = *(f32 *)(s + 0x14);
        tmp[2] = *(f32 *)(s + 0x18) - playerMapOffsetZ;
        PSMTXMultVec(view, tmp, (f32 *)(s + 0x1c));
    } else {
        *(int *)(s + 0x1c) = *(int *)(s + 0x10);
        *(int *)(s + 0x20) = *(int *)(s + 0x14);
        *(int *)(s + 0x24) = *(int *)(s + 0x18);
    }
}

extern void GXInitSpecularDir(u8 *lt_obj, f32 x, f32 y, f32 z);
extern void GXInitLightColor(u8 *lt_obj, void *color);
extern void GXLoadLightObjImm(u8 *lt_obj, int lightId);
extern void GXInitLightPos(u8 *lt_obj, f32 x, f32 y, f32 z);
extern void GXInitLightDir(u8 *lt_obj, f32 x, f32 y, f32 z);
extern void GXInitLightAttnK(u8 *lt_obj, f32 k0, f32 k1, f32 k2);
extern void GXSetChanCtrl(int channel, int enable, int ambSrc, int matSrc, int lightMask, int diffFn,
                          int attnFn);
extern void GXSetNumChans(int numChannels);
extern void PSVECScale(f32 *src, f32 *dst, f32 scale);
extern void PSVECAdd(f32 *a, f32 *b, f32 *out);
extern f32 lbl_803DE7A4;
extern f32 *Camera_GetInverseViewMatrix(void);
extern void Obj_BuildInverseWorldTransformMatrix(u8 *obj, f32 *out);
extern void PSMTXConcat(f32 *a, f32 *b, f32 *ab);

#pragma push
#pragma scheduling off
#pragma peephole off
void modelStruct2LightFn_8001e178(u8 *light, u8 *obj, int lightId) {
    f32 viewPos[3];
    f32 *view;
    int lightType;

    view = Camera_GetViewMatrix();
    lightType = *(int *)(light + 0x50);
    switch (lightType) {
    case 2:
    case 8:
        if (lbl_803DCA31 != 0) {
            f32 worldPos[3];
            if (*(int *)(light + 0x60) == 0) {
                worldPos[0] = *(f32 *)(obj + 0xc) - playerMapOffsetX;
                worldPos[1] = *(f32 *)(obj + 0x10);
                worldPos[2] = *(f32 *)(obj + 0x14) - playerMapOffsetZ;
                PSMTXMultVec(view, worldPos, viewPos);
            } else {
                *(IVec3 *)viewPos = *(IVec3 *)(obj + 0xc);
            }
            PSVECSubtract((f32 *)(light + 0x1c), viewPos, viewPos);
            GXInitLightPos(light + 0x68, viewPos[0], viewPos[1], viewPos[2]);
        } else {
            GXInitLightPos(light + 0x68, *(f32 *)(light + 0x1c), *(f32 *)(light + 0x20),
                           *(f32 *)(light + 0x24));
        }
        GXInitLightDir(light + 0x68, *(f32 *)(light + 0x40), *(f32 *)(light + 0x44),
                       *(f32 *)(light + 0x48));
        if (obj != NULL && (*(u32 *)(*(int *)(obj + 0x50) + 0x44) & 0x10) == 0) {
            u8 rgba[4];
            u32 color;
            rgba[0] = (f32)light[0xa8] * *(f32 *)(light + 0x134);
            rgba[1] = (f32)light[0xa9] * *(f32 *)(light + 0x134);
            rgba[2] = (f32)light[0xaa] * *(f32 *)(light + 0x134);
            rgba[3] = (f32)light[0xab] * *(f32 *)(light + 0x134);
            color = *(u32 *)rgba;
            GXInitLightColor(light + 0x68, &color);
            GXInitLightAttnK(light + 0x68, lbl_803DE760, lbl_803DE75C, lbl_803DE75C);
        } else {
            u32 color;
            color = *(u32 *)(light + 0xa8);
            GXInitLightColor(light + 0x68, &color);
            GXInitLightAttnK(light + 0x68, *(f32 *)(light + 0x124), *(f32 *)(light + 0x128),
                             *(f32 *)(light + 0x12c));
        }
        break;
    case 4: {
        f32 worldPos[3];
        u32 color;
        if (obj != NULL) {
            if (*(int *)(light + 0x60) == 0) {
                worldPos[0] = *(f32 *)(obj + 0xc) - playerMapOffsetX;
                worldPos[1] = *(f32 *)(obj + 0x10);
                worldPos[2] = *(f32 *)(obj + 0x14) - playerMapOffsetZ;
                PSMTXMultVec(view, worldPos, viewPos);
            } else {
                *(IVec3 *)viewPos = *(IVec3 *)(obj + 0xc);
            }
        } else {
            viewPos[0] = lbl_803DE75C;
            viewPos[1] = lbl_803DE75C;
            viewPos[2] = lbl_803DE75C;
        }
        PSVECScale((f32 *)(light + 0x40), (f32 *)(light + 0x1c), lbl_803DE7A4);
        PSVECAdd((f32 *)(light + 0x1c), viewPos, viewPos);
        GXInitLightPos(light + 0x68, viewPos[0], viewPos[1], viewPos[2]);
        color = *(u32 *)(light + 0xa8);
        GXInitLightColor(light + 0x68, &color);
        GXInitLightAttnK(light + 0x68, lbl_803DE760, lbl_803DE75C, lbl_803DE75C);
        break;
    }
    }
    GXLoadLightObjImm(light + 0x68, lightId);
}
#pragma pop

void modelStruct2_setLights(int channel, u8 *light, u8 *obj) {
    f32 viewDir[3];
    f32 localDir[3];
    u32 color;
    f32 *view;
    int lightId;
    int offset;
    int lightType;

    offset = channel * 0x10;
    if (lbl_8033BE60[channel].mode == 0 || lbl_8033BE60[channel].mode == 2) {
        modelStruct2LightFn_8001e178(light, obj, lbl_803DCA34);
    } else {
        lightId = lbl_803DCA34;
        view = Camera_GetViewMatrix();
        lightType = *(int *)(light + 0x50);
        if (lightType != 3) {
            if (lightType < 3) {
                if (lightType < 2) {
                } else {
                    PSVECSubtract((f32 *)(obj + 0xc), (f32 *)(light + 0x10), localDir);
                    PSVECNormalize(localDir, localDir);
                    if (*(int *)(light + 0x60) == 0) {
                        PSMTXMultVecSR(view, localDir, viewDir);
                    } else {
                        *(int *)&viewDir[0] = *(int *)&localDir[0];
                        *(int *)&viewDir[1] = *(int *)&localDir[1];
                        *(int *)&viewDir[2] = *(int *)&localDir[2];
                    }
                    GXInitSpecularDir(light + 0xc0, viewDir[0], viewDir[1], viewDir[2]);
                }
            } else if (lightType < 5) {
                GXInitSpecularDir(light + 0xc0, *(f32 *)(light + 0x40), *(f32 *)(light + 0x44),
                                  *(f32 *)(light + 0x48));
            }
        }
        color = *(u32 *)(light + 0x100);
        GXInitLightColor(light + 0xc0, &color);
        GXLoadLightObjImm(light + 0xc0, lightId);
    }
    lbl_8033BE60[channel].lightMask |= lbl_803DCA34;
    lbl_803DCA34 <<= 1;
}

void gxColorFn_8001e634(void) {
    int activeMask;
    int lightMask;
    int channel;
    int attnFn;
    Elem8033BE60 *entry;

    activeMask = 0;
    channel = 0;
    entry = lbl_8033BE60;
    do {
        if (entry->active != 0) {
            if (entry->mode == 0) {
                lightMask = entry->lightMask;
                if (lightMask != 0) {
                    attnFn = 1;
                } else {
                    attnFn = 2;
                }
                GXSetChanCtrl(channel, lightMask != 0, 0, entry->matSrc, lightMask, lightMask != 0 ? 2 : 0,
                              attnFn);
            } else if (entry->mode == 2) {
                lightMask = entry->lightMask;
                attnFn = lightMask != 0 ? 1 : 2;
                GXSetChanCtrl(channel, lightMask != 0, 0, entry->matSrc, lightMask, 0, attnFn);
            } else {
                lightMask = entry->lightMask;
                attnFn = lightMask != 0 ? 0 : 2;
                GXSetChanCtrl(channel, lightMask != 0, 0, entry->matSrc, lightMask, 0, attnFn);
            }
            activeMask = (activeMask | (1 << channel)) & 0xff;
        }
        entry++;
        channel++;
    } while (channel <= 5);

    activeMask &= 0xff;

    if ((activeMask & 1) != 0) {
        if ((activeMask & 4) == 0) {
            GXSetChanCtrl(2, 0, 0, 0, 0, 0, 2);
        }
    } else if ((activeMask & 4) != 0) {
        GXSetChanCtrl(0, 0, 0, 0, 0, 0, 2);
    }

    if ((activeMask & 2) != 0) {
        if ((activeMask & 8) == 0) {
            GXSetChanCtrl(3, 0, 0, 0, 0, 0, 2);
        }
    } else if ((activeMask & 8) != 0) {
        GXSetChanCtrl(1, 0, 0, 0, 0, 0, 2);
    }

    if ((activeMask & 0x2a) != 0) {
        GXSetNumChans(2);
    } else if ((activeMask & 0x15) != 0) {
        GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
        GXSetNumChans(1);
    } else {
        GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
        GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
        GXSetNumChans(0);
    }
}

void updateLights(void) {
    f32 viewPos[3];
    f32 concatMtx[16];
    f32 *view;
    u8 *light;
    int i;
    int fadeState;

    view = Camera_GetViewMatrix();
    for (i = 0; i < lbl_803DCA30; i++) {
        light = lbl_8033BEC0[i];
        fadeState = *(int *)(light + 0x58);
        if (fadeState == 1) {
            *(f32 *)(light + 0x138) += *(f32 *)(light + 0x13c);
            if (*(f32 *)(light + 0x138) >= lbl_803DE760) {
                *(f32 *)(light + 0x138) = lbl_803DE760;
                *(int *)(light + 0x58) = 2;
            }
        } else if (fadeState == 3) {
            *(f32 *)(light + 0x138) += *(f32 *)(light + 0x13c);
            if (*(f32 *)(light + 0x138) <= lbl_803DE788) {
                *(f32 *)(light + 0x138) = lbl_803DE788;
                *(int *)(light + 0x58) = 0;
                light[0x4c] = 0;
            }
        }

        if (light[0x4c] != 0) {
            if (*(int *)(light + 0x50) != 4) {
                if (*(void **)light != NULL) {
                    Obj_TransformLocalPointByWorldMatrix(*(u8 **)light, (f32 *)(light + 4), (f32 *)(light + 0x10),
                                                         1);
                }
                if (*(int *)(light + 0x60) == 0) {
                    viewPos[0] = *(f32 *)(light + 0x10) - playerMapOffsetX;
                    viewPos[1] = *(f32 *)(light + 0x14);
                    viewPos[2] = *(f32 *)(light + 0x18) - playerMapOffsetZ;
                    PSMTXMultVec(view, viewPos, (f32 *)(light + 0x1c));
                } else {
                    *(int *)(light + 0x1c) = *(int *)(light + 0x10);
                    *(int *)(light + 0x20) = *(int *)(light + 0x14);
                    *(int *)(light + 0x24) = *(int *)(light + 0x18);
                }
            }

            if (*(void **)light != NULL) {
                Obj_TransformLocalVectorByWorldMatrix(*(void **)light, (f32 *)(light + 0x28),
                                                       (f32 *)(light + 0x34));
            }
            if (*(int *)(light + 0x60) == 0) {
                PSMTXMultVecSR(view, (f32 *)(light + 0x34), (f32 *)(light + 0x40));
            } else {
                *(int *)(light + 0x40) = *(int *)(light + 0x34);
                *(int *)(light + 0x44) = *(int *)(light + 0x38);
                *(int *)(light + 0x48) = *(int *)(light + 0x3c);
            }

            if (*(int *)(light + 0x2d8) != 0) {
                lightFn_8001d168(light);
            } else {
                light[0xa8] = (u8)(int)((f32)light[0xac] * *(f32 *)(light + 0x138));
                light[0xa9] = (u8)(int)((f32)light[0xad] * *(f32 *)(light + 0x138));
                light[0xaa] = (u8)(int)((f32)light[0xae] * *(f32 *)(light + 0x138));
                light[0xab] = (u8)(int)((f32)light[0xaf] * *(f32 *)(light + 0x138));
                light[0x100] = (u8)(int)((f32)light[0x104] * *(f32 *)(light + 0x138));
                light[0x101] = (u8)(int)((f32)light[0x105] * *(f32 *)(light + 0x138));
                light[0x102] = (u8)(int)((f32)light[0x106] * *(f32 *)(light + 0x138));
                light[0x103] = (u8)(int)((f32)light[0x107] * *(f32 *)(light + 0x138));
            }

            if (*(int *)(light + 0x50) == 8) {
                Obj_BuildInverseWorldTransformMatrix(*(u8 **)light, (f32 *)(light + 0x170));
                PSMTXConcat((f32 *)(light + 0x170), Camera_GetInverseViewMatrix(), concatMtx);
                PSMTXConcat((f32 *)(light + 0x1b0), concatMtx, (f32 *)(light + 0x230));
            }
        }
    }
}

extern int *lbl_803DCB60;
extern void fileLoadToBufferOffset(int id, void *buf, int offset, int size);

#pragma peephole off
#pragma dont_inline on
int modelGetAmapSize(int a, int b, int c) {
    int size;
    if (b != 0) {
        size = c * 2 + 8;
        while (size & 7) {
            size++;
        }
    } else {
        size = c * 4;
        while (size & 7) {
            size++;
        }
        fileLoadToBufferOffset(0x31, lbl_803DCB60, (a & ~3) << 2, 0x20);
        size += lbl_803DCB60[(a & 3) + 1] - lbl_803DCB60[a & 3];
    }
    return size;
}
#pragma dont_inline reset
#pragma peephole reset

extern void *mmAlloc(int size, int type, int flag);
extern void *memset(void *dst, int val, int n);

void *Obj_AllocObjectSetup(int size, int b) {
    u8 *p = mmAlloc(size, 0xe, 0);
    memset(p, 0, size);
    *(int *)(p + 0x14) = -1;
    p[6] = 0x64;
    p[7] = 0x96;
    p[4] = 8;
    p[5] = 4;
    *(s16 *)p = b;
    p[2] = size;
    return p;
}

extern void *getCurrentDataFile(int id);
extern int lbl_803DCB68;
extern void *lbl_803DCB4C;
extern int lbl_803DCB58;
extern void shaderInit(u8 *def, void *out, int arg, int n);

void ObjModel_RelocateModelData(u8 *m) {
    int i;
    if (*(u32 *)(m + 0x58)) {
        *(u32 *)(m + 0x58) += (u32)m;
    }
    if (*(u32 *)(m + 0x3c)) {
        *(u32 *)(m + 0x3c) += (u32)m;
        if (*(u32 *)(m + 0x18)) {
            *(u32 *)(m + 0x18) += (u32)m;
        }
        if (*(u32 *)(m + 0x1c)) {
            *(u32 *)(m + 0x1c) += (u32)m;
        }
        if (*(u32 *)(m + 0x40)) {
            *(u32 *)(m + 0x40) += (u32)m;
        }
    }
    if (*(u32 *)(m + 0x54)) {
        *(u32 *)(m + 0x54) += (u32)m;
    }
    if (*(u32 *)(m + 0x20)) {
        *(u32 *)(m + 0x20) += (u32)m;
    }
    *(u32 *)(m + 0x28) += (u32)m;
    if (*(u32 *)(m + 0x2c)) {
        *(u32 *)(m + 0x2c) += (u32)m;
    }
    if (*(u32 *)(m + 0x30)) {
        *(u32 *)(m + 0x30) += (u32)m;
    }
    if (*(u32 *)(m + 0x34)) {
        *(u32 *)(m + 0x34) += (u32)m;
    }
    if (*(u32 *)(m + 0xd4)) {
        *(u32 *)(m + 0xd4) += (u32)m;
    }
    if (*(u32 *)(m + 0xd0)) {
        *(u32 *)(m + 0xd0) += (u32)m;
    }
    if (*(u32 *)(m + 0xdc)) {
        *(u32 *)(m + 0xdc) += (u32)m;
    }
    if (*(u32 *)(m + 0xa4)) {
        *(u32 *)(m + 0xa4) += (u32)m;
    }
    if (*(u32 *)(m + 0xa8)) {
        *(u32 *)(m + 0xa8) += (u32)m;
    }
    if (*(u32 *)(m + 0xc8)) {
        *(u32 *)(m + 0xc8) += (u32)m;
    }
    if (*(u32 *)(m + 0xcc)) {
        *(u32 *)(m + 0xcc) += (u32)m;
    }
    if (*(u32 *)(m + 0x38)) {
        *(u32 *)(m + 0x38) += (u32)m;
    }
    for (i = 0; i < m[0xf5] + m[0xf6]; i++) {
        *(u32 *)(*(u8 **)(m + 0xd0) + i * 0x1c) += (u32)m;
    }
    for (i = 0; i < m[0xf9]; i++) {
        *(u32 *)(*(u8 **)(m + 0xdc) + i * 4) += (u32)m;
    }
    if (*(u32 *)(m + 0x5c)) {
        *(u32 *)(m + 0x5c) += (u32)m;
    }
    if (*(u32 *)(m + 0x60)) {
        *(u32 *)(m + 0x60) += (u32)m;
    }
}

extern int getTableFileEntry(int fileId, int index, int *out);
extern void loadModelsBin();
extern int loadAndDecompressDataFile(int id, void *buf, int blockOff, int len, int a, int b, int c);

#pragma dont_inline on
void *ObjModel_LoadModelData(int id) {
    int a18, a14, a10, aC, a8;
    void *model;
    if (getTableFileEntry(0x2a, id, &a18) == 0) {
        return NULL;
    }
    ((void (*)(int, int *, int *, int *, int *, int))loadModelsBin)(a18, &a10, &aC, &a8, &a14, id);
    aC = roundUpTo8(aC);
    aC += 0xb0;
    model = (void *)roundUpTo16((int)mmAlloc(a14 + modelGetAmapSize(id, a8, a10) + 0x1f4, 9, 0));
    loadAndDecompressDataFile(0x2b, model, a18, a14, 0, id, 0);
    *(s16 *)((u8 *)model + 0x84) = aC;
    *(u16 *)((u8 *)model + 0x4) = id;
    *(u16 *)((u8 *)model + 0xec) = a10;
    *(u16 *)((u8 *)model + 0x2) &= ~0x40;
    *(u8 *)model = 1;
    if (*(u16 *)((u8 *)model + 0xec) == 0) {
        *(u16 *)((u8 *)model + 0x2) |= 2;
    }
    if (a8 != 0) {
        *(u16 *)((u8 *)model + 0x2) |= 0x40;
    }
    return model;
}
#pragma dont_inline reset

void ObjModel_ResolveRenderOpTextures(u8 *m) {
    int j, k;
    u8 *op;
    for (j = 0; j < m[0xf8]; j++) {
        op = *(u8 **)(m + 0x38) + j * 0x44;
        for (k = 0; k < op[0x41]; k++) {
            u8 *e = op + k * 8;
            if (*(int *)(e + 0x24) != -1) {
                *(int *)(e + 0x24) = ((int *)*(u8 **)(m + 0x20))[*(int *)(e + 0x24)];
            } else {
                *(int *)(e + 0x24) = 0;
            }
        }
        if (*(int *)(op + 0x34) != -1) {
            *(int *)(op + 0x34) = ((int *)*(u8 **)(m + 0x20))[*(int *)(op + 0x34)];
        } else {
            *(int *)(op + 0x34) = 0;
        }
        if (*(int *)(op + 0x38) != -1) {
            *(int *)(op + 0x38) = ((int *)*(u8 **)(m + 0x20))[*(int *)(op + 0x38)];
        } else {
            *(int *)(op + 0x38) = 0;
        }
        if (*(int *)(op + 0x1c) == -1) {
            *(int *)(op + 0x1c) = 0;
        } else if (*(int *)(op + 0x1c) == -2) {
            *(int *)(op + 0x1c) = 0;
        } else {
            *(int *)(op + 0x1c) = 1;
        }
        if (*(int *)(op + 0x18) != -1) {
            *(int *)(op + 0x18) = ((int *)*(u8 **)(m + 0x20))[*(int *)(op + 0x18)];
        } else {
            *(int *)(op + 0x18) = 0;
        }
        if (!(*(u16 *)(m + 0xe2) & 0xc)) {
            *(int *)(op + 0x8) = 0;
        }
        if (!(*(u16 *)(m + 0xe2) & 0xe00)) {
            *(int *)(op + 0x14) = 0;
        }
    }
}

#pragma dont_inline on
void ObjModel_RelocateAnimData(u8 *m, u8 *dst) {
    int i;
    *(u8 **)(m + 0x94) = *(u8 **)(m + 0xa4);
    for (i = 0; i < *(u16 *)(m + 0x8a); i++) {
        *(int *)(*(u8 **)(dst + 0x40) + i * 4) = *(int *)(*(u8 **)(m + 0xa4) + i * 0x74 + 0x60);
        if (*(u32 *)(*(u8 **)(m + 0xa4) + i * 0x74 + 0x64) < *(u32 *)(m + 0xa8)) {
            *(u32 *)(*(u8 **)(m + 0xa4) + i * 0x74 + 0x64) =
                *(u32 *)(m + 0xa8) + *(u32 *)(*(u8 **)(m + 0xa4) + i * 0x74 + 0x64);
        }
    }
    *(u8 **)(m + 0xb8) = *(u8 **)(m + 0xc8);
    for (i = 0; i < *(u16 *)(m + 0xae); i++) {
        *(int *)(*(u8 **)(dst + 0x44) + i * 4) =
            *(int *)(dst + 0x24) + *(int *)(*(u8 **)(m + 0xc8) + i * 0x74 + 0x60);
        if (*(u32 *)(*(u8 **)(m + 0xc8) + i * 0x74 + 0x64) < *(u32 *)(m + 0xcc)) {
            *(u32 *)(*(u8 **)(m + 0xc8) + i * 0x74 + 0x64) =
                *(u32 *)(m + 0xcc) + *(u32 *)(*(u8 **)(m + 0xc8) + i * 0x74 + 0x64);
        }
    }
}
#pragma dont_inline reset

void ObjModel_LoadRenderOpTextures(u8 *model, int arg) {
    int i;
    u8 *hdr = *(u8 **)model;
    if (*(u16 *)(model + 0x18) & 0x40) {
        return;
    }
    *(u16 *)(model + 0x18) |= 0x40;
    for (i = 0; i < (*(u8 **)model)[0xf8]; i++) {
        shaderInit(*(u8 **)(hdr + 0x38) + i * 0x44, *(u8 **)(model + 0x34) + i * 0xc, arg,
                   *(u16 *)(hdr + 0xe2));
    }
}

int loadModelAndAnimTabs(void) {
    int *p = getCurrentDataFile(0x2a);
    if (p == NULL) {
        return 0;
    }
    lbl_803DCB68 = 0;
    while (*p != -1) {
        p++;
        lbl_803DCB68++;
    }
    lbl_803DCB68--;
    lbl_803DCB4C = getCurrentDataFile(0x2f);
    if (lbl_803DCB4C == NULL) {
        return 0;
    }
    lbl_803DCB58 = 0;
    return 1;
}

int gameBitDecrement(int bit) {
    int val = GameBit_Get(bit);
    if (val != 0) {
        val--;
        GameBit_Set(bit, val);
        return val;
    }
    return 0;
}

void initRotationMtx(f32 *m, f32 a, f32 b, f32 c) {
    f32 z = lbl_803DE7C0;
    m[0] = z;
    m[1] = z;
    m[2] = z;
    m[3] = z;
    m[4] = z;
    m[5] = z;
    m[6] = z;
    m[7] = z;
    m[8] = z;
    m[9] = z;
    m[10] = z;
    m[11] = z;
    m[12] = z;
    m[13] = z;
    m[14] = z;
    m[15] = z;
    m[0] = a;
    m[5] = b;
    m[10] = c;
}

int mmGetRegionForPtr(u8 *ptr) {
    int i;
    for (i = 0; i < lbl_803DCB42; i++) {
        u8 *start = gMmRegionTable[i].start;
        if (ptr > start && ptr < start + gMmRegionTable[i].size) {
            return i;
        }
    }
    return -1;
}

#pragma dont_inline on
void *mmInitRegion(u8 *buf, int size, int numSlots) {
    int regIdx = lbl_803DCB42++;
    int after = size - numSlots * 0x1c;
    int i;
    u8 *slot;
    int freePtr;
    gMmRegionTable[regIdx].numSlots = numSlots;
    gMmRegionTable[regIdx].f4 = 0;
    gMmRegionTable[regIdx].start = buf;
    gMmRegionTable[regIdx].size = size;
    gMmRegionTable[regIdx].f10 = 0;
    slot = gMmRegionTable[regIdx].start;
    for (i = 0; i < gMmRegionTable[regIdx].numSlots; i++) {
        *(s16 *)(slot + 0xe) = i;
        slot += 0x1c;
    }
    slot = gMmRegionTable[regIdx].start;
    freePtr = (int)buf + numSlots * 0x1c;
    if (freePtr & 0x1f) {
        *(int *)(slot + 0) = (freePtr & ~0x1f) + 0x20;
    } else {
        *(int *)(slot + 0) = freePtr;
    }
    *(int *)(slot + 4) = after;
    *(s16 *)(slot + 8) = 0;
    *(s16 *)(slot + 0xa) = -1;
    *(s16 *)(slot + 0xc) = -1;
    gMmRegionTable[regIdx].f4++;
    return gMmRegionTable[regIdx].start;
}
#pragma dont_inline reset

extern u32 OSGetTick(void);
extern void heapFree(int region, int slotIdx);
extern char sMmFreeInvalidLocationError[];
extern char sMmAllocFreeMessageBlock[];
extern int lbl_803DCB34;
extern void OSReport(char *fmt, ...);
extern void waitNextFrame(void);
extern void GXFlush_(int a, int b);
extern char sMmStbfStackTooDeepError[];
extern s16 gMmDeferredFreeCount;

typedef struct {
    void *ptr;
    u8 delay;
    u8 pad[3];
} DeferredFree;
extern DeferredFree gMmDeferredFreeStack[];

extern char sMmShowInfoFBMemoryStoreMessageBlock[];
extern char sMmStoreAllocationTag;
extern int gMmNextStoreHandle;
extern void *gMmStoreArray[];

typedef struct {
    void *buf;
    void *bufCur;
    int size;
    int handle;
} MmStore;

int mmCreateMemoryStore(int size) {
    char *msg = sMmShowInfoFBMemoryStoreMessageBlock;
    MmStore *store;
    void **p;
    int i = 0;
    if (size <= 0) {
        OSReport(msg + 0x1e8, size);
        return 0;
    }
    if (size > 0x4000) {
        OSReport(msg + 0x218, size, 0x4000);
        return 0;
    }
    store = (MmStore *)mmAlloc(0x10, 0, (int)&sMmStoreAllocationTag);
    if (store == NULL) {
        OSReport(msg + 0x26c);
        return 0;
    }
    store->size = size;
    store->handle = gMmNextStoreHandle++;
    store->buf = NULL;
    store->bufCur = NULL;
    store->buf = mmAlloc(store->size, 0, (int)(msg + 0x2a8));
    if (store->buf == NULL) {
        OSReport(msg + 0x2bc);
        if (gMmFreeDelay == 0) {
            mmFree(store);
        } else {
            mmFreeDeferred(store);
        }
        return 0;
    }
    store->bufCur = store->buf;
    p = gMmStoreArray;
    while (i < 0x20) {
        if (*p == NULL) {
            gMmStoreArray[i] = store;
            break;
        }
        p++;
        if (++i == 0x20) {
            void *buf;
            OSReport(msg + 0x2f8);
            buf = store->buf;
            if (gMmFreeDelay == 0) {
                mmFree(buf);
            } else {
                mmFreeDeferred(buf);
            }
            if (gMmFreeDelay == 0) {
                mmFree(store);
            } else {
                mmFreeDeferred(store);
            }
            return 0;
        }
    }
    return store->handle;
}

void mmFreeDeferred(void *p) {
    DeferredFree *stack;
    if (gMmDeferredFreeCount == 0x7d0) {
        waitNextFrame();
        GXFlush_(1, 0);
        waitNextFrame();
        GXFlush_(1, 0);
        stack = gMmDeferredFreeStack;
        while (gMmDeferredFreeCount > 0) {
            DeferredFree *top;
            mmFree(stack[0].ptr);
            top = &stack[gMmDeferredFreeCount];
            stack[0].ptr = top[-1].ptr;
            stack[0].delay = top[-1].delay;
            gMmDeferredFreeCount--;
        }
        OSReport(sMmStbfStackTooDeepError);
    }
    gMmDeferredFreeStack[gMmDeferredFreeCount].ptr = p;
    gMmDeferredFreeStack[gMmDeferredFreeCount].delay = gMmFreeDelay;
    gMmDeferredFreeCount++;
}

typedef struct {
    void *key;
    int size;
    s16 type;
    s16 prev;
    s16 next;
    s16 stack;
    int f10;
    int f14;
    int f18;
} HeapItem;

typedef struct {
    void *stores[0x20];
    DeferredFree deferred[2000];
    MmRegion regions[8];
} MmGlobal;

extern void SaveGame_updateTransientMapBits(void);
extern int lbl_803DCB30;
extern int lbl_803DCB1C;
extern char sMemStatsFormat[];
extern int lbl_803DCB20;
extern int lbl_803DCB24;
extern int lbl_803DCB28;
extern int lbl_803DCB2C;

#pragma peephole on
void mmFreeTick(int arg) {
    MmGlobal *g = (MmGlobal *)gMmStoreArray;
    int i;
    DeferredFree *d;
    int k;
    HeapItem *base;
    HeapItem *item;
    s16 next;

    lbl_803DCB1C++;
    lbl_803DCB14++;

    d = g->deferred;
    for (i = 0; i < gMmDeferredFreeCount;) {
        d->delay--;
        if (d->delay == 0) {
            mmFree(d->ptr);
            d->ptr = g->deferred[gMmDeferredFreeCount - 1].ptr;
            d->delay = g->deferred[gMmDeferredFreeCount - 1].delay;
            gMmDeferredFreeCount--;
        } else {
            d++;
            i++;
        }
    }

    for (k = 0; k < 0x20; k++) {
        MmStore *s = (MmStore *)g->stores[k];
        if (s != NULL) {
            s->bufCur = s->buf;
        }
    }
    SaveGame_updateTransientMapBits();

    lbl_803DCB20 = 0;
    lbl_803DCB28 = 0;
    lbl_803DCB24 = 0;
    lbl_803DCB2C = 0;

    if (lbl_803DCB42 > 1) {
        base = (HeapItem *)g->regions[1].start;
        item = base;
        do {
            if (item->type != 0) {
                lbl_803DCB24 += item->size;
            }
            next = item->next;
            if (next != -1) {
                item = &base[next];
            }
        } while (next != -1);

        base = (HeapItem *)g->regions[2].start;
        item = base;
        do {
            if (item->type != 0) {
                lbl_803DCB28 += item->size;
            }
            next = item->next;
            if (next != -1) {
                item = &base[next];
            }
        } while (next != -1);

        base = (HeapItem *)g->regions[3].start;
        item = base;
        do {
            if (item->type != 0) {
                lbl_803DCB2C += item->size;
            }
            next = item->next;
            if (next != -1) {
                item = &base[next];
            }
        } while (next != -1);
    }

    if (lbl_803DCB30++ % 500 == 0) {
        OSReport(sMemStatsFormat,
            0, g->regions[0].size,
            lbl_803DCB24, g->regions[1].size,
            lbl_803DCB28, g->regions[2].size,
            lbl_803DCB2C, g->regions[3].size,
            g->regions[0].f4, g->regions[0].numSlots,
            g->regions[1].f4, g->regions[1].numSlots,
            g->regions[2].f4, g->regions[2].numSlots,
            g->regions[3].f4, g->regions[3].numSlots);
    }
}
#pragma peephole reset

void mmFree(void *p) {
    int region;
    int i;
    u8 *slot;
    u8 *base;
    lbl_803DCB34 = OSGetTick();
    region = mmGetRegionForPtr(p);
    if (region != -1) {
        base = gMmRegionTable[region].start;
        i = 0;
        do {
            slot = base + i * 0x1c;
            if (*(void **)slot == p) {
                s16 t = *(s16 *)(slot + 8);
                if (t == 1 || t == 4) {
                    heapFree(region, i);
                } else {
                    OSReport(sMmFreeInvalidLocationError, p);
                }
                return;
            }
            i = *(s16 *)(slot + 0xc);
        } while (i != -1);
    }
    OSReport(sMmAllocFreeMessageBlock, p);
}

extern void *gMmStoreArray[];
extern char sMmAllocateFromFBMemoryStoreMissingHandleError[];
extern char sMmMemoryStoreMessageBlock[];

int mmAllocateFromFBMemoryStore(int handle, int size) {
    void **p;
    int *found;
    int i;
    int avail;
    found = NULL;
    i = 0;
    p = gMmStoreArray;
    while (i < 0x20) {
        int *store = (int *)*p;
        if (store != NULL && handle == store[3]) {
            found = (int *)gMmStoreArray[i];
            break;
        }
        p++;
        if (++i == 0x20) {
            OSReport(sMmAllocateFromFBMemoryStoreMissingHandleError);
            return 0;
        }
    }
    if (found != NULL) {
        avail = found[2] - (found[1] - found[0]);
        if (avail < size) {
            OSReport(sMmMemoryStoreMessageBlock);
            return 0;
        }
        found[1] += size;
        return found[1] - size;
    }
    return 0;
}

extern void *OSGetArenaLo(void);
extern void *OSGetArenaHi(void);
extern void *OSAllocFromHeap(int heap, int size);
extern void DCFlushRange(void *addr, u32 nBytes);
extern int __OSCurrHeap;
extern int lbl_803DCB18;
extern void *lbl_803DD498;
extern void *lbl_803DCAFC;

void mmInit(void) {
    int size;
    void *p;
    u8 *lo;
    lbl_803DCB42 = 0;
    lo = OSGetArenaLo();
    size = (u8 *)OSGetArenaHi() - lo - 0x6c0000 - 0x720;
    lbl_803DCB18 = size;
    p = OSAllocFromHeap(__OSCurrHeap, size);
    DCFlushRange(p, size);
    mmInitRegion(p, size, 0xfa);

    p = OSAllocFromHeap(__OSCurrHeap, 0x6ed);
    lbl_803DD498 = p;
    lbl_803DCAFC = (u8 *)p + 0x6ec;

    p = OSAllocFromHeap(__OSCurrHeap, 0x1c0000);
    DCFlushRange(p, 0x1c0000);
    mmInitRegion(p, 0x1c0000, 0x352);

    p = OSAllocFromHeap(__OSCurrHeap, 0x9ffa0);
    DCFlushRange(p, 0x9ffa0);
    mmInitRegion(p, 0x9ffa0, 0x352);

    p = OSAllocFromHeap(__OSCurrHeap, 0x45ffa0);
    DCFlushRange(p, 0x45ffa0);
    mmInitRegion(p, 0x45ffa0, 0x244);

    lbl_803DCB14++;
    gMmFreeDelay = 2;
    gMmDeferredFreeCount = 0;
}

extern char sMmSpawnedUnalignedSlotWarning[];
extern int lbl_803DCB1C;
extern char sMemStatsFormat[];
extern int lbl_803DCB20;
extern int lbl_803DCB24;
extern int lbl_803DCB28;
extern int lbl_803DCB2C;

int printHeapStats(void) {
    OSReport(sMemStatsFormat,
        lbl_803DCB20, gMmRegionTable[0].size,
        lbl_803DCB24, gMmRegionTable[1].size,
        lbl_803DCB28, gMmRegionTable[2].size,
        lbl_803DCB2C, gMmRegionTable[3].size,
        gMmRegionTable[0].f4, gMmRegionTable[0].numSlots,
        gMmRegionTable[1].f4, gMmRegionTable[1].numSlots,
        gMmRegionTable[2].f4, gMmRegionTable[2].numSlots,
        gMmRegionTable[3].f4, gMmRegionTable[3].numSlots);
    return lbl_803DCB20 + (lbl_803DCB24 + lbl_803DCB28 + lbl_803DCB2C);
}

int heapSpawnSlot(int region, int idx, int size, int type, int newType, int f10val, int tag);
int changeHeapSlot(int region, int idx, int newSize, int type, int newType, int f10val, int tag);
extern void reportAllocFail(int, int, int, int, int, int, int, int, int, int, int);
extern int lbl_803DB430;
extern int lbl_803DCB0C;
extern int lbl_803DCC7C;

int mmAllocFromRegion(int region, int size, int type, int tag) {
    char *msg = sMmShowInfoFBMemoryStoreMessageBlock;
    int bestIdx;
    HeapItem *base;
    HeapItem *it;
    HeapItem *res;
    int bestSize;
    int largest;
    int t28;
    int t27;
    int idx;

    largest = 0;
    t28 = 0;
    t27 = 0;

    if (gMmRegionTable[region].f4 + 1 == gMmRegionTable[region].numSlots) {
        OSReport(msg + 0x4b8, tag, region);
        return 0;
    }

    if (size & 0x1f) {
        size = (size & ~0x1f) + 0x20;
    }

    bestIdx = -1;
    bestSize = 0x7fffffff;
    base = (HeapItem *)gMmRegionTable[region].start;
    idx = 0;

    if (region == 0 && size < 0x33450) {
        it = base;
        while (it->next != -1) {
            idx = it->next;
            it = &base[idx];
        }
        do {
            it = &base[idx];
            if (it->type == 0) {
                if (it->size >= size) {
                    if (it->size < bestSize) {
                        bestSize = it->size;
                        bestIdx = idx;
                    }
                } else if (it->size > largest) {
                    largest = it->size;
                }
            }
            idx = it->prev;
        } while (idx != -1);
    } else {
        do {
            it = &base[idx];
            if (it->type == 0) {
                if (it->size >= size) {
                    if (it->size < bestSize) {
                        bestSize = it->size;
                        bestIdx = idx;
                        if (region == 0) {
                            break;
                        }
                    }
                } else if (it->size > largest) {
                    largest = it->size;
                }
            }
            idx = it->next;
        } while (idx != -1);
    }

    if (bestIdx != -1) {
        gMmRegionTable[region].f10 += size;
        if (gMmRegionTable[region].f10 < 0 || gMmRegionTable[region].f10 > gMmRegionTable[region].size) {
            OSReport(msg + 0x50c);
        }
        if (lbl_803DB430 != 0 && region == 0 && size < 0x33450) {
            bestIdx = heapSpawnSlot(region, bestIdx, size, 1, 0, type, tag);
        } else {
            changeHeapSlot(region, bestIdx, size, 1, 0, type, tag);
        }
        res = &base[bestIdx];
        if (lbl_803DCB0C == 0x3ef) {
            OSReport(msg + 0x53c);
        }
        res->f18 = lbl_803DCB0C++;
        lbl_803DCB14++;
        return (int)res->key;
    }

    if ((region == 2 && size > 0x3000) || region == 3 || region == 1) {
        HeapItem *b0;
        HeapItem *b1;
        OSReport(msg + 0x54c, tag, region, type, size);
        b0 = (HeapItem *)gMmRegionTable[0].start;
        it = b0;
        while (it->next != -1) {
            it = &b0[it->next];
            if (it->size > t28 && it->type == 0) {
                t28 = it->size;
            }
        }
        b1 = (HeapItem *)gMmRegionTable[1].start;
        it = b1;
        while (it->next != -1) {
            it = &b1[it->next];
            if (it->size > t27 && it->type == 0) {
                t27 = it->size;
            }
        }
        reportAllocFail(
            gMmRegionTable[0].size / 1024,
            gMmRegionTable[0].size / 1024 - lbl_803DCB20 / 1024,
            gMmRegionTable[1].size / 1024,
            gMmRegionTable[1].size / 1024 - lbl_803DCB24 / 1024,
            gMmRegionTable[2].size / 1024,
            gMmRegionTable[2].size / 1024 - lbl_803DCB28 / 1024,
            lbl_803DCC7C,
            lbl_803DCB1C,
            size, t28, t27);
    }
    return 0;
}

int heapSpawnSlot(int region, int idx, int size, int type, int newType, int f10val, int tag) {
    MmRegion *reg;
    HeapItem *base;
    int oldSize;
    while (size % 32 != 0) {
        size++;
    }
    reg = &gMmRegionTable[region];
    base = (HeapItem *)reg->start;
    base[idx].type = type;
    oldSize = base[idx].size;
    base[idx].size = size;
    base[idx].f10 = f10val;
    if (oldSize > size) {
        s16 oldNext;
        int ni = base[reg->f4++].stack;
        base[idx].type = newType;
        while ((oldSize - size) % 32 != 0) {
            size++;
        }
        base[idx].size = oldSize - size;
        base[ni].type = type;
        base[ni].key = (char *)base[idx].key + oldSize - size;
        if ((int)base[ni].key % 32 != 0) {
            OSReport(sMmSpawnedUnalignedSlotWarning, base[ni].stack, base[ni].key, base[ni].size);
        }
        base[ni].size = size;
        base[ni].f10 = f10val;
        base[ni].f14 = lbl_803DCB1C;
        oldNext = base[idx].next;
        base[ni].next = oldNext;
        base[ni].prev = idx;
        base[idx].next = ni;
        if (oldNext != -1) {
            base[oldNext].prev = ni;
        }
        return ni;
    }
    return idx;
}

int changeHeapSlot(int region, int idx, int newSize, int type, int newType, int f10val, int tag) {
    MmRegion *reg = &gMmRegionTable[region];
    HeapItem *base = (HeapItem *)reg->start;
    int oldSize;
    base[idx].type = type;
    oldSize = base[idx].size;
    base[idx].size = newSize;
    base[idx].f10 = f10val;
    if (oldSize > newSize) {
        s16 oldNext;
        int ni = base[reg->f4++].stack;
        base[ni].key = (char *)base[idx].key + newSize;
        if ((int)base[ni].key % 32 != 0) {
            OSReport(sMmSpawnedUnalignedSlotWarning, base[ni].stack, base[ni].key, base[ni].size);
        }
        base[ni].size = oldSize - newSize;
        base[ni].type = newType;
        oldNext = base[idx].next;
        base[ni].next = oldNext;
        base[ni].prev = idx;
        base[idx].next = ni;
        if (oldNext != -1) {
            base[oldNext].prev = ni;
        }
        base[idx].f14 = lbl_803DCB1C;
        return ni;
    }
    return idx;
}

extern char sMmFreeMemoryUsageCorruptedError[];

void heapFree(int region, int idx) {
    HeapItem *base = (HeapItem *)gMmRegionTable[region].start;
    s16 next = base[idx].next;
    s16 prev = base[idx].prev;
    base[idx].type = 0;
    lbl_803DCB14++;
    gMmRegionTable[region].f10 -= base[idx].size;
    if (gMmRegionTable[region].f10 < 0 || gMmRegionTable[region].f10 > gMmRegionTable[region].size) {
        OSReport(sMmFreeMemoryUsageCorruptedError);
    }
    if (next != -1 && base[next].type == 0) {
        s16 nn;
        base[idx].size += base[next].size;
        nn = base[next].next;
        base[idx].next = nn;
        if (nn != -1) {
            base[nn].prev = idx;
        }
        base[--gMmRegionTable[region].f4].stack = next;
    }
    if (prev != -1 && base[prev].type == 0) {
        s16 in;
        base[prev].size += base[idx].size;
        in = base[idx].next;
        base[prev].next = in;
        if (in != -1) {
            base[in].prev = prev;
        }
        base[--gMmRegionTable[region].f4].stack = idx;
    }
}

int getHeapItemSize(void *ptr) {
    int i = mmGetRegionForPtr(ptr);
    HeapItem *items = (HeapItem *)gMmRegionTable[i].start;
    int idx = 0;
    for (;;) {
        HeapItem *item = &items[idx];
        if (item->key == ptr) {
            return item->size;
        }
        idx = item->next;
        if (idx == -1) {
            return -1;
        }
    }
}

void *AtomicSList_Pop(void **list) {
    int intr = OSDisableInterrupts();
    void *head = *list;
    if (head == NULL) {
        OSRestoreInterrupts(intr);
        return NULL;
    }
    *list = *(void **)head;
    OSRestoreInterrupts(intr);
    return head;
}

f32 interpolate(f32 a, f32 t, f32 exp) {
    if (t <= lbl_803DE7C4) {
        return a * (lbl_803DE7C4 - powfBitEstimate(lbl_803DE7C4 - t, exp));
    }
    return lbl_803DE7C0;
}

int atan2i(int y, int x) {
    return (int)(lbl_803DE7D8 * fn_802924B4((f32)y, (f32)x));
}
#pragma pop

extern void *memcpy(void *dst, const void *src, int n);
extern void LCLoadBlocks(void *destTag, void *srcAddr, u32 numBlocks);
extern u32 PPCMfhid2(void);
extern void DCInvalidateRange(void *addr, u32 nBytes);
extern void LCEnable(void);
extern void ObjModel_InitScratchBuffers(void);
extern void setGQR6_2(int a, int b, int c, int d);
extern void GXInitLightSpot(u8 *lt_obj, f32 cutoff, int spot_func);
extern void GXInitLightDistAttn(u8 *lt_obj, f32 ref_dist, f32 ref_br, int dist_func);
extern void GXGetLightAttnK(u8 *lt_obj, f32 *k0, f32 *k1, f32 *k2);
extern void PSVECSubtract(f32 *a, f32 *b, f32 *out);
extern f32 PSVECMag(f32 *v);
extern void PSVECScale(f32 *src, f32 *dst, f32 scale);
extern f32 PSVECDotProduct(f32 *a, f32 *b);
extern f32 lbl_803DE760;
extern f32 lbl_803DE75C;
extern f32 lbl_803DE768;
extern f32 lbl_803DE76C;
extern f32 lbl_803DE758;
extern f32 lbl_803DE790;
extern f32 lbl_802C1A88[];

#pragma push
#pragma scheduling off
#pragma peephole off
int objMove(u8 *obj, f32 dx, f32 dy, f32 dz) {
    int n;
    *(f32 *)(obj + 0xc) += dx;
    *(f32 *)(obj + 0x10) += dy;
    *(f32 *)(obj + 0x14) += dz;
    ObjGroup_GetObjects(0, &n);
    return 0;
}

#pragma dont_inline on
void copyToCache(void *dst, void *src, u32 count) {
    if (lbl_803DD610 != 4 && lbl_803DD610 != 0) {
        int len;
        if (count != 0) {
            len = count << 5;
        } else {
            len = 0x1000;
        }
        memcpy(dst, src, len);
    } else {
        LCLoadBlocks(dst, src, count);
    }
}
#pragma dont_inline reset

#pragma dont_inline on
int fn_8001F978(u32 srcAddr, u32 size, u32 *cacheCursor, u32 *outEnd, u32 limit) {
    register u32 src;
    register u32 copySize;
    register u32 *cursor;
    register u32 *endOut;
    register u32 maxEnd;
    u32 alignOffset;
    u32 end;
    u8 *dst;

    src = srcAddr;
    copySize = size;
    cursor = cacheCursor;
    endOut = outEnd;
    maxEnd = limit;
    dst = getCache();
    alignOffset = src & 0x1f;
    copySize = (copySize + alignOffset + 0x1f) & ~0x1f;
    end = *cursor + copySize;
    if (end <= maxEnd) {
        src -= alignOffset;
        *endOut = end;
        dst += *cursor;
        *cursor = (u32)(dst + alignOffset);
        copySize >>= 5;
        while (copySize > 0x7f) {
            copyToCache(dst, (void *)src, 0);
            dst += 0x1000;
            src += 0x1000;
            copySize -= 0x80;
        }
        if (copySize != 0) {
            copyToCache(dst, (void *)src, copySize);
        }
        return 1;
    }
    *endOut = *cursor;
    *cursor = src;
    return 0;
}
#pragma dont_inline reset

void ObjModel_InitRenderBuffers(void) {
    if ((PPCMfhid2() & 0x10000000) == 0) {
        void *cache = getCache();
        DCInvalidateRange(cache, 0x4000);
        LCEnable();
    }
    ObjModel_InitScratchBuffers();
    setGQR6_2(7, 4, 7, 4);
}

typedef struct {
    s16 *start;
    s16 *end;
    u8 _8[4];
    u8 size;
    u8 stride;
    u8 _e[2];
    s16 *iter;
} ModelStream;
extern ModelStream *lbl_803DCB54;
extern void *memset(void *dst, int val, int n);

void modelFn_800292e0(void) {
    u8 buf[8];
    lbl_803DCB54->iter = lbl_803DCB54->start;
    while (lbl_803DCB54->iter != lbl_803DCB54->end) {
        s16 *iter = lbl_803DCB54->iter;
        if (*iter == -1) {
            memset(buf, 0, lbl_803DCB54->size);
        } else {
            memcpy(buf, iter + 1, lbl_803DCB54->size);
        }
        lbl_803DCB54->iter += lbl_803DCB54->stride;
    }
}

#pragma dont_inline on
void *animationLoad(int id, s16 a, s16 b, int e, int f) {
    lbl_8033BF88.f0 = 1;
    lbl_8033BF88.f1 = 7;
    lbl_8033BF88.f4 = a;
    lbl_8033BF88.f8 = id;
    lbl_8033BF88.fc = b;
    lbl_8033BF88.f20 = e;
    lbl_8033BF88.f24 = f;
    return loadAsset(&lbl_8033BF88);
}
#pragma dont_inline reset

void fn_8001DA60(u8 *obj, f32 cutoff, int mode) {
    *(f32 *)(obj + 0xb4) = cutoff;
    *(int *)(obj + 0xb8) = mode;
    if (mode == 0) {
        GXInitLightAttnA(obj + 0x68, lbl_803DE760, lbl_803DE75C, lbl_803DE75C);
    } else {
        GXInitLightSpot(obj + 0x68, *(f32 *)(obj + 0xb4), *(int *)(obj + 0xb8));
    }
}

void lightDistAttenFn_8001dc38(u8 *obj, f32 a, f32 b) {
    *(f32 *)(obj + 0x140) = a;
    *(f32 *)(obj + 0x144) = b;
    GXInitLightDistAttn(obj + 0x68, *(f32 *)(obj + 0x140), lbl_803DE758, 2);
    GXGetLightAttnK(obj + 0x68, (f32 *)(obj + 0x124), (f32 *)(obj + 0x128), (f32 *)(obj + 0x12c));
}

#pragma dont_inline on
int modelColorFn_8001cdac(u8 *light, u8 *obj) {
    f32 localPos[3];
    f32 worldPos[3];
    f32 projected[3];
    f32 cornerPos[3];
    f32 corners[24];
    f32 extent;
    f32 scaledExtent;
    u32 clipMask;
    u32 combinedClipMask;
    u32 *cornerWords;
    u32 *sourceWords;
    int i;

    extent = *(f32 *)(obj + 0xa8);
    scaledExtent = *(f32 *)(obj + 8) * extent;
    cornerWords = (u32 *)corners;
    sourceWords = (u32 *)lbl_802C1A88;
    i = 12;
    do {
        cornerWords[0] = sourceWords[0];
        cornerWords[1] = sourceWords[1];
        cornerWords += 2;
        sourceWords += 2;
    } while (--i != 0);

    worldPos[0] = *(f32 *)(obj + 0xc) - playerMapOffsetX;
    worldPos[1] = *(f32 *)(obj + 0x10);
    worldPos[2] = *(f32 *)(obj + 0x14) - playerMapOffsetZ;
    PSMTXMultVec((f32 *)(light + 0x170), worldPos, localPos);

    if (*(int *)(light + 0x168) == 0) {
        if (*(f32 *)(light + 0x15c) < localPos[0] - extent ||
            localPos[0] + scaledExtent < *(f32 *)(light + 0x158) ||
            *(f32 *)(light + 0x150) < localPos[1] - extent ||
            localPos[1] + scaledExtent < *(f32 *)(light + 0x154) ||
            *(f32 *)(light + 0x164) < localPos[2] - extent ||
            localPos[2] + scaledExtent < *(f32 *)(light + 0x160)) {
            return 0;
        }
        return 1;
    }

    if (*(f32 *)(light + 0x164) < localPos[2] - extent ||
        localPos[2] + scaledExtent < *(f32 *)(light + 0x160)) {
        return 0;
    }

    combinedClipMask = 0x3f;
    for (i = 0; i < 8; i++) {
        cornerPos[0] = localPos[0] + scaledExtent * corners[i * 3 + 0];
        cornerPos[1] = localPos[1] + scaledExtent * corners[i * 3 + 1];
        cornerPos[2] = localPos[2] + scaledExtent * corners[i * 3 + 2];
        PSMTXMultVec((f32 *)(light + 0x1f0), cornerPos, projected);
        if (projected[2] != lbl_803DE75C) {
            projected[0] /= projected[2];
            projected[1] /= projected[2];
        }

        clipMask = 0;
        if (cornerPos[2] < *(f32 *)(light + 0x160)) {
            clipMask |= 0x10;
        }
        if (*(f32 *)(light + 0x164) < cornerPos[2]) {
            clipMask |= 0x20;
        }
        if (projected[0] < lbl_803DE75C) {
            clipMask |= 1;
        } else if (projected[0] > lbl_803DE760) {
            clipMask |= 2;
        }
        if (projected[1] < lbl_803DE75C) {
            clipMask |= 4;
        } else if (projected[1] > lbl_803DE760) {
            clipMask |= 8;
        }
        if (clipMask == 0) {
            return 1;
        }
        combinedClipMask &= clipMask;
        if (combinedClipMask == 0) {
            return 1;
        }
    }

    return 0;
}
#pragma dont_inline reset

#pragma dont_inline on
f32 ModelLightStruct_getLightAmount(u8 *light, u8 *obj) {
    f32 delta[3];
    f32 dist;
    f32 amount;

    if (*(void **)(obj + 0xc4) != NULL) {
        obj = *(u8 **)(obj + 0xc4);
    }

    PSVECSubtract((f32 *)(obj + 0x18), (f32 *)(light + 0x10), delta);
    dist = PSVECMag(delta) - *(f32 *)(obj + 0xa8) * *(f32 *)(obj + 8);
    if (dist > lbl_803DE768 || dist > *(f32 *)(light + 0x144)) {
        return lbl_803DE75C;
    }

    if (dist < *(f32 *)(light + 0x140)) {
        amount = lbl_803DE760;
    } else {
        amount = lbl_803DE760 - (dist - *(f32 *)(light + 0x140)) /
                                    (*(f32 *)(light + 0x144) - *(f32 *)(light + 0x140));
    }

    if (*(int *)(light + 0xb8) != 0) {
        PSVECScale(delta, delta, lbl_803DE760 / dist);
        PSVECDotProduct((f32 *)(light + 0x34), delta);
    }

    return amount;
}
#pragma dont_inline reset

#pragma dont_inline on
void fn_8001E928(u8 **outLights, int maxLights, int *outCount, f32 minX, f32 minY, f32 minZ, f32 maxX,
                 f32 maxY, f32 maxZ) {
    f32 center[3];
    f32 delta[3];
    u8 *candidates[20];
    u8 *light;
    f32 dist;
    f32 radius;
    f32 intensity;
    f32 red;
    f32 green;
    f32 blue;
    int candidateCount;
    int selectedCount;
    int i;

    center[0] = lbl_803DE790 * (minX + maxX);
    center[1] = lbl_803DE790 * (minY + maxY);
    center[2] = lbl_803DE790 * (minZ + maxZ);

    candidateCount = 0;
    for (i = 0; i < lbl_803DCA30; i++) {
        light = lbl_8033BEC0[i];
        if (light[0x4c] != 0 && *(int *)(light + 0x50) == 2 && *(f32 *)(light + 0x144) > lbl_803DE75C &&
            light[0x2fb] != 0) {
            PSVECSubtract(center, (f32 *)(light + 0x10), delta);
            dist = PSVECMag(delta);
            radius = *(f32 *)(light + 0x144);
            if (*(f32 *)(light + 0x10) + radius >= minX &&
                *(f32 *)(light + 0x14) + radius >= minY &&
                *(f32 *)(light + 0x18) + radius >= minZ &&
                *(f32 *)(light + 0x10) - radius <= maxX &&
                *(f32 *)(light + 0x14) - radius <= maxY &&
                *(f32 *)(light + 0x18) - radius <= maxZ) {
                intensity = lbl_803DE760 /
                            (*(f32 *)(light + 0x124) +
                             dist * (*(f32 *)(light + 0x12c) * dist + *(f32 *)(light + 0x128)));
                red = intensity * (f32)light[0xa8];
                if (red < lbl_803DE75C) {
                    red = lbl_803DE75C;
                } else if (red > lbl_803DE76C) {
                    red = lbl_803DE76C;
                }
                green = intensity * (f32)light[0xa9];
                if (green < lbl_803DE75C) {
                    green = lbl_803DE75C;
                } else if (green > lbl_803DE76C) {
                    green = lbl_803DE76C;
                }
                blue = intensity * (f32)light[0xaa];
                if (blue < lbl_803DE75C) {
                    blue = lbl_803DE75C;
                } else if (blue > lbl_803DE76C) {
                    blue = lbl_803DE76C;
                }
                if (green < red) {
                    green = red;
                }
                *(f32 *)(light + 0x130) = green;
                if (blue < *(f32 *)(light + 0x130)) {
                    blue = *(f32 *)(light + 0x130);
                }
                *(f32 *)(light + 0x130) = blue;

                selectedCount = candidateCount;
                candidateCount++;
                candidates[selectedCount] = light;
                if (candidateCount >= 20) {
                    break;
                }
            }
        }
    }

    if (maxLights > candidateCount) {
        maxLights = candidateCount;
    }

    *outCount = 0;
    while (*outCount < maxLights) {
        intensity = lbl_803DE75C;
        for (i = 0; i < candidateCount; i++) {
            if (*(f32 *)(candidates[i] + 0x130) > intensity) {
                light = candidates[i];
                intensity = *(f32 *)(light + 0x130);
            }
        }
        selectedCount = *outCount;
        *outCount = selectedCount + 1;
        outLights[selectedCount] = light;
        *(f32 *)(light + 0x130) = lbl_803DE75C;
    }
}
#pragma dont_inline reset

#pragma dont_inline on
void modelLightFn_8001ec94(u8 *obj, u8 **outLights, int maxLights, int *outCount, int typeMask) {
    f32 delta[3];
    u8 *candidates[20];
    u8 *light;
    f32 intensity;
    f32 dist;
    f32 red;
    f32 green;
    f32 blue;
    u32 objectLightMask;
    int candidateCount;
    int i;
    int selectedCount;
    int lightType;

    if (obj != NULL) {
        objectLightMask = (1 << *(u8 *)(*(u32 *)(obj + 0x50) + 0x8d)) & 0xff;
    } else {
        objectLightMask = 1;
    }

    candidateCount = 0;
    for (i = 0; i < lbl_803DCA30; i++) {
        light = lbl_8033BEC0[i];
        lightType = *(int *)(light + 0x50);
        if (light[0x4c] != 0 && (lightType & typeMask) != 0 &&
            (light[0x64] & objectLightMask) != 0) {
            if (lightType == 4) {
                *(f32 *)(light + 0x130) = lbl_803DE768;
            } else if (lightType == 8) {
                if (*(void **)(light + 0x16c) == NULL || modelColorFn_8001cdac(light, obj) == 0) {
                    *(f32 *)(light + 0x130) = lbl_803DE75C;
                } else {
                    PSVECSubtract((f32 *)(obj + 0x18), (f32 *)(light + 0x10), delta);
                    dist = PSVECMag(delta);
                    intensity = lbl_803DE764;
                    *(f32 *)(light + 0x130) = intensity + intensity / dist;
                    *(f32 *)(light + 0x134) = ModelLightStruct_getLightAmount(light, obj);
                }
            } else {
                intensity = ModelLightStruct_getLightAmount(light, obj);
                *(f32 *)(light + 0x134) = intensity;
                red = intensity * (f32)light[0xa8];
                if (red < lbl_803DE75C) {
                    red = lbl_803DE75C;
                } else if (red > lbl_803DE76C) {
                    red = lbl_803DE76C;
                }
                green = intensity * (f32)light[0xa9];
                if (green < lbl_803DE75C) {
                    green = lbl_803DE75C;
                } else if (green > lbl_803DE76C) {
                    green = lbl_803DE76C;
                }
                blue = intensity * (f32)light[0xaa];
                if (blue < lbl_803DE75C) {
                    blue = lbl_803DE75C;
                } else if (blue > lbl_803DE76C) {
                    blue = lbl_803DE76C;
                }
                if (green < red) {
                    green = red;
                }
                *(f32 *)(light + 0x130) = green;
                if (blue < *(f32 *)(light + 0x130)) {
                    blue = *(f32 *)(light + 0x130);
                }
                *(f32 *)(light + 0x130) = blue;
            }

            if (*(f32 *)(light + 0x130) > lbl_803DE75C) {
                *(f32 *)(light + 0x130) += (f32)((int)light[0x2fc] << 8);
                selectedCount = candidateCount;
                candidateCount++;
                candidates[selectedCount] = light;
                if (candidateCount >= 20) {
                    break;
                }
            }
        }
    }

    if (maxLights > candidateCount) {
        maxLights = candidateCount;
    }

    *outCount = 0;
    while (*outCount < maxLights) {
        intensity = lbl_803DE75C;
        for (i = 0; i < candidateCount; i++) {
            if (*(f32 *)(candidates[i] + 0x130) > intensity) {
                light = candidates[i];
                intensity = *(f32 *)(light + 0x130);
            }
        }
        selectedCount = *outCount;
        *outCount = selectedCount + 1;
        outLights[selectedCount] = light;
        *(f32 *)(light + 0x130) = -*(f32 *)(light + 0x130);
    }
}
#pragma dont_inline reset
#pragma pop

extern u8 lbl_803DC9A7;
extern u8 lbl_803DC9A6;
extern u8 lbl_803DC9A5;
extern u8 lbl_803DC9A4;
extern u8 lbl_802C7400[];

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void mtx44Transpose(f32 *src, f32 *dst) {
    dst[0] = src[0];
    dst[1] = src[4];
    dst[2] = src[8];
    dst[4] = src[1];
    dst[5] = src[5];
    dst[6] = src[9];
    dst[8] = src[2];
    dst[9] = src[6];
    dst[10] = src[10];
    dst[3] = src[12];
    dst[7] = src[13];
    dst[11] = src[14];
}
#pragma dont_inline reset

extern void setMatrixFromObjectPos(f32 *mtx, u8 *obj);
extern void PSMTXConcat(f32 *a, f32 *b, f32 *ab);

void model_multMtxs(u8 *model, f32 *out) {
    u8 *hdr = *(u8 **)model;
    int i;
    for (i = 0; i < hdr[0xf3]; i++) {
        u8 *h = *(u8 **)model;
        u32 cnt = h[0xf3];
        int lim;
        int j = i;
        f32 *base;
        if (cnt != 0) {
            lim = cnt + h[0xf4];
        } else {
            lim = 1;
        }
        if (j >= lim) {
            j = 0;
        }
        base = *(f32 **)(model + 0xc + (*(u16 *)(model + 0x18) & 1) * 4);
        PSMTXConcat(out, base + j * 0x10, base + j * 0x10);
    }
}

#pragma dont_inline on
void setMatrixFromObjectTransposed(void *obj, f32 *out) {
    f32 m[16];
    setMatrixFromObjectPos(m, (u8 *)obj);
    out[0] = m[0];
    out[1] = m[4];
    out[2] = m[8];
    out[4] = m[1];
    out[5] = m[5];
    out[6] = m[9];
    out[8] = m[2];
    out[9] = m[6];
    out[10] = m[10];
    out[3] = m[12];
    out[7] = m[13];
    out[11] = m[14];
}
#pragma dont_inline reset

void Matrix_TransformPoint(f32 *m, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz) {
    *ox = m[12] + (m[0] * x + m[4] * y + m[8] * z);
    *oy = m[13] + (m[1] * x + m[5] * y + m[9] * z);
    *oz = m[14] + (m[2] * x + m[6] * y + m[10] * z);
}

void objFn_8002b67c(u8 *obj) {
    u8 *dst;
    u8 *src;
    int idx;

    if (obj == NULL) {
        return;
    }
    dst = *(u8 **)(obj + 0x78);
    if (dst == NULL) {
        return;
    }
    src = *(u8 **)(*(u8 **)(obj + 0x50) + 0x40);
    idx = obj[0xe4];
    src += idx * 0x18;
    dst += idx * 5;
    dst[0] = src[0xc];
    dst[1] = src[0xd];
    dst[2] = src[0xe];
    dst[3] = src[0xf];
    dst[4] = src[0x10];
}

void lightFn_8001d6b0(u8 *obj) {
    s16 v;

    if (obj[0x2f8] == 0) {
        return;
    }
    if (obj[0x4c] == 0) {
        return;
    }
    v = obj[0x2f9] + *(s8 *)(obj + 0x2fa);
    if (v < 0) {
        v = 0;
        obj[0x2fa] = 0;
    } else if (v > 0xff) {
        v = 0xff;
        obj[0x2fa] = 0;
    }
    obj[0x2f9] = v;
}

#pragma dont_inline on
void gameTextSetColor(u8 r, u8 g, u8 b, u8 a) {
    if (gameTextDrawFunc != NULL) {
        lbl_803DC9A7 = r;
        lbl_803DC9A6 = g;
        lbl_803DC9A5 = b;
        lbl_803DC9A4 = a;
    } else {
        int i = lbl_803DC9C8;
        GameTextSlot *s;
        lbl_803DC9C8 = i + 1;
        s = &lbl_8033A540[i];
        s->v = 3;
        s->f4 = r;
        s->f8 = g;
        s->fc = b;
        s->f10 = a;
    }
}
#pragma dont_inline reset

void gameTextSetWindowStrPos(int idx, int x, int y) {
    if (gameTextDrawFunc != NULL) {
        s16 sx = x;
        u8 *p = lbl_802C7400 + idx * 0x20;
        *(s16 *)(p + 0x18) = sx;
        *(s16 *)(p + 0x1a) = y;
    } else {
        int i = lbl_803DC9C8;
        GameTextSlot *s;
        lbl_803DC9C8 = i + 1;
        s = &lbl_8033A540[i];
        s->v = 4;
        s->f4 = idx;
        s->f8 = x;
        s->fc = y;
    }
}
#pragma pop

extern void textureFree(void *tex);
extern void *textureLoadAsset(int asset);
extern void *lbl_8033BE54[];
extern void *lbl_8033B240[];
extern int lbl_803DCA14;
extern f32 lbl_803DE8B8;
extern int lbl_803DC9FC;
extern void *lbl_803DC9F8;
extern u8 lbl_803DC9F7;
extern u8 lbl_803DC9F6;
extern u8 lbl_803DC9F5;
extern u8 lbl_803DC9F4;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma optimize_for_size on
void gameTextInitFn_8001bd14(void) {
    int i;
    int zero;
    int *scratch;

    zero = 0;
    lbl_803DCA04 = zero;
    lbl_803DCA00 = 1;
    lbl_803DB3E0 = -1;

    scratch = (int *)lbl_8033B240;
    i = 8;
    do {
        scratch[0] = zero;
        scratch[1] = zero;
        scratch[2] = zero;
        scratch[3] = zero;
        scratch[4] = zero;
        scratch[5] = zero;
        scratch[6] = zero;
        scratch[7] = zero;
        scratch += 8;
        scratch[0] = zero;
        scratch[1] = zero;
        scratch[2] = zero;
        scratch[3] = zero;
        scratch[4] = zero;
        scratch[5] = zero;
        scratch[6] = zero;
        scratch[7] = zero;
        scratch += 8;
        scratch[0] = zero;
        scratch[1] = zero;
        scratch[2] = zero;
        scratch[3] = zero;
        scratch[4] = zero;
        scratch[5] = zero;
        scratch[6] = zero;
        scratch[7] = zero;
        scratch += 8;
        scratch[0] = zero;
        scratch[1] = zero;
        scratch[2] = zero;
        scratch[3] = zero;
        scratch[4] = zero;
        scratch[5] = zero;
        scratch[6] = zero;
        scratch[7] = zero;
        scratch += 8;
        i--;
    } while (i != 0);
}
#pragma optimize_for_size reset

#pragma dont_inline on
void subtitleFn_8001b700(void) {
    void **slot;
    int i;
    int oldDelay;

    if (lbl_803DCA04 != 0) {
        lbl_803DCA04 = 0;
        i = 0;
        slot = lbl_8033B240;
        while (i < lbl_803DCA14) {
            if (*slot != NULL) {
                oldDelay = mmSetFreeDelay(0);
                mm_free(*slot);
                mmSetFreeDelay(oldDelay);
                *slot = NULL;
            }
            slot++;
            i++;
        }

        if (lbl_803DB3E0 != -1) {
            gameTextLoadDir(lbl_803DB3E0);
            lbl_803DB3E0 = -1;
        }
    }
}

#pragma dont_inline reset

void fn_8001BDD4(int mode) {
    switch (mode) {
    case 3:
        textureFree(lbl_8033BE54[0]);
        textureFree(lbl_8033BE54[1]);
        textureFree(lbl_8033BE54[2]);
        break;
    }
}

void fn_8001BE2C(int mode) {
    switch (mode) {
    case 3:
        lbl_8033BE54[0] = textureLoadAsset(0x43b);
        lbl_8033BE54[1] = textureLoadAsset(0x43e);
        lbl_8033BE54[2] = textureLoadAsset(0x43d);
        break;
    }
}

int fn_8002B8F0(u8 *obj) {
    *(f32 *)(obj + 0xc) += timeDelta * (lbl_803DE8B8 * (*(f32 *)(obj + 0xfc) + *(f32 *)(obj + 0x24)));
    *(f32 *)(obj + 0x10) += timeDelta * (lbl_803DE8B8 * (*(f32 *)(obj + 0x100) + *(f32 *)(obj + 0x28)));
    *(f32 *)(obj + 0x14) += timeDelta * (lbl_803DE8B8 * (*(f32 *)(obj + 0x104) + *(f32 *)(obj + 0x2c)));
    return 1;
}

void fn_80026C88(u8 *p) {
    int i;
    for (i = 0; i < *(int *)(p + 4); i++) {
        mm_free(*(void **)(*(u8 **)p + i * 0xc));
    }
    mm_free(*(void **)p);
    mm_free(p);
}

extern f32 lbl_803DE858;
extern f32 lbl_803DE85C;
extern f32 lbl_803DE860;
extern f32 lbl_803DE828;
extern f32 lbl_803DE864;

void *allocModelStruct2(int **models, int count) {
    int i;
    int offset;
    int *model;
    u8 *entryBase;
    u8 *state;

    state = mmAlloc(0x1c, 0x1a, 0);
    *(int *)(state + 4) = count;
    state[0x19] = 0;
    state[0x18] = 0;
    entryBase = mmAlloc(count * 0xc, 0x1a, 0);
    *(u8 **)state = entryBase;
    offset = 0;
    for (i = 0; i < count; i++) {
        model = models[i];
        *(int **)(entryBase + offset + 4) = model;
        *(int *)(entryBase + offset + 8) = model[1];
        *(void **)(entryBase + offset) = mmAlloc((*(int *)(entryBase + offset + 8) + 1) * 0x54, 0x1a, 0);
        offset += 0xc;
    }
    *(f32 *)(state + 8) = lbl_803DE858;
    *(f32 *)(state + 0xc) = lbl_803DE85C;
    *(f32 *)(state + 0x10) = lbl_803DE860;
    *(f32 *)(state + 0x14) = lbl_803DE828;
    state[0x1a] = 1;
    return state;
}

void Model_GetVertexPosition(u8 *model, int vertexIndex, f32 *out) {
    s16 *vertex;
    f32 scale;

    vertex = (s16 *)(*(u8 **)(model + 0x28) + vertexIndex * 6);
    if ((*(u16 *)(model + 2) & 0x800) != 0) {
        out[0] = (f32)vertex[0];
        out[1] = (f32)vertex[1];
        out[2] = (f32)vertex[2];
    } else {
        scale = lbl_803DE864;
        out[0] = (f32)vertex[0] * scale;
        out[1] = (f32)vertex[1] * scale;
        out[2] = (f32)vertex[2] * scale;
    }
}

void textFn_8001bb78(int x) {
    if (lbl_803DCA00 != 0) {
        lbl_803DC9FC = x;
        lbl_803DC9F8 = getCurGameText();
        lbl_803DC9F0 = 0;
        lbl_803DB3E0 = -1;
        lbl_803DCA04 = 1;
        lbl_803DC9F7 = 0xff;
        lbl_803DC9F6 = 0xff;
        lbl_803DC9F5 = 0xff;
        lbl_803DC9F4 = 0xff;
    }
}

void Obj_ApplyPendingParentLinks(void) {
    int i;
    for (i = 0; i < lbl_803DCB84; i++) {
        u8 *obj = ((u8 **)lbl_803DCB88)[i];
        obj[0xaf] &= ~7;
        {
            u8 *parent = *(u8 **)(obj + 0xc0);
            if (parent != NULL && *(void **)(obj + 0x30) == NULL &&
                *(void **)(parent + 0x30) != NULL) {
                *(void **)(obj + 0x30) = *(void **)(parent + 0x30);
                *(void **)(obj + 0xc0) = NULL;
            }
        }
    }
}
#pragma pop

extern void DCFlushRange(void *addr, u32 nBytes);
extern void LCStoreBlocks(void *destAddr, void *srcTag, u32 numBlocks);
extern void objFreeObjDef(void *def, int flags);
extern f32 lbl_803DE808;
extern f32 lbl_803DE810;
extern u8 *lbl_803DCADC;
#define gGameBitTable lbl_803DCADC
extern int lbl_803DCB94;
extern void **lbl_803DCB98;

#pragma push
#pragma scheduling off
#pragma peephole off
void Matrix_TransformVector(f32 *m, f32 *v, f32 *out) {
    f32 vx = v[0];
    f32 vy = v[1];
    f32 vz = v[2];
    out[0] = vx * m[0] + vy * m[4] + vz * m[8];
    out[1] = vx * m[1] + vy * m[5] + vz * m[9];
    out[2] = vx * m[2] + vy * m[6] + vz * m[10];
}

extern int rand(void);
extern f32 lbl_803DE7F8;
extern f64 lbl_803DE800;
extern f64 lbl_803DE7E0;

#pragma dont_inline on
int randomGetRange(int lo, int hi) {
    f32 v;
    if (lo == hi) {
        return lo;
    }
    v = ((f32)(u32)rand() / lbl_803DE7F8) * (lbl_803DE7C4 + (f32)hi - (f32)lo);
    return (int)(v + (f32)lo);
}
#pragma dont_inline reset

extern s16 lbl_803DCAD8;
extern u8 *lbl_803DCAE0;
#define gGameBitCount lbl_803DCAD8
#define gGameBitSaveData lbl_803DCAE0

u32 GameBit_Get(int eventId) {
    s16 id = (s16)eventId & 0xfff;
    u8 flags;
    u8 *base;
    int start;
    int i;
    u32 bit;
    u32 result;

    if (id == 0x95) {
        return 1;
    }
    if (id == 0x96) {
        return 0;
    }
    if (eventId == -1) {
        return 0;
    }
    if (id < 0 || id >= gGameBitCount) {
        return 0;
    }
    flags = gGameBitTable[id * 4 + 2];
    switch (flags >> 6) {
    case 0:
        base = gGameBitSaveData + 0xef0;
        break;
    case 1:
        base = gGameBitSaveData + 0x564;
        break;
    case 2:
        base = gGameBitSaveData + 0x24;
        break;
    case 3:
        base = gGameBitSaveData + 0x5d8;
        break;
    }
    start = *(u16 *)(gGameBitTable + id * 4);
    result = 0;
    bit = 1;
    for (i = start; i <= (flags & 0x1f) + start; i++) {
        if ((1 << (i & 7)) & base[i >> 3]) {
            result |= bit;
        }
        bit <<= 1;
    }
    if (eventId & 0x8000) {
        result &= 1;
        result ^= 1;
    }
    return result;
}

extern int isSaveGameLoading(void);
extern void gameBitFn_800ea2e0(int a);
extern char lbl_802CA4E0[];
extern void OSReport(char *fmt, ...);
#define GameBit_RequestSync gameBitFn_800ea2e0
#define sGameBitSetDuringSaveLoadWarning lbl_802CA4E0

void GameBit_Set(int eventId, int value) {
    s16 id;
    u8 flags;
    u8 *base;
    int limit;
    int start;
    int end;
    int i;
    u32 bit;

    if (isSaveGameLoading()) {
        OSReport(sGameBitSetDuringSaveLoadWarning, eventId, value);
        return;
    }
    if (eventId & 0x8000) {
        value = (value & 1) ^ 1;
    }
    id = (s16)eventId & 0xfff;
    if (id == 0x95) {
        return;
    }
    if (id == 0x96) {
        return;
    }
    if (eventId == -1) {
        return;
    }
    if (id < 0 || id >= gGameBitCount) {
        return;
    }
    flags = gGameBitTable[id * 4 + 2];
    switch (flags >> 6) {
    case 0:
        base = gGameBitSaveData + 0xef0;
        limit = 0x80;
        break;
    case 1:
        base = gGameBitSaveData + 0x564;
        limit = 0x74;
        break;
    case 2:
        base = gGameBitSaveData + 0x24;
        limit = 0x144;
        break;
    case 3:
        base = gGameBitSaveData + 0x5d8;
        limit = 0xac;
        break;
    }
    if (flags & 0x20) {
        GameBit_RequestSync(gGameBitTable[id * 4 + 3]);
    }
    start = *(u16 *)(gGameBitTable + id * 4);
    bit = 1;
    end = (gGameBitTable[id * 4 + 2] & 0x1f) + start + 1;
    for (i = start; i < end; i++) {
        int byteIdx = i >> 3;
        int mask;
        if (byteIdx >= limit) {
            break;
        }
        mask = 1 << (i & 7);
        if (value & bit) {
            base[byteIdx] |= mask;
        } else {
            base[byteIdx] &= ~mask;
        }
        bit <<= 1;
    }
}

void copyMatrix44(f32 *src, f32 *dst) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
    dst[4] = src[4];
    dst[5] = src[5];
    dst[6] = src[6];
    dst[7] = src[7];
    dst[8] = src[8];
    dst[9] = src[9];
    dst[10] = src[10];
    dst[11] = src[11];
    dst[12] = src[12];
    dst[13] = src[13];
    dst[14] = src[14];
    dst[15] = src[15];
}

void Vec3_Normalize(f32 *v) {
    f32 len = sqrtf(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
    if (len != lbl_803DE808) {
        f32 s = lbl_803DE810 / len;
        v[0] *= s;
        v[1] *= s;
        v[2] *= s;
    }
}

int gameBitIncrement(int bit) {
    int val = GameBit_Get(bit) + 1;
    int max = 1 << ((gGameBitTable[bit * 4 + 2] & 0x1f) + 1);
    if (val < max) {
        GameBit_Set(bit, val);
    } else {
        val--;
    }
    return val;
}

#pragma dont_inline on
void memcpyToCache(void *dst, void *src, u32 count) {
    if (lbl_803DD610 != 4 && lbl_803DD610 != 0) {
        int len;
        if (count != 0) {
            len = count << 5;
        } else {
            len = 0x1000;
        }
        memcpy(dst, src, len);
        DCFlushRange(dst, len);
    } else {
        LCStoreBlocks(dst, src, count);
    }
}
#pragma dont_inline reset

void Obj_FlushDeferredFreeList(void) {
    int i;
    for (i = 0; i < lbl_803DCB94; i++) {
        void *p = lbl_803DCB98[i];
        if (p != NULL) {
            objFreeObjDef(p, 0);
            lbl_803DCB98[i] = NULL;
        }
    }
    lbl_803DCB94 = 0;
}

void *ObjAnim_LoadCachedMove(int a, int b, int c, int d) {
    void *out = NULL;
    animationLoad((int)&out, a, b, c, d);
    return out;
}
#pragma pop

extern void C_MTXLightPerspective(f32 *m, f32 fovY, f32 aspect, f32 scaleS, f32 scaleT, f32 transS, f32 transT);
extern f32 lbl_803DE790;
extern u8 *lbl_80340898[];
extern u8 *lbl_80340880[];

#pragma push
#pragma scheduling off
#pragma peephole off
void fn_8001D878(u8 *obj, f32 a, f32 b) {
    *(f32 *)(obj + 0x148) = a;
    *(f32 *)(obj + 0x14c) = b;
    *(int *)(obj + 0x168) = 1;
    C_MTXLightPerspective((f32 *)(obj + 0x1b0), *(f32 *)(obj + 0x148), *(f32 *)(obj + 0x14c),
                          lbl_803DE790, lbl_803DE790, lbl_803DE790, lbl_803DE790);
    C_MTXLightPerspective((f32 *)(obj + 0x1f0), *(f32 *)(obj + 0x148), *(f32 *)(obj + 0x14c),
                          lbl_803DE790, lbl_803DE790, lbl_803DE790, lbl_803DE790);
}

extern void C_MTXLightOrtho(f32 *m, f32 t, f32 b, f32 l, f32 r, f32 scaleS, f32 scaleT,
                            f32 transS, f32 transT);

void fn_8001D8F0(u8 *obj, f32 a, f32 b, f32 c, f32 d, f32 e, f32 f) {
    f32 fScale;
    f32 eScale;

    *(f32 *)(obj + 0x150) = a;
    *(f32 *)(obj + 0x154) = b;
    *(f32 *)(obj + 0x158) = c;
    *(f32 *)(obj + 0x15c) = d;
    *(int *)(obj + 0x168) = 0;
    fScale = f * lbl_803DE790;
    eScale = e * lbl_803DE790;
    C_MTXLightOrtho((f32 *)(obj + 0x1b0), *(f32 *)(obj + 0x150), *(f32 *)(obj + 0x154),
                    *(f32 *)(obj + 0x158), *(f32 *)(obj + 0x15c), fScale, eScale, fScale,
                    eScale);
    C_MTXLightOrtho((f32 *)(obj + 0x1f0), *(f32 *)(obj + 0x150), *(f32 *)(obj + 0x154),
                    *(f32 *)(obj + 0x158), *(f32 *)(obj + 0x15c), lbl_803DE790, lbl_803DE790,
                    lbl_803DE790, lbl_803DE790);
}

#pragma dont_inline on
void ObjModel_InitScratchBuffers(void) {
    u8 *c = getCache();
    lbl_80340898[0] = c;
    lbl_80340898[1] = c + 0x1000;
    lbl_80340898[2] = c + 0x2000;
    lbl_80340898[3] = c + 0x3000;
    c = getCache();
    lbl_80340880[0] = c;
    lbl_80340880[1] = c + 0x1000;
    lbl_80340880[2] = c + 0x1800;
    lbl_80340880[3] = c + 0x2000;
    lbl_80340880[4] = c + 0x3000;
    lbl_80340880[5] = c + 0x3800;
}
#pragma dont_inline reset
#pragma pop

extern void GXInitLightAttn(u8 *lt_obj, f32 a0, f32 a1, f32 a2, f32 k0, f32 k1, f32 k2);
extern u8 curGameTexts[];

#pragma push
#pragma scheduling off
#pragma peephole off
void fn_8002B6D8(u8 *obj, int a, int b, int c, u8 d, u8 e) {
    u8 *p;
    if (obj == NULL) {
        return;
    }
    p = *(u8 **)(obj + 0x78);
    if (p == NULL) {
        return;
    }
    p += obj[0xe4] * 5;
    if (a != 0) {
        p[0] = a >> 2;
    }
    if (c != 0) {
        p[1] = c >> 2;
    }
    if (b != 0) {
        p[2] = b >> 2;
    }
    if (d != 0) {
        p[3] = d;
    }
    if (e != 0) {
        p[4] = e;
    }
}

void dvdCancelCallback_8001b39c(int a, u8 *match) {
    int i;
    u8 *p = curGameTexts;
    for (i = 8; i != 0; i--) {
        if (match == p) {
            *(int *)(p + 0x44) = 5;
            return;
        }
        p += 0x4c;
    }
}

void gameTextOpenCallback_8001b3d0(int status, u8 *match) {
    int i;
    u8 *p = curGameTexts;
    if (status != -1 && status != -3) {
        for (i = 8; i != 0; i--) {
            if (match == p) {
                *(int *)(p + 0x44) = 2;
                return;
            }
            p += 0x4c;
        }
    } else {
        p = curGameTexts;
        for (i = 8; i != 0; i--) {
            if (match == p) {
                *(int *)(p + 0x44) = 5;
                return;
            }
            p += 0x4c;
        }
    }
}

void fn_8001D994(u8 *obj, f32 a, f32 b) {
    *(f32 *)(obj + 0x10c) = a;
    *(f32 *)(obj + 0x110) = b;
    GXInitLightAttn(obj + 0xc0, lbl_803DE75C, lbl_803DE75C, lbl_803DE760,
                    *(f32 *)(obj + 0x10c) * lbl_803DE790, lbl_803DE75C,
                    lbl_803DE760 - *(f32 *)(obj + 0x10c) * lbl_803DE790);
}
#pragma pop

extern void ObjModel_SetBlendChannelTargets(u8 *model, int ch, int a, int b, f32 w, int c);
extern f32 lbl_803DE828;

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_ClearBlendChannels(u8 *model) {
    if (*(void **)(*(u8 **)model + 0xdc) != NULL) {
        ObjModel_SetBlendChannelTargets(model, 0, -1, -1, lbl_803DE828, 7);
        ObjModel_SetBlendChannelTargets(model, 1, -1, -1, lbl_803DE828, 7);
        ObjModel_SetBlendChannelTargets(model, 2, -1, -1, lbl_803DE828, 7);
    }
}
#pragma pop

extern f32 lbl_803DE840;

#pragma scheduling off
#pragma peephole off
void ObjModel_SetBlendChannelTargets(u8 *model, int channel, int a, int b, f32 weight, int flags) {
    u8 *ch;
    u8 *hdr;
    if (channel > 2) {
        return;
    }
    hdr = *(u8 **)model;
    if (*(void **)(hdr + 0xdc) == NULL) {
        return;
    }
    if (a < -1) {
        return;
    }
    if (b < -1) {
        return;
    }
    if (a >= hdr[0xf9]) {
        return;
    }
    if (b >= hdr[0xf9]) {
        return;
    }
    ch = *(u8 **)(model + 0x28) + channel * 0x10;
    if (a == -1 && b == -1) {
        if ((s8)ch[0xc] == -1 && (s8)ch[0xd] == -1) {
            return;
        }
        flags |= 6;
    }
    if ((s8)ch[0xc] == a && (s8)ch[0xd] == b) {
        return;
    }
    *(s8 *)(ch + 0xc) = a;
    *(s8 *)(ch + 0xd) = b;
    if (!(flags & 0x10)) {
        *(f32 *)(ch + 0x0) = lbl_803DE828;
    }
    *(f32 *)(ch + 0x4) = lbl_803DE840;
    *(f32 *)(ch + 0x8) = weight;
    ch[0xe] = flags | 4;
}
#pragma scheduling reset
#pragma peephole reset

extern void modelApplyBoneTransforms(int a, int b, u16 c, void *d, void *e, int f);
extern f32 lbl_803DE818;
extern f32 lbl_803DE868;
extern f32 lbl_803DE86C;
extern f32 lbl_803DE870;

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_ApplyBlendChannels(u8 *model) {
    u8 *hdr;
    u8 *ch;
    int i;
    s16 defFrame;
    int arrB[3] = {0, 0, 0};
    int arrA[3] = {0, 0, 0};
    void *boneA;
    void *boneB;
    int arg0;
    int arg1;
    int fl;
    f32 w;
    f32 t;
    f32 r;

    hdr = *(u8 **)model;
    if (*(void **)(hdr + 0xdc) == NULL) {
        return;
    }
    defFrame = *(u16 *)(hdr + 0xe4) + 1;
    for (i = 0; i < 3; i++) {
        ch = *(u8 **)(model + 0x28) + i * 0x10;
        if (*(f32 *)(ch + 0x0) != *(f32 *)(ch + 0x4)) {
            ch[0xe] &= ~0xc;
            ch[0xe] |= 4;
        }
        fl = ch[0xe] & 0xc;
        arrA[i] = fl;
        if ((s8)ch[0xc] != -1 || (s8)ch[0xd] != -1 || fl != 0) {
            arrB[i] = 1;
        }
        if (arrA[i] & 4) {
            ch[0xe] &= ~4;
            ch[0xe] |= 8;
        } else if (arrA[i] & 8) {
            ch[0xe] &= ~8;
        }
    }
    if (arrB[0] == 0 && arrB[1] == 0 && arrB[2] == 0) {
        return;
    }
    if (arrB[1]) {
        arrB[0] = 0;
    }
    if (arrA[2]) {
        arrA[0] = 1;
        arrA[1] = 1;
    }
    if ((arrB[0] && arrA[0]) || (arrB[1] && arrA[1])) {
        if (arrB[2]) {
            arrA[2] = 1;
        }
    }
    for (i = 0; i < 3; i++) {
        if (arrB[i] && *(void **)(hdr + 0xa4)) {
            arrA[i] = 1;
        }
        ch = *(u8 **)(model + 0x28) + i * 0x10;
        if (ch[0xe] & 2) {
            ch[0xe] &= ~2;
            *(f32 *)(ch + 0x0) = lbl_803DE828;
        }
        if (arrB[i] && arrA[i]) {
            if ((s8)ch[0xc] > -1) {
                boneA = (void *)((int *)(*(u8 **)(hdr + 0xdc)))[(s8)ch[0xc]];
            } else {
                boneA = &defFrame;
            }
            if ((s8)ch[0xd] > -1) {
                boneB = (void *)((int *)(*(u8 **)(hdr + 0xdc)))[(s8)ch[0xd]];
            } else {
                boneB = &defFrame;
            }
            if (i == 2) {
                if (arrB[0] == 0 && arrB[1] == 0) {
                    arg0 = *(int *)(hdr + 0x28);
                } else {
                    arg0 = *(int *)(model + ((*(u16 *)(model + 0x18) >> 1) & 1) * 4 + 0x1c);
                }
            } else {
                arg0 = *(int *)(hdr + 0x28);
            }
            w = *(f32 *)(ch + 0x0);
            if (w > lbl_803DE818) {
                *(f32 *)(ch + 0x0) = lbl_803DE818;
            } else if (w < lbl_803DE828) {
                if (ch[0xe] & 0x20) {
                    if (w < lbl_803DE840) {
                        *(f32 *)(ch + 0x0) = lbl_803DE840;
                    }
                } else {
                    *(f32 *)(ch + 0x0) = lbl_803DE828;
                }
            }
            w = *(f32 *)(ch + 0x0);
            if (w >= lbl_803DE828) {
                t = w;
                r = lbl_803DE868 * t + lbl_803DE86C * (t * t) - t * (t * t);
            } else {
                t = w * lbl_803DE840;
                r = (lbl_803DE868 * t + lbl_803DE86C * (t * t) - t * (t * t)) * lbl_803DE840;
            }
            arg1 = *(int *)(model + ((*(u16 *)(model + 0x18) >> 1) & 1) * 4 + 0x1c);
            modelApplyBoneTransforms(arg0, arg1, *(u16 *)(hdr + 0xe4), boneA, boneB,
                (int)(lbl_803DE870 * r));
            model[0x60] = 1;
        }
        if (*(f32 *)(ch + 0x4) != *(f32 *)(ch + 0x0)) {
            *(f32 *)(ch + 0x4) = *(f32 *)(ch + 0x0);
        }
    }
}
#pragma pop

extern f32 lbl_803DE874;
extern f32 lbl_803DE878;
extern f32 lbl_803DE87C;

#pragma peephole off
void ObjModel_AdvanceBlendChannels(u8 *model, f32 dt) {
    int i;
    u8 *ch;
    if (*(void **)(*(u8 **)model + 0xdc) == NULL) {
        return;
    }
    for (i = 0; i < 3; i++) {
        ch = *(u8 **)(model + 0x28) + i * 0x10;
        if ((s8)ch[0xc] == -1 && (s8)ch[0xd] == -1) {
            continue;
        }
        if (ch[0xe] & 1) {
            continue;
        }
        *(f32 *)(ch + 0x0) = *(f32 *)(ch + 0x8) * dt + *(f32 *)(ch + 0x0);
        if (*(f32 *)(ch + 0x0) >= lbl_803DE874) {
            *(f32 *)(ch + 0x0) = lbl_803DE874;
            *(f32 *)(ch + 0x8) = lbl_803DE878;
            ch[0xe] &= ~4;
        } else if (*(f32 *)(ch + 0x0) <= lbl_803DE87C) {
            *(f32 *)(ch + 0x0) = lbl_803DE87C;
            *(f32 *)(ch + 0x8) = lbl_803DE878;
            ch[0xe] &= ~4;
        }
    }
}
#pragma peephole reset

extern void *modelLoadFn_80025ae4(u8 *p, int b, int isType1, int c);
extern void modelLoadColorFn_80024ec8(void *m, void *data);
extern void ObjModel_RelocateAnimData(u8 *p, u8 *m);
extern void DCStoreRange(void *p, int size);

#pragma push
#pragma scheduling off
#pragma peephole off
void *ObjModel_LoadAnimData(u8 *p, int b, int c) {
    void *m = modelLoadFn_80025ae4(p, b, p[0] == 1, c);
    modelLoadColorFn_80024ec8(m, *(void **)((u8 *)m + 0x2c));
    if (*(void **)((u8 *)m + 0x30) != NULL) {
        modelLoadColorFn_80024ec8(m, *(void **)((u8 *)m + 0x30));
    }
    ObjModel_RelocateAnimData(p, m);
    *(int *)(p + 8) = 0;
    DCStoreRange(p, *(int *)(p + 0xc));
    return m;
}
#pragma pop

extern void *ObjModel_LoadModelData(int id);
extern void ObjModel_RelocateModelData(u8 *model);
extern void ObjModel_ResolveRenderOpTextures(u8 *model);
extern int modelLoadAnimations(void *model, int id, void *animBase);
extern int modelLoad_calcSizes(void *model, int arg, int *out, int flag);
extern int ModelList_getHeader(void *list, int index, void *out);
extern void modelInitModelList(void *list, s16 index, void *out);
extern int textureLoad(int id, int flag);
extern s16 *lbl_803DCB64;

void *ObjModel_Load(int id, int arg2, int *outSize) {
    int sizes[7];
    u8 *header;
    int off;
    u8 *h;
    int i;
    int realId;
    int tex;
    if (id < 0) {
        realId = -id;
    } else {
        fileLoadToBufferOffset(0x2c, lbl_803DCB64, id * 2, 8);
        realId = lbl_803DCB64[0];
    }
    if (ModelList_getHeader(lbl_803DCB54, realId, &header) == 0) {
        header = ObjModel_LoadModelData(realId);
        ObjModel_RelocateModelData(header);
        h = header;
        i = 0;
        off = i;
        for (; i < h[0xf2]; i++) {
            tex = textureLoad(-(*(int *)(*(int *)(h + 0x20) + off) | 0x8000), 1);
            *(int *)(*(int *)(h + 0x20) + off) = tex;
            off += 4;
        }
        ObjModel_ResolveRenderOpTextures(header);
        modelLoadAnimations(header, realId, (u8 *)header + *(int *)((u8 *)header + 0xc));
        modelInitModelList(lbl_803DCB54, realId, &header);
    } else {
        (*(u8 *)header)++;
    }
    *outSize = modelLoad_calcSizes(header, arg2, sizes, 0);
    return header;
}

extern void OSReport(char *fmt, ...);
extern void *loadCharacter(s16 *data, int flags, int arg2, int arg3, void *parent, int unused);
extern void Obj_RegisterObject(u8 *obj, int b);
extern char sObjSetupObjectLoadingLockedWarning[];
extern char lbl_802CAC54[];

#pragma peephole off
#pragma scheduling off
void *Obj_SetupObject(int a, int b, int c, int d, int e) {
    void *obj;
    if (getLoadedFileFlags(0) & 0x100000) {
        OSReport(sObjSetupObjectLoadingLockedWarning, d);
        return NULL;
    }
    obj = loadCharacter((s16 *)a, b, c, d, (void *)e, 0);
    if (obj != NULL) {
        Obj_RegisterObject(obj, b);
        OSReport(lbl_802CAC54, *(int *)((u8 *)obj + 0x50) + 0x91);
    }
    return obj;
}
#pragma scheduling reset

#pragma scheduling off
void *loadObjectAtObject(u8 *src, int arg1) {
    int type = *(s8 *)(src + 0xac);
    int objF30 = *(int *)(src + 0x30);
    void *obj;
    if (getLoadedFileFlags(0) & 0x100000) {
        OSReport(sObjSetupObjectLoadingLockedWarning, -1);
        obj = NULL;
    } else {
        obj = loadCharacter((s16 *)arg1, 5, type, -1, (void *)objF30, 0);
        if (obj != NULL) {
            Obj_RegisterObject(obj, 5);
            OSReport(lbl_802CAC54, *(int *)((u8 *)obj + 0x50) + 0x91);
        }
    }
    return obj;
}
#pragma scheduling reset
#pragma peephole reset

extern void ShaderDef_free(int *def);
extern void model_adjustModelList(void *list, int index);
extern void *textureIdxToPtr(int id);
extern void model_findIdxInModelList(void *list, void *header, int *outIndex);
extern void *lbl_803DCB50;
extern void *allocModelStruct(int size, int align);
extern int *lbl_803DCB5C;

#pragma push
#pragma scheduling off
void ObjModel_InitResourceCaches(void) {
    void *m;
    lbl_803DCB54 = allocModelStruct(0x8c, 4);
    lbl_803DCB50 = allocModelStruct(0xc4, 4);
    m = mmAlloc(0x830, 0xa, 0);
    lbl_803DCB64 = m;
    lbl_803DCB60 = (int *)((u8 *)m + 0x800);
    lbl_803DCB5C = (int *)((u8 *)m + 0x810);
    loadModelAndAnimTabs();
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_Release(u8 *model) {
    u8 *header;
    int i;
    if (*(u16 *)(model + 0x18) & 0x40) {
        *(u16 *)(model + 0x18) &= ~0x40;
        for (i = 0; i < (*(u8 **)model)[0xf8]; i++) {
            ShaderDef_free((int *)(*(u8 **)(model + 0x34) + i * 0xc));
        }
    }
    header = *(u8 **)model;
    if (*(void **)(model + 0x58) != NULL) {
        mm_free(*(void **)(model + 0x58));
    }
    if (--*(u8 *)header == 0) {
        model_adjustModelList(lbl_803DCB54, *(u16 *)(header + 0x4));
        for (i = 0; i < header[0xf2]; i++) {
            textureFree(textureIdxToPtr(*(int *)(*(u8 **)(header + 0x20) + i * 4)));
        }
        if (*(void **)(header + 0x64) != NULL && *(u16 *)(header + 0xec) != 0) {
            for (i = 0; i < *(u16 *)(header + 0xec); i++) {
                void *tex = *(void **)(*(u8 **)(header + 0x64) + i * 4);
                if (tex != NULL && (s8)--*(u8 *)tex <= 0) {
                    int idx;
                    model_findIdxInModelList(lbl_803DCB50, &tex, &idx);
                    model_adjustModelList(lbl_803DCB50, idx);
                    mm_free(tex);
                }
            }
        }
        mm_free(header);
    }
}
#pragma pop

extern void setGQR6(u32 v);
extern void mapSetup();
extern void *memset(void *dst, int val, int n);
extern void Music_Trigger(int triggerId, int mode);
extern u8 lbl_803DCA38;
extern int lbl_803DCAF8;
extern int lbl_803DCAF4;
extern u8 lbl_803DCA40;
extern u8 lbl_803DCA41;
extern u8 lbl_8033BFB8[];
extern int lbl_803DCAD4;
extern u8 lbl_803DCA44;
extern f32 lbl_803DE7B4;
extern f32 lbl_803DB420;

#pragma push
#pragma scheduling off
#pragma peephole off
void setGQR6_2(int a, int b, int c, int d) {
    setGQR6((((a << 8) + b) << 16) | ((c << 8) + d));
}

void mapLoadByCoords(int arg) {
    lbl_803DCA38 = 0;
    mapSetup(arg, &lbl_803DCAF8, &lbl_803DCAF4);
    lbl_803DCA40 = 1;
    lbl_803DCA41 = 1;
    memset(lbl_8033BFB8, 0, 0x3c0);
    lbl_803DCAD4 = 0;
    lbl_803DCA39 = 1;
    lbl_803DCA44 = 0;
    Music_Trigger(0xc9, 0);
    Music_Trigger(0xd0, 0);
    lbl_803DB420 = lbl_803DE7B4;
}

extern void objLoadPlayerFromSave(u8 *obj);
extern f32 lbl_803DE88C;

void Obj_RunInitCallback(u8 *obj, int cb, int unused) {
    s16 mode = *(s16 *)(obj + 0x46);
    if (mode == 0x1f || mode == 0) {
        objLoadPlayerFromSave(obj);
    } else {
        int *p = *(int **)(obj + 0x68);
        if (p != NULL) {
            int fn = ((int *)*p)[1];
            if (fn != -1 && (void *)fn != NULL) {
                ((void (*)(u8 *))fn)(obj);
            }
        }
    }
    {
        int *q = *(int **)(obj + 0x64);
        if (q != NULL) {
            q[0xc] |= 8;
        }
    }
    {
        f32 v;
        *(f32 *)(obj + 0x80) = *(f32 *)(obj + 0xc);
        *(f32 *)(obj + 0x84) = *(f32 *)(obj + 0x10);
        *(f32 *)(obj + 0x88) = *(f32 *)(obj + 0x14);
        *(f32 *)(obj + 0x8c) = *(f32 *)(obj + 0xc);
        *(f32 *)(obj + 0x90) = *(f32 *)(obj + 0x10);
        *(f32 *)(obj + 0x94) = *(f32 *)(obj + 0x14);
        v = lbl_803DE88C;
        *(f32 *)(obj + 0xfc) = v;
        *(f32 *)(obj + 0x100) = v;
        *(f32 *)(obj + 0x104) = v;
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void objGetWeaponDa(u8 *obj, int dummy, int *out, int key, u8 load) {
    int i;
    s16 *tbl;
    s16 da2;

    tbl = (s16 *)*(int *)(*(u8 **)(obj + 0x50) + 0x28);
    *out = 0;
    if (tbl == NULL) {
        return;
    }
    i = 0;
    while (tbl[i] != -1) {
        if (tbl[i] == key) {
            da2 = tbl[i + 1];
            *out = tbl[i + 2];
            if (*out > 0x800) {
                *out = 0x800;
            }
            if (load) {
                getTabEntry(out[1], 0x34, da2, *out);
            } else {
                fileLoadToBufferOffset(0x34, (void *)out[1], da2, *out);
            }
            return;
        }
        i += 3;
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjAnim_LoadMoveEvents(u8 *obj, int dummy, int *out, int key, u8 load) {
    int i;
    s16 *tbl;
    s16 da2;

    tbl = (s16 *)*(int *)(*(u8 **)(obj + 0x50) + 0x20);
    *out = 0;
    if (tbl == NULL) {
        return;
    }
    i = 0;
    while (tbl[i] != -1) {
        if (tbl[i] == key) {
            da2 = tbl[i + 1];
            *out = tbl[i + 2];
            if (*out > 0x50) {
                *out = 0x50;
            }
            if (load == 0) {
                getTabEntry(out[1], 0x40, da2, *out);
            } else {
                fileLoadToBufferOffset(0x40, (void *)out[1], da2, *out);
            }
            return;
        }
        i += 3;
    }
}
#pragma pop

typedef struct {
    int state;
    u8 pad04[4];
    u8 dirId;
    u8 languageId;
    u8 pad0a[0x1e];
} GameTextLoadRequest;

typedef struct {
    u8 pad00[0x3c];
    void *loadHandle;
    void *dvdFileInfo;
    int state;
    u8 dirId;
    u8 languageId;
    u8 active;
    u8 sourceId;
} GameTextLoadSlot;

#define GAMETEXT_PATH_BUFFER_OFFSET 0x380
#define GAMETEXT_COMMAND_STRING_BUFFER_OFFSET 0x3c0
#define GAMETEXT_LOAD_REQUESTS_OFFSET 0x15dc
#define GAMETEXT_SEQUENCE_LOAD_STATE_OFFSET 0x1604
#define GAMETEXT_FONT_SLOT_OFFSET 0x1610
#define GAMETEXT_LOAD_SLOTS_OFFSET 0x1660
#define GAMETEXT_PENDING_REQUEST_SCAN_OFFSET (GAMETEXT_LOAD_REQUESTS_OFFSET - 0x1c)
#define GAMETEXT_LOAD_SLOT_COUNT 8
#define GAMETEXT_PENDING_SOURCE_COUNT 4
#define GAMETEXT_INVALID_DIR 0xff
#define GAMETEXT_INVALID_LANGUAGE 6
#define GAMETEXT_MAP_DIR_COUNT 0x49
#define GAMETEXT_LANGUAGE_COUNT 6
#define GAMETEXT_SEQUENCE_SOURCE_ID 1

extern u8 lbl_80339980[];
extern int lbl_803DC9D0;
extern int lbl_803DC9D4;
extern int lbl_803DC9D8;
extern int lbl_803DC9E0;
extern char *sMapDirectoryNameTable[];
extern char *sLanguageNameTable[][2];
extern char sGameTextMapPathFormat[];
extern char sGameTextSequencePathFormat[];
extern int sprintf(char *s, const char *format, ...);
extern void setFileInfo(void *fileInfo);
extern void *loadFileByPathAsync(char *path, void *fileInfo, int flags, void *callback);
extern void DVDCancelAsync(void *fileInfo, void *callback);
extern void setLanguageFn_8001ad64(void *slot);
extern void textDisplayFn_800168dc(int a, int b);
extern void gameTextFn_8001658c(int a, int b, int c);
extern void gameTextRenderStrs(int a, int b);
extern void hudDrawRect(int x0, int y0, int x1, int y1, void *color);
extern void Sfx_StopFromObject(int obj, int sfxId);
extern f32 lbl_803DE704;
extern f32 lbl_803DE71C;
extern char lbl_803DB3D4[];
extern int lbl_803DB3C8;
extern int lbl_803DC99C;
extern int lbl_803DC984;
extern int lbl_803DC988;
extern int lbl_803DC98C;
extern u8 lbl_803DC990;
extern u8 lbl_803DC991;
extern u8 lbl_803DC992;
extern void *lbl_803DC9CC;
extern u8 *lbl_803DC9C4;
extern int lbl_803DC9BC;
extern int lbl_803DC97C;
extern u8 *lbl_803DC974;
extern int lbl_803DC978;
extern u8 lbl_803DC980;
extern int lbl_803DB378;
extern void gameTextLoadGraphicsFn_8001a918(void);

typedef struct ObjPathTransform {
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    u8 pad06[2];
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ObjPathTransform;

extern void mtxRotateByVec3s(f32 *mtx, void *transform);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma optimize_for_size on
void gameTextInitFn_8001a234(void) {
    u8 *gameTextBase;
    u8 *p;
    u8 *textWindow;
    u8 *glyphPage;
    u8 **glyphPagePtr;
    u8 *fontState;
    u8 *request;
    u8 *clearPtr;
    f32 zero;
    int i;
    int j;

    gameTextBase = lbl_80339980;

    i = 0x94;
    textWindow = lbl_802C7400 + 0x1280;
    p = textWindow;
    while (p -= 0x20, i-- != 0) {
        *(u16 *)(p + 8) = *(u16 *)(p + 2);
        *(u16 *)(p + 0xa) = *(u16 *)(p + 6);
    }

    i = 8;
    glyphPage = gameTextBase + 0x2c0;
    glyphPagePtr = (u8 **)(gameTextBase + 0xc0);
    fontState = gameTextBase + 0xa0;
    while (glyphPage -= 0x40, glyphPagePtr--, fontState -= 0xc, i-- != 0) {
        *glyphPagePtr = glyphPage;
        *(u16 *)fontState = 0xffff;
        *(u16 *)(fontState + 2) = 1;
        fontState[4] = 0xff;
        fontState[5] = 0;
        fontState[6] = 0;
        fontState[7] = 0;
        *(u8 ***)(fontState + 8) = glyphPagePtr;
    }

    i = 0x94;
    while (textWindow -= 0x20, i-- != 0) {
        textWindow[0x1e] = 0xff;
    }

    i = 4;
    request = gameTextBase + 0x1660;
    zero = lbl_803DE704;
    while (request -= 0x28, i-- != 0) {
        *(int *)(request + 8) = 0;
        *(int *)(request + 0xc) = 0;
        *(int *)(request + 0) = 0;
        *(int *)(request + 4) = 0;
        *(int *)(request + 0x1c) = 0;
        *(f32 *)(request + 0x20) = zero;
        request[0x24] = 0xff;
        request[0x25] = 6;

        j = 3;
        clearPtr = request + 0xc;
        while (clearPtr -= 4, j-- != 0) {
            *(int *)(clearPtr + 0x10) = 0;
        }
    }

    gameTextFonts = gameTextBase + GAMETEXT_FONT_SLOT_OFFSET;
    lbl_803DC9E8 = 2;
    curLanguage = -1;
    curGameTextDir = (void *)-1;
    lbl_803DC9CC = NULL;
    lbl_803DC9E0 = -1;
    lbl_803DC9D8 = -1;
    lbl_803DC9BC = 0;
    lbl_803DC9A7 = 0xff;
    lbl_803DC9A6 = 0xff;
    lbl_803DC9A5 = 0xff;
    lbl_803DC9A4 = 0xff;
    lbl_803DC9C8 = 0;
    lbl_803DC9C4 = gameTextBase + GAMETEXT_COMMAND_STRING_BUFFER_OFFSET;
    lbl_803DC97C = 0;
    textWindow = gameTextBase + 0x40;
    lbl_803DC974 = textWindow;
    lbl_803DC978 = *(int *)*(void **)(textWindow + 8);
    lbl_803DC992 = 0;
    lbl_803DC991 = 0;
    lbl_803DC990 = 0;
    lbl_803DC98C = 5;
    lbl_803DC988 = 5;
    lbl_803DC984 = 1;
    lbl_803DC980 = 0;
    gameTextLoadGraphicsFn_8001a918();
    curGameTextDir = (void *)3;
    lbl_803DB378 = mmCreateMemoryStore(0x800);
}
#pragma optimize_for_size reset

void gameTextRun(void) {
    u8 *gameTextBase;
    GameTextLoadSlot *slot;
    GameTextLoadSlot *freeSlot;
    u8 *pending;
    char *path;
    int sourceId;
    int dirId;
    int languageId;
    int i;
    GameTextSlot *cmd;
    u8 *textWindow;
    int color;
    double zero;
    double fadeLimit;

    gameTextBase = lbl_80339980;

    slot = (GameTextLoadSlot *)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do {
        if (slot->state == 2) {
            setLanguageFn_8001ad64(slot);
        }
        slot++;
    } while (i-- != 0);

    sourceId = 0;
    pending = gameTextBase + GAMETEXT_PENDING_REQUEST_SCAN_OFFSET;
    do {
        dirId = pending[0x24];
        if ((u8)dirId != GAMETEXT_INVALID_DIR) {
            freeSlot = (GameTextLoadSlot *)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
            if (freeSlot->active != 0) {
                freeSlot++;
                if (freeSlot->active != 0) {
                    freeSlot++;
                    if (freeSlot->active != 0) {
                        freeSlot++;
                        if (freeSlot->active != 0) {
                            freeSlot++;
                            if (freeSlot->active != 0) {
                                freeSlot++;
                                if (freeSlot->active != 0) {
                                    freeSlot++;
                                    if (freeSlot->active != 0) {
                                        freeSlot++;
                                        if (freeSlot->active != 0) {
                                            freeSlot = NULL;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (freeSlot != NULL) {
                languageId = pending[0x25];
                freeSlot->state = 1;
                freeSlot->dirId = (u8)dirId;
                freeSlot->languageId = (u8)languageId;
                freeSlot->active = 1;
                freeSlot->sourceId = (u8)sourceId;
                path = (char *)(gameTextBase + GAMETEXT_PATH_BUFFER_OFFSET);
                sprintf(path, sGameTextMapPathFormat, sMapDirectoryNameTable[dirId],
                        sLanguageNameTable[languageId][0]);
                setFileInfo(freeSlot);
                freeSlot->loadHandle =
                    loadFileByPathAsync(path, &freeSlot->dvdFileInfo, 1, gameTextOpenCallback_8001b3d0);
                setFileInfo(NULL);
                pending[0x24] = GAMETEXT_INVALID_DIR;
                pending[0x25] = GAMETEXT_INVALID_LANGUAGE;
            }
        }
        pending += 0x28;
        sourceId++;
    } while (sourceId < GAMETEXT_PENDING_SOURCE_COUNT);

    slot = (GameTextLoadSlot *)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do {
        if ((slot->state == 5 || slot->state == 6) && slot->loadHandle != NULL) {
            mm_free(slot->loadHandle);
            slot->loadHandle = NULL;
            slot->dvdFileInfo = NULL;
            slot->active = 0;
        }
        slot++;
    } while (i-- != 0);

    zero = lbl_803DE704;
    fadeLimit = lbl_803DE71C;
    for (i = 7; i >= 0; i--) {
        f32 *alpha = (f32 *)(gameTextBase + 0x20 + i * 4);
        f32 *timer = (f32 *)(gameTextBase + 0x40 + i * 4);
        u8 *entry = gameTextBase + 0xa0 + i * 0xc;

        if ((double)*timer > zero) {
            *alpha += timeDelta;
            if ((double)*alpha > fadeLimit) {
                *timer = (f32)zero;
                *alpha = (f32)zero;
                sprintf(**(char ***)(entry + 8), lbl_803DB3D4);
            }
        }
    }

    if (*(int *)(gameTextFonts + 0x1c) == 1) {
        *(f32 *)(gameTextFonts + 0x20) += timeDelta;
    } else {
        *(f32 *)(gameTextFonts + 0x20) = lbl_803DE704;
    }

    textWindow = lbl_802C7400;
    for (i = 0x25; i > 0; i--) {
        *(u16 *)(textWindow + 0x1c) &= 0xfffe;
        textWindow += 0x20;
        *(u16 *)(textWindow + 0x1c) &= 0xfffe;
        textWindow += 0x20;
        *(u16 *)(textWindow + 0x1c) &= 0xfffe;
        textWindow += 0x20;
        *(u16 *)(textWindow + 0x1c) &= 0xfffe;
        textWindow += 0x20;
    }

    lbl_803DC99C = 0;
    lbl_803DC9AA = 0;
    lbl_803DC9A8 = 0;

    cmd = lbl_8033A540;
    i = lbl_803DC9C8;
    while (i-- != 0) {
        switch (cmd->v) {
        case 3:
            lbl_803DC9A7 = (u8)cmd->f4;
            lbl_803DC9A6 = (u8)cmd->f8;
            lbl_803DC9A5 = (u8)cmd->fc;
            lbl_803DC9A4 = (u8)cmd->f10;
            break;
        case 4:
            textWindow = lbl_802C7400 + cmd->f4 * 0x20;
            *(s16 *)(textWindow + 0x18) = (s16)cmd->f8;
            *(s16 *)(textWindow + 0x1a) = (s16)cmd->fc;
            break;
        case 1:
            textDisplayFn_800168dc(cmd->f4, cmd->f8);
            break;
        case 2:
            gameTextFn_8001658c(cmd->f4, cmd->f8, cmd->fc);
            break;
        case 5:
            if (lbl_803DC9CC != NULL) {
                gameTextRenderStrs(cmd->f4, ((u8 *)lbl_803DC9CC - lbl_802C7400) / 0x20);
            }
            break;
        case 6:
            gameTextRenderStrs(cmd->f4, cmd->f8);
            break;
        case 7:
            textWindow = lbl_802C7400 + cmd->f8 * 0x20;
            *(s16 *)(textWindow + 0x18) = (s16)cmd->fc;
            *(s16 *)(textWindow + 0x1a) = (s16)cmd->f10;
            gameTextRenderStrs(cmd->f4, cmd->f8);
            break;
        case 8:
            if (cmd->f4 == 0xff) {
                lbl_803DC9CC = NULL;
            } else {
                lbl_803DC9CC = lbl_802C7400 + cmd->f4 * 0x20;
            }
            break;
        case 9:
            ((void (*)(void))cmd->f4)();
            break;
        case 10:
            lbl_803DC9AA = (u16)cmd->f4;
            lbl_803DC9A8 = (u16)cmd->f8;
            break;
        case 11:
            lbl_803DC9AA = 0;
            lbl_803DC9A8 = 0;
            break;
        case 12:
            lbl_803DC984 = cmd->f4;
            break;
        case 14:
            lbl_803DC992 = (u8)cmd->f4;
            lbl_803DC991 = (u8)cmd->f8;
            lbl_803DC990 = (u8)cmd->fc;
            break;
        case 13:
            lbl_803DC98C = cmd->f4;
            lbl_803DC988 = cmd->f8;
            break;
        case 15:
            gameTextFonts = gameTextBase + GAMETEXT_PENDING_REQUEST_SCAN_OFFSET + cmd->f4 * 0x28;
            lbl_803DC9E8 = cmd->f4;
            if (cmd->f4 == 2) {
                color = lbl_803DB3C8;
                hudDrawRect(0, 0, 0xa00, 0x780, &color);
                lbl_803DC99C = 0;
            }
            break;
        }
        cmd++;
    }

    if (lbl_803DC99C == 0) {
        Sfx_StopFromObject(0, 0x397);
    }
    lbl_803DC9C8 = 0;
    lbl_803DC9C4 = gameTextBase + GAMETEXT_COMMAND_STRING_BUFFER_OFFSET;

    textWindow = lbl_802C7400 + 0x1280;
    for (i = 0x94; i > 0; i--) {
        textWindow -= 0x20;
        *(s16 *)(textWindow + 0x18) = 0;
        *(s16 *)(textWindow + 0x1a) = 0;
    }
    lbl_803DC9CC = NULL;
}

void loadGameTextSequence(int sequenceSlotDir, int sequenceId) {
    int oldHeap;
    int languageId;
    int languageTableOffset;
    GameTextLoadSlot *slot;
    GameTextLoadSlot *freeSlot;
    char *path;
    u8 *gameTextBase;
    u8 *languageTable;
    int i;

    gameTextBase = lbl_80339980;
    languageId = curLanguage;
    languageTableOffset = languageId << 3;
    languageTable = (u8 *)sLanguageNameTable;
    oldHeap = testAndSet_onlyUseHeap3(0);
    if (getGameState() != 0 && getGameState() != 1) {
        testAndSet_onlyUseHeap3(oldHeap);
        return;
    }

    lbl_803DC9D0 = lbl_803DC9D4;
    if (curLanguage < 0 || curLanguage >= 6) {
        testAndSet_onlyUseHeap3(oldHeap);
        return;
    }

    slot = (GameTextLoadSlot *)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do {
        if (slot->sourceId == GAMETEXT_SEQUENCE_SOURCE_ID) {
            if (slot->state == 1) {
                slot->state = 4;
                DVDCancelAsync(slot, dvdCancelCallback_8001b39c);
            }
            if (slot->state == 3 && slot->active != 0) {
                mmSetFreeDelay(0);
                mm_free(slot->loadHandle);
                mmSetFreeDelay(2);
                slot->loadHandle = NULL;
                slot->dvdFileInfo = NULL;
                slot->active = 0;
            }
        }
        slot++;
    } while (i-- != 0);

    *(int *)(gameTextBase + GAMETEXT_SEQUENCE_LOAD_STATE_OFFSET) = 1;
    freeSlot = (GameTextLoadSlot *)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    if (freeSlot->active != 0) {
        freeSlot++;
        if (freeSlot->active != 0) {
            freeSlot++;
            if (freeSlot->active != 0) {
                freeSlot++;
                if (freeSlot->active != 0) {
                    freeSlot++;
                    if (freeSlot->active != 0) {
                        freeSlot++;
                        if (freeSlot->active != 0) {
                            freeSlot++;
                            if (freeSlot->active != 0) {
                                freeSlot++;
                                if (freeSlot->active != 0) {
                                    freeSlot = NULL;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    freeSlot->state = 1;
    freeSlot->dirId = (u8)sequenceSlotDir;
    freeSlot->languageId = (u8)curLanguage;
    freeSlot->active = 1;
    freeSlot->sourceId = GAMETEXT_SEQUENCE_SOURCE_ID;
    path = (char *)(gameTextBase + GAMETEXT_PATH_BUFFER_OFFSET);
    sprintf(path, sGameTextSequencePathFormat, sequenceId,
            *(char **)(languageTable + languageTableOffset));
    setFileInfo(freeSlot);
    freeSlot->loadHandle =
        loadFileByPathAsync(path, &freeSlot->dvdFileInfo, 1, gameTextOpenCallback_8001b3d0);
    setFileInfo(NULL);
    testAndSet_onlyUseHeap3(oldHeap);
}

void gameTextLoadForCurMap(int sourceId) {
    int oldHeap;
    int dirId;
    int languageId;
    GameTextLoadSlot *slot;
    GameTextLoadSlot *freeSlot;
    GameTextLoadRequest *request;
    char *path;
    u8 *gameTextBase;
    int i;

    gameTextBase = lbl_80339980;
    oldHeap = testAndSet_onlyUseHeap3(0);
    if (getGameState() != 0 && getGameState() != 1) {
        testAndSet_onlyUseHeap3(oldHeap);
        return;
    }

    dirId = (int)curGameTextDir;
    languageId = curLanguage;
    lbl_803DC9D8 = dirId;
    lbl_803DC9E0 = languageId;
    if (dirId < 0 || dirId >= GAMETEXT_MAP_DIR_COUNT ||
        languageId < 0 || languageId >= GAMETEXT_LANGUAGE_COUNT) {
        testAndSet_onlyUseHeap3(oldHeap);
        return;
    }

    slot = (GameTextLoadSlot *)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do {
        if (slot->sourceId == sourceId) {
            if (slot->state == 1) {
                slot->state = 4;
                DVDCancelAsync(slot, dvdCancelCallback_8001b39c);
            }
            if (slot->state == 3 && slot->active != 0) {
                mmSetFreeDelay(0);
                if (slot->loadHandle != NULL) {
                    mm_free(slot->loadHandle);
                }
                mmSetFreeDelay(2);
                slot->loadHandle = NULL;
                slot->dvdFileInfo = NULL;
                slot->active = 0;
            }
        }
        slot++;
    } while (i-- != 0);

    request = (GameTextLoadRequest *)(gameTextBase + GAMETEXT_LOAD_REQUESTS_OFFSET +
                                      sourceId * sizeof(GameTextLoadRequest));
    request->state = 1;
    request->dirId = (u8)curGameTextDir;
    request->languageId = (u8)curLanguage;

    freeSlot = (GameTextLoadSlot *)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    if (freeSlot->active != 0) {
        freeSlot++;
        if (freeSlot->active != 0) {
            freeSlot++;
            if (freeSlot->active != 0) {
                freeSlot++;
                if (freeSlot->active != 0) {
                    freeSlot++;
                    if (freeSlot->active != 0) {
                        freeSlot++;
                        if (freeSlot->active != 0) {
                            freeSlot++;
                            if (freeSlot->active != 0) {
                                freeSlot++;
                                if (freeSlot->active != 0) {
                                    freeSlot = NULL;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (freeSlot != NULL) {
        dirId = request->dirId;
        languageId = request->languageId;
        freeSlot->state = 1;
        freeSlot->dirId = (u8)dirId;
        freeSlot->languageId = (u8)languageId;
        freeSlot->active = 1;
        freeSlot->sourceId = (u8)sourceId;
        path = (char *)(gameTextBase + GAMETEXT_PATH_BUFFER_OFFSET);
        sprintf(path, sGameTextMapPathFormat, sMapDirectoryNameTable[dirId],
                sLanguageNameTable[languageId][0]);
        setFileInfo(freeSlot);
        freeSlot->loadHandle =
            loadFileByPathAsync(path, &freeSlot->dvdFileInfo, 1, gameTextOpenCallback_8001b3d0);
        setFileInfo(NULL);
        request->dirId = GAMETEXT_INVALID_DIR;
        request->languageId = GAMETEXT_INVALID_LANGUAGE;
    }

    testAndSet_onlyUseHeap3(oldHeap);
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void Obj_BuildInverseWorldTransformMatrix(u8 *obj, f32 *out) {
    ObjPathTransform transform;
    f32 rotMtx[16];

    if (*(void **)(obj + 0x30) == NULL) {
        *(f32 *)(obj + 0xc) -= playerMapOffsetX;
        *(f32 *)(obj + 0x14) -= playerMapOffsetZ;
    }
    transform.x = -*(f32 *)(obj + 0xc);
    transform.y = -*(f32 *)(obj + 0x10);
    transform.z = -*(f32 *)(obj + 0x14);
    transform.rotX = -*(s16 *)(obj + 0x0);
    transform.rotY = -*(s16 *)(obj + 0x2);
    transform.rotZ = -*(s16 *)(obj + 0x4);
    transform.scale = lbl_803DE890;
    mtxRotateByVec3s(rotMtx, &transform);
    mtx44Transpose(rotMtx, out);
    if (*(void **)(obj + 0x30) == NULL) {
        *(f32 *)(obj + 0xc) += playerMapOffsetX;
        *(f32 *)(obj + 0x14) += playerMapOffsetZ;
    }
}
#pragma pop

extern s16 lbl_803DCBC4;

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjList_PartitionForRender(int *out) {
    void **arr;
    void *tmp;
    int stop;
    int i;
    int j;
    int hi;

    *out = lbl_803DCB84;
    if (lbl_803DCBC4 != 0) {
        return;
    }
    i = 0;
    j = lbl_803DCB84 - 1;
    hi = j;
    while (i <= j) {
        arr = (void **)lbl_803DCB88;
        stop = 0;
        while (i <= hi && stop == 0) {
            if (*(int *)(*(u8 **)((u8 *)arr[i] + 0x50) + 0x44) & 1) {
                i++;
            } else {
                stop = -1;
            }
        }
        stop = 0;
        while (j >= 0 && stop == 0) {
            if (*(int *)(*(u8 **)((u8 *)arr[j] + 0x50) + 0x44) & 1) {
                stop = -1;
            } else {
                j--;
            }
        }
        if (i < j) {
            tmp = arr[i];
            arr[i] = arr[j];
            ((void **)lbl_803DCB88)[j] = tmp;
            i++;
            j--;
        }
    }
    lbl_803DCBC4 = i;
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_BuildWorldTransformMatrix(u8 *obj, f32 *mtx, int flags) {
    f32 savedZ;
    f32 parentMtx[16];
    void *parent;

    if (*(void **)(obj + 0x30) == NULL) {
        *(f32 *)(obj + 0xc) -= playerMapOffsetX;
        *(f32 *)(obj + 0x14) -= playerMapOffsetZ;
    }
    if ((u8)flags != 0) {
        savedZ = *(f32 *)(obj + 0x8);
        if ((*(u16 *)(obj + 0xb0) & 0x8) == 0) {
            *(f32 *)(obj + 0x8) = lbl_803DE890;
        }
    }
    setMatrixFromObjectTransposed(obj, mtx);
    if ((u8)flags != 0) {
        *(f32 *)(obj + 0x8) = savedZ;
    }
    parent = *(void **)(obj + 0x30);
    if (parent == NULL) {
        *(f32 *)(obj + 0xc) += playerMapOffsetX;
        *(f32 *)(obj + 0x14) += playerMapOffsetZ;
    } else {
        Obj_BuildWorldTransformMatrix(parent, (f32 *)parentMtx, 1);
        PSMTXConcat((f32 *)parentMtx, mtx, mtx);
    }
}
#pragma dont_inline reset
#pragma pop

extern f32 fsin16(int angle);
extern f32 lbl_803DE7F0;

#pragma push
#pragma scheduling off
#pragma fp_contract off
void mtxRotateByVec3s(f32 *mtx, void *transform) {
    f32 cx;
    f32 sx;
    f32 cy;
    f32 sy;
    f32 cz;
    f32 sz;
    f32 x;
    f32 y;
    f32 z;
    f32 zero;

    cx = (f32)(int)(lbl_803DE7D0 * fcos16((u16)*(s16 *)transform)) * lbl_803DE7F0;
    sx = (f32)(int)(lbl_803DE7D0 * fsin16((u16)*(s16 *)transform)) * lbl_803DE7F0;
    cy = (f32)(int)(lbl_803DE7D0 * fcos16((u16)*(s16 *)((u8 *)transform + 2))) * lbl_803DE7F0;
    sy = (f32)(int)(lbl_803DE7D0 * fsin16((u16)*(s16 *)((u8 *)transform + 2))) * lbl_803DE7F0;
    cz = (f32)(int)(lbl_803DE7D0 * fcos16((u16)*(s16 *)((u8 *)transform + 4))) * lbl_803DE7F0;
    sz = (f32)(int)(lbl_803DE7D0 * fsin16((u16)*(s16 *)((u8 *)transform + 4))) * lbl_803DE7F0;

    mtx[0] = sx * sz - (cy * cz) * cx;
    mtx[1] = (cy * sz) * cx + sx * cz;
    mtx[2] = -(cx * sy);
    zero = lbl_803DE7C0;
    mtx[3] = zero;
    mtx[4] = -(sy * cz);
    mtx[5] = sy * sz;
    mtx[6] = cy;
    mtx[7] = zero;
    mtx[8] = (cy * cz) * sx + cx * sz;
    mtx[9] = cx * cz - (cy * sz) * sx;
    mtx[10] = sx * sy;
    mtx[11] = zero;
    x = *(f32 *)((u8 *)transform + 0xc);
    y = *(f32 *)((u8 *)transform + 0x10);
    z = *(f32 *)((u8 *)transform + 0x14);
    mtx[12] = mtx[4] * y + mtx[0] * x + mtx[8] * z;
    mtx[13] = mtx[5] * y + mtx[1] * x + mtx[9] * z;
    mtx[14] = mtx[6] * y + mtx[2] * x + mtx[10] * z;
    mtx[15] = lbl_803DE7C4;
}
#pragma pop

extern int lbl_803DCB9C;
extern s16 *lbl_803DCBA0;
extern char sObjUnknownTypeUsingDummyObjectWarning[];
extern f64 lbl_803DE8B0;
extern f64 lbl_803DE8A8;
extern f32 lbl_803DE8CC;
extern f32 lbl_803DE8D0;
extern u8 *loadObjectFile(int id);
extern int objGetTotalDataSize(void *tmpl, u8 *def, s16 *data, int flags);
extern void modelInitBones(f32 scale, void *model);
extern int shadowInit(void *obj, int cursor, int arg);
extern void debugPrintf(char *fmt, ...);
extern int objCallback_80074d04();
extern int modelCb_80073d04();
extern int modelCb_80074518();

typedef struct LoadedObj {
    u8 pad00[0x06];
    s16 flags06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
    u8 pad18[0x18];
    void *parent;
    u8 pad34[0x2];
    u8 f36;
    u8 pad37[0x5];
    f32 f3c;
    f32 f40;
    s16 f44;
    s16 seqId;
    s16 typeId;
    u8 pad4a[0x2];
    s16 *data;
    u8 *def;
    void *f54;
    u8 pad58[0x4];
    int f5c;
    int f60;
    u8 pad64[0x4];
    int **dll;
    int f6c;
    int f70;
    int f74;
    int f78;
    u8 **models;
    u8 pad80[0x22];
    s16 fa2;
    u8 pada4[0x4];
    f32 cullDist;
    s8 fac;
    u8 padad[0x3];
    u16 fb0;
    s16 fb2;
    s16 fb4;
    u8 padb6[0x2];
    int fb8;
    u8 padbc[0x20];
    int fdc;
    u8 pade0[0x11];
    u8 ff1;
    s8 ff2;
    u8 padf3[0x15];
    int f108;
} LoadedObj;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void *loadCharacter(s16 *data, int flags, int arg2, int arg3, void *parent, int unused) {
    int size;
    int offsets[20];
    void *models[20];
    LoadedObj tmpl;
    LoadedObj *tp;
    s16 seq;
    int id;
    u8 *def;
    int fnFlags;
    int (*fp)(void *);
    int (*fp2)(void *, int);
    int flags29;
    int total;
    int i;
    int count;
    int idx;
    LoadedObj *obj;
    int base;
    int cursor;
    u8 n;
    u16 h;
    u8 cb;
    f32 max;
    int m;
    u32 v;
    s16 seq2;
    int sz;
    int tmp;
    int j;
    int k;

    seq = *data;
    if (flags & 2) {
        id = seq;
    } else {
        if (seq > lbl_803DCB9C) {
            return NULL;
        }
        id = lbl_803DCBA0[seq];
    }
    memset(&tmpl, 0, 0x10c);
    tp = &tmpl;
    def = loadObjectFile(id);
    tmpl.def = def;
    if (def == NULL || (int)def == -1) {
        debugPrintf(sObjUnknownTypeUsingDummyObjectWarning, id, *data, tmpl.seqId);
        return NULL;
    }
    tmpl.f44 = *(s16 *)(def + 0x52);
    tmpl.scale = *(f32 *)(def + 4);
    tmpl.flags06 = 2;
    if (*(u32 *)(def + 0x44) & 0x80) {
        tmpl.flags06 = tmpl.flags06 | 0x80;
    }
    if (*(u32 *)(def + 0x44) & 0x40000) {
        tmpl.fb0 = tmpl.fb0 | 0x80;
    }
    if (flags & 4) {
        tmpl.flags06 = tmpl.flags06 | 0x2000;
    }
    tmpl.x = *(f32 *)(data + 4);
    tmpl.y = *(f32 *)(data + 6);
    tmpl.z = *(f32 *)(data + 8);
    tmpl.typeId = (s16)id;
    tmpl.data = data;
    tmpl.seqId = seq;
    tmpl.fb2 = (s16)arg3;
    tmpl.fac = (s8)arg2;
    tmpl.fa2 = -1;
    tmpl.fb4 = -1;
    tmpl.f36 = 0xff;
    tmpl.fdc = 0;
    tmpl.ff1 = 0xff;
    tmpl.f3c = (f32)(int)(((u8 *)data)[6] << 3);
    tmpl.f40 = (f32)(int)(((u8 *)data)[7] << 3);
    n = (((u8 *)data)[5] & 0x18) >> 3;
    tmpl.ff2 = n;
    if (n == 0) {
        tmpl.ff2 = *(s8 *)(tmpl.def + 0x8e);
    } else {
        tmpl.ff2 = n - 1;
    }
    tmpl.dll = NULL;
    if ((int)*(s16 *)(def + 0x50) != -1) {
        tmpl.dll = Resource_Acquire(*(s16 *)(def + 0x50) & 0xffff, 6);
    }
    switch (tmpl.seqId) {
    case 0:
    case 0x1f:
        fnFlags = 0x1cb;
        break;
    default:
        if (tmpl.dll != NULL && (int)(fp = (int (*)(void *))*(int *)(*(int *)tmpl.dll + 0x18)) != -1 && fp != NULL) {
            fnFlags = fp(tp);
        } else {
            fnFlags = 0;
        }
        break;
    }
    if (*(u32 *)(def + 0x44) & 0x20) {
        flags29 = fnFlags & ~1;
    } else {
        flags29 = fnFlags | 1;
    }
    if (*(s16 *)(def + 0x48) != 0) {
        flags29 |= 2;
    } else {
        flags29 &= ~2;
    }
    if (*(s16 *)(def + 0x48) == 3) {
        flags29 |= 0x8000;
    }
    if (*(u32 *)(def + 0x44) & 1) {
        flags29 |= 0x200;
    }
    total = 0;
    i = 0;
    count = *(s8 *)(def + 0x55);
    if (flags29 & 0x400) {
        idx = (flags29 >> 0xb) & 0xf;
        if (idx < count) {
            models[idx] = ObjModel_Load(-(*(int **)(def + 8))[idx], flags29, &size);
            offsets[idx] = 0;
            total = size;
        }
    } else if (!(flags29 & 0x200)) {
        for (; i < count; i++) {
            models[i] = ObjModel_Load(-(*(int **)(def + 8))[i], flags29, &size);
            offsets[i] = total;
            total += size;
        }
    }
    base = objGetTotalDataSize(tp, def, data, flags29);
    obj = mmAlloc(base + total, 0xe, 0);
    memcpy(obj, &tmpl, 0x10c);
    memset((u8 *)obj + 0x10c, 0, base + total - 0x10c);
    obj->models = (u8 **)(obj + 1);
    *(u32 *)(obj->def + 0x44) |= 0x800000;
    i = 0;
    obj->f108 = 0;
    if (flags29 & 0x400) {
        idx = (flags29 >> 0xb) & 0xf;
        if (idx < count) {
            obj->models[idx] = (u8 *)obj + base + offsets[idx];
            ObjModel_LoadAnimData(models[idx], flags29, (int)obj->models[idx]);
            if (!(*(u16 *)(*(u8 **)obj->models[idx] + 2) & 0x8000)) {
                *(u32 *)(obj->def + 0x44) &= 0xff7fffff;
            }
            ObjModel_LoadRenderOpTextures(obj->models[idx], (int)obj);
            modelInitBones(obj->scale, obj->models[idx]);
            if (*(u32 *)(obj->def + 0x44) & 0x800) {
                ObjModel_SetRenderCallback(obj->models[idx], objCallback_80074d04);
            } else {
                cb = *(u8 *)(obj->def + 0x5f);
                if (cb & 1) {
                    ObjModel_SetRenderCallback(obj->models[idx], modelCb_80073d04);
                } else if (cb & 0x80) {
                    ObjModel_SetRenderCallback(obj->models[idx], modelCb_80074518);
                }
            }
        }
    } else if (!(flags29 & 0x200)) {
        for (; i < count; i++) {
            obj->models[i] = (u8 *)obj + base + offsets[i];
            ObjModel_LoadAnimData(models[i], flags29, (int)obj->models[i]);
            h = *(u16 *)(*(u8 **)obj->models[i] + 2);
            if (!(h & 0x8000) && !(h & 0x4000)) {
                *(u32 *)(obj->def + 0x44) &= 0xff7fffff;
            }
            ObjModel_LoadRenderOpTextures(obj->models[i], (int)obj);
            modelInitBones(obj->scale, obj->models[i]);
            if (*(u32 *)(obj->def + 0x44) & 0x800) {
                ObjModel_SetRenderCallback(obj->models[i], objCallback_80074d04);
            } else {
                cb = *(u8 *)(obj->def + 0x5f);
                if (cb & 1) {
                    ObjModel_SetRenderCallback(obj->models[i], modelCb_80073d04);
                } else if (cb & 0x80) {
                    ObjModel_SetRenderCallback(obj->models[i], modelCb_80074518);
                }
            }
        }
    }
    cursor = roundUpTo4((int)obj->models + *(s8 *)(def + 0x55) * 4);
    switch (obj->seqId) {
    case 0:
    case 0x1f:
        sz = 0x8e0;
        break;
    default:
        if (obj->dll != NULL && (fp2 = (int (*)(void *, int))*(int *)(*(int *)obj->dll + 0x1c)) != NULL) {
            sz = fp2(obj, cursor);
        } else {
            sz = 0;
        }
        break;
    }
    if (sz != 0) {
        obj->fb8 = cursor;
        cursor += sz;
    } else {
        obj->fb8 = 0;
    }
    if ((flags29 & 0x40) || (*(u32 *)(obj->def + 0x44) & 0x400000)) {
        seq2 = obj->seqId;
        tmp = roundUpTo4(cursor);
        obj->f60 = tmp;
        cursor = roundUpTo8(tmp + 8);
        *(int *)(obj->f60 + 4) = cursor;
        ObjAnim_LoadMoveEvents((u8 *)obj, seq2, (int *)obj->f60, 0, 1);
        cursor += 0x50;
    }
    if ((flags29 & 0x100) && *(void **)obj->models != NULL) {
        tmp = roundUpTo4(cursor);
        obj->f5c = tmp;
        cursor = roundUpTo8(tmp + 8);
        *(int *)(obj->f5c + 4) = cursor;
        cursor += 0x800;
    }
    if ((flags29 & 2) && *(s16 *)(def + 0x48) != 0) {
        cursor = shadowInit(obj, cursor, 0);
    }
    max = lbl_803DE8CC;
    i = 0;
    for (; i < *(s8 *)(obj->def + 0x55); i++) {
        m = *(int *)((u8 *)obj->models + i * 4);
        if (m != 0) {
            if ((f32)modelFileHeaderGetCullDistance(*(u8 **)m) > max) {
                max = (f32)modelFileHeaderGetCullDistance(*(u8 **)m);
            }
        }
    }
    v = *(u8 *)(obj->def + 0x73);
    if (v != 0) {
        max = max * ((lbl_803DE8CC * (f32)v) / lbl_803DE8D0);
    }
    obj->cullDist = max;
    if (*(u8 *)(def + 0x61) != 0) {
        cursor = ObjHits_AllocObjectState(obj, cursor);
        if (*(s8 *)(def + 0x65) & 8) {
            cursor = ObjHitbox_AllocRotatedBounds(obj, cursor);
        }
    }
    if (*(u8 *)(def + 0x5a) != 0) {
        tmp = roundUpTo4(cursor);
        obj->f6c = tmp;
        cursor = tmp + *(u8 *)(def + 0x5a) * 0x12;
    }
    if (*(u8 *)(def + 0x59) != 0) {
        tmp = roundUpTo4(cursor);
        obj->f70 = tmp;
        cursor = tmp + *(u8 *)(def + 0x59) * 0x10;
    }
    if (*(u8 *)(def + 0x72) != 0) {
        tmp = roundUpTo4(cursor);
        obj->f74 = tmp;
        cursor = tmp + *(u8 *)(def + 0x72) * 0x18;
    }
    if (*(u8 *)(def + 0x61) != 0 && *(u8 *)(def + 0x66) != 0) {
        tmp = roundUpTo4(cursor);
        cursor = ObjHitReact_InitState(obj->seqId, (int)*(u8 **)obj->models, obj->f54, tmp, obj);
    }
    if (*(u8 *)(def + 0x72) != 0) {
        obj->f78 = roundUpTo4(cursor);
        i = 0;
        k = 0;
        j = 0;
        for (; i < *(u8 *)(def + 0x72); i++) {
            ((u8 *)obj->f78)[j + 4] = ((u8 *)*(int *)(def + 0x40))[k + 0x10];
            ((u8 *)obj->f78)[j] = ((u8 *)*(int *)(def + 0x40))[k + 0xc];
            ((u8 *)obj->f78)[j + 3] = ((u8 *)*(int *)(def + 0x40))[k + 0xf];
            ((u8 *)obj->f78)[j + 1] = ((u8 *)*(int *)(def + 0x40))[k + 0xd];
            ((u8 *)obj->f78)[j + 2] = ((u8 *)*(int *)(def + 0x40))[k + 0xe];
            k += 0x18;
            j += 5;
        }
    }
    obj->parent = parent;
    return obj;
}
#pragma dont_inline reset
#pragma pop

extern void *lbl_8033BE40[];
extern int lbl_803DB3EC;
extern void *lbl_803DCA24;
extern void *lbl_803DCA28;
extern u32 lbl_803DE740;
extern u8 *gameTextGetCurBox(void);
extern void gameTextFn_8001628c(int id, int a, int b, int *x0, int *x1, int *y0, int *y1);
extern void gameTextBoxFn_800164b0(int id, int idx, int *x0, int *x1, int *y0, int *y1);
extern void drawTexture(f32 x, f32 y, void *tex, int alpha, int scale);
extern void drawScaledTexture(f32 x, f32 y, void *tex, int alpha, int scale, int w, int h, int flag);
extern void drawPartialTexture(f32 x, f32 y, void *tex, int alpha, int scale, int w, int h, int part, int flag);
extern void drawHudBox(int x, int y, int w, int h, int alpha, int flag);
extern void boxDrawFn_8001c5ac(u16 *strPtr, int boxId, u8 *box);

#pragma push
#pragma scheduling off
#pragma dont_inline on
void gameTextDrawBox(u16 *strPtr, int boxId, u8 *box) {
    u32 colorB;
    u32 colorA;
    int c6y1;
    int c6y0;
    int c6x1;
    int c6x0;
    int c3y1;
    int c3y0;
    int c3x1;
    int c3x0;
    s16 savedX;
    s16 savedY;
    u16 f;
    u8 *cur;
    int hw;
    int hh;
    int cx;
    int cy;
    u16 h7;
    u16 w7;
    s16 y7;
    s16 x7;
    s16 x2;
    int w2;
    int xw;
    s16 y2;
    int half;
    int rem;

    savedX = *(s16 *)(box + 0x18);
    savedY = *(s16 *)(box + 0x1a);
    f = *(u16 *)(box + 0x1c);
    if (f & 1) {
        return;
    }
    *(u16 *)(box + 0x1c) = f | 1;
    switch (*(u8 *)(box + 0x13)) {
    case 5:
        return;
    case 7:
        if ((int)getCurGameText() == 3) {
            colorB = lbl_803DE740;
            hudDrawRect(*(s16 *)(box + 0x14), *(s16 *)(box + 0x16),
                        *(s16 *)(box + 0x14) + *(u16 *)(box + 8),
                        *(s16 *)(box + 0x16) + *(u16 *)(box + 0xa), &colorB);
        } else {
            h7 = *(u16 *)(box + 0xa);
            w7 = *(u16 *)(box + 8);
            y7 = *(s16 *)(box + 0x16);
            x7 = *(s16 *)(box + 0x14);
            GXSetScissor(0, 0, 0x280, 0x1e0);
            drawHudBox(x7, y7, (s16)w7, (s16)h7, 0xff, 1);
        }
        break;
    case 1:
        colorA = lbl_803DE740;
        hudDrawRect(*(s16 *)(box + 0x14), *(s16 *)(box + 0x16),
                    *(s16 *)(box + 0x14) + *(u16 *)(box + 8),
                    *(s16 *)(box + 0x16) + *(u16 *)(box + 0xa), &colorA);
        break;
    case 6:
        if (strPtr == NULL) {
            return;
        }
        cur = gameTextGetCurBox();
        if (strPtr != NULL) {
            gameTextFn_8001628c(*strPtr, 0, 0, &c6x0, &c6x1, &c6y0, &c6y1);
        } else if (boxId != 0) {
            gameTextBoxFn_800164b0(boxId, (int)(box - lbl_802C7400) / 0x20, &c6x0, &c6x1, &c6y0, &c6y1);
        }
        gameTextFn_80017434(cur);
        hw = (c6x1 - c6x0) >> 1;
        hh = (c6y1 - c6y0) >> 1;
        cx = c6x0 + hw;
        cy = c6y0 + hh;
        drawScaledTexture((f32)(c6x0 - lbl_803DB3EC), (f32)(c6y0 - lbl_803DB3EC), lbl_803DCA24, 0xff, 0x100,
                          hw + lbl_803DB3EC, hh + lbl_803DB3EC, 0);
        drawScaledTexture((f32)cx, (f32)(c6y0 - lbl_803DB3EC), lbl_803DCA24, 0xff, 0x100,
                          hw + lbl_803DB3EC, hh + lbl_803DB3EC, 1);
        drawScaledTexture((f32)(c6x0 - lbl_803DB3EC), (f32)cy, lbl_803DCA24, 0xff, 0x100,
                          hw + lbl_803DB3EC, hh + lbl_803DB3EC, 2);
        drawScaledTexture((f32)cx, (f32)cy, lbl_803DCA24, 0xff, 0x100,
                          hw + lbl_803DB3EC, hh + lbl_803DB3EC, 3);
        break;
    case 0:
        drawScaledTexture((f32)*(s16 *)(box + 0x14), (f32)*(s16 *)(box + 0x16), lbl_803DCA28, 0xff, 0x100,
                          *(u16 *)(box + 8), *(u16 *)(box + 0xa), 0);
        break;
    case 3:
        cur = gameTextGetCurBox();
        if (strPtr != NULL) {
            gameTextFn_8001628c(*strPtr, 0, 0, &c3x0, &c3x1, &c3y0, &c3y1);
        } else if (boxId != 0) {
            gameTextBoxFn_800164b0(boxId, (int)(box - lbl_802C7400) / 0x20, &c3x0, &c3x1, &c3y0, &c3y1);
        }
        gameTextFn_80017434(cur);
        drawTexture((f32)(c3x0 - 0x16), (f32)(c3y0 - 9), lbl_8033BE40[5], *(u8 *)(box + 0x1e), 0x100);
        drawScaledTexture((f32)c3x0, (f32)(c3y0 - 9), lbl_8033BE40[6], *(u8 *)(box + 0x1e), 0x100,
                          c3x1 - c3x0, 0x24, 0);
        drawTexture((f32)c3x1, (f32)(c3y0 - 9), lbl_8033BE40[7], *(u8 *)(box + 0x1e), 0x100);
        break;
    case 2:
        x2 = *(s16 *)(box + 0x14);
        w2 = *(u16 *)(box + 8);
        xw = x2 + w2;
        y2 = *(s16 *)(box + 0x16);
        half = w2 >> 1;
        if (half > 0xc) {
            half = 0xc;
        }
        rem = w2 - half * 2;
        if (rem < 0) {
            rem = 0;
        }
        GXSetScissor(0, 0, 0x280, 0x1e0);
        drawTexture((f32)(x2 - 0x34), (f32)(y2 - 0x23), lbl_8033BE40[0], *(u8 *)(box + 0x1e), 0x100);
        drawTexture((f32)xw, (f32)(y2 - 0x23), lbl_8033BE40[4], *(u8 *)(box + 0x1e), 0x100);
        if (half != 0) {
            drawScaledTexture((f32)x2, (f32)(y2 - 0x13), lbl_8033BE40[1], *(u8 *)(box + 0x1e), 0x100,
                              half, 0x3a, 0);
            drawPartialTexture((f32)(xw - half), (f32)(y2 - 0x13), lbl_8033BE40[3], *(u8 *)(box + 0x1e), 0x100,
                               half, 0x3a, 0xc - half, 0);
        }
        if (rem != 0) {
            drawScaledTexture((f32)(x2 + half), (f32)(y2 - 0x13), lbl_8033BE40[2], *(u8 *)(box + 0x1e), 0x100,
                              rem, 0x3a, 0);
        }
        break;
    case 4:
        boxDrawFn_8001c5ac(strPtr, boxId, box);
        break;
    }
    *(s16 *)(box + 0x18) = savedX;
    *(s16 *)(box + 0x1a) = savedY;
}
#pragma dont_inline reset
#pragma pop

extern void OSInit(void);
extern void DVDInit(void);
extern void VIInit(void);
extern void PADInit(void);
extern u8 OSGetProgressiveMode(void);
extern int OSGetResetCode(void);
extern void OSSetProgressiveMode(int mode);
extern void videoInit(void *rmode, int arg);
extern void setDisplayCopyFilter(void);
extern void initLoadingScreenTextures(void);
extern void mmInit(void);
extern void gxTransformFn_8004a83c(void);
extern void Camera_InitState(void);
extern void doQueuedLoads(void);
extern void initControllers(void);
extern int mmSetFreeDelay(int delay);
extern void padUpdate(void);
extern u8 audioInit(void);
extern void allocSomething32bytes(void);
extern u8 initLoadFiles(void);
extern void initFn_8006d020(void);
extern void dvdCheckError(void);
extern void gameTextRun(void);
extern int VIGetDTVStatus(void);
extern u32 getButtonsHeld(int pad);
extern void viFn_8004a56c(int arg);
extern void fn_80137D28(void);
extern void loadTextureFiles(void);
extern void initMapBlocks(void);
extern void ObjModel_InitResourceCaches(void);
extern void Resource_ResetRefCounts(void);
extern void gameTextInit(void);
extern void Obj_InitObjectSystem(void);
extern void fn_80137998(void);
extern void mapInitFn_80069990(void);
extern void initTextures(void);
extern void mapInitFn_8006fccc(void);
extern void initGameTimer(void);
extern void ObjModel_InitRenderBuffers(void);
extern void _initCardAndDsp(void);
extern void fn_802B6F48(void);
extern void loadTaskTexts(void);
extern void gameTextInitFn_8001bd14(void);
extern void initMaps(void);
extern void initFn_800534f8(void);
extern void titleScreenDrawFn_80093db4(void);
extern int getDataFileSize(int id);
extern void loadUiDll(int arg);
extern void doNothing_beforeTitleScreen(void);
extern void setDrawCloudsAndLights(int arg);
extern void OSSetSaveRegion(void *start, void *end);
extern void VISetBlack(int black);
extern void VIFlush(void);
extern void VIWaitForRetrace(void);
extern void askProgressiveScanMode(void);
extern void initViewport(void);
extern void tvInit(void);
extern u8 GXNtsc480IntDf[];
extern u8 GXNtsc480Prog[];
extern void *lbl_803DCCF0;
extern u8 lbl_803DCAE4;
extern u8 lbl_8033C3B8[];
extern u8 lbl_8033C378[];
extern char sMainFinishedInitMessage[];
extern void *gGameUIInterface;
extern void *gCameraInterface;
extern void *lbl_803DCA94;
extern void *gPlayerInterface;
extern void *gObjectTriggerInterface;
extern void *gScreenTransitionInterface;
extern void *gSHthorntailAnimationInterface;
extern void *gSky2Interface;
extern void *gNewCloudsInterface;
extern void *gCloudActionInterface;
extern void *gCheckpointInterface;
extern void *gTitleMenuControlInterface;
extern void *gTitleMenuControlInterfaceCopy;
extern void *gExpgfxInterface;
extern void *gModgfxInterface;
extern void *gProjgfxInterface;
extern void *gPlayerShadowInterface;
extern void *gPartfxInterface;
extern void *gScreensInterface;
extern void *gWaterfxInterface;
extern void *gRomCurveInterface;
extern void *gTitleMenuLinkInterface;
extern void *gPathControlInterface;
extern int *gMapEventInterface;
extern void *gBaddieControlInterface;
extern void *gMinimapInterface;
extern void *lbl_803DCAC0;
extern void *gTitleMenuItemInterface;
extern u8 lbl_803DCA3F;

#pragma push
#pragma scheduling off
#pragma dont_inline on
void init(void) {
    u8 audioDone;
    u8 filesDone;
    u8 once;
    int delay;
    u8 dtv;

    audioDone = 0;
    filesDone = 0;
    once = 0;
    OSInit();
    DVDInit();
    VIInit();
    PADInit();
    LCEnable();
    {
        register u32 v;
        asm {
            li v, 0x4
            oris v, v, 0x4
            mtspr 914, v
            li v, 0x5
            oris v, v, 0x5
            mtspr 915, v
            li v, 0x6
            oris v, v, 0x6
            mtspr 916, v
            li v, 0x7
            oris v, v, 0x7
            mtspr 917, v
        }
    }
    lbl_803DCCF0 = GXNtsc480IntDf;
    lbl_803DCAE4 = OSGetProgressiveMode();
    if (OSGetResetCode() != 0 && lbl_803DCAE4 == 1) {
        lbl_803DCCF0 = GXNtsc480Prog;
        OSSetProgressiveMode(1);
    } else {
        OSSetProgressiveMode(0);
    }
    videoInit(lbl_8033C3B8, 0);
    setDisplayCopyFilter();
    initLoadingScreenTextures();
    mmInit();
    testAndSet_onlyUseHeap3(1);
    gxTransformFn_8004a83c();
    testAndSet_onlyUseHeap3(0);
    Camera_InitState();
    testAndSet_onlyUseHeap3(1);
    gameTextInitFn_8001a234();
    testAndSet_onlyUseHeap3(0);
    gameTextLoadDir(3);
    testAndSet_onlyUseHeap3(1);
    initControllers();
    delay = mmSetFreeDelay(0);
    do {
        mmFreeTick(0);
        padUpdate();
        checkReset();
        waitNextFrame();
        if (audioDone == 0) {
            audioDone = audioInit();
        }
        if (once == 0) {
            testAndSet_onlyUseHeap3(1);
            allocSomething32bytes();
        }
        if (audioDone != 0 && filesDone == 0) {
            testAndSet_onlyUseHeap3(1);
            filesDone = initLoadFiles();
        }
        if (once == 0) {
            testAndSet_onlyUseHeap3(1);
            initFn_8006d020();
        }
        once = 1;
        runLoadingScreens();
        dvdCheckError();
        gameTextRun();
        if (*(u8 *)lbl_803DCAFC == 0) {
            dtv = 0;
            if (VIGetDTVStatus() != 0) {
                if (OSGetResetCode() != 0 && lbl_803DCAE4 != 1 && (getButtonsHeld(0) & 0x200) != 0) {
                    dtv = 1;
                }
                if (OSGetResetCode() == 0 && (lbl_803DCAE4 == 1 || (getButtonsHeld(0) & 0x200) != 0)) {
                    dtv = 1;
                }
            }
            *(u8 *)lbl_803DCAFC = dtv;
        }
        GXFlush_(1, 0);
    } while ((filesDone == 0 || audioDone == 0) && lbl_803DCA3D == 0);
    while (lbl_803DCA3D != 0) {
        mmFreeTick(0);
        padUpdate();
        checkReset();
        waitNextFrame();
        GXFlush_(1, 0);
    }
    mmSetFreeDelay(delay);
    testAndSet_onlyUseHeap3(1);
    viFn_8004a56c(5);
    fn_80137D28();
    loadTextureFiles();
    initMapBlocks();
    ObjModel_InitResourceCaches();
    Resource_ResetRefCounts();
    gameTextInit();
    gameTextLoadDir(0x15);
    Obj_InitObjectSystem();
    fn_80137998();
    mapInitFn_80069990();
    initTextures();
    mapInitFn_8006fccc();
    initGameTimer();
    ObjModel_InitRenderBuffers();
    _initCardAndDsp();
    fn_802B6F48();
    loadTaskTexts();
    gameTextInitFn_8001bd14();
    initMaps();
    gGameUIInterface = Resource_Acquire(0, 0xf);
    gCameraInterface = Resource_Acquire(1, 0x17);
    lbl_803DCA94 = Resource_Acquire(0x12, 8);
    gPlayerInterface = Resource_Acquire(0xf, 0x16);
    gObjectTriggerInterface = Resource_Acquire(2, 0x1d);
    gScreenTransitionInterface = Resource_Acquire(0x16, 4);
    gSHthorntailAnimationInterface = Resource_Acquire(5, 0xf);
    gSky2Interface = Resource_Acquire(6, 0xc);
    gNewCloudsInterface = Resource_Acquire(7, 8);
    gCloudActionInterface = Resource_Acquire(9, 0xa);
    gCheckpointInterface = Resource_Acquire(3, 0xd);
    gTitleMenuControlInterface = Resource_Acquire(4, 0x24);
    gTitleMenuControlInterfaceCopy = gTitleMenuControlInterface;
    gExpgfxInterface = Resource_Acquire(0xa, 0xa);
    gModgfxInterface = Resource_Acquire(0xb, 0xc);
    gProjgfxInterface = Resource_Acquire(0xc, 8);
    gPlayerShadowInterface = Resource_Acquire(0xd, 3);
    gPartfxInterface = Resource_Acquire(0xe, 2);
    gScreensInterface = Resource_Acquire(0x11, 3);
    gWaterfxInterface = Resource_Acquire(0x13, 7);
    gRomCurveInterface = Resource_Acquire(0x14, 0x26);
    gTitleMenuLinkInterface = Resource_Acquire(0x3c, 7);
    gPathControlInterface = Resource_Acquire(0x15, 9);
    gMapEventInterface = Resource_Acquire(0x17, 0x24);
    lbl_803DCAB4 = (int *)Resource_Acquire(0x18, 6);
    gBaddieControlInterface = Resource_Acquire(0x19, 0x16);
    gMinimapInterface = Resource_Acquire(0x31, 2);
    lbl_803DCAC0 = Resource_Acquire(0x2f, 0xc);
    gTitleMenuItemInterface = Resource_Acquire(0x3d, 0xa);
    initFn_800534f8();
    titleScreenDrawFn_80093db4();
    testAndSet_onlyUseHeap3(0);
    loadAssetFileById((int)&lbl_803DCADC, 0x33);
    lbl_803DCAD8 = (s16)(getDataFileSize(0x33) >> 1);
    lbl_803DCAE0 = (*(u8 *(**)(void))(*(int *)gMapEventInterface + 0x88))();
    lbl_803DCA3F = 1;
    loadUiDll(2);
    doNothing_beforeTitleScreen();
    doQueuedLoads();
    setDrawCloudsAndLights(0);
    if (*(u8 *)lbl_803DCAFC != 0) {
        OSSetSaveRegion(lbl_803DCAFC, (u8 *)lbl_803DCAFC + 1);
        VISetBlack(0);
        VIFlush();
        VIWaitForRetrace();
        askProgressiveScanMode();
    }
    OSSetSaveRegion(NULL, NULL);
    memcpy(lbl_8033C378, lbl_803DCCF0, 0x3c);
    lbl_803DCCF0 = lbl_8033C378;
    initViewport();
    tvInit();
    OSReport(sMainFinishedInitMessage);
}
#pragma dont_inline reset
#pragma pop

extern u8 *textureAlloc(u32 w, u32 h, int kind, int a, int b, int c, int d, int e, int f);

typedef struct GameTextCharset {
    u8 *strings;
    u8 *entries;
    int headerCount;
    int count;
    u8 pad10[0xc];
    int status;
} GameTextCharset;

#pragma push
#pragma scheduling off
#pragma dont_inline on
void setLanguageFn_8001ad64(void *reqp) {
    u8 *req = (u8 *)reqp;
    GameTextCharset *cs;
    int *data;
    u8 *hdr;
    int ofs;
    int *table;
    int numStrings;
    int *strs;
    int i;
    u8 *txt;
    int *texHdr;
    u16 *p;
    u16 *texStart;
    int **slot;
    int kind;
    u32 bpp;
    u32 w;
    u32 h;
    int n;
    u32 size;
    u16 *newBuf;
    u16 *old;
    int delta;
    int *strs2;

    DCStoreRange(*(void **)(req + 0x3c), *(u32 *)(req + 0x40));
    if (req[0x4b] == 1) {
        cs = (GameTextCharset *)&lbl_8033AF40[1];
    } else if (req[0x4b] == 3) {
        cs = (GameTextCharset *)&lbl_8033AF40[3];
    } else {
        cs = (GameTextCharset *)&lbl_8033AF40[0];
        curGameTextDir = (void *)req[0x48];
        curLanguage = req[0x49];
    }
    data = *(int **)(req + 0x3c);
    cs->headerCount = data[0];
    if (cs->headerCount == 0) {
        cs->status = 3;
        *(int *)(req + 0x44) = 6;
        return;
    }
    cs->strings = (u8 *)(data + 1);
    hdr = (u8 *)data + cs->headerCount * 16;
    cs->count = *(u16 *)(hdr + 4);
    ofs = *(u16 *)(hdr + 6);
    cs->entries = hdr + 8;
    table = (int *)(cs->entries + cs->count * 12);
    numStrings = table[0];
    strs = table + 1;
    for (i = 0; i < cs->count; i++) {
        *(int **)(cs->entries + i * 12 + 8) = strs + *(int *)(cs->entries + i * 12 + 8);
    }
    txt = (u8 *)(table + numStrings + 1);
    for (i = 0; i < numStrings; i++) {
        strs[i] = strs[i] + (int)txt;
    }
    texHdr = (int *)(txt + ofs);
    p = (u16 *)((u8 *)texHdr + texHdr[0] + 4);
    texStart = p;
    slot = (int **)cs;
    while (1) {
        kind = p[0];
        bpp = p[1];
        w = p[2];
        h = p[3];
        p += 4;
        if (w == 0 && h == 0) {
            break;
        }
        switch (kind) {
        case 1:
            kind = 5;
            break;
        case 2:
            kind = 0;
            break;
        }
        if (slot[4] != NULL) {
            mmSetFreeDelay(0);
            mm_free(slot[4]);
            mmSetFreeDelay(2);
        }
        slot[4] = (int *)textureAlloc(w, h, kind, 0, 0, 0, 0, 1, 1);
        if (slot[4] != NULL) {
            if (bpp == 4) {
                u8 *dst8 = (u8 *)slot[4] + 0x60;
                u8 *src8 = (u8 *)p;
                n = (int)(w * h) >> 1;
                for (i = 0; i < n; i++) {
                    dst8[i] = src8[i];
                }
                DCFlushRange((u8 *)slot[4] + 0x60, *(u32 *)((u8 *)slot[4] + 0x44));
            } else {
                u16 *dst16 = (u16 *)((u8 *)slot[4] + 0x60);
                u16 *src16 = p;
                n = w * h;
                for (i = 0; i < n; i++) {
                    dst16[i] = src16[i];
                }
                DCFlushRange((u8 *)slot[4] + 0x60, *(u32 *)((u8 *)slot[4] + 0x44));
            }
        }
        p += (int)(w * h * bpp) >> 4;
        slot = slot + 1;
    }
    size = (u32)((u8 *)texStart - *(u8 **)(req + 0x3c));
    newBuf = (u16 *)mmAlloc(size, 0x1a, 0);
    old = *(u16 **)(req + 0x3c);
    delta = (int)newBuf - (int)old;
    n = size >> 1;
    for (i = 0; i < n; i++) {
        newBuf[i] = old[i];
    }
    cs->strings = cs->strings + delta;
    cs->entries = cs->entries + delta;
    for (i = 0; i < cs->count; i++) {
        *(int *)(cs->entries + i * 12 + 8) = *(int *)(cs->entries + i * 12 + 8) + delta;
    }
    strs2 = (int *)((u8 *)strs + delta);
    for (i = 0; i < numStrings; i++) {
        strs2[i] = strs2[i] + delta;
    }
    mmSetFreeDelay(0);
    mm_free(*(void **)(req + 0x3c));
    *(int *)(req + 0x3c) = 0;
    mmSetFreeDelay(2);
    *(u16 **)(req + 0x3c) = newBuf;
    cs->status = 2;
    *(int *)(req + 0x44) = 3;
}
#pragma dont_inline reset
#pragma pop

extern void fn_802B4DE0(u8 *obj, int flag);
extern void Resource_Release(void *res);
extern void Obj_FreeObject(u8 *obj);
extern void fn_80059A50(int arg);
extern void setShadowFlag_803db658(int v);
extern void *textureFn_8006c5c4(void);
extern u8 *lbl_803DCBA4;
extern u8 *lbl_803DCBA8;
extern char sObjFreeObjdefError[];

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void objFreeObjDef(void *objp, int flag) {
    u8 *obj = (u8 *)objp;
    int defs[46];
    void (*fp)(u8 *, int);
    void (*cb)(u8 *);
    void (*cb2)(u8 *, int, int, int, int);
    void (*cb3)(void);
    int i;
    int count;
    int n;
    u8 *o;
    int *bp;
    void *curTex;
    u8 *tex;
    int t2;
    s8 modelCount;
    int group;
    int type;

    if (*(s8 *)(obj + 0xe9) != 0) {
        ObjContact_RemoveObjectCallbacks(obj);
    }
    switch (*(s16 *)(obj + 0x46)) {
    case 0:
    case 0x1f:
        fn_802B4DE0(obj, flag);
        break;
    default:
        if (*(int **)(obj + 0x68) != NULL) {
            fp = (void (*)(u8 *, int))*(int *)(*(int *)(obj + 0x68) + 0x14);
            if (fp != NULL) {
                fp(obj, flag);
            }
            Resource_Release(*(void **)(obj + 0x68));
            *(int *)(obj + 0x68) = 0;
        }
        break;
    }
    (*(void (**)(u8 *))(*(int *)gTitleMenuControlInterface + 0x48))(obj);
    (*(void (**)(u8 *))(*(int *)gExpgfxInterface + 0x28))(obj);
    if (*(u32 *)(*(u8 **)(obj + 0x50) + 0x44) & 0x40) {
        ObjGroup_RemoveObject(obj, 6);
        if (flag == 0) {
            count = 0;
            for (i = 0; i < lbl_803DCB84; i++) {
                o = ((u8 **)lbl_803DCB88)[i];
                if (*(u8 **)(o + 0x30) == obj) {
                    *(int *)(o + 0x30) = 0;
                    if (*(int *)(o + 0x4c) != 0) {
                        defs[count] = (int)o;
                        count++;
                    }
                }
            }
            for (i = 0; i < count; i++) {
                Obj_FreeObject((void *)defs[i]);
            }
            fn_80059A50(*(u8 *)(obj + 0x34));
        }
    }
    if (flag == 0 && *(s16 *)(obj + 0x44) == 0x10) {
        for (i = 0; i < lbl_803DCB84; i++) {
            if (*(u8 **)(((u8 **)lbl_803DCB88)[i] + 0xc0) == obj) {
                *(int *)(((u8 **)lbl_803DCB88)[i] + 0xc0) = 0;
            }
        }
    }
    for (i = 0; i < lbl_803DCB84; i++) {
        if (*(s16 *)(((u8 **)lbl_803DCB88)[i] + 0x44) == 0x10) {
            bp = *(int **)(((u8 **)lbl_803DCB88)[i] + 0xb8);
            if (*(u8 **)bp == obj) {
                *bp = 0;
                *((u8 *)bp + 0x8f) = 1;
            }
        }
    }
    if (*(s8 *)(*(u8 **)(obj + 0x50) + 0x56) > 0) {
        ObjGroup_RemoveObject(obj, 8);
    }
    if (*(int *)(obj + 0x64) != 0) {
        if (*(s16 *)(*(u8 **)(obj + 0x50) + 0x48) == 1) {
            setShadowFlag_803db658(1);
        }
        if (*(int *)(*(u8 **)(obj + 0x64) + 4) != 0) {
            curTex = textureFn_8006c5c4();
            tex = *(u8 **)(*(u8 **)(obj + 0x64) + 4);
            if (tex != curTex) {
                if ((*(u8 *)(*(u8 **)(obj + 0x50) + 0x5f) & 4) == 0) {
                    textureFree(tex);
                } else {
                    mm_free(tex);
                }
            }
        }
        if (*(int *)(*(u8 **)(obj + 0x64) + 8) != 0) {
            mm_free(*(void **)(*(u8 **)(obj + 0x64) + 8));
        }
        t2 = *(int *)(*(u8 **)(obj + 0x64) + 0x10);
        if (t2 != 0 && t2 != -1) {
            mm_free((void *)t2);
        }
    }
    if (*(int *)(obj + 0xdc) != 0) {
        mm_free(*(void **)(obj + 0xdc));
        *(int *)(obj + 0xdc) = 0;
    }
    modelCount = *(s8 *)(*(u8 **)(obj + 0x50) + 0x55);
    for (i = 0; i < modelCount; i++) {
        if (*(int *)(*(u8 **)(obj + 0x7c) + i * 4) != 0) {
            ObjModel_Release(*(u8 **)(*(u8 **)(obj + 0x7c) + i * 4));
        }
    }
    if (*(u8 *)(obj + 0xe5) & 1) {
        *(u16 *)(obj + 0xe6) = 0;
        *(u8 *)(obj + 0xe5) = *(u8 *)(obj + 0xe5) & ~1;
        *(u8 *)(obj + 0xf0) = 0;
        ObjModel_ClearRenderAttachment(*(u8 **)(*(u8 **)(obj + 0x7c) + *(s8 *)(obj + 0xad) * 4));
        cb2 = (void (*)(u8 *, int, int, int, int))*(int *)(*(int *)lbl_803DCAB4 + 0xc);
        cb2(obj, 0x7fb, 0, 0x50, 0);
        cb2 = (void (*)(u8 *, int, int, int, int))*(int *)(*(int *)lbl_803DCAB4 + 0xc);
        cb2(obj, 0x7fc, 0, 0x32, 0);
    }
    if (*(u8 *)(obj + 0xe5) & 2) {
        Obj_ClearModelColorFadeRecursive(obj);
    }
    group = ObjGroup_GetObjectGroup(obj);
    if (group != 0) {
        ObjGroup_RemoveObject(obj, group - 1);
    }
    type = *(s16 *)(obj + 0x48);
    if (*(s8 *)(lbl_803DCBA4 + type) == 0) {
        debugPrintf(sObjFreeObjdefError);
    } else {
        *(s8 *)(lbl_803DCBA4 + type) -= 1;
        if (*(s8 *)(lbl_803DCBA4 + type) == 0) {
            o = ((u8 **)lbl_803DCBA8)[type];
            if (*(int *)(o + 0x30) != 0) {
                mm_free(*(void **)(o + 0x30));
            }
            if (*(int *)(o + 0x34) != 0) {
                mm_free(*(void **)(o + 0x34));
            }
            mm_free(o);
        }
    }
    if (*(s16 *)(obj + 0xb4) >= 0) {
        if (flag == 0) {
            cb3 = (void (*)(void))*(int *)(*(int *)gObjectTriggerInterface + 0x4c);
            cb3();
        }
        *(s16 *)(obj + 0xb4) = 0xffff;
    }
    if ((*(u16 *)(obj + 6) & 0x2000) && *(int *)(obj + 0x4c) != 0) {
        mm_free(*(void **)(obj + 0x4c));
    }
    mm_free(obj);
}
#pragma dont_inline reset
#pragma pop

extern void lbl_80006C6C(int *out, u8 *a, void *buf, int c, int d, u8 *e, int f, int g);
extern u8 lbl_80340740[];

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void modelAnimFn_80024524(u8 *hdr, u8 *stk, int n)
{
    u8 *p2;
    u8 *p4;
    int i;
    u8 *p5;
    u8 *p6;
    u8 *q;
    int bv;
    int off;
    int k;
    int n2;
    int t;
    f32 g;

    i = 0;
    p2 = stk;
    p4 = stk;
    for (; i < n; i++) {
        if (*(u16 *)(hdr + 2) & 0x40) {
            p6 = *(u8 **)(stk + *(u16 *)(p2 + 0x44) * 4 + 0x1c);
            p5 = p6;
            p6 += 0x80;
        } else {
            p5 = *(u8 **)(hdr + 0x68) + *(u16 *)(p2 + 0x44) * (((*(u8 *)(hdr + 0xf3) - 1) & ~7) + 8);
            p6 = *(u8 **)(*(u8 **)(hdr + 0x64) + *(u16 *)(p2 + 0x44) * 4);
        }
        bv = *(u8 *)(*(u8 **)(p4 + 0x34) + 2);
        k = 0;
        off = 0;
        q = p5;
        while (k < *(u8 *)(hdr + 0xf3)) {
            *(u8 *)(i + *(int *)(hdr + 0x3c) + off + 2) = *q;
            off += 0x1c;
            k++;
            q++;
        }
        n2 = (int)*(f32 *)(p4 + 4);
        g = (f32)n2;
        if (g != *(f32 *)(p4 + 4)) {
            *(s16 *)(p2 + 0x4c) = (s16)bv;
        } else {
            *(s16 *)(p2 + 0x4c) = 0;
        }
        if (*(s8 *)(stk + i + 0x60) != 0 && g == *(f32 *)(p4 + 0x14) - lbl_803DE818) {
            *(s16 *)(p2 + 0x4c) = (s16)(-bv * n2);
        }
        t = *(s16 *)(p6 + 2) + bv * n2;
        *(u8 **)(p4 + 0x2c) = p6 + t;
        p2 += 2;
        p4 += 4;
    }
}

#pragma peephole off
void modelWalkAnimFn_800248b8(u8 *a, u8 *b, u8 *c, int d, f32 e)
{
    u8 stk[0x64];
    int px;
    int fl;
    u8 *hdr;
    int v;
    int sv;
    int n;
    int j;
    int idx;
    u8 bvv;
    f32 fb;
    f32 fa;

    hdr = *(u8 **)b;
    px = ((int *)(b + (*(u16 *)(b + 0x18) & 1) * 4))[3];
    *(f32 *)(c + 4) = e * *(f32 *)(c + 0x14);
    fl = 0;
    if (*(u16 *)(hdr + 2) & 8) {
        *(u32 *)(stk + 0x1c) = *(u32 *)(c + 0x1c);
        *(u32 *)(stk + 0x20) = *(u32 *)(c + 0x20);
        *(u32 *)(stk + 0x24) = *(u32 *)(c + 0x24);
        *(u32 *)(stk + 0x28) = *(u32 *)(c + 0x28);
        for (j = 0; j < 2; j++) {
            if (*(u16 *)(c + 0x58)) {
                idx = j;
            } else {
                idx = 0;
            }
            *(u16 *)(stk + j * 2 + 0x44) = *(u16 *)(c + idx * 2 + 0x44);
            *(u8 *)(stk + j + 0x60) = *(u8 *)(c + idx + 0x60);
            *(f32 *)(stk + j * 4 + 0x14) = *(f32 *)(c + idx * 4 + 0x14);
            *(f32 *)(stk + j * 4 + 4) = *(f32 *)(c + idx * 4 + 4);
            *(u32 *)(stk + j * 4 + 0x34) = *(u32 *)(c + idx * 4 + 0x34);
        }
        *(u16 *)(stk + 0x58) = *(u16 *)(c + 0x58);
        modelAnimFn_80024524(hdr, stk, 2);
        sv = *(s8 *)(c + 0x63);
        if (sv & 1) {
            fl |= 0x10;
        }
        if (sv & 4) {
            fl |= 0x20;
        }
        lbl_80006C6C(&px, a, stk, *(int *)(hdr + 0x3c), *(u8 *)(hdr + 0xf3), lbl_80340740, d, fl | 0x40);
    } else {
        u8 *p4;
        u8 *p2;
        int i;
        int m;

        i = 0;
        p4 = c;
        p2 = c;
        for (; i < 2; i++) {
            if (i != 0) {
                v = *(u16 *)(c + 0x5c);
            } else {
                v = *(u16 *)(c + 0x5a);
            }
            if (v != 0) {
                if (*(u16 *)(c + 0x58)) {
                    m = 4 << i;
                } else {
                    m = 0;
                }
                bvv = *(u8 *)(c + i + 0x60);
                *(u8 *)(stk + 0x60) = bvv;
                fa = *(f32 *)(p4 + 0x14);
                *(f32 *)(stk + 0x14) = fa;
                fb = *(f32 *)(p4 + 4);
                *(f32 *)(stk + 4) = fb;
                *(u32 *)(stk + 0x34) = *(u32 *)(p4 + 0x34);
                *(u8 *)(stk + 0x61) = bvv;
                *(f32 *)(stk + 0x18) = fa;
                *(f32 *)(stk + 8) = fb;
                *(u32 *)(stk + 0x38) = *(u32 *)(p4 + 0x3c);
                if (*(u16 *)(hdr + 2) & 0x40) {
                    *(u16 *)(stk + 0x44) = 0;
                    *(u16 *)(stk + 0x46) = 1;
                    *(u32 *)(stk + 0x1c) = *(u32 *)(c + *(u16 *)(p2 + 0x44) * 4 + 0x1c);
                    *(u32 *)(stk + 0x20) = *(u32 *)(c + *(u16 *)(p2 + 0x48) * 4 + 0x24);
                } else {
                    *(u16 *)(stk + 0x44) = *(u16 *)(p2 + 0x44);
                    *(u16 *)(stk + 0x46) = *(u16 *)(p2 + 0x48);
                }
                *(u16 *)(stk + 0x58) = (u16)v;
                modelAnimFn_80024524(hdr, stk, 2);
                lbl_80006C6C(&px, a, stk, *(int *)(hdr + 0x3c), *(u8 *)(hdr + 0xf3), lbl_80340740, d, m);
                if (m != 0) {
                    fl |= 1 << i;
                }
            }
            p4 += 4;
            p2 += 2;
        }
        if ((*(u16 *)(c + 0x5a) == 0 && *(u16 *)(c + 0x5c) == 0) || fl != 0) {
            n = 1;
            if (*(u16 *)(c + 0x58) != 0) {
                n = 2;
            }
            *(u32 *)(stk + 0x1c) = *(u32 *)(c + 0x1c);
            *(u32 *)(stk + 0x20) = *(u32 *)(c + 0x20);
            *(u32 *)(stk + 0x24) = *(u32 *)(c + 0x24);
            *(u32 *)(stk + 0x28) = *(u32 *)(c + 0x28);
            for (j = 0; j < n; j++) {
                *(u16 *)(stk + j * 2 + 0x44) = *(u16 *)(c + j * 2 + 0x44);
                *(u8 *)(stk + j + 0x60) = *(u8 *)(c + j + 0x60);
                *(f32 *)(stk + j * 4 + 0x14) = *(f32 *)(c + j * 4 + 0x14);
                *(f32 *)(stk + j * 4 + 4) = *(f32 *)(c + j * 4 + 4);
                *(u32 *)(stk + j * 4 + 0x34) = *(u32 *)(c + j * 4 + 0x34);
            }
            *(u16 *)(stk + 0x58) = *(u16 *)(c + 0x58);
            modelAnimFn_80024524(hdr, stk, n);
            sv = *(s8 *)(c + 0x63);
            if (sv & 1) {
                fl |= 0x10;
            }
            if (sv & 4) {
                fl |= 0x20;
            }
            lbl_80006C6C(&px, a, stk, *(int *)(hdr + 0x3c), *(u8 *)(hdr + 0xf3), lbl_80340740, d, fl);
        }
    }
}
#pragma dont_inline reset
#pragma pop

extern void *animLoadFromTable(u8 *hdr, int idx, int a, u8 *b);

#define LOADCOLOR_BLOCK(OFF)                                                          \
    {                                                                                 \
        u32 v;                                                                        \
        int idx;                                                                      \
        int sz4;                                                                      \
        u8 buf[4];                                                                    \
        int sz;                                                                       \
        u8 *hp;                                                                       \
                                                                                      \
        v = *(u32 *)(p2 + (OFF));                                                     \
        idx = **(s16 **)(hdr + 0x6c);                                                 \
        if ((getLoadedFileFlags(0) & 0x100000) == 0 || *(u16 *)(hdr + 4) == 1 ||      \
            *(u16 *)(hdr + 4) == 3) {                                                 \
            if (v == 0) {                                                             \
                if (ModelList_getHeader(lbl_803DCB50, idx, &hp) == 0) {               \
                    sz4 = *(int *)((u8 *)lbl_803DCB4C + idx * 4);                     \
                    loadAndDecompressDataFile(0x30, 0, sz4, 0, (int)&sz, idx, 1);     \
                    hp = (u8 *)mmAlloc(sz, 10, 0);                                    \
                    loadAndDecompressDataFile(0x30, (void *)hp, sz4, sz, (int)buf, idx, 0); \
                    *hp = 1;                                                          \
                    modelInitModelList(lbl_803DCB50, idx, &hp);                       \
                } else {                                                              \
                    *hp += 1;                                                         \
                }                                                                     \
            } else {                                                                  \
                animLoadFromTable(hdr, idx, 0, (u8 *)v);                               \
            }                                                                         \
        }                                                                             \
    }

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void modelLoadColorFn_80024ec8(void *m, void *data)
{
    u8 *p2 = (u8 *)data;
    u8 *hdr;
    u8 *mdl;
    f32 f;

    hdr = *(u8 **)m;
    *(u16 *)(p2 + 0x44) = 0;
    *(u16 *)(p2 + 0x5e) = 0;
    *(u16 *)(p2 + 0x58) = 0;
    *(u16 *)(p2 + 0x5a) = 0;
    *(u16 *)(p2 + 0x5c) = 0;
    f = lbl_803DE828;
    *(f32 *)(p2 + 0xc) = f;
    *(f32 *)(p2 + 4) = f;
    *(f32 *)(p2 + 0x14) = f;
    *(u8 *)(p2 + 0x60) = 0;
    if (*(u16 *)(hdr + 0xec) != 0) {
        if (*(u16 *)(hdr + 2) & 0x40) {
            LOADCOLOR_BLOCK(0x1c)
            LOADCOLOR_BLOCK(0x20)
            LOADCOLOR_BLOCK(0x24)
            LOADCOLOR_BLOCK(0x28)
            *(u16 *)(p2 + 0x44) = 0;
            mdl = *(u8 **)(p2 + *(u16 *)(p2 + 0x44) * 4 + 0x1c) + 0x80;
        } else {
            mdl = *(u8 **)(*(u8 **)(hdr + 0x64) + *(u16 *)(p2 + 0x44) * 4);
        }
        *(u8 **)(p2 + 0x34) = mdl + 6;
        *(s8 *)(p2 + 0x60) = (s8)(*(u8 *)(mdl + 1) & 0xf0);
        *(f32 *)(p2 + 0x14) = (f32)*(u8 *)(*(u8 **)(p2 + 0x34) + 1);
        if (*(s8 *)(p2 + 0x60) == 0) {
            *(f32 *)(p2 + 0x14) -= lbl_803DE818;
        }
        *(u8 *)(p2 + 0x61) = *(u8 *)(p2 + 0x60);
        *(u32 *)(p2 + 0x38) = *(u32 *)(p2 + 0x34);
        *(u16 *)(p2 + 0x46) = *(u16 *)(p2 + 0x44);
        *(f32 *)(p2 + 8) = *(f32 *)(p2 + 4);
        *(f32 *)(p2 + 0x18) = *(f32 *)(p2 + 0x14);
        *(f32 *)(p2 + 0x10) = *(f32 *)(p2 + 0xc);
        *(u32 *)(p2 + 0x3c) = *(u32 *)(p2 + 0x34);
        *(u16 *)(p2 + 0x48) = *(u16 *)(p2 + 0x44);
        *(u32 *)(p2 + 0x40) = *(u32 *)(p2 + 0x34);
        *(u16 *)(p2 + 0x4a) = *(u16 *)(p2 + 0x44);
    }
}
#pragma dont_inline reset
#pragma pop

#define BLENDTBL_ENTRY(K, OFF)                              \
    if (p[K] != 0) {                                        \
        ((s16 *)lbl_80340740)[w++] = (s16)(v1 + (OFF));     \
        ((s16 *)lbl_80340740)[w++] = (s16)(v2 + (OFF));     \
        ((s16 *)lbl_80340740)[w++] = p[K];                  \
        ((s16 *)lbl_80340740)[w++] = p[K];                  \
    }

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void ObjModel_BuildAnimBlendTable(u8 *obj, u8 *p2, u8 *hdr)
{
    int poff;
    u8 *md;
    int boff;
    int i;
    u32 u;
    int v1;
    int w;
    s16 *p;
    u8 *b1;
    int v2;
    u8 *b2;

    if (*(u16 *)(hdr + 2) & 0x40) {
        b1 = *(u8 **)(p2 + *(u16 *)(p2 + 0x44) * 4 + 0x1c);
        b2 = *(u8 **)(p2 + *(u16 *)(p2 + 0x46) * 4 + 0x1c);
    } else {
        b1 = *(u8 **)(hdr + 0x68) + *(u16 *)(p2 + 0x44) * (((*(u8 *)(hdr + 0xf3) - 1) & ~7) + 8);
        b2 = *(u8 **)(hdr + 0x68) + *(u16 *)(p2 + 0x46) * (((*(u8 *)(hdr + 0xf3) - 1) & ~7) + 8);
    }
    md = *(u8 **)(obj + 0x50);
    boff = 0;
    w = 0;
    i = 0;
    poff = 0;
    for (; i < (int)*(u8 *)(md + 0x5a); i++) {
        u = *(u8 *)(*(u8 **)(md + 0x10) + boff + *(s8 *)(obj + 0xad) + 1);
        if (u != 0xff) {
            p = (s16 *)(*(u8 **)(obj + 0x6c) + poff);
            v1 = *(s8 *)(b1 + u) << 6;
            v2 = *(s8 *)(b2 + u) << 6;
            BLENDTBL_ENTRY(0, 0)
            BLENDTBL_ENTRY(1, 2)
            BLENDTBL_ENTRY(2, 4)
            BLENDTBL_ENTRY(3, 0xc)
            BLENDTBL_ENTRY(4, 0xe)
            BLENDTBL_ENTRY(5, 0x10)
            BLENDTBL_ENTRY(6, 0x18)
            BLENDTBL_ENTRY(7, 0x1a)
            BLENDTBL_ENTRY(8, 0x1c)
        }
        boff = *(s8 *)(md + 0x55) + boff + 1;
        poff += 0x12;
    }
    ((s16 *)lbl_80340740)[w++] = 0x1000;
    ((s16 *)lbl_80340740)[w] = 0x1000;
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void *modelLoadFn_80025ae4(u8 *p, int b, int isType1, int c)
{
    u8 *out;
    int szs[7];
    int pos;
    int end;
    int n;
    int k;
    int o2;
    u8 *q;
    f32 f;

    out = (u8 *)c;
    if (p == 0) {
        return 0;
    }
    modelLoad_calcSizes(p, b, szs, 0);
    pos = roundUpTo32((int)out + 0x64);
    *(int *)(out + 0xc) = pos;
    pos += szs[6] >> 1;
    *(int *)(out + 0x10) = pos;
    pos += szs[6] >> 1;
    *(int *)(out + 0x5c) = *(int *)(out + 0xc);
    if (*(u8 *)(p + 0xf9) != 0 || *(int *)(p + 0xa4) != 0 || (*(u16 *)(p + 2) & 0x10)) {
        pos = roundUpTo32(pos);
        *(int *)(out + 0x1c) = pos;
        pos = roundUpTo32(pos + *(u16 *)(p + 0xe4) * 6);
        *(int *)(out + 0x20) = pos;
        end = pos + *(u16 *)(p + 0xe4) * 6;
        memcpy(*(void **)(out + 0x1c), *(void **)(p + 0x28), *(u16 *)(p + 0xe4) * 6);
        DCFlushRange(*(void **)(out + 0x1c), *(u16 *)(p + 0xe4) * 6);
        memcpy(*(void **)(out + 0x20), *(void **)(p + 0x28), *(u16 *)(p + 0xe4) * 6);
        DCFlushRange(*(void **)(out + 0x20), *(u16 *)(p + 0xe4) * 6);
        pos = roundUpTo32(end);
    } else {
        end = *(int *)(p + 0x28);
        *(int *)(out + 0x20) = end;
        *(int *)(out + 0x1c) = end;
    }
    if (*(int *)(p + 0xc8) != 0) {
        if (*(u8 *)(p + 0x24) & 8) {
            n = 9;
        } else {
            n = 3;
        }
        pos = roundUpTo32(pos);
        *(int *)(out + 0x24) = pos;
        end = pos + *(u16 *)(p + 0xe6) * n;
        memcpy(*(void **)(out + 0x24), *(void **)(p + 0x2c), *(u16 *)(p + 0xe6) * n);
        DCFlushRange(*(void **)(out + 0x24), n * *(u16 *)(p + 0xe6));
        pos = roundUpTo32(end);
    } else {
        *(int *)(out + 0x24) = *(int *)(p + 0x2c);
    }
    pos = roundUpTo4(pos);
    *(int *)(out + 0x2c) = pos;
    pos += 0x68;
    if (b & 0x80) {
        *(int *)(out + 0x30) = pos;
        pos += 0x68;
    }
    if (*(u16 *)(p + 2) & 0x40) {
        pos = roundUpTo8(pos);
        q = *(u8 **)(out + 0x2c);
        *(int *)(q + 0x1c) = pos;
        pos += szs[5];
        *(int *)(q + 0x20) = pos;
        pos += szs[5];
        *(int *)(q + 0x24) = pos;
        pos += szs[5];
        *(int *)(q + 0x28) = pos;
        pos += szs[5];
        q = *(u8 **)(out + 0x30);
        if (q != 0) {
            *(int *)(q + 0x1c) = pos;
            pos += szs[5];
            *(int *)(q + 0x20) = pos;
            pos += szs[5];
            *(int *)(q + 0x24) = pos;
            pos += szs[5];
            *(int *)(q + 0x28) = pos;
            pos += szs[5];
        }
    }
    if (*(u8 *)(p + 0xf9) != 0) {
        pos = roundUpTo4(pos);
        *(int *)(out + 0x28) = pos;
        pos += 0x30;
        q = *(u8 **)(out + 0x28);
        *(s8 *)(q + 0xc) = -1;
        *(s8 *)(q + 0xd) = -1;
        f = lbl_803DE828;
        *(f32 *)(q + 0) = f;
        *(f32 *)(q + 4) = f;
        *(f32 *)(q + 8) = f;
        q = *(u8 **)(out + 0x28);
        *(s8 *)(q + 0x1c) = -1;
        *(s8 *)(q + 0x1d) = -1;
        *(f32 *)(q + 0x10) = f;
        *(f32 *)(q + 0x14) = f;
        *(f32 *)(q + 0x18) = f;
        q = *(u8 **)(out + 0x28);
        *(s8 *)(q + 0x2c) = -1;
        *(s8 *)(q + 0x2d) = -1;
        *(f32 *)(q + 0x20) = f;
        *(f32 *)(q + 0x24) = f;
        *(f32 *)(q + 0x28) = f;
    }
    if (szs[1] > 0) {
        pos = roundUpTo4(pos);
        *(int *)(out + 0x48) = pos;
        pos += *(u8 *)(p + 0xf7) * 0x10;
        *(int *)(out + 0x4c) = pos;
        pos += *(u8 *)(p + 0xf7) * 0x10;
        *(int *)(out + 0x50) = *(int *)(out + 0x48);
    }
    if (*(int *)(p + 0x3c) != 0 && *(u8 *)(p + 0xf3) != 0 && *(int *)(p + 0x18) != 0 && *(int *)(p + 0x1c) != 0) {
        pos = roundUpTo4(pos);
        *(int *)(out + 0x14) = pos;
        pos += 0x1c;
        *(int *)(*(u8 **)(out + 0x14) + 0) = pos;
        pos += *(u8 *)(p + 0xf3) * 0xc;
        *(int *)(*(u8 **)(out + 0x14) + 4) = pos;
        pos += *(u8 *)(p + 0xf3) * 4;
        *(int *)(*(u8 **)(out + 0x14) + 8) = pos;
        pos += *(u8 *)(p + 0xf3) * 4;
        *(int *)(*(u8 **)(out + 0x14) + 0xc) = pos;
        pos += *(u8 *)(p + 0xf3) * 4;
        *(int *)(*(u8 **)(out + 0x14) + 0x10) = pos;
        pos += *(u8 *)(p + 0xf3) * 4;
        *(int *)(*(u8 **)(out + 0x14) + 0x18) = pos;
        pos += *(u8 *)(p + 0xf3);
    } else {
        *(int *)(out + 0x14) = 0;
    }
    if (*(int *)(p + 0xa4) != 0) {
        pos = roundUpTo4(pos);
        *(int *)(out + 0x40) = pos;
        pos += *(u16 *)(p + 0x8a) * 4;
    }
    if (*(int *)(p + 0xc8) != 0) {
        pos = roundUpTo4(pos);
        *(int *)(out + 0x44) = pos;
        pos += *(u16 *)(p + 0xae) * 4;
    }
    pos = roundUpTo4(pos);
    *(int *)(out + 0x34) = pos;
    pos += *(u8 *)(p + 0xf8) * 0xc;
    k = 0;
    o2 = 0;
    for (; k < (int)*(u8 *)(p + 0xf8); k++) {
        *(u8 *)(*(u8 **)(out + 0x34) + o2 + 8) = 0;
        o2 += 0xc;
    }
    if (b & 0x8000) {
        pos = fn_80022E0C(pos);
        *(int *)(out + 0x54) = pos;
        *(u8 *)(*(u8 **)(out + 0x54) + 0x18) = 0;
    }
    *(int *)(out + 0x58) = 0;
    *(u8 **)(out + 0) = p;
    *(u8 *)(out + 0x60) = 0;
    return out;
}
#pragma dont_inline reset
#pragma pop

extern char sModelAnimationBufferOverflowWarning[];

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma opt_loop_invariants off
#pragma dont_inline on
int modelLoadAnimations(void *model, int id, void *animBase)
{
    u8 *hdr = (u8 *)model;
    u8 *buf = (u8 *)animBase;
    int *tbl;
    int base;
    int aln;
    int sz;
    int o;
    int slot;
    int i;
    int cnt;
    int toff;
    int woff;
    int anim;
    int sz4;
    int idxout;
    u8 *q2;
    u8 buf2[4];
    int sz2;
    u8 *hp2;
    u8 *pc;
    int d;

    aln = 0;
    tbl = lbl_803DCB60;
    fileLoadToBufferOffset(0x2d, tbl, id << 1, 0x10);
    base = *(s16 *)tbl;
    if (*(u16 *)(hdr + 0xec) == 0) {
        return 0;
    }
    sz = (*(u16 *)(hdr + 0xec) << 1) + 8;
    if (sz > 0x800) {
        debugPrintf(sModelAnimationBufferOverflowWarning, sz);
    }
    fileLoadToBufferOffset(0x31, lbl_803DCB60, (id & ~3) << 2, 0x20);
    *(int *)(hdr + 0x80) = *(int *)((u8 *)lbl_803DCB60 + (id & 3) * 4);
    sz4 = *(int *)((u8 *)lbl_803DCB60 + (id & 3) * 4);
    id = *(int *)((u8 *)lbl_803DCB60 + (id & 3) * 4 + 4) - sz4;
    if (*(u16 *)(hdr + 2) & 0x40) {
        *(u8 **)(hdr + 0x6c) = buf;
        while (sz & 7) {
            sz++;
        }
        aln = sz;
        buf += sz;
        fileLoadToBufferOffset(0x2e, *(void **)(hdr + 0x6c), base, sz);
    } else {
        fileLoadToBufferOffset(0x2e, lbl_803DCB64, base, sz);
        *(s16 **)(hdr + 0x6c) = lbl_803DCB64;
    }
    o = 0;
    slot = 1;
    *(s16 *)(hdr + (slot - 1) * 2 + 0x70) = o;
    i = 0;
    for (; i < (int)*(u16 *)(hdr + 0xec); i++) {
        if (*(s16 *)(*(u8 **)(hdr + 0x6c) + o) == -1) {
            *(s16 *)(hdr + slot++ * 2 + 0x70) = (s16)(i + 1);
        }
        o += 2;
    }
    if ((*(u16 *)(hdr + 2) & 0x40) == 0) {
        *(int *)(hdr + 0x6c) = 0;
        *(u8 **)(hdr + 0x64) = buf;
        buf += *(u16 *)(hdr + 0xec) * 4;
        aln += *(u16 *)(hdr + 0xec) * 4;
        while (aln & 7) {
            buf++;
            aln++;
        }
        *(u8 **)(hdr + 0x68) = buf;
        fileLoadToBufferOffset(0x32, *(void **)(hdr + 0x68), *(int *)(hdr + 0x80), id);
        cnt = 0;
        toff = 0;
        woff = toff;
        do {
            anim = *(s16 *)((u8 *)lbl_803DCB64 + toff);
            if (anim != -1) {
                if ((getLoadedFileFlags(0) & 0x100000) && *(u16 *)(hdr + 4) != 1 &&
                    *(u16 *)(hdr + 4) != 3) {
                    pc = 0;
                } else {
                    if (ModelList_getHeader(lbl_803DCB50, anim, &hp2) == 0) {
                        sz4 = *(int *)((u8 *)lbl_803DCB4C + anim * 4);
                        loadAndDecompressDataFile(0x30, 0, sz4, 0, (int)&sz2, anim, 1);
                        hp2 = (u8 *)mmAlloc(sz2, 10, 0);
                        loadAndDecompressDataFile(0x30, (void *)hp2, sz4, sz2, (int)buf2, anim, 0);
                        *hp2 = 1;
                        modelInitModelList(lbl_803DCB50, anim, &hp2);
                    } else {
                        *hp2 += 1;
                    }
                    pc = hp2;
                }
                *(u8 **)(*(u8 **)(hdr + 0x64) + woff) = pc;
                if (*(u8 **)(*(u8 **)(hdr + 0x64) + woff) == 0) {
                    int k;
                    int o3;

                    k = 0;
                    o3 = 0;
                    for (; k < cnt; k++) {
                        q2 = *(u8 **)(*(u8 **)(hdr + 0x64) + o3);
                        if (q2 != 0) {
                            d = *q2 - 1;
                            *q2 = d;
                            if ((s8)d <= 0) {
                                model_findIdxInModelList(lbl_803DCB50, &q2, &idxout);
                                model_adjustModelList(lbl_803DCB50, idxout);
                                mm_free(q2);
                            }
                        }
                        o3 += 4;
                    }
                    *(int *)(hdr + 0x64) = 0;
                    return 1;
                }
            } else {
                *(int *)(*(u8 **)(hdr + 0x64) + woff) = 0;
            }
            toff += 2;
            woff += 4;
            cnt++;
        } while (cnt < (int)*(u16 *)(hdr + 0xec));
    } else {
        *(int *)(hdr + 0x64) = 0;
    }
    return 0;
}
#pragma dont_inline reset
#pragma pop

extern void playerUpdateWhileTimeStopped(u8 *obj);
extern void playerRenderQuakeSpell(void);
extern void playerUpdate(u8 *obj);
extern void Sfx_PlayFromObject(u8 *obj, int sfx);
extern void Obj_GetWorldPosition(u8 *obj, void *x, void *y, void *z);
extern u32 lbl_803DCB78;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_UpdateObject(u8 *obj)
{
    u8 *t;
    void (*cb)(u8 *, int, int, int, int);
    void (*cb2)(u8 *);

    if (*(u16 *)(obj + 0xb0) & 0x40) {
        return;
    }
    if (lbl_803DCB78 & 1) {
        switch (*(s16 *)(obj + 0x46)) {
        case 0:
        case 0x1f:
            playerUpdateWhileTimeStopped(obj);
            break;
        case 0x69:
            playerRenderQuakeSpell();
            break;
        case 0x4f3:
        case 0x882:
        case 0x887:
            cb2 = (void (*)(u8 *))*(int *)(**(int **)(obj + 0x68) + 8);
            cb2(obj);
            break;
        }
        return;
    }
    if (*(u8 *)(obj + 0xe5) != 0 && *(int *)(obj + 0xc4) == 0 && (*(u8 *)(obj + 0xe5) & 2)) {
        Obj_TickModelColorFadeRecursive(obj);
    }
    if (*(int *)(obj + 0xc0) != 0) {
        if (*(int *)(obj + 0xc8) != 0) {
            t = *(u8 **)(*(u8 **)(obj + 0xc8) + 0x54);
            if (t != 0) {
                *(int *)(t + 0x50) = 0;
                *(u8 *)(*(u8 **)(*(u8 **)(obj + 0xc8) + 0x54) + 0x71) = 0;
            }
        }
        if (*(int *)(obj + 0x54) == 0) {
            return;
        }
        *(int *)(*(u8 **)(obj + 0x54) + 0x50) = 0;
        *(u8 *)(*(u8 **)(obj + 0x54) + 0x71) = 0;
        return;
    }
    if ((*(s16 *)(obj + 6) & 8) == 0) {
        *(f32 *)(obj + 0x80) = *(f32 *)(obj + 0xc);
        *(f32 *)(obj + 0x84) = *(f32 *)(obj + 0x10);
        *(f32 *)(obj + 0x88) = *(f32 *)(obj + 0x14);
        *(f32 *)(obj + 0x8c) = *(f32 *)(obj + 0x18);
        *(f32 *)(obj + 0x90) = *(f32 *)(obj + 0x1c);
        *(f32 *)(obj + 0x94) = *(f32 *)(obj + 0x20);
    }
    *(f32 *)(obj + 0xfc) = *(f32 *)(obj + 0x24);
    *(f32 *)(obj + 0x100) = *(f32 *)(obj + 0x28);
    *(f32 *)(obj + 0x104) = *(f32 *)(obj + 0x2c);
    if (*(u8 *)(obj + 0xe5) != 0 && *(int *)(obj + 0xc4) == 0 && (*(u8 *)(obj + 0xe5) & 1)) {
        *(s16 *)(obj + 0xe6) = (s16)(int)((f32)*(s16 *)(obj + 0xe6) - timeDelta);
        if (*(s16 *)(obj + 0xe6) <= 0) {
            *(s16 *)(obj + 0xe6) = 0;
            *(u8 *)(obj + 0xe5) &= ~1;
            *(u8 *)(obj + 0xf0) = 0;
            ObjModel_ClearRenderAttachment(*(u8 **)(*(u8 **)(obj + 0x7c) + *(s8 *)(obj + 0xad) * 4));
            cb = (void (*)(u8 *, int, int, int, int))*(int *)(*lbl_803DCAB4 + 0xc);
            cb(obj, 0x7fb, 0, 0x50, 0);
            cb = (void (*)(u8 *, int, int, int, int))*(int *)(*lbl_803DCAB4 + 0xc);
            cb(obj, 0x7fc, 0, 0x32, 0);
            Sfx_PlayFromObject(obj, 0x47b);
        }
    }
    if ((*(u16 *)(obj + 0xb0) & 0x8000) == 0) {
        switch (*(s16 *)(obj + 0x46)) {
        case 0:
        case 0x1f:
            playerUpdate(obj);
            break;
        default:
            if (*(int **)(obj + 0x68) == 0) {
                goto skip;
            }
            cb2 = (void (*)(u8 *))*(int *)(**(int **)(obj + 0x68) + 8);
            if (cb2 != 0) {
                cb2(obj);
            }
            break;
        }
        Obj_GetWorldPosition(obj, obj + 0x18, obj + 0x1c, obj + 0x20);
    }
skip:
    if (*(int *)(obj + 0x54) != 0) {
        if (*(int *)(obj + 0xc8) != 0) {
            t = *(u8 **)(*(u8 **)(obj + 0xc8) + 0x54);
            if (t != 0) {
                *(int *)(t + 0x50) = 0;
                *(u8 *)(*(u8 **)(*(u8 **)(obj + 0xc8) + 0x54) + 0x71) = 0;
            }
        }
        *(int *)(*(u8 **)(obj + 0x54) + 0x50) = 0;
        *(u8 *)(*(u8 **)(obj + 0x54) + 0x71) = 0;
    }
    if (*(int *)(obj + 0x58) != 0) {
        *(u8 *)(*(u8 **)(obj + 0x58) + 0x10f) = 0;
    }
}
#pragma dont_inline reset
#pragma pop

extern void objFn_80065604(void);
extern void Obj_UpdateModelBlendStates(void);
extern void ObjHitReact_ResetActiveObjects(int);
extern int Obj_BuildTransformMatrixSlot(int obj);
extern void playerDoHitDetection(int obj);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_UpdateAllObjects(u8 flags)
{
    int f;
    int off;
    int timeStop;
    u8 *obj2;
    int child;
    int obj;
    int count1;
    int count2;
    u8 *t;
    void (*cb)(int);

    f = flags;
    lbl_803DCB78 = f;
    off = *(s16 *)((u8 *)&lbl_803DCB7C + 2);
    timeStop = f & 1;
    if (timeStop == 0) {
        objFn_80065604();
    }
    Obj_UpdateModelBlendStates();
    ObjHitReact_ResetActiveObjects(lbl_803DCB84);
    obj = *(int *)((u8 *)&lbl_803DCB7C + 4);
    while (obj != 0 && *(s8 *)(obj + 0xae) == 0x64) {
        Obj_UpdateObject((u8 *)obj);
        obj = *(int *)(obj + off);
    }
    while (obj != 0 && (*(u32 *)(*(int *)(obj + 0x50) + 0x44) & 0x40)) {
        Obj_UpdateObject((u8 *)obj);
        *(s8 *)(obj + 0x35) = (s8)Obj_BuildTransformMatrixSlot(obj);
        obj = *(int *)(obj + off);
    }
    if (timeStop == 0) {
        ObjHitReact_UpdateResetObjects();
    }
    for (; obj != 0; obj = *(int *)(obj + off)) {
        t = *(u8 **)(obj + 0x54);
        if (t != 0) {
            if ((*(u8 *)(t + 0x62) & 8) == 0 || (*(s16 *)(t + 0x60) & 1) == 0) {
                Obj_UpdateObject((u8 *)obj);
            }
        } else {
            Obj_UpdateObject((u8 *)obj);
        }
    }
    obj2 = (u8 *)ObjGroup_GetObjects(0, &count1);
    if (count1 != 0) {
        obj2 = *(u8 **)obj2;
    } else {
        obj2 = 0;
    }
    if (obj2 != 0 && *(u8 **)(obj2 + 0xc8) != 0) {
        *(int *)(*(u8 **)(obj2 + 0xc8) + 0x30) = *(int *)(obj2 + 0x30);
        Obj_UpdateObject(*(u8 **)(obj2 + 0xc8));
    }
    if (timeStop == 0) {
        ObjHits_Update(lbl_803DCB84);
        obj = *(int *)((u8 *)&lbl_803DCB7C + 4);
        for (; obj != 0; obj = *(int *)(obj + off)) {
            if ((*(u16 *)(obj + 0xb0) & 0x2000) == 0) {
                switch (*(s16 *)(obj + 0x46)) {
                case 0:
                case 0x1f:
                    playerDoHitDetection(obj);
                    break;
                default:
                    if (*(int **)(obj + 0x68) == 0) {
                        goto next;
                    }
                    cb = (void (*)(int))*(int *)(**(int **)(obj + 0x68) + 0xc);
                    if (cb == 0) {
                        goto next;
                    }
                    cb(obj);
                    break;
                }
                Obj_GetWorldPosition((u8 *)obj, (u8 *)(obj + 0x18), (u8 *)(obj + 0x1c), (u8 *)(obj + 0x20));
            }
        next:;
        }
        obj2 = (u8 *)ObjGroup_GetObjects(0, &count2);
        if (count2 != 0) {
            obj2 = *(u8 **)obj2;
        } else {
            obj2 = 0;
        }
        if (obj2 != 0 && *(u8 **)(obj2 + 0xc8) != 0) {
            *(int *)(*(u8 **)(obj2 + 0xc8) + 0x30) = *(int *)(obj2 + 0x30);
            child = *(int *)(obj2 + 0xc8);
            if ((*(u16 *)(child + 0xb0) & 0x2000) == 0) {
                switch (*(s16 *)(child + 0x46)) {
                case 0:
                case 0x1f:
                    playerDoHitDetection(child);
                    break;
                default:
                    if (*(int **)(child + 0x68) == 0) {
                        goto done;
                    }
                    cb = (void (*)(int))*(int *)(**(int **)(child + 0x68) + 0xc);
                    if (cb == 0) {
                        goto done;
                    }
                    cb(child);
                    break;
                }
                Obj_GetWorldPosition((u8 *)child, (u8 *)(child + 0x18), (u8 *)(child + 0x1c), (u8 *)(child + 0x20));
            }
        }
    done:
        (*(void (**)(u8))(*(int *)gWaterfxInterface + 4))(framesThisStep);
    }
    if ((f & 2) == 0) {
        (*(void (**)(int, int, int))(*(int *)gModgfxInterface + 0xc))(0, 0, 0);
        (*(void (**)(int, u8, int, int))(*(int *)gExpgfxInterface + 0xc))(0, framesThisStep, 0, 0);
    }
    if (timeStop == 0) {
        ObjHits_TickPriorityHitCooldowns();
        (*(void (**)(void))(*(int *)gObjectTriggerInterface + 0x28))();
        (*(void (**)(void))(*(int *)gObjectTriggerInterface + 0x18))();
        (*(void (**)(u8))(*(int *)gCameraInterface + 8))(framesThisStep);
    }
}
#pragma dont_inline reset
#pragma pop

extern int getCurMapType(void);
extern void Obj_ResetObjectSystem(void);
extern u8 lbl_802CABF8[];
extern s16 lbl_803DB44C[2];
extern f32 lbl_803DE8BC;
extern f32 lbl_803DE8C0;
extern f32 lbl_803DE8C4;
extern f32 lbl_803DE8C8;
extern f32 fn_80293E80(f32);
extern f32 sin(f32);
extern int getCurUiDll(void);
extern u8 *Camera_GetCurrentViewSlot(void);
extern int lbl_803DCB70;
extern void playerUpdateFn_8005649c(void);

typedef struct CharSpawn {
    s16 id;
    u8 unk2;
    u8 unk3;
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 x;
    f32 y;
    f32 z;
    int unk14;
} CharSpawn;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void mapSetupPlayer(void)
{
    u8 *base;
    int playerNo;
    int mapType;
    u8 *obj;
    f32 *pos;
    f32 x, y, z;
    int uiDll;
    u8 *view;
    u8 *vp;
    CharSpawn spawn;

    base = (u8 *)&lbl_802CABF8;
    mapType = getCurMapType();
    if (mapType == 2 || mapType == 3) {
        OSReport((char *)(base + 0x70));
        Obj_ResetObjectSystem();
    } else {
        playerNo = (*(u8 (**)(void))(*gMapEventInterface + 0x74))();
        pos = (*(f32 *(**)(void))(*gMapEventInterface + 0x90))();
        x = pos[0];
        y = pos[1];
        z = pos[2];
        obj = 0;
        if (playerNo > -1 && mapType != 4) {
            OSReport((char *)(base + 0x88), mapType, playerNo);
            memset(&spawn, 0, 0x18);
            spawn.unk14 = -1;
            spawn.unk3 = 0;
            spawn.unk4 = 1;
            spawn.unk5 = 4;
            spawn.unk6 = 0xff;
            spawn.unk7 = 0xff;
            spawn.id = lbl_803DB44C[playerNo];
            spawn.unk2 = 0x18;
            spawn.x = x;
            spawn.y = y;
            spawn.z = z;
            if (getLoadedFileFlags(0) & 0x100000) {
                OSReport((char *)(base + 0x20), -1);
                obj = 0;
            } else {
                obj = loadCharacter((s16 *)&spawn, 1, -1, -1, 0, 0);
                if (obj != 0) {
                    Obj_RegisterObject(obj, 1);
                    OSReport((char *)(base + 0x5c), *(int *)(obj + 0x50) + 0x91);
                }
            }
        }
        *(f32 *)(base + 8) = lbl_803DE8BC * fn_80293E80((lbl_803DE8C0 * (f32)(*(s8 *)((u8 *)pos + 0xc) << 8)) / lbl_803DE8C4) + x;
        *(f32 *)(base + 0xc) = lbl_803DE8C8 + y;
        *(f32 *)(base + 0x10) = lbl_803DE8BC * sin((lbl_803DE8C0 * (f32)(*(s8 *)((u8 *)pos + 0xc) << 8)) / lbl_803DE8C4) + z;
        uiDll = getCurUiDll();
        if ((u32)(uiDll - 2) <= 4 || uiDll == 7) {
            (*(void (**)(u8 *, f32, f32, f32))(*(int *)gCameraInterface + 4))(obj, *(f32 *)(base + 8), *(f32 *)(base + 0xc), *(f32 *)(base + 0x10));
            (*(void (**)(int, int, int, int, int, int, int))(*(int *)gCameraInterface + 0x1c))(0x57, 0, 3, 0, 0, 0, 0);
            (*(void (**)(u8 *, int))(*(int *)gCameraInterface + 0x28))(obj, 0);
            (*(void (**)(int))(*(int *)gCameraInterface + 8))(1);
        } else {
            (*(void (**)(u8 *, f32, f32, f32))(*(int *)gCameraInterface + 4))(obj, *(f32 *)(base + 8), *(f32 *)(base + 0xc), *(f32 *)(base + 0x10));
            (*(void (**)(int, int, int, int, u8 *, int, int))(*(int *)gCameraInterface + 0x1c))(0x42, 0, 0, 0x20, base, 0, 0xff);
            (*(void (**)(int))(*(int *)gCameraInterface + 8))(1);
        }
        vp = Camera_GetCurrentViewSlot();
        view = (*(u8 *(**)(void))(*(int *)gCameraInterface + 0xc))();
        *(f32 *)(vp + 0xc) = *(f32 *)(view + 0x18);
        *(f32 *)(vp + 0x10) = *(f32 *)(view + 0x1c);
        *(f32 *)(vp + 0x14) = *(f32 *)(view + 0x20);
        (*(void (**)(u8 *))(*(int *)gTitleMenuControlInterface + 0x10))(obj);
        lbl_803DCB70 = 0;
        playerUpdateFn_8005649c();
    }
}
#pragma dont_inline reset
#pragma pop

extern u16 OSGetFontEncode(void);
extern void OSLoadFont(void *buf, void *tmp);
extern void OSGetFontWidth(u8 *s, int *width);
extern void OSGetFontTexel(u8 *s, void *img, int pos, int stride, int *width);
extern u8 lbl_803DC968;
extern u16 lbl_802C8D40[];
extern int lbl_803DB3C4;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void gameTextLoadGraphicsFn_8001a918(void)
{
    u8 *fontData;
    u8 *base30;
    u8 *base31;
    u8 *buf;
    int sizeA;
    int sizeB;
    u8 *bufA;
    u8 *bufB;
    int savedHeap;
    int count;
    u8 *glyph;
    int x;
    int y;
    int wbytes;
    u8 s[3];
    int width;

    fontData = (u8 *)lbl_802C8F40;
    base30 = (u8 *)lbl_802C8680;
    base31 = (u8 *)lbl_8033AF40;
    savedHeap = testAndSet_onlyUseHeap3(0);
    buf = mmAlloc(0x120, 0x1a, 0);
    switch (OSGetFontEncode()) {
    case 0:
        sizeA = 0x3000;
        sizeB = 0x10120;
        curLanguage = 0;
        lbl_803DC968 = 0;
        break;
    case 1:
        sizeA = 0x4d000;
        sizeB = 0x90ee4;
        curLanguage = 4;
        lbl_803DC968 = 1;
        break;
    }
    bufA = mmAlloc(sizeA, 0x1a, 0);
    bufB = mmAlloc(sizeB, 0x1a, 0);
    OSLoadFont(bufB, bufA);
    if (*(int *)(base31 + 0x58) == 0) {
        if (lbl_803DC968) {
            *(u8 **)(base31 + 0x50) = fontData;
            *(int *)(base31 + 0x58) = 0x55;
            *(u8 **)(base31 + 0x54) = fontData + 0x8ec;
            *(int *)(base31 + 0x5c) = 7;
        } else {
            *(u8 **)(base31 + 0x50) = fontData + 0x940;
            *(int *)(base31 + 0x58) = 0x2b;
            *(u8 **)(base31 + 0x54) = fontData + 0xe24;
            *(int *)(base31 + 0x5c) = 7;
        }
    }
    *(u8 **)(base31 + 0x60) = textureAlloc(0x200, 0x60, 0, 0, 0, 0, 0, 1, 1);
    *(u16 *)(base30 + 0x60) = *(int *)(base31 + 0x58);
    *(u8 *)(base30 + 0x64) = 0x30;
    *(u8 *)(base30 + 0x65) = 0x20;
    *(u16 *)(base30 + 0x68) = 0;
    *(u16 *)(base30 + 0x6a) = 0x18;
    count = *(int *)(base31 + 0x58);
    glyph = *(u8 **)(base31 + 0x50);
    x = 0;
    y = 0;
    while (count--) {
        if (lbl_803DC968) {
            int c = *(int *)glyph;
            u16 *p = lbl_802C8D40;
            int i;
            u32 val;
            int hi;
            u8 lo;
            for (i = 0xfd; i > 0; i -= 2) {
                if (p[0] == c) {
                    val = p[1];
                    goto found;
                }
                p++;
                if (p[0] == c) {
                    val = p[1];
                    goto found;
                }
                p++;
            }
            val = 0;
        found:
            hi = (val >> 8) & 0xff;
            lo = val;
            if (hi == 0) {
                s[0] = lo;
                s[1] = 0;
            } else {
                s[0] = hi;
                s[1] = lo;
                s[2] = 0;
            }
        } else {
            s[0] = *(int *)glyph;
            s[1] = 0;
        }
        OSGetFontWidth(s, &width);
        if (width > *(u16 *)(base30 + 0x68)) {
            *(u16 *)(base30 + 0x68) = width;
        }
        wbytes = width >> 3;
        if ((width & 7) != 0) {
            wbytes++;
        }
        {
            u32 *q = (u32 *)buf;
            int j = 0x47;
            do {
                q[0] = 0;
                q[1] = 0;
                q[2] = 0;
                q[3] = 0;
                q[4] = 0;
                q[5] = 0;
                q[6] = 0;
                q[7] = 0;
                q[8] = 0;
                q += 9;
                j -= 9;
            } while (j > 0);
        }
        OSGetFontTexel(s, buf, 0, 6, &width);
        if (x + 0x18 > 0x200) {
            x = 0;
            y += 0x18;
        }
        *(u16 *)(glyph + 4) = x;
        *(u16 *)(glyph + 6) = y;
        *(u8 *)(glyph + 8) = 0;
        *(u8 *)(glyph + 9) = 0;
        *(u8 *)(glyph + 0xa) = 0;
        *(u8 *)(glyph + 0xb) = 0;
        *(u8 *)(glyph + 0xc) = width;
        *(u8 *)(glyph + 0xd) = 0x18;
        *(u8 *)(glyph + 0xe) = 6;
        *(u8 *)(glyph + 0xf) = 0;
        {
            u32 *src = (u32 *)buf;
            int tx = *(u16 *)(glyph + 4) >> 3;
            int ty = *(u16 *)(glyph + 6) >> 3;
            int txEnd = tx + 3;
            int tyEnd = ty + 3;
            int cnt = txEnd - tx;
            int row;
            for (row = ty; row < tyEnd; row++) {
                int off = tx << 5;
                int j2 = tx;
                int n;
                if (j2 < txEnd) {
                    n = cnt;
                    do {
                        u8 *dst = *(u8 **)(base31 + 0x60) + off;
                        u32 tmp;
                        dst += row * lbl_803DB3C4;
                        *(u32 *)(dst + 0x60) = src[0];
                        *(u32 *)(dst + 0x64) = src[1];
                        *(u32 *)(dst + 0x68) = src[2];
                        *(u32 *)(dst + 0x6c) = src[3];
                        *(u32 *)(dst + 0x70) = src[4];
                        *(u32 *)(dst + 0x74) = src[5];
                        *(u32 *)(dst + 0x78) = src[6];
                        tmp = src[7];
                        src += 8;
                        *(u32 *)(dst + 0x7c) = tmp;
                        off += 0x20;
                        j2++;
                    } while (--n != 0);
                }
            }
        }
        x += wbytes << 3;
        glyph += 0x10;
    }
    DCFlushRange(*(u8 **)(base31 + 0x60) + 0x60, 0x20000);
    mm_free(bufA);
    mm_free(bufB);
    mm_free(buf);
    testAndSet_onlyUseHeap3(savedHeap);
    *(int *)(base31 + 0x6c) = 2;
}
#pragma dont_inline reset
#pragma pop

extern void fn_80013B6C(int *p, int n);
extern void AudioStream_StopAll(void);
extern int lbl_803DB448;
extern int lbl_803DCB8C;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_ResetObjectSystem(void)
{
    int off;
    int i;
    int zero;

    i = 0;
    off = i;
    zero = i;
    for (; i < lbl_803DCB94; i++) {
        if (*(void **)((int)lbl_803DCB98 + off) != 0) {
            objFreeObjDef(*(void **)((int)lbl_803DCB98 + off), 0);
            *(int *)((int)lbl_803DCB98 + off) = zero;
        }
        off += 4;
    }
    lbl_803DCB94 = 0;
    lbl_803DB448 = 0;
    i = lbl_803DCB84 - 1;
    off = i << 2;
    for (; i >= 0; i--) {
        Obj_FreeObject(*(void **)((int)lbl_803DCB88 + off));
        off -= 4;
    }
    i = 0;
    off = i;
    zero = i;
    for (; i < lbl_803DCB94; i++) {
        if (*(void **)((int)lbl_803DCB98 + off) != 0) {
            objFreeObjDef(*(void **)((int)lbl_803DCB98 + off), 0);
            *(int *)((int)lbl_803DCB98 + off) = zero;
        }
        off += 4;
    }
    lbl_803DB448 = 2;
    lbl_803DCB94 = 0;
    lbl_803DCB8C = 0;
    lbl_803DCB84 = 0;
    fn_80013B6C(&lbl_803DCB7C, 0x38);
    lbl_803DCB94 = 0;
    lbl_803DCB8C = 0;
    lbl_803DCB70 = 0;
    lbl_803DCB84 = 0;
    fn_80013B6C(&lbl_803DCB7C, 0x38);
    lbl_803DCBC4 = 0;
    ObjGroup_ClearAll();
    ObjHits_ResetWorkBuffers();
    (*(void (**)(int, int))(*(int *)gCameraInterface + 0x28))(0, 0);
    AudioStream_StopAll();
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_UpdateModelBlendStates(void)
{
    int joff;
    u8 *obj;
    int j;
    int i;
    int k;
    int ioff;
    u8 *walker;
    int koff;
    u8 *child;
    u8 *m;
    u8 *c0;
    u8 *bp;

    i = 0;
    ioff = 0;
    for (; i < lbl_803DCB84; i++) {
        obj = *(u8 **)((int)lbl_803DCB88 + ioff);
        if (obj != 0 && *(void **)(obj + 0x50) != 0) {
            m = *(u8 **)(obj + 0x64);
            if (m != 0) {
                *(int *)(m + 0xc) = 0;
            }
            j = 0;
            joff = 0;
            for (; j < *(s8 *)(*(u8 **)(obj + 0x50) + 0x55); j++) {
                m = *(u8 **)(*(u8 **)(obj + 0x7c) + joff);
                if (m != 0) {
                    *(u16 *)(m + 0x18) &= ~8;
                    if (*(u8 *)(*(u8 **)m + 0xf9) != 0) {
                        ObjModel_AdvanceBlendChannels(m, timeDelta);
                    }
                }
                joff += 4;
            }
            j = 0;
            walker = obj;
            for (; j < *(u8 *)(obj + 0xeb); j++) {
                child = *(u8 **)(walker + 0xc8);
                if (child != 0 && *(void **)(child + 0x50) != 0) {
                    k = 0;
                    koff = k;
                    for (; k < *(s8 *)(*(u8 **)(child + 0x50) + 0x55); k++) {
                        m = *(u8 **)(*(u8 **)(child + 0x7c) + koff);
                        if (m != 0) {
                            *(u16 *)(m + 0x18) &= ~8;
                            if (*(u8 *)(*(u8 **)m + 0xf9) != 0) {
                                c0 = *(u8 **)(child + 0xc0);
                                if (c0 != 0) {
                                    bp = *(u8 **)(c0 + 0xb8);
                                } else {
                                    bp = 0;
                                }
                                if (c0 == 0 || (bp != 0 && *(s8 *)(bp + 0x56) == 0)) {
                                    ObjModel_AdvanceBlendChannels(m, timeDelta);
                                }
                            }
                        }
                        koff += 4;
                    }
                }
                walker += 4;
            }
        }
        ioff += 4;
    }
}
#pragma dont_inline reset
#pragma pop

extern void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, void *ox, void *oy, void *oz);
extern void mapLoadForObject(int id, void *obj);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_RegisterObject(u8 *obj, int flags)
{
    int id;
    int prev;
    int cur;
    int off;

    if (*(void **)(obj + 0x30) != 0) {
        Obj_TransformLocalPointToWorld(*(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14), obj + 0x18, obj + 0x1c, obj + 0x20);
    } else {
        *(f32 *)(obj + 0x18) = *(f32 *)(obj + 0xc);
        *(f32 *)(obj + 0x1c) = *(f32 *)(obj + 0x10);
        *(f32 *)(obj + 0x20) = *(f32 *)(obj + 0x14);
    }
    *(f32 *)(obj + 0x8c) = *(f32 *)(obj + 0x18);
    *(f32 *)(obj + 0x90) = *(f32 *)(obj + 0x1c);
    *(f32 *)(obj + 0x94) = *(f32 *)(obj + 0x20);
    *(f32 *)(obj + 0x80) = *(f32 *)(obj + 0xc);
    *(f32 *)(obj + 0x84) = *(f32 *)(obj + 0x10);
    *(f32 *)(obj + 0x88) = *(f32 *)(obj + 0x14);
    Obj_RunInitCallback(obj, *(int *)(obj + 0x4c), 0);
    if (*(u8 **)(obj + 0x54) != 0) {
        *(f32 *)(*(u8 **)(obj + 0x54) + 0x10) = *(f32 *)(obj + 0xc);
        *(f32 *)(*(u8 **)(obj + 0x54) + 0x14) = *(f32 *)(obj + 0x10);
        *(f32 *)(*(u8 **)(obj + 0x54) + 0x18) = *(f32 *)(obj + 0x14);
        *(f32 *)(*(u8 **)(obj + 0x54) + 0x1c) = *(f32 *)(obj + 0xc);
        *(f32 *)(*(u8 **)(obj + 0x54) + 0x20) = *(f32 *)(obj + 0x10);
        *(f32 *)(*(u8 **)(obj + 0x54) + 0x24) = *(f32 *)(obj + 0x14);
    }
    id = *(s16 *)(*(u8 **)(obj + 0x50) + 0x78);
    if (id > -1) {
        mapLoadForObject(id, obj);
    }
    if (*(u32 *)(*(u8 **)(obj + 0x50) + 0x44) & 0x40) {
        ObjGroup_AddObject(obj, 6);
        if (*(s8 *)(obj + 0xae) != 0x5a && (*(u32 *)(*(u8 **)(obj + 0x50) + 0x44) & 0x40)) {
            *(u8 *)(obj + 0xae) = 0x5a;
        }
    } else {
        if (*(s8 *)(obj + 0xae) == 0) {
            *(u8 *)(obj + 0xae) = 0x50;
        }
    }
    if (flags & 1) {
        *(u16 *)(obj + 0xb0) |= 0x10;
        ((u8 **)lbl_803DCB88)[lbl_803DCB84++] = obj;
        if (*(u16 *)(obj + 0xb0) & 0x10) {
            prev = 0;
            cur = *(int *)((u8 *)&lbl_803DCB7C + 4);
            off = *(s16 *)((u8 *)&lbl_803DCB7C + 2);
            while (cur != 0 && *(s8 *)(obj + 0xae) < *(s8 *)(cur + 0xae)) {
                prev = cur;
                cur = *(int *)(cur + off);
            }
            objListAdd(&lbl_803DCB7C, prev, (int)obj);
        }
    }
    if (*(s8 *)(*(u8 **)(obj + 0x50) + 0x56) > 0) {
        ObjGroup_AddObject(obj, 8);
    }
    if (*(u32 *)(*(u8 **)(obj + 0x50) + 0x44) & 1) {
        lbl_803DCBC4 = 0;
    }
}
#pragma dont_inline reset
#pragma pop

extern void Sfx_RemoveLoopedObjectSoundForObject(u8 *obj);
extern void Sfx_StopObjectChannel(u8 *obj, int ch);
extern char sObjFreeNonExistentObjectWarning[];
extern void *lbl_803DCB90;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_FreeObject(u8 *obj)
{
    u8 **p;
    int n;
    int i;
    u8 **base;
    int off;
    u8 *q;

    if (*(u16 *)(obj + 0xb0) & 0x40) {
        return;
    }
    Sfx_RemoveLoopedObjectSoundForObject(obj);
    Sfx_StopObjectChannel(obj, 0x7f);
    if (*(u16 *)(obj + 0xb0) & 0x10) {
        i = 0;
        p = (u8 **)lbl_803DCB88;
        for (n = lbl_803DCB84; n > 0; n--) {
            if (*p == obj) {
                break;
            }
            p++;
            i++;
        }
        if (i < lbl_803DCB84) {
            lbl_803DCB84--;
            off = i << 2;
            for (; i < lbl_803DCB84; i++) {
                q = (u8 *)lbl_803DCB88 + off;
                *(int *)q = *(int *)(q + 4);
                off += 4;
            }
        } else {
            OSReport(sObjFreeNonExistentObjectWarning);
        }
        if (*(u16 *)(obj + 0xb0) & 0x10) {
            objList_remove(&lbl_803DCB7C, obj);
        }
        lbl_803DCBC4 = 0;
    }
    for (i = 0; i < lbl_803DCB94; i++) {
    }
    *(u16 *)(obj + 0xb0) |= 0x40;
    if (*(u8 *)(obj + 0xea) != 0) {
        i = 0;
        base = (u8 **)lbl_803DCB90;
        p = base;
        for (n = lbl_803DCB8C; n > 0; n--) {
            if (*p == obj) {
                break;
            }
            p++;
            i++;
        }
        if (i != lbl_803DCB8C) {
            return;
        }
        if (lbl_803DCB8C < 0x18) {
            base[lbl_803DCB8C] = obj;
            lbl_803DCB8C++;
            return;
        }
    }
    if (lbl_803DB448 == 2) {
        i = lbl_803DCB94;
        if (lbl_803DCB94 != 0) {
            i = 0;
            p = (u8 **)lbl_803DCB98;
            for (n = lbl_803DCB94; n > 0; n--) {
                if (*p == obj) {
                    break;
                }
                p++;
                i++;
            }
        }
        if (i == lbl_803DCB94) {
            ((u8 **)lbl_803DCB98)[lbl_803DCB94] = obj;
            lbl_803DCB94++;
            if (lbl_803DCB94 == 400) {
                lbl_803DCB94--;
            }
        }
    } else {
        objFreeObjDef(obj, !lbl_803DB448);
    }
}
#pragma dont_inline reset
#pragma pop

extern void *lbl_803DCBC0;
extern int *lbl_803DCBBC;
extern int lbl_803DCBB8;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_InitObjectSystem(void)
{
    s16 *p;
    int *q;
    int i;

    lbl_803DCB98 = (void **)mmAlloc(0x640, 0xe, 0);
    lbl_803DCB90 = mmAlloc(0x60, 0xe, 0);
    lbl_803DCBC0 = mmAlloc(0x10, 0xe, 0);
    loadAssetFileById((int)&lbl_803DCBA0, 0x3f);
    lbl_803DCB9C = (getDataFileSize(0x3f) >> 1) - 1;
    for (p = lbl_803DCBA0 + lbl_803DCB9C; *p == 0;) {
        p--;
        lbl_803DCB9C--;
    }
    loadAssetFileById((int)&lbl_803DCBBC, 0x3d);
    lbl_803DCBB8 = 0;
    for (q = lbl_803DCBBC; *q != -1;) {
        q++;
        lbl_803DCBB8++;
    }
    lbl_803DCBB8--;
    lbl_803DCBA8 = (u8 *)mmAlloc(lbl_803DCBB8 * 4, 0xe, 0);
    lbl_803DCBA4 = (u8 *)mmAlloc(lbl_803DCBB8, 0xe, 0);
    for (i = 0; i < lbl_803DCBB8; i++) {
        lbl_803DCBA4[i] = 0;
    }
    loadAssetFileById((int)&lbl_803DCBB4, 0x16);
    loadAssetFileById((int)&lbl_803DCBB0, 0x17);
    lbl_803DCBAC = 0;
    for (q = lbl_803DCBB0; *q != -1;) {
        q++;
        lbl_803DCBAC++;
    }
    lbl_803DCB88 = mmAlloc(0x960, 0xe, 0);
    ObjHits_InitWorkBuffers();
    lbl_803DCB94 = 0;
    lbl_803DCB8C = 0;
    lbl_803DCB70 = 0;
    lbl_803DCB84 = 0;
    fn_80013B6C(&lbl_803DCB7C, 0x38);
    lbl_803DCBC4 = 0;
    ObjGroup_ClearAll();
    ObjHits_ResetWorkBuffers();
}
#pragma dont_inline reset
#pragma pop

extern int loadModLines(int n, s16 *out);
extern void intersectModLineBuild(u8 *buf);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
u8 *loadObjectFile(int id)
{
    int size;
    int base;
    u8 *buf;
    int off;
    int n;
    s16 modLine;

    if (id >= lbl_803DCBB8) {
        return 0;
    }
    if (lbl_803DCBA4[id] != 0) {
        lbl_803DCBA4[id]++;
        return *(u8 **)((int)lbl_803DCBA8 + (id << 2));
    }
    off = id << 2;
    base = ((int *)lbl_803DCBBC)[id];
    {
        int *t = (int *)((int)lbl_803DCBBC + off);
        size = t[1] - base;
    }
    buf = (u8 *)mmAlloc(size, 0xe, 0);
    if (buf != 0) {
        fileLoadToBufferOffset(0x3e, buf, base, size);
        if (*(void **)(buf + 0x20) != 0) {
            *(int *)(buf + 0x20) = (int)buf + *(int *)(buf + 0x20);
        }
        if (*(void **)(buf + 0x24) != 0) {
            *(int *)(buf + 0x24) = (int)buf + *(int *)(buf + 0x24);
        }
        if (*(void **)(buf + 0x28) != 0) {
            *(int *)(buf + 0x28) = (int)buf + *(int *)(buf + 0x28);
        }
        *(int *)(buf + 8) = (int)buf + *(int *)(buf + 8);
        *(int *)(buf + 0xc) = (int)buf + *(int *)(buf + 0xc);
        *(int *)(buf + 0x10) = (int)buf + *(int *)(buf + 0x10);
        if (*(void **)(buf + 0x18) != 0) {
            *(int *)(buf + 0x18) = (int)buf + *(int *)(buf + 0x18);
        }
        if (*(void **)(buf + 0x40) != 0) {
            *(int *)(buf + 0x40) = (int)buf + *(int *)(buf + 0x40);
        }
        if (*(void **)(buf + 0x1c) != 0) {
            *(int *)(buf + 0x1c) = (int)buf + *(int *)(buf + 0x1c);
        }
        *(int *)(buf + 0x2c) = (int)buf + *(int *)(buf + 0x2c);
        *(int *)(buf + 0x30) = 0;
        *(int *)(buf + 0x34) = 0;
        n = (s8)buf[0x5d];
        if (n > -1) {
            *(int *)(buf + 0x30) = loadModLines(n, &modLine);
            *(u8 *)(buf + 0x5c) = modLine;
            intersectModLineBuild(buf);
        }
        *(u8 **)((int)lbl_803DCBA8 + off) = buf;
        lbl_803DCBA4[id] = 1;
        return buf;
    }
    return 0;
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int objGetTotalDataSize(void *tmpl, u8 *def, s16 *data, int flags)
{
    int size;
    int extra;
    int (*cb)(void *, int);

    size = *(s8 *)(def + 0x55) * 4 + 0x10c;
    switch (*(s16 *)((u8 *)tmpl + 0x46)) {
    case 0:
    case 0x1f:
        extra = 0x8e0;
        break;
    default:
        if (*(int **)((u8 *)tmpl + 0x68) == 0) {
            goto none;
        }
        cb = (int (*)(void *, int))*(int *)(**(int **)((u8 *)tmpl + 0x68) + 0x1c);
        if (cb == 0) {
            goto none;
        }
        extra = cb(tmpl, size);
        break;
    none:
        extra = 0;
        break;
    }
    size += extra;
    if ((flags & 0x40) || (*(u32 *)(def + 0x44) & 0x400000)) {
        size = roundUpTo8(roundUpTo4(size) + 8) + 0x50;
    }
    if (flags & 0x100) {
        size = roundUpTo8(roundUpTo4(size) + 8) + 0x800;
    }
    if ((flags & 2) && *(s16 *)(def + 0x48) != 0) {
        size = roundUpTo4(size) + 0x44;
    }
    if (*(u8 *)(def + 0x61) != 0) {
        size = roundUpTo4(size) + 0xb8;
        if (*(s8 *)(def + 0x65) & 8) {
            size += 0x110;
        }
    }
    if (*(u8 *)(def + 0x5a) != 0) {
        size = roundUpTo4(size) + *(u8 *)(def + 0x5a) * 0x12;
    }
    if (*(u8 *)(def + 0x59) != 0) {
        size = roundUpTo4(size) + *(u8 *)(def + 0x59) * 0x10;
    }
    if (*(u8 *)(def + 0x72) != 0) {
        size = roundUpTo4(size) + *(u8 *)(def + 0x72) * 0x18;
    }
    if (*(u8 *)(def + 0x61) != 0 && *(u8 *)(def + 0x66) != 0) {
        size = roundUpTo8(size) + 0x12c;
    }
    if (*(u8 *)(def + 0x72) != 0) {
        size = roundUpTo4(size) + *(u8 *)(def + 0x72) * 5;
    }
    return roundUpTo32(size);
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void *stackCreate(int count, int size)
{
    u8 *s;
    int prev;
    void **first;
    void **cur;
    u8 *next;
    int n;

    prev = testAndSet_onlyUseHeaps1and2(2);
    s = mmAlloc(size * count + 0x20, 0x11, 0);
    testAndSet_onlyUseHeaps1and2(prev);
    *(s16 *)(s + 0xc) = size;
    *(s16 *)(s + 0xe) = count;
    *(u16 *)(s + 0x10) = 0;
    *(int *)(s + 4) = *(s16 *)(s + 0xe) * *(s16 *)(s + 0xc) + 0x20 + (int)s;
    first = (void **)(s + 0x20);
    cur = first;
    next = (u8 *)first + size;
    n = count - 2;
    for (; n > 0; n--) {
        *cur = next;
        cur = (void **)*cur;
        next += size;
    }
    *cur = 0;
    *(void **)s = first;
    cur = *(void ***)s;
    while (cur != 0) {
        int ok = 0;
        if (cur >= first && cur < *(void ***)(s + 4)) {
            ok = 1;
        }
        if (ok == 0) {
            break;
        }
        cur = (void **)*cur;
    }
    return s;
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void *mmAlloc(int size, int type, int flag)
{
    void *result;
    u8 ok;
    u8 i;

    if (size == 0) {
        return 0;
    }
    ok = 1;
    for (i = 0; ok && i < 100; i++) {
        if (lbl_803DB434 == 1) {
            result = (void *)mmAllocFromRegion(1, size, type, flag);
            if (result == 0) {
                result = (void *)mmAllocFromRegion(2, size, type, flag);
            }
            if (result == 0) {
                return result;
            }
        } else if (lbl_803DCB08 != 0) {
            result = (void *)mmAllocFromRegion(3, size, type, flag);
            if (result == 0) {
                return result;
            }
        } else if (size >= 0x3000) {
            result = (void *)mmAllocFromRegion(0, size, type, flag);
            if (result == 0) {
                result = (void *)mmAllocFromRegion(1, size, type, flag);
            }
        } else if (size >= 0x400) {
            result = (void *)mmAllocFromRegion(1, size, type, flag);
            if (result == 0) {
                result = (void *)mmAllocFromRegion(2, size, type, flag);
            }
            if (result == 0) {
                result = (void *)mmAllocFromRegion(0, size, type, flag);
            }
        } else {
            result = (void *)mmAllocFromRegion(2, size, type, flag);
            if (result == 0) {
                result = (void *)mmAllocFromRegion(1, size, type, flag);
            }
            if (result == 0) {
                result = (void *)mmAllocFromRegion(0, size, type, flag);
            }
        }
        ok = 0;
    }
    return result;
}
#pragma dont_inline reset
#pragma pop


#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma opt_strength_reduction off
#pragma opt_loop_invariants off
void mtxFn_80022404(int a, int b, f32 *out)
{
    f32 tmp[16];
    int j;
    int i;
    int row;
    int aoff;
    f32 zero;
    int toff;
    int boff;
    int o3, o2, o1;
    f32 a0, a1, a2, a3;

    row = 0;
    aoff = 0;
    zero = lbl_803DE7C0;
    for (i = 0; i < 4; i++) {
        boff = 0;
        toff = row << 2;
        o1 = (row + 1) * 4;
        o2 = (row + 2) * 4;
        o3 = (row + 3) * 4;
        for (j = 0; j < 4; j++) {
            *(f32 *)((int)tmp + toff) = zero;
            a0 = *(f32 *)(a + aoff);
            *(f32 *)((int)tmp + toff) += a0 * *(f32 *)(b + boff);
            a1 = *(f32 *)(a + o1);
            *(f32 *)((int)tmp + toff) += a1 * *(f32 *)(b + (j + 4) * 4);
            a2 = *(f32 *)(a + o2);
            *(f32 *)((int)tmp + toff) += a2 * *(f32 *)(b + (j + 8) * 4);
            a3 = *(f32 *)(a + o3);
            *(f32 *)((int)tmp + toff) += a3 * *(f32 *)(b + (j + 12) * 4);
            toff += 4;
            boff += 4;
        }
        row += 4;
        aoff += 0x10;
    }
    for (i = 0; i < 16; i++) {
        *(f32 *)((int)out + i * 4) = *(f32 *)((int)tmp + i * 4);
    }
}
#pragma opt_loop_invariants reset
#pragma opt_strength_reduction reset
#pragma dont_inline reset
#pragma pop

extern f32 lbl_803DE7E8;
extern f32 lbl_803DE7EC;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void fn_800218AC(s16 *a, f32 *v)
{
    f32 x, y, z;
    f32 s1, s2;
    f32 c;

    x = v[0];
    y = v[1];
    z = v[2];

    c = fn_80293E80((lbl_803DE7E8 * (f32)a[0]) / lbl_803DE7EC);
    s1 = x * c;
    s2 = z * c;
    c = sin((lbl_803DE7E8 * (f32)a[0]) / lbl_803DE7EC);
    x *= c;
    z *= c;
    x += s2;
    z -= s1;

    c = fn_80293E80((lbl_803DE7E8 * (f32)a[1]) / lbl_803DE7EC);
    s1 = y * c;
    s2 = z * c;
    c = sin((lbl_803DE7E8 * (f32)a[1]) / lbl_803DE7EC);
    y *= c;
    z *= c;
    y -= s2;
    z += s1;

    c = fn_80293E80((lbl_803DE7E8 * (f32)a[2]) / lbl_803DE7EC);
    s1 = x * c;
    s2 = y * c;
    c = sin((lbl_803DE7E8 * (f32)a[2]) / lbl_803DE7EC);
    x *= c;
    y *= c;
    x -= s2;
    y += s1;

    v[0] = x;
    v[1] = y;
    v[2] = z;
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int modelLoad_calcSizes(void *model, int flags, int *sizes, int a4)
{
    u8 *hdr = (u8 *)model;
    int total;

    if (*(u16 *)(hdr + 0xec) != 0) {
        sizes[6] = ((u32)*(u8 *)(hdr + 0xf3) + (u32)*(u8 *)(hdr + 0xf4)) * 0x80;
    } else {
        sizes[6] = 0x80;
    }
    if (*(u8 *)(hdr + 0xf9) != 0 || *(void **)(hdr + 0xa4) != 0 || (*(u16 *)(hdr + 2) & 0x10) != 0) {
        sizes[0] = (u32)*(u16 *)(hdr + 0xe4) * 0xc + 0x60;
    } else {
        sizes[0] = 0;
    }
    if (*(void **)(hdr + 0xc8) != 0) {
        int cur = sizes[0];
        int n = *(u16 *)(hdr + 0xe6);
        int k;
        if (*(u8 *)(hdr + 0x24) & 8) {
            k = 9;
        } else {
            k = 3;
        }
        cur = n * k + cur;
        sizes[0] = cur + 0x40;
    }
    {
        int half = *(u8 *)(hdr + 0xf7) << 4;
        sizes[1] = half << 1;
    }
    sizes[3] = 0;
    if ((*(u16 *)(hdr + 2) & 0x40) != 0) {
        sizes[5] = *(s16 *)(hdr + 0x84);
        while ((sizes[5] & 7) != 0) {
            sizes[5] = sizes[5] + 1;
        }
        sizes[3] = sizes[5] << 2;
    }
    sizes[4] = 0x68;
    if ((flags & 0x80) != 0) {
        sizes[4] = sizes[4] << 1;
        sizes[3] = sizes[3] << 1;
    }
    if (*(u8 *)(hdr + 0xf9) != 0 || a4 != 0) {
        sizes[4] = sizes[4] + 0x30;
        total = sizes[6] + sizes[1] + sizes[3] + sizes[4] + 0x6c;
    } else {
        total = sizes[3] + sizes[6] + sizes[1] + sizes[4] + 0x6c;
    }
    total = total + sizes[0];
    if (*(void **)(hdr + 0x3c) != 0 && *(u8 *)(hdr + 0xf3) != 0 && *(void **)(hdr + 0x18) != 0) {
        total = (u32)*(u8 *)(hdr + 0xf3) * 0x1e + 0x1c + total;
    }
    if (*(void **)(hdr + 0xa4) != 0) {
        total = (u32)*(u16 *)(hdr + 0x8a) * 4 + total;
        total = total + 4;
    }
    if (*(void **)(hdr + 0xc8) != 0) {
        total = (u32)*(u16 *)(hdr + 0xae) * 4 + total;
        total = total + 4;
    }
    total = total + (u32)*(u8 *)(hdr + 0xf8) * 0xc;
    if ((flags & 0x8000) != 0) {
        total = total + 0x1a;
    }
    return roundUpTo32(((total + 0x2f) & ~0xf) + 0x10);
}
#pragma dont_inline reset
#pragma pop

extern f32 lbl_803DE850;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline on
void fn_80026928(int *obj, int b, int *p3)
{
    int off4;
    int off54;
    int i;

    i = 0;
    off4 = 0;
    off54 = off4;
    for (; i < p3[2]; i++) {
        int e = *(int *)(*(int *)p3[1] + off4);
        int dst = *p3 + off54;
        int idx;
        u8 *hdr;
        u32 n;
        int lim;

        *(f32 *)(dst + 0x18) = *(f32 *)(*(int *)(b + 0x3c) + e * 0x1c + 4);
        *(f32 *)(dst + 0x1c) = *(f32 *)(*(int *)(b + 0x3c) + e * 0x1c + 8);
        *(f32 *)(dst + 0x20) = *(f32 *)(*(int *)(b + 0x3c) + e * 0x1c + 0xc);

        idx = e;
        hdr = *(u8 **)obj;
        n = *(u8 *)(hdr + 0xf3);
        if (n != 0) {
            lim = n + *(u8 *)(hdr + 0xf4);
        } else {
            lim = 1;
        }
        if (e >= lim) {
            idx = 0;
        }
        *(f32 *)(dst + 0) = *(f32 *)(*(int *)((int)obj + ((*(u16 *)((u8 *)obj + 0x18) & 1) << 2) + 0xc) + idx * 0x40 + 0xc);

        idx = e;
        hdr = *(u8 **)obj;
        n = *(u8 *)(hdr + 0xf3);
        if (n != 0) {
            lim = n + *(u8 *)(hdr + 0xf4);
        } else {
            lim = 1;
        }
        if (e >= lim) {
            idx = 0;
        }
        *(f32 *)(dst + 4) = *(f32 *)(*(int *)((int)obj + ((*(u16 *)((u8 *)obj + 0x18) & 1) << 2) + 0xc) + idx * 0x40 + 0x1c);

        idx = e;
        hdr = *(u8 **)obj;
        n = *(u8 *)(hdr + 0xf3);
        if (n != 0) {
            lim = n + *(u8 *)(hdr + 0xf4);
        } else {
            lim = 1;
        }
        if (e >= lim) {
            idx = 0;
        }
        *(f32 *)(dst + 8) = *(f32 *)(*(int *)((int)obj + ((*(u16 *)((u8 *)obj + 0x18) & 1) << 2) + 0xc) + idx * 0x40 + 0x2c);

        off4 += 4;
        off54 += 0x54;
    }
    {
        int out = *p3 + i * 0x54;
        f32 z = lbl_803DE828;
        int e2;
        u8 *hdr2;
        u32 n2;
        int lim2;

        *(f32 *)(out + 0x18) = z;
        *(f32 *)(out + 0x1c) = z;
        *(f32 *)(out + 0x20) = lbl_803DE850;
        {
            int *arr = (int *)*(int *)p3[1];
            int *top = &arr[p3[2]];
            e2 = top[-1];
        }
        hdr2 = *(u8 **)obj;
        n2 = *(u8 *)(hdr2 + 0xf3);
        if (n2 != 0) {
            lim2 = n2 + *(u8 *)(hdr2 + 0xf4);
        } else {
            lim2 = 1;
        }
        if (e2 >= lim2) {
            e2 = 0;
        }
        PSMTXMultVec((f32 *)(obj[(*(u16 *)((u8 *)obj + 0x18) & 1) + 3] + e2 * 0x40), (f32 *)(out + 0x18), (f32 *)out);
    }
}
#pragma dont_inline reset
#pragma dont_inline reset
#pragma pop

extern void uiDll_runFrameStartAndLoadNext(void);
extern void getButtonsJustPressed(int pad);
extern void updateEnvironment(int a);
extern void timeFn_8006f400(f32 dt);
extern void uiDll_runFrameEndAndLoadNext(void);
extern void trackIntersect(void);
extern void doPendingMapLoads(void);
extern void resetSomeGxFlags(void);
extern void sceneRender(int a, int b, int c, int d, int e, int f);
extern void curUiDllDraw(int a, int b, int c, int d);
extern void Camera_ApplyCurrentViewport(int a);
extern int lbl_803DCAD0;
extern f32 lbl_803DE7B0;
extern f32 lbl_803DE7B8;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void gameUpdate(void)
{
    Obj_GetPlayerObject();
    lbl_803DCA42 = 0;
    mainLoopDoGameText();
    if (lbl_803DCA3A == 0) {
        (*(void (**)(void))(*(int *)gCameraInterface + 0x54))();
    }
    uiDll_runFrameStartAndLoadNext();
    camcontrol_playTargetTypeSfx();
    getButtonsJustPressed(0);
    Obj_UpdateAllObjects(lbl_803DCA3C);
    if (lbl_803DCA3A == 0) {
        void *player;
        int idx;
        u8 *rec;
        int t;

        updateEnvironment(0);
        (*(void (**)(void))(*(int *)gMapEventInterface + 0x70))();
        player = Obj_GetPlayerObject();
        idx = lbl_803DCAD4;
        rec = (u8 *)lbl_8033BFB8 + idx * 16;
        t = lbl_803DCAD0 + framesThisStep;
        lbl_803DCAD0 = t;
        if (player != 0) {
            *(f32 *)(rec + 0) = *(f32 *)((u8 *)player + 0xc);
            *(f32 *)(rec + 4) = *(f32 *)((u8 *)player + 0x10);
            *(f32 *)(rec + 8) = *(f32 *)((u8 *)player + 0x14);
            *(int *)(rec + 0xc) = t;
            lbl_803DCAD4 = idx + 1;
            if (lbl_803DCAD4 >= 0x3c) {
                lbl_803DCAD4 = 0;
            }
        }
    }
    timeFn_8006f400(timeDelta);
    uiDll_runFrameEndAndLoadNext();
    trackIntersect();
    playerUpdateFn_8005649c();
    doPendingMapLoads();
    Obj_ApplyPendingParentLinks();
    (*(void (**)(void))(*(int *)gCheckpointInterface + 0x3c))();
    resetSomeGxFlags();
    if (lbl_803DCA46 == 0) {
        sceneRender(0, 0, 0, 0, 0, 0);
        (*(void (**)(int))(*(int *)gScreensInterface + 0xc))(0);
        if (lbl_803DCA48 == 0) {
            curUiDllDraw(0, 0, 0, 0);
        }
        (*(void (**)(void))(*(int *)gMinimapInterface + 8))();
        if (lbl_803DCA48 == 0) {
            dvdCheckError();
        }
        gameTextRun();
    } else {
        lbl_803DCA46 = lbl_803DCA46 - 1;
        if (lbl_803DCA46 < 0) {
            lbl_803DCA46 = 0;
        }
    }
    if (lbl_803DCA42 != 0) {
        if (lbl_803DCA44 == 0) {
            lbl_803DB420 = lbl_803DB420 + timeDelta;
            if (lbl_803DB420 >= lbl_803DE7B0) {
                Music_Trigger(lbl_803DCAF0, 1);
                lbl_803DCA44 = 1;
            }
        }
        if (lbl_803DB420 >= lbl_803DE7B0) {
            lbl_803DB420 = lbl_803DE7B8;
        }
    } else {
        if (lbl_803DCA44 != 0) {
            lbl_803DB420 = lbl_803DB420 - timeDelta;
            if (lbl_803DB420 <= lbl_803DE7B0) {
                Music_Trigger(0xc9, 0);
                Music_Trigger(0xd0, 0);
                lbl_803DCA44 = 0;
            }
        }
        if (lbl_803DB420 <= lbl_803DE7B0) {
            lbl_803DB420 = lbl_803DE7B4;
        }
    }
    Camera_ApplyCurrentViewport(0);
    {
        s8 t = lbl_803DCA3B - framesThisStep;
        lbl_803DCA3B = t;
        if (t < 0) {
            lbl_803DCA3B = 0;
        }
    }
}
#pragma dont_inline reset
#pragma pop

extern void voxmaps_updateTimers(void);
extern void viewportEffectFn_8000e380(void);
extern void loadDataFiles(void);
extern void audioUpdate(void);
extern void Sfx_UpdateLoopedObjectSounds(void);
extern void debugPrintDraw(int a);
extern void drawRect(f32 a, f32 b, int w, int h);
extern void objRenderFn_8003b8f4(int obj, int b, int c, int d, int e, f32 a);
extern void objRenderFuzz(void);
extern void textFn_8001b46c(int a);
extern void doNothing_endOfFrame(void);
extern f32 lbl_803DE7A8;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void gameLoop(void)
{
    waitNextFrame();
    if (lbl_803DCA3D == 1) {
        padUpdate();
        voxmaps_updateTimers();
        gameUpdate();
        viewportEffectFn_8000e380();
        doNothing_startOfFrame();
        loadDataFiles();
        audioUpdate();
        Sfx_UpdateLoopedObjectSounds();
    }
    debugPrintDraw(0);
    (*(void (**)(int, int, int))(*(int *)gScreenTransitionInterface + 4))(0, 0, 0);
    if (lbl_803DCA3D == 1) {
        if (lbl_803DCA48 != 0) {
            if (lbl_803DCA46 == 0) {
                int *p;
                int i;

                drawRect(lbl_803DE7B0, lbl_803DE7B0, 0x280, 0x1e0);
                i = 0;
                p = (int *)&lbl_803DCAE8;
                for (; i < lbl_803DCA48; i++) {
                    objRenderFn_8003b8f4(*p, 0, 0, 0, 0, lbl_803DE7A8);
                    if (*(s16 *)(*p + 0x46) == 0x882 || *(s16 *)(*p + 0x46) == 0x887) {
                        objRenderFuzz();
                    }
                    p++;
                }
                curUiDllDraw(0, 0, 0, 0);
            }
            dvdCheckError();
            gameTextRun();
        }
        textFn_8001b46c(0);
        doNothing_endOfFrame();
        gameTextSetDrawFunc(0);
    }
    GXFlush_(1, 1);
    Obj_FlushDeferredFreeList();
    mmFreeTick(1);
    doQueuedLoads();
}
#pragma dont_inline reset
#pragma pop

extern u8 lbl_803DCAC4;
extern int lbl_803DB41C;
extern void setColor_803db5d0(int r, int g, int b);
extern void unloadMap(void);
extern void mapUnload(int a, int b);
extern void fn_801375A0(void);
extern void setForceLoadImmediately(void);
extern void loadMapAndParent(int map);
extern void mapLoadDataFiles(int map);
extern void clearForceLoadImmediately(void);
extern void beginLoadingMap(void);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void doQueuedLoads(void)
{
    if ((s8)lbl_803DCA39 != 0) {
        int old;

        waitNextFrame();
        GXFlush_(1, 0);
        waitNextFrame();
        GXFlush_(1, 0);
        waitNextFrame();
        GXFlush_(1, 0);
        mmSetFreeDelay(0);
        if (lbl_803DCAC4 != 0) {
            setColor_803db5d0(0, 0, 0);
            unloadMap();
            if (lbl_803DCA40 != 0) {
                mapUnload(0, 0x80000000);
                lbl_803DCA40 = 0;
            }
        }
        old = mmSetFreeDelay(0);
        lbl_803DCA39 = 0;
        Camera_InitState();
        fn_801375A0();
        if (lbl_803DB41C > -1) {
            loadUiDll(lbl_803DB41C);
            lbl_803DB41C = -1;
        }
        mmFreeTick(1);
        mmFreeTick(1);
        if (lbl_803DCA41 != 0 && lbl_803DCAF8 != -1) {
            setForceLoadImmediately();
            loadMapAndParent(lbl_803DCAF8);
            if (lbl_803DCAF4 != -1) {
                mapLoadDataFiles(lbl_803DCAF4);
            }
            clearForceLoadImmediately();
            lbl_803DCA41 = 0;
        }
        beginLoadingMap();
        if (lbl_803DCA94 != 0) {
            (*(void (**)(int))(*(int *)lbl_803DCA94 + 0xc))(1);
        }
        mmSetFreeDelay(old);
        lbl_803DCAC4 = 1;
    }
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma opt_common_subs off
void *animLoadFromTable(u8 *hdr, int id, int idx, u8 *out)
{
    int size;
    int flags;
    int out2;
    u8 *buf;
    int stride;

    flags = 0;
    fileLoadToBufferOffset(0x52, &flags, id << 2, 4);
    if (flags & 0x10000000) {
        loadAndDecompressDataFile(0x51, 0, flags, 0, (int)&size, id, 1);
        buf = out + 0x80;
        loadAndDecompressDataFile(0x51, buf, flags, size, (int)&out2, id, 0);
        stride = ((*(u8 *)(hdr + 0xf3) - 1) & ~7) + 8;
        fileLoadToBufferOffset(0x32, out, *(int *)(hdr + 0x80) + idx * stride, stride);
    } else {
        flags = *(u32 *)((int)lbl_803DCB4C + id * 4);
        loadAndDecompressDataFile(0x30, 0, flags, 0, (int)&size, id, 1);
        buf = out + 0x80;
        loadAndDecompressDataFile(0x30, buf, flags, size, (int)&out2, id, 0);
        stride = ((*(u8 *)(hdr + 0xf3) - 1) & ~7) + 8;
        fileLoadToBufferOffset(0x32, out, *(int *)(hdr + 0x80) + idx * stride, stride);
    }
    return buf;
}
#pragma opt_common_subs reset
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void *loadAnimation(int hdr, s16 id, int b, u8 *bufout)
{
    int tmp;
    int size;
    u8 *ptr;
    u32 v;
    int i;

    if ((getLoadedFileFlags(0) & 0x100000) != 0 && *(u16 *)(hdr + 4) != 1 && *(u16 *)(hdr + 4) != 3) {
        return 0;
    }
    if (bufout == 0) {
        i = id;
        if (ModelList_getHeader(lbl_803DCB50, i, &ptr) == 0) {
            v = ((u32 *)lbl_803DCB4C)[i];
            loadAndDecompressDataFile(0x30, 0, v, 0, (int)&size, i, 1);
            ptr = mmAlloc(size, 10, 0);
            loadAndDecompressDataFile(0x30, ptr, v, size, (int)&tmp, i, 0);
            *ptr = 1;
            modelInitModelList(lbl_803DCB50, id, &ptr);
        } else {
            *ptr += 1;
        }
        return ptr;
    }
    return animLoadFromTable((u8 *)hdr, id, (s16)b, bufout);
}
#pragma dont_inline reset
#pragma pop

extern int lbl_803DCA08;
extern f32 lbl_803DCA0C;
extern int lbl_803DCA10;
extern int lbl_803DCA18;
extern int lbl_8033B640[];
extern f32 lbl_8033BA40[];
extern f32 lbl_803DE720;

typedef struct {
    u32 code;
    u16 r, g, b, a;
} SubtitleCmd;

typedef struct {
    u8 pad[0xc];
    u8 *buf;
} AnimBufSel;

extern SubtitleCmd *textFn_80018bc4(int str, int *count);
extern void gameTextShowStr(int str, int a, int b, int c);

#pragma push
#pragma scheduling off
#pragma peephole off
void textFn_8001b46c(int a)
{
    int charset;
    SubtitleCmd *cmds;
    int delay;
    int n;

    if (lbl_803DCA04 == 2) {
        if (lbl_803DC9F0 != 0) {
            charset = gameTextFn_80019b14();
            gameTextSetCharset(1, 2);
        }
        if (getHudHiddenFrameCount() == 0) {
            lbl_803DCA10 += framesThisStep;
        }
        lbl_803DCA0C = (f32)lbl_803DCA10 / lbl_803DE720;
        if (lbl_803DCA08 + 1 < lbl_803DCA18 && lbl_803DCA0C >= lbl_8033BA40[lbl_803DCA08 + 1]) {
            cmds = textFn_80018bc4(lbl_8033B640[lbl_803DCA08], &n);
            if (cmds != NULL) {
                SubtitleCmd *p = &cmds[n];
                while (p--, n-- != 0) {
                    if (p->code == 0xf8ff) {
                        SubtitleCmd *e = &cmds[n];
                        lbl_803DC9F7 = e->r;
                        lbl_803DC9F6 = e->g;
                        lbl_803DC9F5 = e->b;
                        lbl_803DC9F4 = e->a;
                        break;
                    }
                }
                delay = mmSetFreeDelay(0);
                mm_free(cmds);
                mmSetFreeDelay(delay);
            }
            lbl_803DCA08++;
            if (lbl_803DCA08 + 1 >= lbl_803DCA18) {
                subtitleFn_8001b700();
                if (lbl_803DC9F0 != 0) {
                    gameTextSetCharset(charset, 2);
                }
                return;
            }
        }
        gameTextSetColor(lbl_803DC9F7, lbl_803DC9F6, lbl_803DC9F5, lbl_803DC9F4);
        gameTextShowStr(lbl_8033B640[lbl_803DCA08], 10, 0, 0);
        if (lbl_803DC9F0 != 0) {
            gameTextSetCharset(charset, 2);
        }
    }
}
#pragma pop

extern int lbl_803DB3F0;
extern int lbl_803DB3F4;
extern int lbl_803DB3F8;
extern int lbl_803DB3FC;
extern int lbl_803DB400;
extern void *lbl_803DCA20;

#pragma push
#pragma scheduling off
void boxDrawFn_8001c5ac(u16 *strPtr, int boxId, u8 *p)
{
    int x;
    int y;
    int alpha;
    int halfW;
    int halfH;
    int midX;
    int midY;

    alpha = *(u8 *)(p + 0x1e);
    x = *(s16 *)(p + 0x14);
    y = *(s16 *)(p + 0x16);
    halfW = ((x + *(u16 *)(p + 0x8)) - *(s16 *)(p + 0x14)) >> 1;
    halfH = ((y + *(u16 *)(p + 0xa)) - *(s16 *)(p + 0x16)) >> 1;
    midX = x + halfW;
    midY = y + halfH;
    setTextColor(0, lbl_803DB3F4 & 0xff, lbl_803DB3F8 & 0xff, lbl_803DB3FC & 0xff, lbl_803DB400 & 0xff);
    textureSetupFn_800799c0();
    textRenderSetupFn_800795e8();
    textRenderSetupFn_80079804();
    ((void (*)(void *, f32, f32, int, int, int, int, int))drawScaledTexture)(lbl_803DCA20, (f32)(x - lbl_803DB3F0), (f32)(y - lbl_803DB3F0), alpha, 0x100, halfW + lbl_803DB3F0, halfH + lbl_803DB3F0, 0);
    ((void (*)(void *, f32, f32, int, int, int, int, int))drawScaledTexture)(lbl_803DCA20, (f32)midX, (f32)(y - lbl_803DB3F0), alpha, 0x100, halfW + lbl_803DB3F0, halfH + lbl_803DB3F0, 1);
    ((void (*)(void *, f32, f32, int, int, int, int, int))drawScaledTexture)(lbl_803DCA20, (f32)(x - lbl_803DB3F0), (f32)midY, alpha, 0x100, halfW + lbl_803DB3F0, halfH + lbl_803DB3F0, 2);
    ((void (*)(void *, f32, f32, int, int, int, int, int))drawScaledTexture)(lbl_803DCA20, (f32)midX, (f32)midY, alpha, 0x100, halfW + lbl_803DB3F0, halfH + lbl_803DB3F0, 3);
}
#pragma pop

extern int saveGameGetStatus(void);
extern void gameTextShow(int id);
extern void gameTextFn_80016810(int id, int a, int b);
extern void buttonDisable(int pad, int mask);
extern void cardSetStatusNeedInit(void);
extern void cardDeleteFn_8007d99c(void);
extern int lbl_803DCACC;
extern u8 lbl_803DB424;

#pragma push
#pragma scheduling off
#pragma peephole off
void cardShowMessage(void)
{
    u32 held;
    int st;
    u8 ok;

    st = saveGameGetStatus();
    ok = 0;
    if (st < 0xc) {
        cutsceneEnterExit(1, 1);
        lbl_803DCA3C = 0xff;
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        if (lbl_803DCACC == 0) {
            switch (st) {
            case 1:
                gameTextShow(0x325);
                break;
            case 2:
                gameTextShow(0x494);
                break;
            case 3:
                gameTextShow(0x496);
                break;
            case 4:
                gameTextShow(0x32c);
                break;
            case 5:
            case 6:
                gameTextShow(0x326);
                ok = 1;
                break;
            case 9:
                gameTextShow(0x32a);
                break;
            case 10:
                gameTextShow(0x497);
                ok = 1;
                break;
            case 0xb:
                gameTextShow(0x4c7);
                break;
            }
        }
        held = getButtonsHeld(0);
        if (ok) {
            gameTextFn_80016810(0x495, 0, 0xc8);
        } else {
            gameTextFn_80016810(0x493, 0, 0xc8);
        }
        if (held & 0x100) {
            buttonDisable(0, 0x100);
            cardSetStatusNeedInit();
            lbl_803DCA3A = 0;
            lbl_803DCA3C = 0;
            Sfx_SetObjectSoundsPaused(0);
            if (st == 0xa) {
                cardDeleteFn_8007d99c();
            }
        } else if (ok && (held & 0x200)) {
            buttonDisable(0, 0x200);
            lbl_803DB424 = 0;
            lbl_803DCA3A = 0;
            lbl_803DCA3C = 0;
            Sfx_SetObjectSoundsPaused(0);
            cardSetStatusNeedInit();
        }
    }
}
#pragma pop

extern void angleToVec2(int angle, f32 *cosOut, f32 *sinOut);

#pragma push
#pragma scheduling off
void setMatrixFromObjectPos(f32 *m, u8 *p)
{
    f32 scale;
    f32 zero;
    f32 s0;
    f32 c0;
    f32 s1;
    f32 c1;
    f32 s2;
    f32 c2;

    angleToVec2((u16)*(s16 *)(p + 0x0), &s0, &c0);
    angleToVec2((u16)*(s16 *)(p + 0x2), &s1, &c1);
    angleToVec2((u16)*(s16 *)(p + 0x4), &s2, &c2);
    scale = *(f32 *)(p + 0x8);
    m[0] = scale * (s2 * (s1 * s0) + c2 * c0);
    m[1] = scale * (s2 * c1);
    m[2] = scale * (s2 * (s1 * c0) - c2 * s0);
    zero = lbl_803DE7C0;
    m[3] = zero;
    m[4] = scale * (c2 * (s1 * s0) - s2 * c0);
    m[5] = scale * (c2 * c1);
    m[6] = scale * (c2 * (s1 * c0) + s2 * s0);
    m[7] = zero;
    m[8] = scale * (c1 * s0);
    m[9] = -s1 * scale;
    m[10] = scale * (c1 * c0);
    m[11] = zero;
    m[12] = *(f32 *)(p + 0xc);
    m[13] = *(f32 *)(p + 0x10);
    m[14] = *(f32 *)(p + 0x14);
    m[15] = lbl_803DE7C4;
}
#pragma pop

extern void PSVECCrossProduct(f32 *a, f32 *b, f32 *out);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void fn_800213D0(f32 *a, f32 *b, s16 *out0, s16 *out1, s16 *out2)
{
    extern f32 __kernel_sin(f32);
    extern f32 __kernel_cos(f32, f32);
    extern f32 lbl_803DE7C8;
    extern f32 lbl_803DE7CC;
    extern f32 lbl_803DE7D4;
    f32 cross[3];
    f32 sinp;
    f32 c0;
    f32 c1;
    f32 c2;
    f32 b0;
    f32 b1;
    f32 a2;
    f32 roll;
    f32 yaw;

    PSVECCrossProduct(b, a, cross);
    c0 = cross[0];
    c1 = cross[1];
    c2 = cross[2];
    b0 = b[0];
    b1 = b[1];
    a2 = a[2];
    sinp = __kernel_sin(-b[2]);
    if (sinp < lbl_803DE7C8) {
        if (sinp > lbl_803DE7CC) {
            roll = __kernel_cos(c2, a2);
            yaw = __kernel_cos(b0, b1);
        } else {
            roll = lbl_803DE7C0 - __kernel_cos(c1, c0);
            yaw = lbl_803DE7C0;
        }
    } else {
        roll = __kernel_cos(c1, c0) - lbl_803DE7C0;
        yaw = lbl_803DE7C0;
    }
    {
        f32 s = lbl_803DE7D0;
        f32 d = lbl_803DE7D4;
        *out0 = s * yaw / d;
        *out1 = s * sinp / d;
        *out2 = s * roll / d;
    }
}
#pragma pop

extern f32 lbl_802CABB8[];

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void modelAnimFn_80026790(u8 *model, int idx, u8 *m, u8 *anim)
{
    extern f32 lbl_803DCB48;
    extern f32 lbl_803DE844;
    extern f32 lbl_803DE848;
    extern f32 lbl_803DE84C;
    extern f32 lbl_803DE850;
    f32 vec[3];
    u8 *hdr;
    int total;
    u8 *base;
    f32 dot;
    f32 scaled;
    f32 amp;
    int off;
    int i;
    int r;

    idx = 0;
    hdr = *(u8 **)model;
    if (hdr[0xf3] != 0) {
        total = hdr[0xf3] + hdr[0xf4];
    } else {
        total = 1;
    }
    if (idx >= total) {
        idx = 0;
    }
    base = ((AnimBufSel *)(model + ((*(u16 *)(model + 0x18) & 1) << 2)))->buf + idx * 0x40;
    vec[0] = *(f32 *)(base + 0x20);
    vec[1] = *(f32 *)(base + 0x24);
    vec[2] = *(f32 *)(base + 0x28);
    dot = PSVECDotProduct(vec, lbl_802CABB8);
    if (dot < lbl_803DE828) {
        dot = lbl_803DE828;
    }
    scaled = lbl_803DCB48 * (lbl_803DE844 - dot);
    r = randomGetRange((int)(lbl_803DE84C * scaled), (int)(lbl_803DE850 * scaled));
    amp = (f32)r * lbl_803DE848;
    i = 0;
    off = 0;
    while (i < *(int *)(anim + 8) + 1) {
        u8 *p = *(u8 **)anim + off;
        *(f32 *)(p + 0xc) = *(f32 *)(p + 0xc) * *(f32 *)(m + 0xc) + lbl_802CABB8[0] * amp;
        *(f32 *)(p + 0x10) = lbl_802CABB8[1] * amp + (*(f32 *)(p + 0x10) * *(f32 *)(m + 0xc) + *(f32 *)(m + 0x10));
        *(f32 *)(p + 0x14) = *(f32 *)(p + 0x14) * *(f32 *)(m + 0xc) + lbl_802CABB8[2] * amp;
        off += 0x54;
        i++;
    }
}
#pragma dont_inline reset
#pragma pop

extern void PSMTXRotAxisRad(f32 *m, f32 *axis, f32 angle);

#pragma push
#pragma scheduling off
void fn_8002A5DC(u8 *obj)
{
    extern f32 lbl_803DCECC;
    extern f32 lbl_803DCED0;
    extern f32 lbl_803DE888;
    extern f32 lbl_803DE894;
    extern f32 lbl_803DE898;
    f32 m2[16];
    f32 rot[12];
    f32 vecA[3];
    f32 vecB[3];
    f32 cross[3];
    f32 len;
    f32 dz;
    f32 dx;
    f32 denom;
    f32 sum;

    denom = lbl_803DE888 * *(f32 *)(obj + 0xa8);
    denom *= *(f32 *)(obj + 8);
    dx = ((*(f32 *)(obj + 0x88) - lbl_803DCECC) - (*(f32 *)(obj + 0x14) - playerMapOffsetZ)) / denom;
    dz = ((*(f32 *)(obj + 0xc) - lbl_803DCED0) - (*(f32 *)(obj + 0x80) - playerMapOffsetX)) / denom;
    sum = dz * dz + dx * dx;
    if (sum > lbl_803DE88C) {
        len = sqrtf(sum);
        vecA[0] = dz / len;
        vecA[1] = lbl_803DE88C;
        vecA[2] = -dx / len;
        vecB[0] = lbl_803DE88C;
        vecB[1] = lbl_803DE890;
        vecB[2] = lbl_803DE88C;
        PSVECCrossProduct(vecA, vecB, cross);
        PSMTXRotAxisRad(rot, cross, lbl_803DE894 * (lbl_803DE898 * -len));
        setMatrixFromObjectTransposed(obj, m2);
        m2[3] = lbl_803DE88C;
        m2[7] = lbl_803DE88C;
        m2[11] = lbl_803DE88C;
        PSMTXConcat(rot, m2, rot);
        vecA[0] = rot[8];
        vecA[1] = rot[9];
        vecA[2] = rot[10];
        vecB[0] = rot[4];
        vecB[1] = rot[5];
        vecB[2] = rot[6];
        fn_800213D0(vecA, vecB, (s16 *)(obj + 4), (s16 *)(obj + 2), (s16 *)obj);
    }
}
#pragma pop

extern s16 lbl_803DB3E8;
extern u16 lbl_802C9F00[];
extern u16 lbl_802CA100[];

#pragma push
#pragma scheduling off
#pragma opt_strength_reduction off
void gameTextInitFn_8001c794(void) {
    s16 *p;
    void **q;
    int i;
    int j;
    int x;
    int xb;
    int y;
    u16 *dst;
    u16 *src;

    i = 1;
    p = &lbl_803DB3E8 + 1;
    q = (void **)&lbl_803DCA28 + 1;
    while (p--, q--, i-- != 0) {
        *q = textureLoadAsset(*p);
    }

    lbl_803DCA24 = textureAlloc(0x10, 0x10, 5, 0, 0, 0, 0, 1, 1);
    dst = (u16 *)((u8 *)lbl_803DCA24 + 0x60);
    y = 0;
    src = lbl_802C9F00;
    for (i = 0; i < 4; i++) {
        x = 0;
        xb = 0;
        for (j = 0; j < 2; j++) {
            dst[0] = *(u16 *)((u8 *)src + y * 32 + xb);
            dst[1] = src[y * 16 + x + 1];
            dst[2] = src[y * 16 + x + 2];
            dst[3] = src[y * 16 + x + 3];
            dst[4] = *(u16 *)((u8 *)src + y * 32 + 32 + xb);
            dst[5] = src[y * 16 + x + 17];
            dst[6] = src[y * 16 + x + 18];
            dst[7] = src[y * 16 + x + 19];
            dst[8] = *(u16 *)((u8 *)src + y * 32 + 64 + xb);
            dst[9] = src[y * 16 + x + 33];
            dst[10] = src[y * 16 + x + 34];
            dst[11] = src[y * 16 + x + 35];
            dst[12] = *(u16 *)((u8 *)src + y * 32 + 96 + xb);
            dst[13] = src[y * 16 + x + 49];
            dst[14] = src[y * 16 + x + 50];
            dst[15] = src[y * 16 + x + 51];
            xb += 8;
            dst[16] = *(u16 *)((u8 *)src + y * 32 + xb);
            dst[17] = src[y * 16 + x + 5];
            dst[18] = src[y * 16 + x + 6];
            dst[19] = src[y * 16 + x + 7];
            dst[20] = *(u16 *)((u8 *)src + y * 32 + 32 + xb);
            dst[21] = src[y * 16 + x + 21];
            dst[22] = src[y * 16 + x + 22];
            dst[23] = src[y * 16 + x + 23];
            dst[24] = *(u16 *)((u8 *)src + y * 32 + 64 + xb);
            dst[25] = src[y * 16 + x + 37];
            dst[26] = src[y * 16 + x + 38];
            dst[27] = src[y * 16 + x + 39];
            dst[28] = *(u16 *)((u8 *)src + y * 32 + 96 + xb);
            dst[29] = src[y * 16 + x + 53];
            dst[30] = src[y * 16 + x + 54];
            dst[31] = src[y * 16 + x + 55];
            dst += 32;
            x += 8;
            xb += 8;
        }
        y += 4;
    }
    DCFlushRange((u8 *)lbl_803DCA24 + 0x60, 0x200);

    lbl_803DCA20 = textureAlloc(0x14, 0x14, 5, 0, 0, 0, 0, 1, 1);
    dst = (u16 *)((u8 *)lbl_803DCA20 + 0x60);
    y = 0;
    src = lbl_802CA100;
    for (i = 0; i < 5; i++) {
        x = 0;
        xb = 0;
        for (j = 0; j < 5; j++) {
            dst[0] = *(u16 *)((u8 *)src + y * 40 + xb);
            dst[1] = src[y * 20 + x + 1];
            dst[2] = src[y * 20 + x + 2];
            dst[3] = src[y * 20 + x + 3];
            dst[4] = *(u16 *)((u8 *)src + y * 40 + 40 + xb);
            dst[5] = src[y * 20 + x + 21];
            dst[6] = src[y * 20 + x + 22];
            dst[7] = src[y * 20 + x + 23];
            dst[8] = *(u16 *)((u8 *)src + y * 40 + 80 + xb);
            dst[9] = src[y * 20 + x + 41];
            dst[10] = src[y * 20 + x + 42];
            dst[11] = src[y * 20 + x + 43];
            dst[12] = *(u16 *)((u8 *)src + y * 40 + 120 + xb);
            dst[13] = src[y * 20 + x + 61];
            dst[14] = src[y * 20 + x + 62];
            dst[15] = src[y * 20 + x + 63];
            dst += 16;
            x += 4;
            xb += 8;
        }
        y += 4;
    }
    DCFlushRange((u8 *)lbl_803DCA20 + 0x60, 800);
}
#pragma pop

typedef struct ObjHitBufs {
    u8 pad00[0x48];
    u8 *bufs[2];
    u8 *cur;
} ObjHitBufs;

#pragma push
#pragma scheduling off
#pragma peephole off
void objUpdateHitSpheres(u8 *a, u8 *b, u8 *c, u8 *d, u8 *e) {
    extern f32 lbl_803DE828;
    extern f32 lbl_803DCED0;
    extern f32 lbl_803DCECC;
    u8 *mtx;
    int srcOff;
    int dstOff;
    u8 *prev;
    int i;
    void *result;
    u8 *state;
    u8 *arr;
    u8 *src;
    f32 vec[3];
    f32 zero;
    u32 sel;
    int idx;
    int count;
    u32 cnt;
    int lim;
    ObjHitBufs *st;

    result = NULL;
    state = *(u8 **)(e + 0x54);
    if (state != NULL) {
        if (*(u8 *)(*(u8 **)(e + 0x50) + 0x66) != 0) {
            count = (int)*(s16 *)(state + 4) >> 2;
            if (count > 0) {
                arr = *(u8 **)(state + 8);
                idx = (int)(*(f32 *)(e + 0x98) * (f32)count);
                if (idx >= count) {
                    idx = count - 1;
                }
                result = *(void **)(arr + idx * 4);
            }
        } else {
            result = *(void **)(state + 0x48);
        }
    }

    if (*(u8 **)(c + 0x54) != NULL) {
        *(u8 *)(*(u8 **)(c + 0x54) + 0xaf) -= 1;
        if (*(s8 *)(*(u8 **)(c + 0x54) + 0xaf) < 0) {
            *(u8 *)(*(u8 **)(c + 0x54) + 0xaf) = 0;
        }
        *(u32 *)(*(u8 **)(c + 0x54) + 0x4c) = *(u32 *)(*(u8 **)(c + 0x54) + 0x48);
        *(void **)(*(u8 **)(c + 0x54) + 0x48) = result;
    }

    st = (ObjHitBufs *)a;
    *(u16 *)(a + 0x18) ^= 4;
    sel = (*(u16 *)(a + 0x18) >> 2) & 1;
    st->cur = st->bufs[sel];
    mtx = d;
    i = 0;
    srcOff = 0;
    dstOff = srcOff;
    prev = st->bufs[sel ^ 1];
    for (; i < *(u8 *)(b + 0xf7); i++) {
        if (d == NULL) {
            idx = *(s16 *)(*(u8 **)(b + 0x58) + srcOff);
            cnt = *(u8 *)(*(u8 **)a + 0xf3);
            if (cnt != 0) {
                lim = cnt + *(u8 *)(*(u8 **)a + 0xf4);
            } else {
                lim = 1;
            }
            if (idx >= lim) {
                idx = 0;
            }
            mtx = (u8 *)((int *)a)[(*(u16 *)(a + 0x18) & 1) + 3] + idx * 0x40;
        }
        if (i == 0 && e != c) {
            zero = lbl_803DE828;
            vec[0] = zero;
            vec[1] = zero;
            vec[2] = zero;
            PSMTXMultVec((f32 *)mtx, vec, vec);
            *(f32 *)(c + 0xc) = vec[0] + playerMapOffsetX;
            *(f32 *)(c + 0x10) = vec[1];
            *(f32 *)(c + 0x14) = vec[2] + playerMapOffsetZ;
            Obj_GetWorldPosition(c, c + 0x18, c + 0x1c, c + 0x20);
        }
        src = *(u8 **)(b + 0x58);
        vec[0] = *(f32 *)(src + (srcOff + 8));
        vec[1] = *(f32 *)(src + (srcOff + 0xc));
        vec[2] = *(f32 *)(src + (srcOff + 0x10));
        *(f32 *)(st->cur + dstOff) = *(f32 *)(src + (srcOff + 4)) * *(f32 *)(e + 8);
        PSMTXMultVec((f32 *)mtx, vec, (f32 *)(st->cur + (dstOff + 4)));
        *(f32 *)(prev + 4) = (lbl_803DCED0 + *(f32 *)(prev + 4)) - playerMapOffsetX;
        *(f32 *)(prev + 0xc) = (lbl_803DCECC + *(f32 *)(prev + 0xc)) - playerMapOffsetZ;
        srcOff += 0x18;
        dstOff += 0x10;
        prev += 0x10;
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void modelInitBones(f32 scale, void *model) {
    extern f32 lbl_803DE88C;
    extern f32 lbl_803DE890;
    extern f32 lbl_803DE8D4;
    extern f32 lbl_803DE8D8;
    f32 *srcP;
    int off;
    int boneOff;
    f32 *sumP;
    u8 *hdr;
    u8 *tbl;
    int i;
    int parent;
    f32 *src;
    u8 *bone;
    f32 zero;
    f32 sc;
    f32 minScale;
    f32 w;
    f32 len;
    f32 vx;
    f32 vy;
    f32 vz;
    f32 v;
    f32 pv;
    f32 sums[152];
    u8 *m = model;

    sc = scale;
    hdr = *(u8 **)m;
    if (!(!*(u16 *)(hdr + 2) & 0x1000)) {
        if (*(u8 *)(hdr + 0xf3) == 0) {
        } else if ((src = *(f32 **)(hdr + 0x18)) != NULL && (tbl = *(u8 **)(m + 0x14)) != NULL) {
        **(f32 **)(tbl + 4) = src[0] * sc;
        if (**(f32 **)(tbl + 4) == lbl_803DE88C) {
            **(f32 **)(tbl + 4) = src[1] * sc;
        }
        **(f32 **)(tbl + 8) = **(f32 **)(tbl + 4) * **(f32 **)(tbl + 4);
        **(f32 **)(tbl + 0xc) = lbl_803DE8D4;
        **(f32 **)(tbl + 0x10) = **(f32 **)(tbl + 4);
        zero = lbl_803DE88C;
        sums[0] = zero;
        i = 1;
        srcP = src + 1;
        off = 4;
        boneOff = 0x1c;
        sumP = &sums[1];
        minScale = lbl_803DE890;
        for (; i < *(u8 *)(*(u8 **)m + 0xf3); srcP++, off += 4, boneOff += 0x1c, sumP++, i++) {
            *(f32 *)(*(u8 **)(tbl + 4) + off) = sc * *srcP;
            *(f32 *)(*(u8 **)(tbl + 8) + off) =
                *(f32 *)(*(u8 **)(tbl + 4) + off) * *(f32 *)(*(u8 **)(tbl + 4) + off);
            bone = *(u8 **)(hdr + 0x3c) + boneOff;
            parent = *(s8 *)bone;
            vx = *(f32 *)(bone + 4);
            vy = *(f32 *)(bone + 8);
            vz = *(f32 *)(bone + 0xc);
            len = sqrtf(vx * vx + vy * vy + vz * vz);
            *(f32 *)(*(u8 **)(tbl + 0xc) + off) = sc * len;
            if (*(f32 *)(*(u8 **)(tbl + 0xc) + off) == zero) {
                *(f32 *)(*(u8 **)(tbl + 0xc) + off) = lbl_803DE8D8;
            }
            w = *(f32 *)(*(u8 **)(hdr + 0x1c) + off);
            if (w >= minScale) {
                *(f32 *)(*(u8 **)(tbl + 0xc) + off) *= w;
            }
            *sumP = sums[parent] + *(f32 *)(*(u8 **)(tbl + 0xc) + off);
            if (*srcP == zero) {
                *(f32 *)(*(u8 **)(tbl + 0x10) + off) = *(f32 *)(*(u8 **)(tbl + 0x10) + parent * 4);
            } else {
                *(f32 *)(*(u8 **)(tbl + 0x10) + off) = *sumP + *(f32 *)(*(u8 **)(tbl + 4) + off);
                v = *(f32 *)(*(u8 **)(tbl + 0x10) + off);
                pv = *(f32 *)(*(u8 **)(tbl + 0x10) + parent * 4);
                *(f32 *)(*(u8 **)(tbl + 0x10) + off) = (v > pv) ? v : pv;
            }
        }
    }
}
}
#pragma pop

extern void PSMTXTrans(f32 *m, f32 x, f32 y, f32 z);
extern void PSMTXReorder(f32 *src, f32 *dst);

static u8 *modelGetBoneMtx(u8 *m, int idx) {
    u32 cnt;
    int lim;

    cnt = *(u8 *)(*(u8 **)m + 0xf3);
    if (cnt != 0) {
        lim = cnt + *(u8 *)(*(u8 **)m + 0xf4);
    } else {
        lim = 1;
    }
    if (idx >= lim) {
        idx = 0;
    }
    return (u8 *)((int *)m)[(*(u16 *)(m + 0x18) & 1) + 3] + idx * 0x40;
}

#pragma push
#pragma scheduling off
#pragma peephole off
void modelInitBoneMtxs(u8 *m, u8 *out) {
    u8 *hdr;
    u32 i;
    u8 *mtx;
    int boneOff;
    u8 *bone;
    f32 tmp[12];

    hdr = *(u8 **)m;
    i = 0;
    boneOff = 0;
    for (; i < *(u8 *)(hdr + 0xf3); i++) {
        mtx = modelGetBoneMtx(m, i);
        bone = *(u8 **)(hdr + 0x3c) + boneOff;
        PSMTXTrans(tmp, -*(f32 *)(bone + 0x10), -*(f32 *)(bone + 0x14), -*(f32 *)(bone + 0x18));
        PSMTXConcat((f32 *)mtx, tmp, tmp);
        PSMTXReorder(tmp, (f32 *)out);
        boneOff += 0x1c;
        out += 0x30;
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void modelInitBoneMtxs2(u8 *m, u8 *out2, u8 *out) {
    u8 *hdr;
    u32 i;
    u8 *mtx;
    int boneOff;
    u8 *bone;
    f32 tmp[12];

    hdr = *(u8 **)m;
    if (*(u8 *)(hdr + 0xf3) == 0) {
        mtx = modelGetBoneMtx(m, 0);
        PSMTXConcat((f32 *)out2, (f32 *)mtx, (f32 *)mtx);
    } else {
        i = 0;
        boneOff = 0;
        for (; i < *(u8 *)(hdr + 0xf3); i++) {
            mtx = modelGetBoneMtx(m, i);
            bone = *(u8 **)(hdr + 0x3c) + boneOff;
            PSMTXTrans(tmp, -*(f32 *)(bone + 0x10), -*(f32 *)(bone + 0x14), -*(f32 *)(bone + 0x18));
            PSMTXConcat((f32 *)mtx, tmp, tmp);
            PSMTXReorder(tmp, (f32 *)out);
            PSMTXConcat((f32 *)out2, (f32 *)mtx, (f32 *)mtx);
            boneOff += 0x1c;
            out += 0x30;
        }
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void modelApplyBoneTransforms(int a, int b, u16 c, void *d, void *e, int f) {
    extern u16 lbl_803DB440;
    extern void modelApplyBoneTransform(void *p, void *out, u16 n, void **pd, void **pe, int f, u16 pos);
    u16 pos;
    u16 chunk;
    u16 words;
    u16 nextChunk;
    u16 nextWords;
    u16 buf;
    u8 *cache;
    u16 t;
    u8 *out;
    u8 *ptr;
    int sync;

    cache = getCache();
    pos = 0;
    if (c > lbl_803DB440) {
        chunk = lbl_803DB440;
    } else {
        chunk = c;
    }
    words = (u32)(chunk * 6 + 0x1f & 0xffe0) >> 5;
    copyToCache(cache, (void *)a, words);
    buf = 0;
    sync = 0;
    while (c != 0) {
        c -= chunk;
        if (c != 0) {
            if (c > lbl_803DB440) {
                nextChunk = lbl_803DB440;
            } else {
                nextChunk = c;
            }
            nextWords = (u32)(nextChunk * 6 + 0x1f & 0xffe0) >> 5;
            copyToCache(cache + (buf ^ 1) * 0x2000, (u8 *)a + (pos + lbl_803DB440) * 6, nextWords);
            sync = 1;
        }
        cacheFn_800229c4(sync);
        t = buf;
        ptr = cache + t * 0x2000;
        out = ptr + 0x1000;
        modelApplyBoneTransform(ptr, out, chunk, &d, &e, f, pos);
        memcpyToCache((u8 *)b + pos * 6, out, words);
        pos += chunk;
        sync = 1;
        buf = t ^ 1;
        chunk = nextChunk;
        words = nextWords;
    }
    cacheFn_800229c4(0);
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma fp_contract off
int RandomTimer_UpdateRangeTrigger(f32 lo, f32 hi, f32 *timer) {
    extern f32 oneOverTimeDelta;
    extern f32 lbl_803DE7F4;
    int trig;
    int range;
    int val;
    u32 rv;
    f32 freq;

    *timer += timeDelta / (freq = lbl_803DE7F4);
    if (*timer > lo) {
        if (*timer > hi) {
            trig = 1;
        } else {
            range = (int)(oneOverTimeDelta * (freq * (hi - lo)));
            if (range == 0) {
                val = 0;
            } else {
                rv = rand();
                val = (int)((f32)rv / lbl_803DE7F8 *
                            ((lbl_803DE7C4 + (f32)range) - lbl_803DE7C0) + lbl_803DE7C0);
            }
            trig = !val;
        }
        if (trig != 0) {
            *timer = lbl_803DE7C0;
        }
        return trig;
    }
    return 0;
}
#pragma pop

extern void fn_80026308(int *a, int b, u8 *p, u8 *q, int d, int i);
extern void fn_80025F38(int *a, int b, u8 *p, u8 *q);

#pragma push
#pragma scheduling off
void playerTailFn_80026b3c(int *a, int b, u8 *p, int d) {
    int i;
    int off;

    if (*(u8 *)(p + 0x1a) != 0) {
        i = 0;
        off = 0;
        for (; i < *(int *)(p + 4); i++) {
            if (*(u8 *)(p + 0x19) == 0) {
                fn_80026928(a, b, (int *)(*(int *)p + off));
            }
            if (getHudHiddenFrameCount() == 0) {
                modelAnimFn_80026790((u8 *)a, b, p, (u8 *)(*(int *)p + off));
                fn_80026308(a, b, p, (u8 *)(*(int *)p + off), d, i);
            } else {
                fn_80025F38(a, b, p, (u8 *)(*(int *)p + off));
            }
            off += 0xc;
        }
        *(u8 *)(p + 0x18) = 1;
        *(u8 *)(p + 0x19) = 1;
    }
}
#pragma pop

#pragma push
#pragma scheduling off
void mathFn_80021ac8(u8 *p, f32 *v) {
    f32 s2;
    f32 c2;
    f32 s1;
    f32 c1;
    f32 s0;
    f32 c0;
    f32 t5;
    f32 t3;
    f32 t2;

    angleToVec2(*(u16 *)(p + 0x0), &s0, &c0);
    angleToVec2(*(u16 *)(p + 0x2), &s1, &c1);
    angleToVec2(*(u16 *)(p + 0x4), &s2, &c2);
    t5 = v[0] * c2 - v[1] * s2;
    t3 = v[1] * c2 + v[0] * s2;
    v[1] = t3 * c1 - v[2] * s1;
    t2 = v[2] * c1 + t3 * s1;
    v[0] = t5 * c0 + t2 * s0;
    v[2] = t2 * c0 - t5 * s0;
}
#pragma pop

extern void stopRumble2(void);

#pragma push
#pragma scheduling off
#pragma peephole off
void cutsceneEnterExit(int entering, int affectSounds) {
    if (entering != 0) {
        stopRumble2();
        if (lbl_803DCA3A == 0 && affectSounds != 0) {
            Sfx_SetObjectSoundsPaused(1);
        }
        if ((s8)(u8)++lbl_803DCA3A > 2) {
            lbl_803DCA3A = 2;
        }
    } else {
        if ((s8)(u8)--lbl_803DCA3A <= 0) {
            lbl_803DCA3C = 0;
            lbl_803DCA3A = 0;
            if (affectSounds != 0) {
                Sfx_SetObjectSoundsPaused(0);
            }
        }
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
int fn_8001860C(u8 *str) {
    int count;
    int off;
    int len;
    u32 ch;

    count = 0;
    off = 0;
    if (str == NULL) {
        return 0;
    }
    while ((ch = utf8GetNextChar(str + off, &len)) != 0) {
        off += len;
        if (ch >= 0xE000 && ch <= 0xF8FF) {
            off += getControlCharLen(ch) * 2;
        } else {
            count++;
        }
    }
    return count;
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
int loadModLines(int idx, s16 *outCount) {
    int result;
    int *hdr;
    int size;
    int start;

    result = 0;
    if (idx > (getDataFileSize(0x38) - 4) >> 2) {
        return 0;
    }
    hdr = mmAlloc(0x10, 0x1a, 0);
    fileLoadToBufferOffset(0x38, hdr, idx << 2, 8);
    start = hdr[0];
    size = hdr[1] - hdr[0];
    if (size > 0) {
        result = (int)mmAlloc(size, 5, 0);
        fileLoadToBufferOffset(0x37, (void *)result, start, size);
    }
    mm_free(hdr);
    *outCount = (u32)size / 20;
    return result;
}
#pragma pop

#pragma push
#pragma scheduling off
void deathRenderFn_8001fd98(u32 h) {
    int *p;
    int n;
    int i;
    int idx;

    idx = -1;
    i = 0;
    p = lbl_803DCAE8;
    n = lbl_803DCA48;
    for (; i < n; i++) {
        if (*p == h) {
            idx = i;
            break;
        }
        p++;
    }
    for (i = idx; i < n - 1; i++) {
        lbl_803DCAE8[i] = lbl_803DCAE8[i + 1];
    }
    lbl_803DCA48--;
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
int fn_80018ED4(u8 *str, u32 target, int *out) {
    int off;
    int len;
    u32 ch;
    int n;
    int i;

    off = 0;
    if (str == NULL) {
        return 0;
    }
    while ((ch = utf8GetNextChar(str + off, &len)) != 0) {
        off += len;
        if (ch >= 0xE000 && ch <= 0xF8FF) {
            n = getControlCharLen(ch);
            if (ch == target) {
                for (i = 0; i < n; i++) {
                    u32 hi = str[off++];
                    u32 lo = str[off++];
                    out[i] = (hi << 8) | lo;
                }
                return 1;
            }
            off += n * 2;
        }
    }
    return 0;
}
#pragma pop

typedef struct {
    int f0, f4, f8, fc, f10;
} MRIState;
extern void modelRenderInstrsState_init(MRIState *state, u8 *data, int bits, int bits2);
extern u8 *modelRenderFn_80006744(u8 *p, int count, MRIState *state, int stride);
extern u8 *fn_80006B1C(MRIState *src, MRIState *dst, int count, int gap);

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_UnpackResourcePayload(u8 *src, int srcSize, u8 *dst, int dstSize) {
    MRIState dstState;
    MRIState srcState;
    u8 *dstBits;
    u8 *srcBits;
    int vertBits;
    u8 *p;
    u8 *end;
    int v;
    int t;

    memcpy(dst, src, *(u16 *)(src + 2));
    srcBits = src + *(u16 *)(dst + 2);
    dstBits = dst + *(u16 *)(dst + 2);
    vertBits = dst[8] << 3;
    modelRenderInstrsState_init(&dstState, dstBits, (dstSize - *(u16 *)(dst + 2)) << 3,
                                (dstSize - *(u16 *)(dst + 2)) << 3);
    modelRenderInstrsState_init(&srcState, srcBits, (srcSize - *(u16 *)(dst + 2)) << 3,
                                (srcSize - *(u16 *)(dst + 2)) << 3);
    memset(dstBits, 0, dstSize - *(u16 *)(dst + 2));
    p = dst + 0xa;
    end = dst + *(u16 *)(dst + 2);
    while (p < end) {
        v = *(s16 *)p;
        p += 2;
        t = v & 0xF;
        if (t != 0) {
            if (t < 0) {
                srcBits = fn_80006B1C(&srcState, &dstState, dst[7], vertBits);
            } else {
                srcBits = modelRenderFn_80006744(srcBits, dst[7], &dstState, vertBits);
            }
        }
    }
    *(u16 *)dst &= ~0x20;
    if (*(u16 *)(dst + 4) != 0) {
        u32 oldOff = *(u16 *)(dst + 4);
        *(u16 *)(dst + 4) = *(u16 *)(dst + 2) + (vertBits >> 3) * (dst[7] + 2);
        *(u16 *)(dst + 4) = (*(u16 *)(dst + 4) + 7) & ~7;
        memcpy(dst + *(u16 *)(dst + 4), src + *(u16 *)(src + 4), srcSize - oldOff);
    }
}
#pragma pop

extern s16 lbl_803DC7A4;
extern s16 lbl_803DC7A6;
extern s16 lbl_803DC7A8;
extern void ObjModel_SampleJointTransform(u8 *model, int a, int b, f32 t, f32 s, f32 *outPos, s16 *outRot);
extern void modelAnimFn_800246a0(u8 *dst, u8 *model, u8 *ch, f32 t, int max, int b, int c, int d, int e, s16 f);

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_UpdateAnimMatrices(u8 *model, u8 *blend, u8 *obj, u8 *dst) {
    u8 *ch;
    u8 *ch2;
    f32 pos[3];
    s16 rot[3];

    ObjModel_BuildAnimBlendTable(obj, *(u8 **)(model + 0x2c), blend);
    *(u16 *)(model + 0x18) ^= 1;
    ch = *(u8 **)(model + 0x2c);
    if ((s8)ch[0x63] & 4) {
        ObjModel_SampleJointTransform(model, 0, 0, *(f32 *)(obj + 0x98), *(f32 *)(obj + 8), pos, rot);
        lbl_803DC7A4 = rot[0];
        lbl_803DC7A6 = rot[1];
        lbl_803DC7A8 = rot[2];
    }
    if (*(u16 *)(*(u8 **)model + 2) & 8) {
        modelWalkAnimFn_800248b8(dst, model, *(u8 **)(model + 0x2c), 0x7f, *(f32 *)(obj + 0x98));
    } else if ((s8)(*(u8 **)(model + 0x2c))[0x63] & 8) {
        ch2 = *(u8 **)(model + 0x30);
        modelAnimFn_800246a0(dst, model, ch, *(f32 *)(obj + 0x98), 0x7f, 0, 0, 2, 0x14,
                             (s16)*(u16 *)(ch + 0x5a));
        modelAnimFn_800246a0(dst, model, ch2, *(f32 *)(obj + 0x9c), 0x7f, 0, 0, 2, 0x18,
                             (s16)*(u16 *)(ch2 + 0x5a));
        modelAnimFn_800246a0(dst, model, ch, *(f32 *)(obj + 0x98), 0x7f, 0, 0, 0, 7,
                             (s16)*(u16 *)(ch2 + 0x58));
        modelAnimFn_800246a0(dst, model, ch, *(f32 *)(obj + 0x98), 0x7f, 0, 1, 1, 1,
                             (s16)*(u16 *)(ch + 0x58));
    } else {
        modelWalkAnimFn_800248b8(dst, model, *(u8 **)(model + 0x2c), 0x7f, *(f32 *)(obj + 0x98));
        ch2 = *(u8 **)(model + 0x30);
        if (ch2 != NULL && *(s16 *)(obj + 0xa2) > -1) {
            ObjModel_BuildAnimBlendTable(obj, *(u8 **)(model + 0x30), blend);
            modelWalkAnimFn_800248b8(dst, model, *(u8 **)(model + 0x30), -1, *(f32 *)(obj + 0x9c));
        }
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
typedef struct {
    u8 _0[0xc];
    int bufs[2];
} MdlSelBufs;
typedef struct {
    u8 _0[0x34];
    int vals[2];
} ChF34;

void modelAnimFn_800246a0(u8 *a, u8 *b, u8 *c, f32 t, int d, int e, int f, int g, int h, s16 w) {
    u8 stk[0x64];
    int px;
    u8 *hdr;
    u32 i2;
    u32 i1;
    int fl;
    u8 *p;

    hdr = *(u8 **)b;
    {
        u32 sel = *(u16 *)(b + 0x18) & 1;
        px = ((MdlSelBufs *)b)->bufs[sel];
    }
    if ((u8)h & 0x10) {
        *(f32 *)(c + 4) = t * *(f32 *)(c + 0x14);
    }
    i1 = (u8)e;
    p = c + i1;
    *(u8 *)(stk + 0x60) = *(u8 *)(p + 0x60);
    p = c + i1 * 4;
    *(f32 *)(stk + 0x14) = *(f32 *)(p + 0x14);
    *(f32 *)(stk + 4) = *(f32 *)(p + 4);
    *(int *)(stk + 0x34) = *(int *)(p + 0x34);
    i2 = (u8)f;
    p = c + i2;
    *(u8 *)(stk + 0x61) = *(u8 *)(p + 0x60);
    p = c + i2 * 4;
    *(f32 *)(stk + 0x18) = *(f32 *)(p + 0x14);
    *(f32 *)(stk + 8) = *(f32 *)(p + 4);
    i2 = (u8)g;
    *(int *)(stk + 0x38) = ((ChF34 *)c)->vals[i2];
    if (*(u16 *)(hdr + 2) & 0x40) {
        *(u16 *)(stk + 0x44) = 0;
        *(u16 *)(stk + 0x46) = 1;
        p = c + i1 * 2;
        p = c + *(u16 *)(p + 0x44) * 4;
        *(int *)(stk + 0x1c) = *(int *)(p + 0x1c);
        if (i2 < 2) {
            p = c + i2 * 2;
            p = c + *(u16 *)(p + 0x44) * 4;
            *(int *)(stk + 0x20) = *(int *)(p + 0x1c);
        } else {
            p = c + i2 * 2;
            p = c + *(u16 *)(p + 0x44) * 4;
            *(int *)(stk + 0x20) = *(int *)(p + 0x24);
        }
    } else {
        p = c + i1 * 2;
        *(u16 *)(stk + 0x44) = *(u16 *)(p + 0x44);
        p = c + i2 * 2;
        *(u16 *)(stk + 0x46) = *(u16 *)(p + 0x44);
    }
    if (w == 0) {
        w = 1;
    }
    *(u16 *)(stk + 0x58) = w;
    modelAnimFn_80024524(hdr, stk, 2);
    fl = h & 0xF;
    if ((fl & 0xC) == 0) {
        int sv = *(s8 *)(c + 0x63);
        if (sv & 1) {
            fl = (u8)(fl | 0x10);
        }
        if (sv & 4) {
            fl = (u8)(fl | 0x20);
        }
    }
    lbl_80006C6C(&px, a, stk, *(int *)(hdr + 0x3c), *(u8 *)(hdr + 0xf3), lbl_80340740, d, (u8)fl);
}
#pragma pop

extern void ObjModel_TransformVerticesWithTranslation(u8 *m1, u8 *m2, u8 *src, int d1, int d2, int count);

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_BlendPrimaryVertexStream(u8 *mtxs, u8 *hdr, u8 *data, int *offs, u8 *out) {
    u16 sizes[2];

    fn_8002A3D4(hdr[6], 7, hdr[6], 7);
    ObjModel_InitScratchBuffers();
    if (*(u16 *)(hdr + 2) != 0) {
        u8 *q;
        int words;
        u32 i;
        u32 nb;
        int bi;
        u8 *dst;
        u8 **cp;

        q = *(u8 **)(hdr + 0xc);
        words = (u32)((q[0x73] << 5) + 0x1f) >> 5;
        copyToCache(lbl_80340898[0], data + *(int *)(q + 0x60), words);
        sizes[0] = words;
        q = *(u8 **)(hdr + 0xc);
        copyToCache(lbl_80340898[1], *(u8 **)(q + 0x64), (u32)((q[0x6f] << 5) + 0x1f) >> 5);
        cp = lbl_80340898;
        for (i = 0; i < (u32)(*(u16 *)(hdr + 2) - 1); i++) {
            q = *(u8 **)(hdr + 0xc) + i * 0x74;
            words = (u32)((q[0xe7] << 5) + 0x1f) >> 5;
            nb = (i + 1) & 1;
            bi = nb * 2;
            copyToCache(cp[(u8)bi], data + *(int *)(q + 0xd4), words);
            sizes[nb] = words;
            {
                u8 *q2 = *(u8 **)(hdr + 0xc) + i * 0x74;
                copyToCache(cp[(u8)((u8)bi + 1)], *(u8 **)(q2 + 0xd8),
                            (u32)((q2[0xe3] << 5) + 0x1f) >> 5);
            }
            cacheFn_800229c4(2);
            dst = out + offs[i];
            ObjModel_TransformVerticesWithTranslation(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                      cp[(u8)((i & 1) * 2) + 1],
                                                      q[0x72] + (int)cp[(u8)((i & 1) * 2)],
                                                      q[0x72] + (int)cp[(u8)((i & 1) * 2)],
                                                      *(u16 *)(q + 0x70));
            memcpyToCache(dst, cp[(u8)((i & 1) * 2)], sizes[i & 1]);
        }
        q = *(u8 **)(hdr + 0xc) + i * 0x74;
        cacheFn_800229c4(0);
        dst = out + offs[i];
        ObjModel_TransformVerticesWithTranslation(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                  lbl_80340898[(u8)((i & 1) * 2) + 1],
                                                  q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                  q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                  *(u16 *)(q + 0x70));
        memcpyToCache(dst, lbl_80340898[(u8)((i & 1) * 2)], sizes[i & 1]);
        cacheFn_800229c4(0);
    }
}
#pragma pop

extern void ObjModel_TransformVerticesLinear(u8 *m1, u8 *m2, u8 *src, int d1, int d2, int count);
extern void ObjModel_TransformQuadVerticesLinear(u8 *m1, u8 *m2, u8 *src, int d1, int d2, int count);

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_BlendSecondaryVertexStream(u8 *mtxs, u8 *hdr, u8 *data, u8 **outs, int quad) {
    u16 sizes[2];

    fn_8002A3D4(hdr[6], 6, hdr[6], 6);
    ObjModel_InitScratchBuffers();
    if (*(u16 *)(hdr + 2) != 0) {
        u8 *q;
        int words;
        u32 i;
        u32 nb;
        int bi;
        u8 *dst;

        q = *(u8 **)(hdr + 0xc);
        words = (u32)((q[0x73] << 5) + 0x1f) >> 5;
        copyToCache(lbl_80340898[0], data + *(int *)(q + 0x60), words);
        sizes[0] = words;
        q = *(u8 **)(hdr + 0xc);
        copyToCache(lbl_80340898[1], *(u8 **)(q + 0x64), (u32)((q[0x6f] << 5) + 0x1f) >> 5);
        for (i = 0; i < (u32)(*(u16 *)(hdr + 2) - 1); i++) {
            q = *(u8 **)(hdr + 0xc) + i * 0x74;
            words = (u32)((q[0xe7] << 5) + 0x1f) >> 5;
            nb = (i + 1) & 1;
            bi = nb * 2;
            copyToCache(lbl_80340898[(u8)bi], data + *(int *)(q + 0xd4), words);
            sizes[nb] = words;
            {
                u8 *q2 = *(u8 **)(hdr + 0xc) + i * 0x74;
                copyToCache(lbl_80340898[(u8)((u8)bi + 1)], *(u8 **)(q2 + 0xd8),
                            (u32)((q2[0xe3] << 5) + 0x1f) >> 5);
            }
            cacheFn_800229c4(2);
            if ((u8)quad) {
                dst = outs[i];
                ObjModel_TransformQuadVerticesLinear(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                     lbl_80340898[(u8)((i & 1) * 2) + 1],
                                                     q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                     q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                     *(u16 *)(q + 0x70));
                memcpyToCache(dst, lbl_80340898[(u8)((i & 1) * 2)], sizes[i & 1]);
            } else {
                dst = outs[i];
                ObjModel_TransformVerticesLinear(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                 lbl_80340898[(u8)((i & 1) * 2) + 1],
                                                 q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                 q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                 *(u16 *)(q + 0x70));
                memcpyToCache(dst, lbl_80340898[(u8)((i & 1) * 2)], sizes[i & 1]);
            }
        }
        q = *(u8 **)(hdr + 0xc) + i * 0x74;
        cacheFn_800229c4(0);
        if ((u8)quad) {
            dst = outs[i];
            ObjModel_TransformQuadVerticesLinear(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                 lbl_80340898[(u8)((i & 1) * 2) + 1],
                                                 q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                 q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                 *(u16 *)(q + 0x70));
            memcpyToCache(dst, lbl_80340898[(u8)((i & 1) * 2)], sizes[i & 1]);
        } else {
            dst = outs[i];
            ObjModel_TransformVerticesLinear(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                             lbl_80340898[(u8)((i & 1) * 2) + 1],
                                             q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                             q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                             *(u16 *)(q + 0x70));
            memcpyToCache(dst, lbl_80340898[(u8)((i & 1) * 2)], sizes[i & 1]);
        }
        cacheFn_800229c4(0);
    }
}
#pragma pop

extern u32 lbl_80339C40[];

#pragma push
#pragma scheduling off
#pragma peephole off
SubtitleCmd *textFn_80018bc4(int str, int *count) {
    int off;
    int n;
    u8 *tbl;
    int len;
    u32 ch;

    off = 0;
    n = 0;
    tbl = (u8 *)lbl_80339C40;
    if ((u8 *)str == NULL) {
        return NULL;
    }
    while ((ch = utf8GetNextChar((u8 *)(str + off), &len)) != 0) {
        off += len;
        if (ch >= 0xE000 && ch <= 0xF8FF) {
            int i;
            int n2;
            u8 *q;

            n++;
            if (n > 0x10) {
                break;
            }
            *(u32 *)tbl = ch;
            q = tbl + 4;
            n2 = getControlCharLen(ch);
            if (n2 > 4) {
                n2 = 4;
            }
            for (i = 0; i < n2; i++) {
                u32 hi = ((u8 *)str)[off++];
                u32 lo = ((u8 *)str)[off++];
                *(u16 *)q = (hi << 8) | lo;
                q += 2;
            }
        }
    }
    if (n == 0) {
        return NULL;
    }
    {
        int size = n * 0xc;
        u8 *buf = mmAlloc(size, 0x1a, 0);
        memcpy(buf, lbl_80339C40, size);
        *count = n;
        return (SubtitleCmd *)buf;
    }
}
#pragma pop
