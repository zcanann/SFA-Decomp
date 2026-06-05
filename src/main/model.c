#include "ghidra_import.h"
#include "main/model_light.h"
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

void FUN_80017438(undefined8 param_1,double param_2,double param_3,undefined4 param_4, undefined4 param_5,int param_6);

void FUN_8001743c(int param_1);

int FUN_80017440(int param_1);

void FUN_80017448(undefined4 param_1,undefined4 param_2,undefined4 *param_3,float *param_4, float *param_5,uint param_6);

void FUN_8001744c(void);

undefined4 FUN_80017450(int param_1,uint param_2,uint *param_3);

int FUN_80017458(int param_1);

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

ushort * FUN_80017470(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, uint param_9);

void FUN_80017478(uint param_1);

void FUN_8001747c(ushort param_1,ushort param_2,uint param_3);

void FUN_80017480(int param_1,undefined4 param_2,undefined4 param_3);

void FUN_80017484(byte param_1,byte param_2,byte param_3,byte param_4);

void FUN_80017488(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, int param_9);

undefined4 FUN_8001748c(void);

void FUN_80017494(int param_1,uint param_2);

undefined4 FUN_80017498(void);

undefined4 FUN_800174a0(void);

double FUN_800174a8(void);

undefined4 FUN_800174b0(int param_1);

void FUN_800174b8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void FUN_800174bc(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12, undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

void FUN_800174c0(void);

void FUN_800174c4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void FUN_800174c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void FUN_800174cc(void);

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
int getControlCharLen(u32 c);
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
void textRenderStr(u8 *str, u8 *win, int mode, f32 x, f32 y, f32 lineH);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void gameTextMeasureString(u8 *str, f32 *outW, f32 *outZero, f32 scale, f32 *outMaxAdv, f32 *outMaxH, int glyphLang);
#pragma pop

extern u8 sGameTextGlyphOrder[];

#pragma push
#pragma scheduling off
#pragma peephole off
void translateToDinoLanguage(u8 *str);
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
void *gameTextGetPhrase(int textId, int phraseIndex);

#pragma dont_inline on
void *gameTextGetStr(int textId);
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
void *gameTextGet(int textId);
#pragma pop

void FUN_800174d4(undefined4 param_1);

undefined4 FUN_800174d8(undefined4 param_1);

void FUN_800174e0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void FUN_800174e4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void FUN_800174e8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void FUN_800174ec(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void FUN_800174f0(undefined4 param_1);

void FUN_800174f4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, uint param_9);

undefined4 FUN_800174f8(void);

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

void FUN_80017508(void);

void FUN_8001750c(int param_1);

void FUN_80017510(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12, undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

void FUN_80017514(undefined4 param_1,undefined4 param_2,int param_3);

void FUN_80017518(undefined4 param_1,undefined4 param_2,int param_3);

void FUN_8001751c(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12, undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

void FUN_80017520(uint *param_1);

void FUN_80017524(undefined4 param_1,undefined4 param_2,undefined param_3,undefined param_4, uint param_5);

undefined4 FUN_80017528(int param_1,int param_2);

double FUN_80017530(int param_1,int param_2);

void FUN_80017538(int param_1);

void FUN_8001753c(int param_1,int param_2,short param_3);

void FUN_80017540(int param_1);

void FUN_80017544(double param_1,int param_2);

void FUN_80017548(int param_1,undefined param_2,undefined param_3,undefined param_4, undefined param_5);

void FUN_8001754c(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12, undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

void FUN_80017550(int param_1,undefined4 *param_2,undefined4 *param_3);

void FUN_80017554(int param_1,undefined4 param_2,undefined4 param_3);

int FUN_80017558(int param_1);

void FUN_80017560(double param_1,int param_2);

void FUN_80017564(double param_1,int param_2);

void FUN_80017568(double param_1,double param_2,int param_3);

void FUN_8001756c(double param_1,double param_2,double param_3,double param_4,double param_5, double param_6,int param_7);

undefined4 FUN_80017570(int param_1);

void FUN_80017578(int param_1,undefined4 param_2);

void FUN_8001757c(double param_1,double param_2,int param_3);

void FUN_80017580(int param_1,undefined param_2,undefined param_3,undefined param_4, undefined param_5);

void FUN_80017584(int param_1,undefined *param_2,undefined *param_3,undefined *param_4, undefined *param_5);

void FUN_80017588(int param_1,undefined param_2,undefined param_3,undefined param_4, undefined param_5);

void FUN_8001758c(double param_1,double param_2,double param_3,int param_4);

void FUN_80017590(double param_1,int param_2,int param_3);

void FUN_80017594(int param_1,undefined param_2,undefined param_3,undefined param_4, undefined param_5);

void FUN_80017598(int param_1,undefined *param_2,undefined *param_3,undefined *param_4, undefined *param_5);

void FUN_8001759c(int param_1,undefined param_2,undefined param_3,undefined param_4, undefined param_5);

void FUN_800175a0(int param_1,undefined param_2);

undefined4 FUN_800175a4(int param_1);

void FUN_800175ac(int param_1,undefined4 param_2);

void FUN_800175b0(int param_1,undefined4 param_2);

void FUN_800175b4(int param_1,undefined4 param_2);

void FUN_800175b8(int param_1,int param_2);

void FUN_800175bc(int param_1,undefined param_2);

void FUN_800175c0(int param_1,undefined param_2);

undefined4 FUN_800175c4(int param_1);

void FUN_800175cc(double param_1,int param_2,char param_3);

void FUN_800175d0(double param_1,double param_2,int param_3);

void FUN_800175d4(double param_1,double param_2,double param_3,int *param_4);

void FUN_800175d8(int param_1,undefined param_2);

double FUN_800175dc(int param_1);

void FUN_800175e4(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4);

void FUN_800175e8(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4);

void FUN_800175ec(double param_1,double param_2,double param_3,int *param_4);

int * FUN_800175f0(int param_1);

void FUN_800175f8(int param_1,int param_2,int param_3);

void FUN_800175fc(undefined4 param_1,undefined4 param_2,int param_3);

void FUN_80017600(int param_1,undefined4 param_2,undefined4 param_3);

void FUN_80017604(void);

void FUN_80017608(undefined param_1);

void FUN_8001760c(undefined8 param_1,double param_2,double param_3,double param_4,double param_5, double param_6,undefined4 param_7,undefined4 param_8,int *param_9);

void FUN_80017610(undefined4 param_1,undefined4 param_2,int param_3,int *param_4,uint param_5);

void FUN_80017614(int param_1,undefined *param_2,undefined *param_3,undefined *param_4);

void FUN_80017618(int param_1,undefined param_2,undefined param_3,undefined param_4);

void FUN_8001761c(void);

void FUN_80017620(uint param_1);

int * FUN_80017624(int param_1,char param_2);

void FUN_8001762c(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12, undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

void FUN_80017630(void);

void FUN_80017634(void);

void FUN_80017638(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12, undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

void FUN_8001763c(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12, undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

void FUN_80017640(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12, undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

void FUN_80017644(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12, undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

void FUN_80017648(void);

void FUN_8001764c(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void FUN_80017650(undefined4 param_1,undefined4 param_2,uint *param_3,uint *param_4,uint param_5);

void FUN_80017654(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

undefined FUN_80017658(int *param_1);

void FUN_80017660(int param_1);

void FUN_80017664(undefined4 param_1);

void FUN_80017668(void);

void FUN_8001766c(void);

void FUN_80017670(short param_1);

int FUN_80017674(void);

void FUN_8001767c(void);

uint FUN_80017680(uint param_1);

uint FUN_80017688(uint param_1);

uint FUN_80017690(uint param_1);

void FUN_80017698(uint param_1,uint param_2);

undefined4 FUN_8001769c(void);

void FUN_800176a4(undefined param_1);

uint FUN_800176a8(void);

void FUN_800176b0(undefined param_1);

void FUN_800176b4(undefined param_1);

undefined FUN_800176b8(void);

void FUN_800176c0(undefined param_1);

void FUN_800176c4(int param_1,int param_2);

void FUN_800176c8(int param_1);

void FUN_800176cc(void);

int FUN_800176d0(void);

void FUN_800176d8(void);

void FUN_800176dc(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12, undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

void FUN_800176e0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void FUN_800176e4(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9, undefined4 param_10,undefined4 param_11,int param_12,undefined4 param_13, int param_14,undefined4 param_15,undefined4 param_16);

void FUN_800176e8(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9, undefined4 param_10,undefined4 param_11,int param_12,undefined4 param_13, int param_14,undefined4 param_15,undefined4 param_16);

void FUN_800176ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12, undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

void FUN_800176f0(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9, undefined4 param_10,undefined4 param_11,int param_12,undefined4 param_13, int param_14,undefined4 param_15,undefined4 param_16);

double FUN_800176f4(double param_1,double param_2,double param_3);

void FUN_800176fc(undefined4 param_1,undefined4 param_2,undefined2 *param_3,undefined2 *param_4, undefined2 *param_5);

void FUN_80017700(ushort *param_1,float *param_2);

void FUN_80017704(undefined4 *param_1,undefined4 *param_2);

double FUN_80017708(float *param_1,float *param_2);

void FUN_80017710(float *param_1,float *param_2);

double FUN_80017714(float *param_1,float *param_2);

void FUN_8001771c(float *param_1,float *param_2);

int FUN_80017720(void);

int FUN_80017728(void);

int FUN_80017730(void);

int FUN_80017738(void);

void FUN_80017740(double param_1,double param_2,double param_3,float *param_4);

void FUN_80017744(undefined4 param_1,float *param_2);

void FUN_80017748(ushort *param_1,float *param_2);

void FUN_8001774c(float *param_1,int param_2);

void FUN_80017750(double param_1,int param_2);

void FUN_80017754(float *param_1,ushort *param_2);

uint FUN_80017758(double param_1,double param_2,float *param_3);

uint FUN_80017760(uint param_1,uint param_2);

void FUN_80017768(undefined4 *param_1,undefined4 *param_2);

void FUN_8001776c(float *param_1,float *param_2,float *param_3);

void FUN_80017770(int param_1,int param_2,float *param_3);

void FUN_80017774(float *param_1,float *param_2,float *param_3);

void FUN_80017778(double param_1,double param_2,double param_3,float *param_4,float *param_5, float *param_6,float *param_7);

void FUN_8001777c(float *param_1,float *param_2,float *param_3);

void FUN_80017780(double param_1,float *param_2,float *param_3,float *param_4);

void FUN_80017784(float *param_1);

void FUN_80017788(float *param_1,float *param_2,float *param_3);

void FUN_8001778c(float *param_1);

void FUN_80017790(uint param_1,uint param_2,int param_3);

void FUN_80017794(int param_1);

void FUN_80017798(uint param_1,uint param_2,int param_3);

undefined4 FUN_8001779c(void);

int FUN_800177a4(int param_1,int param_2);

uint FUN_800177ac(uint param_1);

undefined4 FUN_800177b4(undefined4 param_1);

undefined4 FUN_800177bc(undefined4 param_1);

int FUN_800177c4(void);

uint FUN_800177cc(uint param_1);

uint FUN_800177d4(uint param_1);

uint FUN_800177dc(uint param_1);

uint FUN_800177e4(uint param_1);

uint FUN_800177ec(uint param_1);

void FUN_800177f4(undefined4 param_1,undefined4 param_2,int param_3,undefined2 param_4, undefined2 param_5,undefined4 param_6);

void FUN_800177f8(undefined4 param_1,undefined4 param_2,int param_3,undefined2 param_4, undefined2 param_5,undefined4 param_6);

void FUN_800177fc(void);

int FUN_80017800(uint param_1);

void FUN_80017808(undefined4 param_1);

void FUN_8001780c(uint param_1);

void FUN_80017810(void);

void FUN_80017814(uint param_1);

undefined4 FUN_80017818(undefined4 param_1);

void FUN_80017820(undefined4 param_1,undefined4 param_2,undefined4 param_3);

uint FUN_80017824(uint param_1);

void FUN_8001782c(undefined param_1);

int FUN_80017830(int param_1,int param_2);

int FUN_80017838(int param_1,int param_2,int param_3);

void FUN_80017840(void);

undefined4 * FUN_80017844(undefined4 *param_1);

void FUN_8001784c(undefined4 *param_1,undefined4 *param_2);

undefined4 * FUN_80017850(int param_1,int param_2);

void FUN_80017858(short *param_1,undefined4 *param_2,int param_3,undefined4 *param_4, undefined4 *param_5,int param_6,int param_7,int param_8);

void FUN_8001785c(void);

void FUN_80017860(int param_1,int param_2,int param_3);

void FUN_80017864(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,uint param_5, uint param_6,uint param_7,uint param_8,short param_9);

void FUN_80017868(undefined4 param_1,undefined4 param_2,int param_3,uint param_4);

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

void FUN_80017874(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, int *param_9,int param_10,undefined4 param_11,undefined4 param_12,uint *param_13, int param_14,undefined4 param_15,undefined4 param_16);

void FUN_80017878(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12, undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

uint FUN_8001787c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, uint param_9,int param_10,int param_11,undefined4 param_12,undefined4 param_13, undefined4 param_14,undefined4 param_15,undefined4 param_16);

void FUN_80017884(int param_1,uint param_2,int *param_3,int param_4);

void FUN_80017888(void);

void FUN_8001788c(void);

void FUN_80017890(undefined4 param_1,undefined4 param_2,int param_3,int *param_4,undefined *param_5, undefined4 param_6);

void FUN_80017894(int param_1,undefined4 param_2,int param_3,int *param_4);

void FUN_80017898(int *param_1,int param_2,int *param_3);

void FUN_8001789c(undefined4 param_1,undefined4 param_2,int *param_3,undefined *param_4);

void FUN_800178a0(int param_1,undefined param_2);

void FUN_800178a4(double param_1,double param_2,double param_3,int param_4);

void FUN_800178a8(int param_1);

void FUN_800178ac(int param_1);

void FUN_800178b0(uint *param_1);

void FUN_800178b4(void);

void FUN_800178b8(int param_1,int param_2,float *param_3);

undefined4 FUN_800178bc(void);

void FUN_800178c4(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4, undefined4 param_5,int param_6,undefined4 param_7,int param_8);

void FUN_800178c8(int *param_1,float *param_2);

void FUN_800178cc(void);

void FUN_800178d0(undefined4 param_1,undefined4 param_2,float *param_3);

void FUN_800178d4(void);

void FUN_800178d8(double param_1,int *param_2);

undefined4 FUN_800178dc(int *param_1);

void FUN_800178e4(double param_1,int *param_2,int param_3);

void FUN_800178e8(double param_1,int *param_2,int param_3,int param_4,int param_5,byte param_6);

void FUN_800178ec(int *param_1);

void FUN_800178f0(undefined4 param_1,undefined4 param_2,int param_3,float *param_4,int param_5);

void FUN_800178f4(double param_1,double param_2,int *param_3,int param_4,int param_5,float *param_6, short *param_7);

void FUN_800178f8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,int param_11,int param_12, undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

char * FUN_800178fc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, int param_9,short param_10,short param_11,int param_12,undefined4 param_13, undefined4 param_14,undefined4 param_15,undefined4 param_16);

int FUN_80017904(int param_1,int param_2);

int FUN_8001790c(int param_1,int param_2);

int FUN_80017914(int param_1,int param_2);

void FUN_8001791c(int *param_1,int param_2,undefined4 *param_3);

void FUN_80017920(int param_1,int param_2);

int FUN_80017924(int param_1,int param_2);

int FUN_8001792c(int param_1,int param_2);

undefined2 FUN_80017934(int param_1);

void FUN_8001793c(int param_1);

void FUN_80017940(undefined4 param_1,int param_2);

int FUN_80017944(int param_1,int param_2);

undefined4 FUN_8001794c(int param_1);

void FUN_80017954(void);

void FUN_80017958(int param_1,undefined4 param_2);

undefined4 FUN_8001795c(int param_1);

void FUN_80017964(int param_1,undefined4 param_2);

void FUN_80017968(int param_1);

void FUN_8001796c(int param_1);

int FUN_80017970(int *param_1,int param_2);

int FUN_80017978(int param_1,int param_2);

void FUN_80017980(void);

void FUN_80017984(int param_1,int param_2,int param_3);

void FUN_80017988(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4);

void FUN_8001798c(int param_1);

void FUN_80017990(int param_1,int param_2);

void FUN_80017994(int param_1);

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

void FUN_800179a0(void);

void FUN_800179a4(int *param_1);

int * FUN_800179a8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, byte *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12, uint *param_13,int param_14,undefined4 param_15,undefined4 param_16);

void FUN_800179b0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,undefined4 *param_11,undefined4 param_12, undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

undefined4 FUN_800179b4(void);

void FUN_800179bc(void);

void FUN_800179c0(void);

void FUN_800179c4(void);

void FUN_800179c8(undefined4 param_1,undefined4 param_2,int param_3,uint *param_4,uint param_5);

void FUN_800179cc(undefined4 param_1,undefined4 param_2,int param_3,int *param_4,int param_5);

void FUN_800179d0(float *param_1,float *param_2,float *param_3,float *param_4,int param_5, int param_6);

void FUN_800179d4(float *param_1,float *param_2,float *param_3,float *param_4,int param_5, int param_6);

void FUN_800179d8(float *param_1,float *param_2,float *param_3,float *param_4,float *param_5, int param_6);

void FUN_800179dc(void);

void FUN_800179e0(void);

void FUN_800179e4(void);

void FUN_800179e8(void);

void FUN_800179ec(undefined4 param_1,undefined4 param_2,ushort *param_3,int param_4);

undefined4 FUN_800179f0(void);

int FUN_800179f8(int param_1,int param_2);

void FUN_80017a00(void);

void FUN_80017a04(void);

void FUN_80017a08(ushort *param_1);

void FUN_80017a0c(int param_1,undefined param_2);

void FUN_80017a10(int param_1,undefined param_2);

void FUN_80017a14(int param_1);

void FUN_80017a18(void);

void FUN_80017a1c(int param_1);

byte FUN_80017a20(int param_1);

void FUN_80017a28(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4, undefined4 param_5,uint param_6);

void FUN_80017a2c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4, undefined4 param_5,uint param_6);

void FUN_80017a30(int param_1);

byte FUN_80017a34(int param_1);

void FUN_80017a3c(ushort *param_1,ushort param_2);

void FUN_80017a40(ushort *param_1,float *param_2,float *param_3);

void FUN_80017a44(ushort *param_1,float *param_2,float *param_3,char param_4);

void FUN_80017a48(float *param_1,short *param_2,float *param_3);

void FUN_80017a4c(short *param_1,undefined4 *param_2);

void FUN_80017a50(ushort *param_1,float *param_2,char param_3);

undefined4 FUN_80017a54(int param_1);

int FUN_80017a5c(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, int param_9,undefined4 param_10);

void FUN_80017a64(int param_1,ushort param_2);

void FUN_80017a68(int param_1);

void FUN_80017a6c(int param_1,int param_2,int param_3,int param_4,char param_5,char param_6);

void FUN_80017a70(int param_1);

void FUN_80017a74(undefined4 param_1);

void FUN_80017a78(int param_1,int param_2);

void FUN_80017a7c(int param_1,char param_2);

undefined4 FUN_80017a80(int param_1);

undefined4 FUN_80017a88(double param_1,double param_2,double param_3,int param_4);

undefined4 FUN_80017a90(void);

undefined4 FUN_80017a98(void);

void FUN_80017aa0(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

undefined2 * FUN_80017aa4(uint param_1,undefined2 param_2);

void FUN_80017aac(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void FUN_80017ab0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void FUN_80017ab4(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void FUN_80017ab8(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, int param_9,undefined4 param_10,uint *param_11,int param_12,uint param_13, undefined4 param_14,undefined4 param_15,undefined4 param_16);

void FUN_80017abc(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, int param_9,undefined4 param_10,uint *param_11,int param_12,uint param_13, undefined4 param_14,undefined4 param_15,undefined4 param_16);

void FUN_80017ac0(short *param_1,undefined4 param_2,undefined4 param_3,int param_4, undefined4 param_5,int param_6,undefined4 param_7,undefined4 param_8);

void FUN_80017ac4(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, int param_9);

void FUN_80017ac8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, int param_9);

void FUN_80017acc(int param_1);

void FUN_80017ad0(int param_1);

void FUN_80017ad4(void);

void FUN_80017ad8(int param_1,int param_2,undefined4 param_3,uint param_4);

void FUN_80017adc(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, int param_9,uint param_10);

void FUN_80017ae0(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,undefined param_11,undefined4 param_12, uint *param_13,int param_14,undefined4 param_15,undefined4 param_16);

void FUN_80017ae4(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,undefined param_11,undefined4 param_12, uint *param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

uint FUN_80017ae8(void);

int FUN_80017af0(int param_1);

int FUN_80017af8(int param_1);

undefined4 FUN_80017b00(undefined4 *param_1,undefined4 *param_2);

void FUN_80017b08(void);

void FUN_80017b0c(undefined4 *param_1);

void FUN_80017b10(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void FUN_80017b14(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

void FUN_80017b18(void);

void FUN_80017b1c(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8, undefined4 param_9,undefined4 param_10,undefined4 param_11,int param_12, undefined4 param_13,int param_14,undefined4 param_15,undefined4 param_16);

void FUN_80017b20(undefined8 param_1,double param_2,double param_3,undefined8 param_4, undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

/* Pattern wrappers. */
void doNothing_8001F678(void);
#pragma dont_inline on
void doNothing_startOfFrame(void);
#pragma dont_inline reset
void doNothing_onSaveSelectScreenExit(void);
int return1_800202BC(void);
int return0_8002969C(void) { return 0x0; }
int return0_8002A5B8(void) { return 0x0; }
void doNothing_afterRenderObject(void);
void doNothing_beforeRenderObject(void);
void fn_8002B85C(void);

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

void Obj_SetModelRenderOpAlpha(u8 *obj, int alpha);

void Obj_SetModelSlotIndex(u8 *obj, int slotIndex);

void Obj_ClearModelSlotIndex(u8 *obj);

void *Obj_GetActiveModel(u8 *obj);

extern int *lbl_803DCAB4;
extern u8 framesThisStep;
extern f32 lbl_803DE88C;
extern f32 lbl_803DE89C;
extern f32 lbl_803DE8A0;
extern void Obj_BuildWorldTransformMatrix(u8 *obj, f32 *mtx, int flags);

void Obj_ClearModelColorFadeRecursive(u8 *obj);

void Obj_TickModelColorFadeRecursive(u8 *obj);

#pragma dont_inline on
void Obj_SetModelColorFadeRecursive(u8 *obj, int frames, u8 red, u8 green, u8 blue, u8 startAtHalf);
#pragma dont_inline reset

void Obj_SetModelColorOverrideRecursive(u8 *obj, u8 red, u8 green, u8 blue, u8 alpha, u8 enabled);

void Obj_ResetModelColorState(u8 *obj);

#pragma peephole off
void Obj_StartModelFadeIn(u8 *obj, int frames);
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
int getGameState(void);
#pragma dont_inline reset

extern u8 lbl_803DCA49;
extern void init(void);
extern void checkReset(void);
extern void gameLoop(void);

void main(void);

#pragma peephole off
void setGameState(int state);

void setTimeStop(int v);

void setShouldResetNextFrame(int v);
#pragma peephole reset

void setFrameCountdown_800202c4(u8 v);

#pragma dont_inline on
int getHudHiddenFrameCount(void);
#pragma dont_inline reset

s16 getScreenBlankFrameCount(void);

int getCurLanguage(void);

#pragma dont_inline on
void *getCurGameText(void);
#pragma dont_inline reset

int objIsFrozen(u8 *obj);

int objGetFlagsE5_2(u8 *obj);

void objSetEventName(u8 *obj, void *name);

void crash(void);

void __set_debug_bba(u8 *p) {
    p[0x19] = 0;
}

#pragma peephole off
int roundUpTo4(int x);

#pragma dont_inline on
int roundUpTo8(int x);

int roundUpTo16(int x);

int roundUpTo32(int x);
#pragma dont_inline reset
#pragma peephole reset

/* Simple field/global accessors. */
extern int lbl_803DC9E8;
extern void *gameTextDrawFunc;
extern u8 *gameTextFonts;
extern u8 lbl_803DCB10;
extern int lbl_803DCAE8[2];
extern u8 lbl_803DCA48;

void modelLightStruct_setGlowProjectionRadius(ModelLightStruct *light, f32 radius);

f32 *modelLightStruct_getProjectionTexMtx(ModelLightStruct *p);

void *modelLightStruct_getProjectionTexture(ModelLightStruct *p);

void modelLightStruct_setProjectionTexture(ModelLightStruct *p, void *v);

int modelLightStruct_getProjectedLightChannelPreference(ModelLightStruct *p);

void modelLightStruct_setProjectedLightChannelPreference(ModelLightStruct *p, int v);

void modelLightStruct_setSelectionPriority(ModelLightStruct *p, u8 v);

int modelLightStruct_getActiveState(ModelLightStruct *p);

f32 modelLightStruct_getRadius(ModelLightStruct *p);

void fn_80026C30(u8 *p, u8 v) {
    p[0x1a] = v;
}

#pragma dont_inline on
int gameTextFn_80019b14(void);
#pragma dont_inline reset

#pragma dont_inline on
void gameTextSetDrawFunc(void *fn);
#pragma dont_inline reset

void modelLightStruct_setAffectsAabbLightSelection(ModelLightStruct *p, u8 v);

void lightSetField4D(ModelLightStruct *p, u8 v);

void lightSetFieldBC_8001db14(ModelLightStruct *p, u8 v);

void modelLightStruct_setLightKind(ModelLightStruct *p, int v);

extern u8 gModelLightCount;
extern void *gModelLightList[];
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
extern void modelLightStruct_setEnabled(ModelLightStruct *light, u8 enabled, f32 duration);
extern void modelLightStruct_startColorFade(ModelLightStruct *light, int mode, s16 frames);
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
void *objCreateLight(int arg, u8 addToList);
#pragma scheduling reset
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma peephole off
void modelLightStruct_freeSlot(void **lightSlot);

void ModelLightStruct_free(ModelLightStruct *light);

void *modelLightStruct_createPointLight(int unused, u8 red, u8 green, u8 blue, u8 setFlag);
#pragma pop

#pragma dont_inline on
#pragma push
#pragma scheduling off
#pragma peephole off
void *objAllocLight(void *owner);
#pragma pop
#pragma dont_inline reset

void modelLightStruct_setProjectionTevModes(ModelLightStruct *p, void *a, void *b);

f32 gameTextFn_80019c00(void);

u8 fn_8001FD88(void **p);

void tailFn_80026c38(u8 *p, f32 a, f32 b, f32 c) {
    *(f32 *)(p + 8) = a;
    *(f32 *)(p + 0xc) = b;
    *(f32 *)(p + 0x10) = c;
}

#pragma peephole off
void texFlagFn_80023cbc(int v);
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
void modelLightStruct_setGlowColor(ModelLightStruct *light, u8 red, u8 green, u8 blue, u8 alpha);

void modelLightStruct_getProjectionTevModes(ModelLightStruct *p, void **a, void **b);

void modelLightStruct_setSpecularTargetColor(ModelLightStruct *p, u8 a, u8 b, u8 c, u8 d);

void modelLightStruct_setDiffuseTargetColor(ModelLightStruct *p, u8 a, u8 b, u8 c, u8 d);

void fn_8001FE90(void);

void fn_8001FEA8(void);

#pragma dont_inline on
int gameTextGetState(int i);
#pragma dont_inline reset

extern void textFn_8001b7b8(void);
extern int lbl_803DC9F0;
extern int lbl_803DCA04;
extern void *lbl_803DC9F8;

void mainLoopDoGameText(void);

void blankScreen(int frames);

void modelLightStruct_getPosition(ModelLightStruct *p, f32 *a, f32 *b, f32 *c);

void modelLightStruct_getWorldPosition(ModelLightStruct *p, f32 *a, f32 *b, f32 *c);

#pragma peephole on
void fn_8001FE74(void *v);
#pragma peephole reset

#pragma dont_inline on
int mmSetFreeDelay(int v);

int testAndSet_onlyUseHeap3(int v);

int testAndSet_onlyUseHeaps1and2(int v);
#pragma dont_inline reset

void colorFn_8001efe0(int i, u8 a, u8 b, u8 c);

int fn_80022E0C(int x);

void modelLightStruct_setObjectLightMaskIndex(ModelLightStruct *p, int n);

void objSetHintTextIdx(u8 *obj, u16 idx);
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
void modelLightStruct_getSpecularColor(ModelLightStruct *p, u8 *a, u8 *b, u8 *c, u8 *d);

void modelLightStruct_getDiffuseColor(ModelLightStruct *p, u8 *a, u8 *b, u8 *c, u8 *d);

void modelLightStruct_setAngularAttenuation(ModelLightStruct *p, f32 a, f32 b, f32 c);

void modelLightStruct_setSpecularColor(ModelLightStruct *p, u8 a, u8 b, u8 c, u8 d);

void modelLightStruct_setDiffuseColor(ModelLightStruct *p, u8 a, u8 b, u8 c, u8 d);

void lightGetColor(int i, u8 *a, u8 *b, u8 *c);

#pragma dont_inline on
void *getCache(void);
#pragma dont_inline reset

f32 getXZDistance(f32 *a, f32 *b);

f32 vec3f_distanceSquared(f32 *a, f32 *b);

void Vec3_ScaleAdd(f32 *a, f32 s, f32 *b, f32 *out);

void modelLightStruct_updateColorFade(ModelLightStruct *light);

void modelLightStruct_startColorFade(ModelLightStruct *light, int mode, s16 frames);

void modelLightStruct_setupGlow(ModelLightStruct *light, u32 textureId, u8 red, u8 green, u8 blue, u8 alpha, f32 scale);

void modelLightStruct_setEnabled(ModelLightStruct *light, u8 enabled, f32 duration);

void modelLightStruct_setProjectionFarZ(ModelLightStruct *p, f32 v);

void modelLightStruct_setProjectionNearZ(ModelLightStruct *p, f32 v);

int Obj_IsLoadingLocked(void);

void objSetSlot(u8 *obj, s8 slot);

#pragma peephole on
void fn_8002B758(void *v);

void fn_8002B860(void *v);
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
extern u8 gModelLightUseModelRelativePositions;
extern int gModelLightNextGXLightId;
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
} ModelLightChannelState;
extern ModelLightChannelState gModelLightChannelStates[];

#pragma push
#pragma scheduling off
#pragma peephole off
void cutsceneExit(void);

void gameTextInit(void);

int getAngle(float y, float x);

int atan2_8002178c(float y, float x);

#pragma dont_inline on
void cacheFn_800229c4(int sync);
#pragma dont_inline reset

void fn_80026C54(u8 *p) {
    p[0x18] = 0;
    *(f32 *)(p + 0x14) += timeDelta;
    if (*(f32 *)(p + 0x14) > lbl_803DE854) {
        *(f32 *)(p + 0x14) -= lbl_803DE854;
    }
}

#pragma dont_inline on
void mm_free(void *p);
#pragma dont_inline reset

void *getTablesBinEntry(int i);

void fn_8002CE14(u8 *obj);

void objRemoveFromListFn_8002ce88(u8 *obj);

void *Obj_GetPlayerObject(void);

void modelLightChannel_configure(int i, int a, int b);

#pragma peephole off
void modelLightChannels_reset(u8 v);
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

void *loadAsset(void *reqVoid);

#pragma push
#pragma scheduling off
#pragma peephole off
void mtxFn_80021ec0(u8 *p, f32 s);

void *ObjList_GetObjects(int *outA, int *outB);

void mapReload(void);

int cos16(u16 angle);

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

f32 Vec3_Length(f32 *v);

f32 Vec_xzDistance(f32 *a, f32 *b);

f32 Vec_distance(f32 *a, f32 *b);

void Vec3_Cross(f32 *a, f32 *b, f32 *out);

extern f32 lbl_803DE808;
extern f32 lbl_803DE80C;

void Vec3_ReflectAgainstNormal(f32 *a, f32 *n, f32 *out);

#pragma dont_inline on
void *loadAssetFileById(int id, int arg);

void *loadTextureFile(int id, int arg);
#pragma dont_inline reset

void Obj_SetActiveModelIndex(u8 *obj, int idx);
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
int setSubtitlesEnabled(int enabled);

void *getTrickyObject(void);

void AtomicSList_Push(void **list, void *node);

ObjListObject *ObjList_FindObjectById(u32 objectId);

extern int lbl_803DB3C8;
extern void hudDrawRect(int x0, int y0, int x1, int y1, void *color);
extern int lbl_803DC9D8;
extern int gameTextFn_8001bcb4(void);
extern int gameTextFn_8001b44c(int x);
extern void gameTextLoadForCurMap(int sourceId);

#pragma dont_inline on
void gameTextSetCharset(int charset, int flags);

#pragma dont_inline reset

void gameTextLoadDir(int dirId);

void gameTextFn_80019804(int flags);

extern u8 lbl_802C7400[];
extern void *lbl_803DC9CC;

void gameTextFn_80017434(u8 *param_1);

void gameTextFn_8001984c(s16 x, s16 y, int flags);

#pragma dont_inline on
void *getTabEntry(int id, int arg, int e, int d);
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
void cutsceneFadeInOut(int a);

int gameTextFn_8001b44c(int x);

#pragma optimize_for_size on
void gameTextLoadTaskText(int taskId);
#pragma optimize_for_size reset

#pragma optimize_for_size on
int gameTextFn_8001bcb4(void);
#pragma optimize_for_size reset

#pragma dont_inline on
void Obj_TransformLocalVectorByWorldMatrix(void *obj, f32 *src, f32 *dst);
#pragma dont_inline reset

extern void PSMTXMultVec(f32 *mtx, f32 *in, f32 *out);
extern f32 lbl_803DE890;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

#pragma dont_inline on
void Obj_TransformLocalPointByWorldMatrix(u8 *obj, f32 *src, f32 *dst, u8 flag);
#pragma dont_inline reset

extern void Vec_normalize(f32 *dst, f32 *src);
extern f32 *Camera_GetViewMatrix(void);
extern void mtxRotateByVec3s(f32 *mtx, void *transform);
extern void mtx44Transpose(f32 *src, f32 *dst);

void fn_8002B2AC(f32 *out, u8 *transform, f32 *in);

void modelLightStruct_setDirection(ModelLightStruct *s, f32 x, f32 y, f32 z);

void modelLightStruct_setPosition(ModelLightStruct *s, f32 x, f32 y, f32 z);

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
void modelLightStruct_loadDiffuseGXLight(u8 *light, u8 *obj, int lightId);
#pragma pop

void modelLightStruct_loadChannelLight(int channel, u8 *light, u8 *obj);

void modelLightChannels_applyGXControls(void);

void updateLights(void);

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

void *Obj_AllocObjectSetup(int size, int b);

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

int gameBitDecrement(int bit);

void initRotationMtx(f32 *m, f32 a, f32 b, f32 c);

int mmGetRegionForPtr(u8 *ptr);

#pragma dont_inline on
void *mmInitRegion(u8 *buf, int size, int numSlots);
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

int mmCreateMemoryStore(int size);

void mmFreeDeferred(void *p);

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
void mmFreeTick(int arg);
#pragma peephole reset

void mmFree(void *p);

extern void *gMmStoreArray[];
extern char sMmAllocateFromFBMemoryStoreMissingHandleError[];
extern char sMmMemoryStoreMessageBlock[];

int mmAllocateFromFBMemoryStore(int handle, int size);

extern void *OSGetArenaLo(void);
extern void *OSGetArenaHi(void);
extern void *OSAllocFromHeap(int heap, int size);
extern void DCFlushRange(void *addr, u32 nBytes);
extern int __OSCurrHeap;
extern int lbl_803DCB18;
extern void *lbl_803DD498;
extern void *lbl_803DCAFC;

void mmInit(void);

extern char sMmSpawnedUnalignedSlotWarning[];
extern int lbl_803DCB1C;
extern char sMemStatsFormat[];
extern int lbl_803DCB20;
extern int lbl_803DCB24;
extern int lbl_803DCB28;
extern int lbl_803DCB2C;

int printHeapStats(void);

int heapSpawnSlot(int region, int idx, int size, int type, int newType, int f10val, int tag);
int changeHeapSlot(int region, int idx, int newSize, int type, int newType, int f10val, int tag);
extern void reportAllocFail(int, int, int, int, int, int, int, int, int, int, int);
extern int lbl_803DB430;
extern int lbl_803DCB0C;
extern int lbl_803DCC7C;

int mmAllocFromRegion(int region, int size, int type, int tag);

int heapSpawnSlot(int region, int idx, int size, int type, int newType, int f10val, int tag);

int changeHeapSlot(int region, int idx, int newSize, int type, int newType, int f10val, int tag);

extern char sMmFreeMemoryUsageCorruptedError[];

void heapFree(int region, int idx);

int getHeapItemSize(void *ptr);

void *AtomicSList_Pop(void **list);

f32 interpolate(f32 a, f32 t, f32 exp);

int atan2i(int y, int x);
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
int objMove(u8 *obj, f32 dx, f32 dy, f32 dz);

#pragma dont_inline on
void copyToCache(void *dst, void *src, u32 count);
#pragma dont_inline reset

#pragma dont_inline on
int fn_8001F978(u32 srcAddr, u32 size, u32 *cacheCursor, u32 *outEnd, u32 limit);
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
void *animationLoad(int id, s16 a, s16 b, int e, int f);
#pragma dont_inline reset

void modelLightStruct_setSpotAttenuation(ModelLightStruct *obj, f32 cutoff, int mode);

void modelLightStruct_setDistanceAttenuation(u8 *obj, f32 a, f32 b);

#pragma dont_inline on
int modelLightStruct_projectedLightIntersectsObject(u8 *light, u8 *obj);
#pragma dont_inline reset

#pragma dont_inline on
f32 modelLightStruct_getObjectIntensity(u8 *light, u8 *obj);
#pragma dont_inline reset

#pragma dont_inline on
void modelLightStruct_selectBrightestAabbLights(u8 **outLights, int maxLights, int *outCount, f32 minX, f32 minY, f32 minZ, f32 maxX, f32 maxY, f32 maxZ);
#pragma dont_inline reset

#pragma dont_inline on
void modelLightStruct_selectObjectLights(u8 *obj, u8 **outLights, int maxLights, int *outCount, int typeMask);
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
void mtx44Transpose(f32 *src, f32 *dst);
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
void setMatrixFromObjectTransposed(void *obj, f32 *out);
#pragma dont_inline reset

void Matrix_TransformPoint(f32 *m, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);

void objFn_8002b67c(u8 *obj);

void modelLightStruct_updateGlowAlpha(ModelLightStruct *light);

#pragma dont_inline on
void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);
#pragma dont_inline reset

void gameTextSetWindowStrPos(int idx, int x, int y);
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
void gameTextInitFn_8001bd14(void);
#pragma optimize_for_size reset

#pragma dont_inline on
void subtitleFn_8001b700(void);

#pragma dont_inline reset

void fn_8001BDD4(int mode);

void fn_8001BE2C(int mode);

int fn_8002B8F0(u8 *obj);

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

void textFn_8001bb78(int x);

void Obj_ApplyPendingParentLinks(void);
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
void Matrix_TransformVector(f32 *m, f32 *v, f32 *out);

extern int rand(void);
extern f32 lbl_803DE7F8;
extern f64 lbl_803DE800;
extern f64 lbl_803DE7E0;

#pragma dont_inline on
int randomGetRange(int lo, int hi);
#pragma dont_inline reset

extern s16 lbl_803DCAD8;
extern u8 *lbl_803DCAE0;
#define gGameBitCount lbl_803DCAD8
#define gGameBitSaveData lbl_803DCAE0

u32 GameBit_Get(int eventId);

extern int isSaveGameLoading(void);
extern void gameBitFn_800ea2e0(int a);
extern char lbl_802CA4E0[];
extern void OSReport(char *fmt, ...);
#define GameBit_RequestSync gameBitFn_800ea2e0
#define sGameBitSetDuringSaveLoadWarning lbl_802CA4E0

void GameBit_Set(int eventId, int value);

void copyMatrix44(f32 *src, f32 *dst);

void Vec3_Normalize(f32 *v);

int gameBitIncrement(int bit);

#pragma dont_inline on
void memcpyToCache(void *dst, void *src, u32 count);
#pragma dont_inline reset

void Obj_FlushDeferredFreeList(void);

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
void modelLightStruct_setupPerspectiveProjection(ModelLightStruct *obj, f32 a, f32 b);

extern void C_MTXLightOrtho(f32 *m, f32 t, f32 b, f32 l, f32 r, f32 scaleS, f32 scaleT,
                            f32 transS, f32 transT);

void modelLightStruct_setupOrthoProjection(ModelLightStruct *obj, f32 a, f32 b, f32 c, f32 d, f32 e, f32 f);

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
void fn_8002B6D8(u8 *obj, int a, int b, int c, u8 d, u8 e);

void dvdCancelCallback_8001b39c(int a, u8 *match);

void gameTextOpenCallback_8001b3d0(int status, u8 *match);

void modelLightStruct_setSpecularAttenuation(ModelLightStruct *obj, f32 a, f32 b);
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
void *Obj_SetupObject(int a, int b, int c, int d, int e);
#pragma scheduling reset

#pragma scheduling off
void *loadObjectAtObject(u8 *src, int arg1);
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

void mapLoadByCoords(int arg);

extern void objLoadPlayerFromSave(u8 *obj);
extern f32 lbl_803DE88C;

void Obj_RunInitCallback(u8 *obj, int cb, int unused);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void objGetWeaponDa(u8 *obj, int dummy, int *out, int key, u8 load);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjAnim_LoadMoveEvents(u8 *obj, int dummy, int *out, int key, u8 load);
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
void gameTextInitFn_8001a234(void);
#pragma optimize_for_size reset

void gameTextRun(void);

void loadGameTextSequence(int sequenceSlotDir, int sequenceId);

void gameTextLoadForCurMap(int sourceId);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void Obj_BuildInverseWorldTransformMatrix(u8 *obj, f32 *out);
#pragma pop

extern s16 lbl_803DCBC4;

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjList_PartitionForRender(int *out);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_BuildWorldTransformMatrix(u8 *obj, f32 *mtx, int flags);
#pragma dont_inline reset
#pragma pop

extern f32 fsin16(int angle);
extern f32 lbl_803DE7F0;

#pragma push
#pragma scheduling off
#pragma fp_contract off
void mtxRotateByVec3s(f32 *mtx, void *transform);
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
void *loadCharacter(s16 *data, int flags, int arg2, int arg3, void *parent, int unused);
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
void gameTextDrawBox(u16 *strPtr, int boxId, u8 *box);
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
void init(void);
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
void setLanguageFn_8001ad64(void *reqp);
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
void objFreeObjDef(void *objp, int flag);
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
void Obj_UpdateObject(u8 *obj);
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
void Obj_UpdateAllObjects(u8 flags);
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
void mapSetupPlayer(void);
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
void gameTextLoadGraphicsFn_8001a918(void);
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
void Obj_ResetObjectSystem(void);
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_UpdateModelBlendStates(void);
#pragma dont_inline reset
#pragma pop

extern void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, void *ox, void *oy, void *oz);
extern void mapLoadForObject(int id, void *obj);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_RegisterObject(u8 *obj, int flags);
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
void Obj_FreeObject(u8 *obj);
#pragma dont_inline reset
#pragma pop

extern void *lbl_803DCBC0;
extern int *lbl_803DCBBC;
extern int lbl_803DCBB8;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_InitObjectSystem(void);
#pragma dont_inline reset
#pragma pop

extern int loadModLines(int n, s16 *out);
extern void intersectModLineBuild(u8 *buf);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
u8 *loadObjectFile(int id);
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int objGetTotalDataSize(void *tmpl, u8 *def, s16 *data, int flags);
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void *stackCreate(int count, int size);
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void *mmAlloc(int size, int type, int flag);
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma opt_strength_reduction off
#pragma opt_loop_invariants off
void mtxFn_80022404(int a, int b, f32 *out);
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
void fn_800218AC(s16 *a, f32 *v);
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
extern u32 getButtonsJustPressed(int pad);
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
void gameUpdate(void);
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
void gameLoop(void);
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
void doQueuedLoads(void);
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
void textFn_8001b46c(int a);
#pragma pop

extern int lbl_803DB3F0;
extern int lbl_803DB3F4;
extern int lbl_803DB3F8;
extern int lbl_803DB3FC;
extern int lbl_803DB400;
extern void *lbl_803DCA20;

#pragma push
#pragma scheduling off
void boxDrawFn_8001c5ac(u16 *strPtr, int boxId, u8 *p);
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
void cardShowMessage(void);
#pragma pop

extern void angleToVec2(int angle, f32 *cosOut, f32 *sinOut);

#pragma push
#pragma scheduling off
void setMatrixFromObjectPos(f32 *m, u8 *p);
#pragma pop

extern void PSVECCrossProduct(f32 *a, f32 *b, f32 *out);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void fn_800213D0(f32 *a, f32 *b, s16 *out0, s16 *out1, s16 *out2);
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
void fn_8002A5DC(u8 *obj);
#pragma pop

extern s16 lbl_803DB3E8;
extern u16 lbl_802C9F00[];
extern u16 lbl_802CA100[];

#pragma push
#pragma scheduling off
#pragma opt_strength_reduction off
void gameTextInitFn_8001c794(void);
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
void modelInitBones(f32 scale, void *model);
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
int RandomTimer_UpdateRangeTrigger(f32 lo, f32 hi, f32 *timer);
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
void mathFn_80021ac8(u8 *p, f32 *v);
#pragma pop

extern void stopRumble2(void);

#pragma push
#pragma scheduling off
#pragma peephole off
void cutsceneEnterExit(int entering, int affectSounds);
#pragma pop

extern int lbl_803DCA18;
extern int lbl_803DCA08;
extern int lbl_803DCA10;
extern f32 lbl_803DE730;
extern f32 lbl_803DE734;
int GameText_CountPrintableChars(u8 *str);
int GameText_FindControlCodeArgs(u8 *str, u32 target, int *out);
extern char **textMeasureFn_80016c9c(char *str, f32 width, f32 height, int *outCount, f32 *outLineH);

typedef struct SubtitleLineTable {
    void *blocks[256];
    char *lines[256];
    f32 times[256];
} SubtitleLineTable;

typedef struct SubtitleTextEntry {
    u8 pad0[2];
    u16 count;
    u8 pad4[4];
    char **strs;
} SubtitleTextEntry;

#pragma push
#pragma optimization_level 1
#pragma scheduling off
#pragma peephole off
void textFn_8001b7b8(void);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
int GameText_CountPrintableChars(u8 *str);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
int loadModLines(int idx, s16 *outCount);
#pragma pop

#pragma push
#pragma scheduling off
void deathRenderFn_8001fd98(u32 h);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
int GameText_FindControlCodeArgs(u8 *str, u32 target, int *out);
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
SubtitleCmd *textFn_80018bc4(int str, int *count);
#pragma pop

extern f32 lbl_803DE880;
extern void fn_80007F78(u8 *ch, s16 *outRot, s16 *outRot2);

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_SampleJointTransform(u8 *model, int b, int idx, f32 t, f32 s, f32 *outPos, s16 *outRot) {
    u8 *ch;
    int saved;
    s16 srot[3];
    u8 *anim;

    if (*(u16 *)(*(u8 **)model + 0xec) == 0) {
        f32 z = lbl_803DE828;
        outPos[0] = z;
        outPos[1] = z;
        outPos[2] = z;
        outRot[0] = 0;
        outRot[1] = 0;
        outRot[2] = 0;
    }
    if (b != 0) {
        ch = *(u8 **)(model + 0x30);
    } else {
        ch = *(u8 **)(model + 0x2c);
    }
    saved = *(int *)(ch + 0x34);
    *(int *)(ch + 0x34) = ((int *)(ch + idx * 4))[0xd];
    if (*(u16 *)(*(u8 **)model + 2) & 0x40) {
        if (idx > 1) {
            anim = ((u8 **)(ch + ((u16 *)(ch + idx * 2))[0x22] * 4))[9] + 0x80;
        } else {
            anim = ((u8 **)(ch + ((u16 *)(ch + idx * 2))[0x22] * 4))[7] + 0x80;
        }
    } else {
        anim = ((u8 **)*(int *)(*(u8 **)model + 0x64))[((u16 *)(ch + idx * 2))[0x22]];
    }
    *(f32 *)(ch + 4) = t * *(f32 *)(ch + 0x14);
    {
        int bv = (*(u8 **)(ch + 0x34))[2];
        f32 fr = *(f32 *)(ch + 4);
        int n = (int)fr;
        f32 fcv = (f32)n;
        if (fcv != fr) {
            *(s16 *)(ch + 0x4c) = (s16)bv;
        } else {
            *(s16 *)(ch + 0x4c) = 0;
        }
        if (*(s8 *)(ch + 0x60) != 0 && fcv == *(f32 *)(ch + 0x14) - lbl_803DE818) {
            *(s16 *)(ch + 0x4c) = (s16)(-bv * n);
        }
        *(u8 **)(ch + 0x2c) = anim + (*(s16 *)(anim + 2) + bv * n);
    }
    fn_80007F78(ch, srot, outRot);
    *(int *)(ch + 0x34) = saved;
    {
        f32 k = lbl_803DE880;
        outPos[0] = k * (f32)srot[0];
        outPos[1] = k * (f32)srot[1];
        outPos[2] = k * (f32)srot[2];
    }
    outPos[0] = outPos[0] + *(f32 *)(*(u8 **)(*(u8 **)model + 0x3c) + 4);
    outPos[1] = outPos[1] + *(f32 *)(*(u8 **)(*(u8 **)model + 0x3c) + 8);
    outPos[2] = outPos[2] + *(f32 *)(*(u8 **)(*(u8 **)model + 0x3c) + 0xc);
    outPos[0] *= s;
    outPos[1] *= s;
    outPos[2] *= s;
}
#pragma pop

extern u8 *gameTextGetBox(int boxId);
extern int padGetStickX(int pad);
extern int padGetCX(int pad);
extern void GXSetCopyFilter(int aa, u8 *samplePattern, int vf, u8 *vfilter);
extern void VIConfigure(void *rm);
extern int lbl_803DB428;
extern int lbl_803DB42C;
extern void *gameTextGetStr(int textId);

#pragma push
#pragma scheduling off
#pragma peephole off
void askProgressiveScanMode(void);
#pragma pop

extern u32 getNewInputs(int pad);
extern int DVDGetDriveStatus(void);
extern void AISetStreamVolLeft(int vol);
extern void AISetStreamVolRight(int vol);
extern void audioStopAll(void);
extern void AISetStreamPlayState(int state);
extern void audioReset(void);
extern void LCDisable(void);
extern void DVDSetAutoInvalidation(int enable);
extern void OSResetSystem(int reset, u32 resetCode, int forceMenu);
extern u8 gAudioStreamPlaying;
extern u8 gAudioStreamDvdState;
extern u8 lbl_803DC950;
extern int lbl_803DC960;
extern u8 lbl_803DCCA6;
extern u8 lbl_803DC951;
extern u8 lbl_803DB425;
extern f32 lbl_803DCAC8;
extern f32 lbl_803DCB00;
extern u8 lbl_803DCAC5;
extern char lbl_802CA460[];
extern f32 lbl_803DE7AC;

#pragma push
#pragma scheduling off
#pragma peephole off
void checkReset(void);
#pragma pop

extern void PSMTXCopy(f32 *src, f32 *dst);
extern void PSMTXTranspose(f32 *src, f32 *dst);
extern void PSMTXIdentity(f32 *m);
extern f32 fn_802920A4(f32 x);
extern f32 lbl_803DE838;
extern f32 lbl_803DE83C;
extern f32 lbl_803DCED0;
extern f32 lbl_803DCECC;
extern f32 playerMapOffsetZ;
extern f32 playerMapOffsetX;

#pragma dont_inline off
static int boneBlendSlotLimit(u8 *model) {
    u8 *p = *(u8 **)model;
    if (p[0xf3] != 0) {
        return p[0xf3] + p[0xf4];
    }
    return 1;
}

typedef struct ModelMtxBanks {
    u8 pad[0xc];
    f32 *banks[2];
} ModelMtxBanks;

#pragma push
#pragma scheduling off
#pragma peephole off
void fn_80025F38(int *a, int b, u8 *blend, u8 *chain) {
    u8 *model = (u8 *)a;
    f32 tmp[12];
    f32 mt[12];
    f32 target[3];
    f32 work[3];
    f32 out[3];
    f32 dir2[3];
    f32 dir1[3];
    f32 axis[3];
    f32 *m;
    int i;
    int idx;
    int nextIdx;
    int prevOff;
    f32 dot;
    f32 cap;
    u8 *bankSel;

    idx = *(s8 *)(*(u8 **)(b + 0x3c) + (*(int ***)(chain + 4))[0][0] * 0x1c);
    if (idx >= boneBlendSlotLimit(model)) {
        idx = 0;
    }
    bankSel = model + ((*(u16 *)(model + 0x18) & 1) << 2);
    PSMTXCopy(*(f32 **)(bankSel + 0xc) + idx * 0x10, tmp);
    idx = (*(int ***)(chain + 4))[0][0];
    if (idx >= boneBlendSlotLimit(model)) {
        idx = 0;
    }
    bankSel = model + ((*(u16 *)(model + 0x18) & 1) << 2);
    m = *(f32 **)(bankSel + 0xc) + idx * 0x10;
    cap = lbl_803DE838;
    for (i = 1; i < *(int *)(chain + 8) + 1; i++) {
        nextIdx = (*(int ***)(chain + 4))[0][i];
        prevOff = (i - 1) * 0x54;
        PSMTXMultVec(tmp, (f32 *)(*(u8 **)chain + prevOff + 0x18), out);
        target[0] = lbl_803DCED0 + (*(f32 *)(*(u8 **)chain + i * 0x54) + *(f32 *)(*(u8 **)chain + i * 0x54 + 0xc)) - playerMapOffsetX;
        target[1] = *(f32 *)(*(u8 **)chain + i * 0x54 + 4) + *(f32 *)(*(u8 **)chain + i * 0x54 + 0x10);
        target[2] = lbl_803DCECC + (*(f32 *)(*(u8 **)chain + i * 0x54 + 8) + *(f32 *)(*(u8 **)chain + i * 0x54 + 0x14)) - playerMapOffsetZ;
        work[0] = *(f32 *)(*(u8 **)chain + i * 0x54 - 0x3c);
        work[1] = *(f32 *)(*(u8 **)chain + i * 0x54 - 0x38);
        work[2] = *(f32 *)(*(u8 **)chain + i * 0x54 - 0x34);
        PSVECAdd(work, (f32 *)(*(u8 **)chain + i * 0x54 + 0x18), work);
        PSMTXMultVec(tmp, work, work);
        PSVECSubtract(target, out, dir1);
        PSVECNormalize(dir1, dir1);
        PSVECSubtract(work, out, dir2);
        PSVECNormalize(dir2, dir2);
        dot = PSVECDotProduct(dir2, dir1);
        if (dot < cap && dot > lbl_803DE83C) {
            if (dot < lbl_803DE818 && dot > lbl_803DE840) {
                PSVECCrossProduct(dir2, dir1, axis);
                if (dot < lbl_803DE840) {
                    dot = lbl_803DE840;
                } else {
                    dot = (lbl_803DE818 - dot) * *(f32 *)(blend + 8) + dot;
                }
                PSMTXTranspose(tmp, mt);
                PSMTXMultVecSR(mt, axis, axis);
                PSMTXRotAxisRad(m, axis, fn_802920A4(dot));
            } else {
                PSMTXIdentity(m);
            }
        }
        PSMTXConcat(tmp, m, m);
        m[3] = out[0];
        m[7] = out[1];
        m[11] = out[2];
        PSMTXCopy(m, tmp);
        work[0] = *(f32 *)(*(u8 **)chain + i * 0x54 + 0x18);
        work[1] = *(f32 *)(*(u8 **)chain + i * 0x54 + 0x1c);
        work[2] = *(f32 *)(*(u8 **)chain + i * 0x54 + 0x20);
        PSMTXMultVec(m, work, work);
        PSMTXCopy(m, (f32 *)(*(u8 **)chain + prevOff + 0x24));
        if (i < *(int *)(chain + 8)) {
            idx = nextIdx;
            if (nextIdx >= boneBlendSlotLimit(model)) {
                idx = 0;
            }
            m = *(f32 **)((u8 *)model + ((*(u16 *)(model + 0x18) & 1) << 2) + 0xc) + idx * 0x10;
        }
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void fn_80026308(int *a, int b, u8 *blend, u8 *chain, int cb, int cbArg) {
    u8 *model = (u8 *)a;
    f32 tmp[12];
    f32 mt[12];
    f32 target[3];
    f32 work[3];
    f32 out[3];
    f32 dir2[3];
    f32 dir1[3];
    f32 axis[3];
    f32 *m;
    int i;
    int idx;
    int nextIdx;
    int prevOff;
    f32 dot;
    f32 cap;

    idx = *(s8 *)(*(u8 **)(b + 0x3c) + (*(int ***)(chain + 4))[0][0] * 0x1c);
    if (idx >= boneBlendSlotLimit(model)) {
        idx = 0;
    }
    PSMTXCopy(*(f32 **)(model + ((*(u16 *)(model + 0x18) & 1) << 2) + 0xc) + idx * 0x10, tmp);
    idx = (*(int ***)(chain + 4))[0][0];
    if (idx >= boneBlendSlotLimit(model)) {
        idx = 0;
    }
    m = *(f32 **)(model + ((*(u16 *)(model + 0x18) & 1) << 2) + 0xc) + idx * 0x10;
    cap = lbl_803DE838;
    for (i = 1; i < *(int *)(chain + 8) + 1; i++) {
        nextIdx = (*(int ***)(chain + 4))[0][i];
        prevOff = (i - 1) * 0x54;
        PSMTXMultVec(tmp, (f32 *)(*(u8 **)chain + prevOff + 0x18), out);
        target[0] = lbl_803DCED0 + (*(f32 *)(*(u8 **)chain + i * 0x54) + *(f32 *)(*(u8 **)chain + i * 0x54 + 0xc)) - playerMapOffsetX;
        target[1] = *(f32 *)(*(u8 **)chain + i * 0x54 + 4) + *(f32 *)(*(u8 **)chain + i * 0x54 + 0x10);
        target[2] = lbl_803DCECC + (*(f32 *)(*(u8 **)chain + i * 0x54 + 8) + *(f32 *)(*(u8 **)chain + i * 0x54 + 0x14)) - playerMapOffsetZ;
        work[0] = *(f32 *)(*(u8 **)chain + i * 0x54 - 0x3c);
        work[1] = *(f32 *)(*(u8 **)chain + i * 0x54 - 0x38);
        work[2] = *(f32 *)(*(u8 **)chain + i * 0x54 - 0x34);
        if ((u32)cb != 0) {
            ((void (*)(int, int *, f32 *, int, int, f32))cb)(b, a, work, cbArg, i, *(f32 *)(blend + 0x14));
        }
        PSVECAdd(work, (f32 *)(*(u8 **)chain + i * 0x54 + 0x18), work);
        PSMTXMultVec(tmp, work, work);
        PSVECSubtract(target, out, dir1);
        PSVECNormalize(dir1, dir1);
        PSVECSubtract(work, out, dir2);
        PSVECNormalize(dir2, dir2);
        dot = PSVECDotProduct(dir2, dir1);
        if (dot < cap && dot > lbl_803DE83C) {
            PSVECCrossProduct(dir2, dir1, axis);
            if (dot < lbl_803DE840) {
                dot = lbl_803DE840;
            } else {
                dot = (lbl_803DE818 - dot) * *(f32 *)(blend + 8) + dot;
            }
            PSMTXTranspose(tmp, mt);
            PSMTXMultVecSR(mt, axis, axis);
            PSMTXRotAxisRad(m, axis, fn_802920A4(dot));
        } else {
            PSMTXIdentity(m);
        }
        PSMTXConcat(tmp, m, m);
        m[3] = out[0];
        m[7] = out[1];
        m[11] = out[2];
        PSMTXCopy(m, tmp);
        work[0] = *(f32 *)(*(u8 **)chain + i * 0x54 + 0x18);
        work[1] = *(f32 *)(*(u8 **)chain + i * 0x54 + 0x1c);
        work[2] = *(f32 *)(*(u8 **)chain + i * 0x54 + 0x20);
        PSMTXMultVec(m, work, work);
        PSMTXCopy(m, (f32 *)(*(u8 **)chain + prevOff + 0x24));
        if (i < *(int *)(chain + 8)) {
            idx = nextIdx;
            if (nextIdx >= boneBlendSlotLimit(model)) {
                idx = 0;
            }
            m = *(f32 **)((u8 *)model + ((*(u16 *)(model + 0x18) & 1) << 2) + 0xc) + idx * 0x10;
        }
        *(f32 *)(*(u8 **)chain + i * 0x54 + 0xc) = work[0] - (lbl_803DCED0 + *(f32 *)(*(u8 **)chain + i * 0x54) - playerMapOffsetX);
        *(f32 *)(*(u8 **)chain + i * 0x54 + 0x10) = work[1] - *(f32 *)(*(u8 **)chain + i * 0x54 + 4);
        *(f32 *)(*(u8 **)chain + i * 0x54 + 0x14) = work[2] - (lbl_803DCECC + *(f32 *)(*(u8 **)chain + i * 0x54 + 8) - playerMapOffsetZ);
        *(f32 *)(*(u8 **)chain + i * 0x54) = work[0];
        *(f32 *)(*(u8 **)chain + i * 0x54 + 4) = work[1];
        *(f32 *)(*(u8 **)chain + i * 0x54 + 8) = work[2];
    }
}
#pragma pop
