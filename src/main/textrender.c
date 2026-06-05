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

#pragma dont_inline on
void *gameTextGetStr(int textId) {
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
#pragma dont_inline reset
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
int return0_8002969C(void);
int return0_8002A5B8(void);
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
void *fn_80028354(u8 *modelFile, int index);

void *fn_80028364(u8 *modelFile, int index);

void *modelFileGetDisplayList(u8 *modelFile, int displayListIndex);

void ObjModel_CopyJointTranslation(u8 *modelBytes, int jointIndex, f32 *out);

void *fn_800283E8(u8 *model, int textureIndex);

void *ObjModel_GetBaseVertexCoords(u8 *model, int vertexIndex);

#pragma dont_inline on
void *ObjModel_GetRenderOp(u8 *model, int renderOpIndex);
#pragma dont_inline reset

u16 modelFileHeaderGetCullDistance(u8 *modelFile);

#pragma dont_inline on
void ObjModel_ClearRenderAttachment(u8 *model);
#pragma dont_inline reset

#pragma dont_inline on
void ObjModel_EnableDefaultRenderCallback(void *obj, u8 *model, f32 *mtx, int enabled, f32 scale);
#pragma dont_inline reset

void *ObjModel_GetCurrentVertexCoords(u8 *model, int vertexIndex);

void *ObjModel_GetPostRenderCallback(u8 *model);

void fn_800284CC(void);

void ObjModel_SetPostRenderCallback(u8 *model, void *callback);

void *ObjModel_GetRenderCallback(u8 *model);

void ObjModel_SetRenderCallback(u8 *model, void *callback);

void ObjModel_ToggleVertexBuffer(u8 *model);

void ObjModel_ToggleMatrixBuffer(u8 *model);

void *ObjModel_GetJointMatrix(u8 *modelBytes, int jointIndex);

void *ObjModel_GetRenderOpTextureRefs(u8 *model, int renderOpIndex);

int ObjModel_GetUnpackedResourceSize(u8 *resource, int baseSize);

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

int getCurLanguage(void) {
    return curLanguage;
}

#pragma dont_inline on
void *getCurGameText(void) {
    return curGameTextDir;
}
#pragma dont_inline reset

int objIsFrozen(u8 *obj);

int objGetFlagsE5_2(u8 *obj);

void objSetEventName(u8 *obj, void *name);

void crash(void);

void __set_debug_bba(u8 *p);

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

void fn_80026C30(u8 *p, u8 v);

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

f32 gameTextFn_80019c00(void) {
    return *(f32 *)(gameTextFonts + 0x20);
}

u8 fn_8001FD88(void **p);

void tailFn_80026c38(u8 *p, f32 a, f32 b, f32 c);

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

void gameTextInit(void) {
    gameTextInitFn_8001c794();
    lbl_803DC980 = 1;
    gameTextLoadDir(0x1c);
}

int getAngle(float y, float x);

int atan2_8002178c(float y, float x);

#pragma dont_inline on
void cacheFn_800229c4(int sync);
#pragma dont_inline reset

void fn_80026C54(u8 *p);

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

asm void setGQR6(register u32 v);

asm void setGQR7(register u32 v);

#pragma dont_inline on
void fn_8002A3D4(int a, int b, int c, int d);
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
int setSubtitlesEnabled(int enabled) {
    int old = lbl_803DCA00;
    lbl_803DCA00 = enabled;
    if (enabled == 0) {
        subtitleFn_8001b700();
    }
    return old;
}

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
void *getTabEntry(int id, int arg, int e, int d);
#pragma dont_inline reset

int ObjModel_HasActiveBlendChannels(u8 *model);

void ObjModel_SetBlendChannelWeight(u8 *model, int channel, f32 weight);
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
int modelGetAmapSize(int a, int b, int c);
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

void ObjModel_RelocateModelData(u8 *m);

extern int getTableFileEntry(int fileId, int index, int *out);
extern void loadModelsBin();
extern int loadAndDecompressDataFile(int id, void *buf, int blockOff, int len, int a, int b, int c);

#pragma dont_inline on
void *ObjModel_LoadModelData(int id);
#pragma dont_inline reset

void ObjModel_ResolveRenderOpTextures(u8 *m);

#pragma dont_inline on
void ObjModel_RelocateAnimData(u8 *m, u8 *dst);
#pragma dont_inline reset

void ObjModel_LoadRenderOpTextures(u8 *model, int arg);

int loadModelAndAnimTabs(void);

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

void ObjModel_InitRenderBuffers(void);

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

void modelFn_800292e0(void);

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

void model_multMtxs(u8 *model, f32 *out);

#pragma dont_inline on
void setMatrixFromObjectTransposed(void *obj, f32 *out);
#pragma dont_inline reset

void Matrix_TransformPoint(f32 *m, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);

void objFn_8002b67c(u8 *obj);

void modelLightStruct_updateGlowAlpha(ModelLightStruct *light);

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

int fn_8002B8F0(u8 *obj);

void fn_80026C88(u8 *p);

extern f32 lbl_803DE858;
extern f32 lbl_803DE85C;
extern f32 lbl_803DE860;
extern f32 lbl_803DE828;
extern f32 lbl_803DE864;

void *allocModelStruct2(int **models, int count);

void Model_GetVertexPosition(u8 *model, int vertexIndex, f32 *out);

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

void *ObjAnim_LoadCachedMove(int a, int b, int c, int d);
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
void ObjModel_InitScratchBuffers(void);
#pragma dont_inline reset
#pragma pop

extern void GXInitLightAttn(u8 *lt_obj, f32 a0, f32 a1, f32 a2, f32 k0, f32 k1, f32 k2);
extern u8 curGameTexts[];

#pragma push
#pragma scheduling off
#pragma peephole off
void fn_8002B6D8(u8 *obj, int a, int b, int c, u8 d, u8 e);

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

void modelLightStruct_setSpecularAttenuation(ModelLightStruct *obj, f32 a, f32 b);
#pragma pop

extern void ObjModel_SetBlendChannelTargets(u8 *model, int ch, int a, int b, f32 w, int c);
extern f32 lbl_803DE828;

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_ClearBlendChannels(u8 *model);
#pragma pop

extern f32 lbl_803DE840;

#pragma scheduling off
#pragma peephole off
void ObjModel_SetBlendChannelTargets(u8 *model, int channel, int a, int b, f32 weight, int flags);
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
void ObjModel_ApplyBlendChannels(u8 *model);
#pragma pop

extern f32 lbl_803DE874;
extern f32 lbl_803DE878;
extern f32 lbl_803DE87C;

#pragma peephole off
void ObjModel_AdvanceBlendChannels(u8 *model, f32 dt);
#pragma peephole reset

extern void *modelLoadFn_80025ae4(u8 *p, int b, int isType1, int c);
extern void modelLoadColorFn_80024ec8(void *m, void *data);
extern void ObjModel_RelocateAnimData(u8 *p, u8 *m);
extern void DCStoreRange(void *p, int size);

#pragma push
#pragma scheduling off
#pragma peephole off
void *ObjModel_LoadAnimData(u8 *p, int b, int c);
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

void *ObjModel_Load(int id, int arg2, int *outSize);

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
void ObjModel_InitResourceCaches(void);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_Release(u8 *model);
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
void setGQR6_2(int a, int b, int c, int d);

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
void objFreeObjDef(void *objp, int flag);
#pragma dont_inline reset
#pragma pop

extern void lbl_80006C6C(int *out, u8 *a, void *buf, int c, int d, u8 *e, int f, int g);
extern u8 lbl_80340740[];

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void modelAnimFn_80024524(u8 *hdr, u8 *stk, int n);

#pragma peephole off
void modelWalkAnimFn_800248b8(u8 *a, u8 *b, u8 *c, int d, f32 e);
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
void modelLoadColorFn_80024ec8(void *m, void *data);
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
void ObjModel_BuildAnimBlendTable(u8 *obj, u8 *p2, u8 *hdr);
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void *modelLoadFn_80025ae4(u8 *p, int b, int isType1, int c);
#pragma dont_inline reset
#pragma pop

extern char sModelAnimationBufferOverflowWarning[];

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma opt_loop_invariants off
#pragma dont_inline on
int modelLoadAnimations(void *model, int id, void *animBase);
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
int modelLoad_calcSizes(void *model, int flags, int *sizes, int a4);
#pragma dont_inline reset
#pragma pop

extern f32 lbl_803DE850;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline on
void fn_80026928(int *obj, int b, int *p3);
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
void *animLoadFromTable(u8 *hdr, int id, int idx, u8 *out);
#pragma opt_common_subs reset
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void *loadAnimation(int hdr, s16 id, int b, u8 *bufout);
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
void modelAnimFn_80026790(u8 *model, int idx, u8 *m, u8 *anim);
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
void objUpdateHitSpheres(u8 *a, u8 *b, u8 *c, u8 *d, u8 *e);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void modelInitBones(f32 scale, void *model);
#pragma pop

extern void PSMTXTrans(f32 *m, f32 x, f32 y, f32 z);
extern void PSMTXReorder(f32 *src, f32 *dst);

#pragma push
#pragma scheduling off
#pragma peephole off
void modelInitBoneMtxs(u8 *m, u8 *out);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void modelInitBoneMtxs2(u8 *m, u8 *out2, u8 *out);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void modelApplyBoneTransforms(int a, int b, u16 c, void *d, void *e, int f);
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
void playerTailFn_80026b3c(int *a, int b, u8 *p, int d);
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
void textFn_8001b7b8(void) {
    int total;
    SubtitleLineTable *s = (SubtitleLineTable *)lbl_8033B240;
    f32 delta;
    f32 curTime;
    int savedCharset;
    SubtitleTextEntry *t;
    u8 *win;
    int i;
    char *str;
    int k;
    int m;
    int oldDelay;
    char **strLines;
    int found;
    int q;
    int n;
    int count;
    int args[3];
    f32 ftotal;

    total = 0;
    curTime = lbl_803DE730;
    if (lbl_803DC9F0 != 0) {
        savedCharset = gameTextFn_80019b14();
        gameTextSetCharset(1, 1);
    }
    t = (SubtitleTextEntry *)gameTextGet(lbl_803DC9FC);
    win = lbl_802C7400 + 0x140;
    lbl_803DCA18 = 0;
    lbl_803DCA14 = 0;
    for (i = 0; i < 256; i++) {
        s->times[i] = lbl_803DE734;
    }
    for (i = 0; i < t->count; i++) {
        str = t->strs[i];
        n = GameText_FindControlCodeArgs((u8 *)str, 0xE018, args);
        if (n != 0) {
            q = args[2] / 60;
            s->times[lbl_803DCA18] = (f32)(args[1] + (args[0] * 60 + q));
        }
        strLines = textMeasureFn_80016c9c(str, (f32)(u32)*(u16 *)(win + 2), *(f32 *)(win + 0xc), &count, NULL);
        if (strLines != NULL) {
            for (k = 0; k < count; k++) {
                s->lines[lbl_803DCA18++] = strLines[k];
            }
            if (s->blocks[lbl_803DCA14] != NULL) {
                oldDelay = mmSetFreeDelay(0);
                mm_free(s->blocks[lbl_803DCA14]);
                mmSetFreeDelay(oldDelay);
            }
            s->blocks[lbl_803DCA14++] = strLines;
        }
    }
    for (k = 0; k < lbl_803DCA18; k++) {
        if (lbl_803DE734 != s->times[k]) {
            curTime = s->times[k];
            total = GameText_CountPrintableChars((u8 *)s->lines[k]);
        } else {
            found = 0;
            m = k;
            for (i = 0; i < 256; i++) {
                ftotal = (f32)total;
                if (m < 255) {
                    if (lbl_803DE734 != s->times[m + 1]) {
                        delta = s->times[m + 1] - curTime;
                        found = 1;
                    }
                    n = GameText_CountPrintableChars((u8 *)s->lines[m]);
                    s->times[m] = (f32)n;
                    total += n;
                    if (found != 0) {
                        for (q = m; q >= k; q--) {
                            s->times[q] = s->times[q + 1] - delta * (s->times[q] / (f32)total);
                        }
                        break;
                    }
                    m++;
                }
            }
        }
    }
    lbl_803DCA08 = 0;
    lbl_803DCA10 = 0;
    lbl_803DCA04 = 2;
    if (lbl_803DC9F0 != 0) {
        gameTextSetCharset(savedCharset, 1);
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
int GameText_CountPrintableChars(u8 *str) {
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
int loadModLines(int idx, s16 *outCount);
#pragma pop

#pragma push
#pragma scheduling off
void deathRenderFn_8001fd98(u32 h);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
int GameText_FindControlCodeArgs(u8 *str, u32 target, int *out) {
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
void ObjModel_UnpackResourcePayload(u8 *src, int srcSize, u8 *dst, int dstSize);
#pragma pop

extern s16 lbl_803DC7A4;
extern s16 lbl_803DC7A6;
extern s16 lbl_803DC7A8;
extern void ObjModel_SampleJointTransform(u8 *model, int a, int b, f32 t, f32 s, f32 *outPos, s16 *outRot);
extern void modelAnimFn_800246a0(u8 *dst, u8 *model, u8 *ch, f32 t, int max, int b, int c, int d, int e, s16 f);

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_UpdateAnimMatrices(u8 *model, u8 *blend, u8 *obj, u8 *dst);
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

void modelAnimFn_800246a0(u8 *a, u8 *b, u8 *c, f32 t, int d, int e, int f, int g, int h, s16 w);
#pragma pop

extern void ObjModel_TransformVerticesWithTranslation(u8 *m1, u8 *m2, u8 *src, int d1, int d2, int count);

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_BlendPrimaryVertexStream(u8 *mtxs, u8 *hdr, u8 *data, int *offs, u8 *out);
#pragma pop

extern void ObjModel_TransformVerticesLinear(u8 *m1, u8 *m2, u8 *src, int d1, int d2, int count);
extern void ObjModel_TransformQuadVerticesLinear(u8 *m1, u8 *m2, u8 *src, int d1, int d2, int count);

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_BlendSecondaryVertexStream(u8 *mtxs, u8 *hdr, u8 *data, u8 **outs, int quad);
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

extern f32 lbl_803DE880;
extern void fn_80007F78(u8 *ch, s16 *outRot, s16 *outRot2);

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_SampleJointTransform(u8 *model, int b, int idx, f32 t, f32 s, f32 *outPos, s16 *outRot);
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

typedef struct ModelMtxBanks {
    u8 pad[0xc];
    f32 *banks[2];
} ModelMtxBanks;

#pragma push
#pragma scheduling off
#pragma peephole off
void fn_80025F38(int *a, int b, u8 *blend, u8 *chain);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void fn_80026308(int *a, int b, u8 *blend, u8 *chain, int cb, int cbArg);
#pragma pop
