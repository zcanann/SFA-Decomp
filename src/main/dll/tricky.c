#include "ghidra_import.h"
#include "main/dll/tricky.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006954();
extern undefined4 FUN_8000695c();
extern undefined4 FUN_80006960();
extern undefined4 FUN_80006984();
extern void* FUN_800069a8();
extern undefined4 FUN_800069d4();
extern double FUN_800069d8();
extern double FUN_800069e4();
extern double FUN_800069f8();
extern undefined4 FUN_80006a00();
extern undefined4 FUN_80006c64();
extern undefined4 FUN_80017484();
extern undefined4 FUN_80017488();
extern undefined4 FUN_80017498();
extern uint GameBit_Get(int eventId);
extern undefined4 FUN_800176c0();
extern undefined4 FUN_800176c8();
extern int FUN_800176d0();
extern int FUN_80017730();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern int FUN_8001792c();
extern undefined8 FUN_80017964();
extern int FUN_80017a54();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined8 FUN_80017ac8();
extern int FUN_80017ae4();
extern int ObjGroup_FindNearestObject();
extern undefined4 FUN_800480a0();
extern undefined4 FUN_800480b4();
extern undefined4 FUN_8004812c();
extern uint FUN_80053078();
extern undefined4 FUN_80053754();
extern undefined4 FUN_8005398c();
extern char FUN_80053be4();
extern int FUN_8005b024();
extern void newshadows_getShadowDiskTexture(int *textureOut);
extern undefined4 FUN_8006f690();
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern undefined4 FUN_8006fd90();
extern undefined4 FUN_8007005c();
extern undefined4 FUN_800709d8();
extern undefined4 FUN_800709e0();
extern undefined4 FUN_800709e8();
extern int playerHasKrazoaSpirit();
extern undefined4 hudDrawMagicBar();
extern undefined8 FUN_801225a8();
extern undefined4 fn_80124A78();
extern undefined4 fn_80124B38();
extern undefined8 FUN_8012c894();
extern undefined4 FUN_802475e4();
extern undefined4 FUN_80247618();
extern undefined4 PSVECDotProduct();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247a7c();
extern undefined4 FUN_80247d2c();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_80258674();
extern undefined4 FUN_80258944();
extern undefined4 FUN_80259000();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025a454();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025a608();
extern undefined4 FUN_8025b94c();
extern undefined4 FUN_8025b9e8();
extern undefined4 FUN_8025bb48();
extern undefined4 FUN_8025bd1c();
extern undefined4 FUN_8025be54();
extern undefined4 FUN_8025be80();
extern undefined4 FUN_8025c1a4();
extern undefined4 FUN_8025c224();
extern undefined4 FUN_8025c2a8();
extern undefined4 FUN_8025c368();
extern undefined4 FUN_8025c428();
extern undefined4 FUN_8025c510();
extern undefined4 GXSetBlendMode();
extern undefined4 FUN_8025c5f0();
extern undefined4 FUN_8025c65c();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025c828();
extern undefined4 FUN_8025ca04();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d848();
extern undefined4 FUN_8025d888();
extern undefined4 FUN_8025d8c4();
extern undefined8 FUN_8025da88();
extern undefined4 FUN_8025db38();
extern undefined4 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286840();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_8028fde8();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_802949ec();
extern uint FUN_80294be4();
extern int FUN_80294dbc();
extern undefined4 SUB42();

extern undefined4 DAT_802c292c;
extern undefined4 DAT_802c2930;
extern undefined4 DAT_802c2934;
extern undefined4 DAT_802c2938;
extern undefined4 DAT_802c293c;
extern undefined4 DAT_802c2940;
extern undefined4 DAT_8031cbf0;
extern undefined4 DAT_80397480;
extern undefined4 DAT_803a9450;
extern undefined4 DAT_803a9490;
extern undefined4 DAT_803a95b0;
extern undefined4 DAT_803a9610;
extern undefined4 DAT_803a9764;
extern undefined4 DAT_803a9768;
extern undefined4 DAT_803a976c;
extern undefined4 DAT_803a978c;
extern undefined4 DAT_803a9790;
extern undefined4 DAT_803a9794;
extern undefined4 DAT_803a9798;
extern undefined4 DAT_803a97a4;
extern undefined4 DAT_803a9f1c;
extern undefined4 DAT_803a9f24;
extern undefined4 DAT_803a9f28;
extern undefined4 DAT_803a9f40;
extern undefined4 DAT_803a9f44;
extern undefined4 DAT_803a9f48;
extern undefined4 DAT_803a9f4c;
extern undefined4 DAT_803a9f50;
extern undefined4 DAT_803a9f58;
extern undefined4 DAT_803a9f5c;
extern undefined4 DAT_803a9f60;
extern undefined4 DAT_803a9f68;
extern undefined4 DAT_803a9f70;
extern undefined4 DAT_803a9f74;
extern undefined4 DAT_803a9f78;
extern undefined4 DAT_803a9f7c;
extern undefined4 DAT_803a9fc4;
extern undefined4 DAT_803a9fc8;
extern undefined4 DAT_803a9fd0;
extern undefined4 DAT_803a9fd4;
extern undefined4 DAT_803a9fe0;
extern undefined4 DAT_803a9fe8;
extern undefined4 DAT_803a9fec;
extern undefined4 DAT_803a9ff0;
extern undefined4 DAT_803a9ff4;
extern undefined4 DAT_803a9ff8;
extern undefined4 DAT_803a9ffc;
extern undefined4 DAT_803aa000;
extern undefined4 DAT_803aa004;
extern int DAT_803aa040;
extern int DAT_803aa04c;
extern int DAT_803aa070;
extern int DAT_803aa080;
extern undefined4 DAT_803aa088;
extern undefined4 DAT_803aa094;
extern undefined DAT_803b0000;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc084;
extern undefined4 DAT_803dc6c0;
extern undefined4 DAT_803dc6c1;
extern undefined4 DAT_803dc6c2;
extern undefined4 DAT_803dc6d8;
extern undefined4 DAT_803dc6f2;
extern undefined4 DAT_803dc750;
extern undefined4 DAT_803dc754;
extern undefined4 DAT_803dc755;
extern undefined4 DAT_803dc756;
extern undefined4 DAT_803dc757;
extern undefined4 DAT_803dc758;
extern undefined4 DAT_803dc778;
extern undefined4 DAT_803dc780;
extern undefined4 DAT_803dc784;
extern undefined4 DAT_803dc788;
extern undefined4 DAT_803dc78c;
extern undefined4 DAT_803dc790;
extern undefined4 DAT_803dc794;
extern undefined4 DAT_803dc798;
extern undefined4 DAT_803dc79c;
extern undefined4 DAT_803dc7a0;
extern undefined4 DAT_803dc7a8;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de3b0;
extern undefined4 DAT_803de3c0;
extern undefined4 DAT_803de3da;
extern undefined4 DAT_803de3db;
extern undefined4 DAT_803de3ec;
extern undefined4 DAT_803de3ee;
extern undefined4 DAT_803de3f0;
extern undefined4 DAT_803de3f2;
extern undefined4 DAT_803de3f8;
extern undefined4 DAT_803de400;
extern undefined4 DAT_803de408;
extern undefined4 DAT_803de412;
extern undefined4 DAT_803de413;
extern undefined4 DAT_803de418;
extern undefined4 DAT_803de428;
extern undefined4 DAT_803de42a;
extern undefined4 DAT_803de42c;
extern undefined4 DAT_803de433;
extern undefined4 DAT_803de445;
extern undefined4 DAT_803de44c;
extern undefined4 DAT_803de450;
extern undefined4 DAT_803de458;
extern undefined4 DAT_803de46c;
extern undefined4 DAT_803de478;
extern undefined4 DAT_803de479;
extern undefined4 DAT_803de4b8;
extern undefined4 DAT_803de4dc;
extern undefined4* DAT_803de4e0;
extern undefined4* DAT_803de4e8;
extern undefined4 DAT_803de4f4;
extern undefined4 DAT_803de504;
extern undefined4 DAT_803de50a;
extern undefined4 DAT_803de550;
extern undefined4 DAT_803de55c;
extern undefined4 DAT_803e2aac;
extern undefined4 DAT_803e2ab0;
extern undefined4 DAT_803e2ab4;
extern undefined4 DAT_803e2ab8;
extern undefined4 DAT_cc008000;
extern f64 DOUBLE_803e2af8;
extern f64 DOUBLE_803e2b08;
extern f64 DOUBLE_803e2b20;
extern f64 DOUBLE_803e2b28;
extern f64 DOUBLE_803e2b30;
extern f64 DOUBLE_803e2b38;
extern f64 DOUBLE_803e2b70;
extern f64 DOUBLE_803e2b78;
extern f64 DOUBLE_803e2b80;
extern f64 DOUBLE_803e2ba0;
extern f64 DOUBLE_803e2bb8;
extern f64 DOUBLE_803e2bc0;
extern f64 DOUBLE_803e2bd0;
extern f64 DOUBLE_803e2bd8;
extern f64 DOUBLE_803e2be0;
extern f64 DOUBLE_803e2be8;
extern f64 DOUBLE_803e2bf8;
extern f64 DOUBLE_803e2c00;
extern f64 DOUBLE_803e2c08;
extern f32 lbl_803DC074;
extern f32 lbl_803DC6F4;
extern f32 lbl_803DC74C;
extern f32 lbl_803DC75C;
extern f32 lbl_803DC760;
extern f32 lbl_803DC764;
extern f32 lbl_803DC768;
extern f32 lbl_803DC76C;
extern f32 lbl_803DC770;
extern f32 lbl_803DC774;
extern f32 lbl_803DC77C;
extern f32 lbl_803DE3E0;
extern f32 lbl_803DE3E4;
extern f32 lbl_803DE470;
extern f32 lbl_803DE474;
extern f32 lbl_803DE47C;
extern f32 lbl_803DE480;
extern f32 lbl_803DE484;
extern f32 lbl_803DE488;
extern f32 lbl_803DE48C;
extern f32 lbl_803DE490;
extern f32 lbl_803DE494;
extern f32 lbl_803DE498;
extern f32 lbl_803DE4BC;
extern f32 lbl_803DE4C4;
extern f32 lbl_803DE4D0;
extern f32 lbl_803E2ABC;
extern f32 lbl_803E2AC0;
extern f32 lbl_803E2AC4;
extern f32 lbl_803E2AC8;
extern f32 lbl_803E2ACC;
extern f32 lbl_803E2AD0;
extern f32 lbl_803E2AD4;
extern f32 lbl_803E2AD8;
extern f32 lbl_803E2ADC;
extern f32 lbl_803E2AE0;
extern f32 lbl_803E2AE4;
extern f32 lbl_803E2AE8;
extern f32 lbl_803E2AEC;
extern f32 lbl_803E2AF0;
extern f32 lbl_803E2B00;
extern f32 lbl_803E2B10;
extern f32 lbl_803E2B14;
extern f32 lbl_803E2B18;
extern f32 lbl_803E2B1C;
extern f32 lbl_803E2B40;
extern f32 lbl_803E2B44;
extern f32 lbl_803E2B4C;
extern f32 lbl_803E2B50;
extern f32 lbl_803E2B54;
extern f32 lbl_803E2B5C;
extern f32 lbl_803E2B60;
extern f32 lbl_803E2B64;
extern f32 lbl_803E2B68;
extern f32 lbl_803E2B88;
extern f32 lbl_803E2B8C;
extern f32 lbl_803E2B90;
extern f32 lbl_803E2B94;
extern f32 lbl_803E2B98;
extern f32 lbl_803E2BB0;
extern f32 lbl_803E2BC8;
extern f32 lbl_803E2BCC;
extern f32 lbl_803E2BF0;
extern f32 lbl_803E2C10;
extern f32 lbl_803E2C14;
extern f32 lbl_803E2C18;
extern f32 lbl_803E2C1C;
extern f32 lbl_803E2C20;
extern f32 lbl_803E2C24;
extern f32 lbl_803E2C28;
extern f32 lbl_803E2C2C;
extern f32 lbl_803E2C30;
extern f32 lbl_803E2C34;
extern undefined* PTR_DAT_8031c228;
extern int iRam803de4e4;
extern undefined4* puRam803de4e4;
extern undefined4* puRam803de4ec;
extern char s_x___2f_8031ccf4[];

/*
 * --INFO--
 *
 * Function: gameUiLoadResources
 * EN v1.0 Address: 0x8011D9B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011DC94
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 gameUiResourcesLoaded;
extern char lbl_803A87F0[];
extern char *lbl_803DD85C;
extern char *lbl_803DD860[];
extern char *lbl_803DD868[];
extern int lbl_8031BF90[];
extern const f32 lbl_803E1E3C;
extern f32 lbl_803E1E40, lbl_803E1E44, lbl_803E1E48, lbl_803E1E4C;
extern f32 lbl_803E1E50, lbl_803E1E54, lbl_803E1E58, lbl_803E1E5C;
extern char *Obj_AllocObjectSetup(int size, int id);
extern char *Obj_SetupObject(char *obj, int a, int b, int c, int d);
extern void *Obj_GetActiveModel(char *obj);
extern void ObjModel_SetRenderCallback(void *model, void *cb);
extern u8 modelFn_80124794[];
extern u8 cMenuRenderFn_80124854[];
extern int fn_8011E0D8();

#pragma scheduling off
#pragma peephole off
void gameUiLoadResources(void)
{
    char *base = lbl_803A87F0;
    if (gameUiResourcesLoaded == 0) {
        char **arrA;
        char **arrB;
        int i;
        int val;
        u32 limit;
        char **arrC;
        int *ids;
        char *p;
        u32 *cnt;
        f32 fb, fc, fa;
        f32 ga, gb;

        val = 0;
        i = 0;
        arrA = (char **)(base + 0xbfc);
        arrB = (char **)(base + 0xbf0);
        fa = lbl_803E1E3C;
        fb = lbl_803E1E40;
        fc = lbl_803E1E44;
        for (; i < 3; i++) {
            *arrA = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x65e), 4, -1, -1, 0);
            *(f32 *)(*arrA + 0xc) = fa;
            *(f32 *)(*arrA + 0x10) = fb;
            *(f32 *)(*arrA + 0x14) = fc;
            *(s16 *)(*arrA + 0x0) = (s16)val;
            *(s8 *)(*arrA + 0xad) = (s8)i;
            ObjModel_SetRenderCallback(Obj_GetActiveModel(*arrA), modelFn_80124794);
            *arrB = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x65f), 4, -1, -1, 0);
            *(f32 *)(*arrB + 0xc) = fa;
            *(f32 *)(*arrB + 0x10) = fb;
            *(f32 *)(*arrB + 0x14) = fc;
            *(s16 *)(*arrB + 0x0) = (s16)val;
            ObjModel_SetRenderCallback(Obj_GetActiveModel(*arrB), cMenuRenderFn_80124854);
            val += 0x5555;
            arrA++;
            arrB++;
        }

        lbl_803DD868[0] = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x6e9), 4, -1, -1, 0);
        *(f32 *)(lbl_803DD868[0] + 0xc) = lbl_803E1E3C;
        *(f32 *)(lbl_803DD868[0] + 0x10) = lbl_803E1E48;
        *(f32 *)(lbl_803DD868[0] + 0x14) = lbl_803E1E4C;
        *(s16 *)(lbl_803DD868[0] + 0x0) = 0x7447;
        *(f32 *)(lbl_803DD868[0] + 0x8) = lbl_803E1E50;

        lbl_803DD868[1] = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x602), 4, -1, -1, 0);
        *(f32 *)(lbl_803DD868[1] + 0xc) = lbl_803E1E3C;
        *(f32 *)(lbl_803DD868[1] + 0x10) = lbl_803E1E54;
        *(f32 *)(lbl_803DD868[1] + 0x14) = lbl_803E1E4C;
        *(s16 *)(lbl_803DD868[1] + 0x0) = 0x7447;
        *(f32 *)(lbl_803DD868[1] + 0x8) = lbl_803E1E58;

        p = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x755), 4, -1, -1, 0);
        lbl_803DD860[0] = p;
        ObjModel_SetRenderCallback(*(void **)*(int *)(p + 0x7c), fn_8011E0D8);

        lbl_803DD860[1] = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x756), 4, -1, -1, 0);
        ObjModel_SetRenderCallback(*(void **)*(int *)(lbl_803DD860[1] + 0x7c), fn_8011E0D8);

        i = 4;
        ids = &lbl_8031BF90[4];
        arrC = (char **)(base + 0xc30);
        ga = lbl_803E1E3C;
        gb = lbl_803E1E5C;
        limit = 0x90000000;
        for (; i < 6; i++) {
            *arrC = Obj_SetupObject(Obj_AllocObjectSetup(0x20, *ids), 4, -1, -1, 0);
            *(f32 *)(*arrC + 0xc) = ga;
            *(f32 *)(*arrC + 0x10) = gb;
            *(f32 *)(*arrC + 0x14) = gb;
            *(s16 *)(*arrC + 0x0) = 0x7447;
            *(f32 *)(*arrC + 0x8) = ga;
            cnt = (u32 *)(*arrC + 0x4c);
            if (*cnt > limit) {
                *cnt = 0;
            }
            ids++;
            arrC++;
        }

        p = Obj_AllocObjectSetup(0x24, 0x14b);
        *(s16 *)(p + 0x1c) = 1;
        lbl_803DD85C = Obj_SetupObject(p, 4, -1, -1, 0);
        gameUiResourcesLoaded = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8011d9b4
 * EN v1.0 Address: 0x8011D9B4
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x8011E014
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011d9b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  double dVar1;
  undefined8 uVar2;
  
  FUN_800176c8(1);
  dVar1 = (double)FUN_800176c0(0xff);
  uVar2 = FUN_8012c894(dVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  DAT_803de400 = 0xb;
  DAT_803de55c = FUN_80017498();
  FUN_80017488(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
  lbl_803DE3E4 = lbl_803E2AE0;
  DAT_803de458 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011daf8
 * EN v1.0 Address: 0x8011DAF8
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x8011E06C
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011daf8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  double extraout_f1;
  undefined8 uVar2;
  
  iVar1 = (**(code **)(*DAT_803dd72c + 0x8c))();
  uVar2 = FUN_8012c894(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  if (*(char *)(iVar1 + 9) == '\0') {
    if (DAT_803dc084 == '\0') {
      DAT_803de400 = 10;
    }
    else {
      DAT_803de400 = 9;
    }
  }
  else {
    DAT_803de400 = 8;
  }
  DAT_803de55c = FUN_80017498();
  FUN_80017488(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
  lbl_803DE3E4 = lbl_803E2AE0;
  DAT_803de458 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011dc74
 * EN v1.0 Address: 0x8011DC74
 * EN v1.0 Size: 676b
 * EN v1.1 Address: 0x8011E104
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011dc74(int param_1,undefined param_2,undefined4 param_3,char param_4)
{
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  local_10 = DAT_803e2ab8;
  local_c = CONCAT31((int3)((uint)DAT_803e2ab4 >> 8),param_2);
  local_14 = local_c;
  FUN_8025c428(1,(byte *)&local_14);
  FUN_8025d80c((float *)&DAT_803a9490,0);
  FUN_8025d848((float *)&DAT_803a9490,0);
  FUN_8025d888(0);
  FUN_80258944(1);
  FUN_8025be54(0);
  FUN_8025a5bc(0);
  FUN_800480b4(param_1,0);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  GXSetBlendMode(0,0xc);
  local_18 = local_10;
  FUN_8025c510(0,(byte *)&local_18);
  FUN_8025be80(0);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025c1a4(0,2,8,0xe,0xf);
  FUN_8025c224(0,7,1,4,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  if (*(int *)(param_1 + 0x50) == 0) {
    FUN_8025ca04(1);
  }
  else {
    FUN_8025be80(1);
    FUN_8025c828(1,0,1,0xff);
    FUN_8025c1a4(1,0xf,0xf,0xf,0);
    FUN_8025c224(1,7,1,4,7);
    FUN_8025c65c(1,0,0);
    FUN_8025c2a8(1,0,0,0,1,0);
    FUN_8025c368(1,0,0,0,1,0);
    FUN_8025ca04(2);
  }
  FUN_80259288(0);
  if (param_4 == '\0') {
    FUN_8025cce8(1,4,5,5);
  }
  else {
    FUN_8025cce8(1,4,1,5);
  }
  gxSetZMode_(0,7,0);
  gxSetPeControl_ZCompLoc_(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011df18
 * EN v1.0 Address: 0x8011DF18
 * EN v1.0 Size: 1340b
 * EN v1.1 Address: 0x8011E3BC
 * EN v1.1 Size: 1464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8011df18(int param_1,int *param_2,int param_3)
{
  int iVar1;
  uint *puVar2;
  uint uVar3;
  double dVar4;
  undefined4 local_100;
  uint local_fc;
  uint local_f8;
  int local_f4;
  float local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
  undefined4 local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  float afStack_d8 [12];
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
  float afStack_78 [2];
  float local_70;
  float local_60;
  float afStack_48 [3];
  float local_3c;
  float local_2c;
  float local_1c;
  
  local_f8 = DAT_803e2ab0;
  local_f0 = DAT_802c292c;
  local_ec = DAT_802c2930;
  local_e8 = DAT_802c2934;
  local_e4 = DAT_802c2938;
  local_e0 = DAT_802c293c;
  local_dc = DAT_802c2940;
  iVar1 = FUN_8001792c(*param_2,param_3);
  puVar2 = (uint *)FUN_800480a0(iVar1,0);
  uVar3 = FUN_80053078(*puVar2);
  FUN_802475e4((float *)&DAT_803a95b0,afStack_48);
  local_3c = lbl_803E2ABC;
  local_2c = lbl_803E2ABC;
  local_1c = lbl_803E2ABC;
  FUN_80247a7c((double)(lbl_803E2AE4 / lbl_803DE48C),(double)(lbl_803E2AE4 / lbl_803DE48C),
               (double)(lbl_803E2AE8 / lbl_803DE48C),afStack_78);
  local_70 = lbl_803E2AEC / lbl_803DE48C;
  local_60 = local_70;
  FUN_80247618(afStack_78,afStack_48,afStack_48);
  FUN_8025d8c4(afStack_48,0x1e,1);
  FUN_80258944(3);
  FUN_8025ca04(3);
  FUN_8025be54(2);
  FUN_8025a5bc(1);
  FUN_8025bd1c(0,0,2);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,&local_f0,'\0');
  FUN_8025b94c(0,0,0,7,1,0,0,0,0,0);
  FUN_8004812c(uVar3,0);
  FUN_80258674(0,1,1,0x1e,0,0x7d);
  FUN_8025c828(0,0,0,4);
  FUN_8025c1a4(0,0xf,0xf,0xf,10);
  FUN_8025c224(0,7,7,7,5);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025a608(4,0,0,0,0,0,2);
  local_fc = local_f8;
  FUN_8025a454(4,&local_fc);
  FUN_8025bd1c(1,0,2);
  FUN_8025bb48(1,0,0);
  FUN_8025b94c(1,1,0,7,1,0,0,1,0,0);
  FUN_80247618((float *)&DAT_80397480,(float *)&DAT_803a95b0,afStack_48);
  dVar4 = (double)(lbl_803E2AF0 * lbl_803DE4D0 * lbl_803DE4D0);
  FUN_80247a7c(dVar4,dVar4,(double)lbl_803E2AE8,afStack_d8);
  FUN_80247618(afStack_d8,afStack_48,afStack_48);
  dVar4 = (double)(lbl_803E2AF0 * (float)((double)lbl_803E2AE8 - dVar4));
  FUN_80247a48(dVar4,dVar4,(double)lbl_803E2ABC,afStack_d8);
  FUN_80247618(afStack_d8,afStack_48,afStack_48);
  FUN_8025d8c4(afStack_48,0x21,0);
  FUN_80258674(1,0,0,0x21,0,0x7d);
  FUN_8025c828(1,1,0,0xff);
  FUN_8025c1a4(1,0xf,0xf,0xf,8);
  FUN_8025c224(1,7,7,7,0);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  local_a8 = lbl_803DC77C;
  local_a4 = lbl_803E2ABC;
  local_a0 = lbl_803E2ABC;
  local_9c = lbl_803E2AF0;
  local_98 = lbl_803E2ABC;
  local_94 = lbl_803DC77C;
  local_90 = lbl_803E2ABC;
  local_8c = lbl_803E2AF0;
  local_88 = lbl_803E2ABC;
  local_84 = lbl_803E2ABC;
  local_80 = lbl_803E2ABC;
  local_7c = lbl_803E2AE8;
  FUN_8025d8c4(&local_a8,0x24,1);
  FUN_80258674(2,1,1,0x24,0,0x7d);
  newshadows_getShadowDiskTexture(&local_f4);
  FUN_8004812c(local_f4,1);
  FUN_8025c5f0(2,0x1c);
  local_100 = DAT_803dc778;
  FUN_8025c510(0,(byte *)&local_100);
  FUN_8025be80(2);
  FUN_8025c828(2,2,1,0xff);
  FUN_8025c1a4(2,0xf,0xf,0xf,0);
  FUN_8025c224(2,7,4,6,0);
  FUN_8025c65c(2,0,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,1,0,0,1,0);
  if (*(short *)(param_1 + 0x46) == 0x755) {
    FUN_80259288(1);
  }
  else {
    FUN_80259288(2);
  }
  FUN_8025cce8(1,4,5,5);
  gxSetZMode_(0,7,0);
  gxSetPeControl_ZCompLoc_(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(10,1);
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e454
 * EN v1.0 Address: 0x8011E454
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011E974
 * EN v1.1 Size: 584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e454(double param_1,double param_2,double param_3,double param_4,int param_5,
                 int param_6,int param_7,int param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011e458
 * EN v1.0 Address: 0x8011E458
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011EBBC
 * EN v1.1 Size: 612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e458(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 undefined param_5,int param_6,int param_7,int param_8,int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011e45c
 * EN v1.0 Address: 0x8011E45C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011EE20
 * EN v1.1 Size: 616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e45c(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 undefined param_5,uint param_6,int param_7,int param_8,uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011e460
 * EN v1.0 Address: 0x8011E460
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011F088
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e460(double param_1,double param_2,int param_3,int param_4,undefined param_5,
                 uint param_6,byte param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011e464
 * EN v1.0 Address: 0x8011E464
 * EN v1.0 Size: 840b
 * EN v1.1 Address: 0x8011F234
 * EN v1.1 Size: 768b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e464(double param_1,double param_2,double param_3,double param_4,ushort param_5,
                 ushort param_6,ushort param_7)
{
  double dVar1;
  float afStack_98 [12];
  float afStack_68 [12];
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  lbl_803DE498 = (float)param_1;
  lbl_803DE494 = (float)param_2;
  lbl_803DE490 = (float)param_3;
  lbl_803DE48C = (float)param_4;
  uStack_34 = (uint)param_5;
  local_38 = 0x43300000;
  lbl_803DE488 =
       (lbl_803E2B10 * (f32)(s32)uStack_34) /
       lbl_803E2B14;
  uStack_2c = (uint)param_6;
  local_30 = 0x43300000;
  lbl_803DE484 =
       (lbl_803E2B10 * (f32)(s32)uStack_2c) /
       lbl_803E2B14;
  uStack_24 = (uint)param_7;
  local_28 = 0x43300000;
  lbl_803DE480 =
       (lbl_803E2B10 * (f32)(s32)uStack_24) /
       lbl_803E2B14;
  PSVECDotProduct((double)lbl_803DE480,afStack_68,0x79);
  PSVECDotProduct((double)lbl_803DE484,afStack_98,0x78);
  FUN_80247618(afStack_98,afStack_68,afStack_68);
  PSVECDotProduct((double)lbl_803DE488,afStack_98,0x7a);
  FUN_80247618(afStack_98,afStack_68,afStack_68);
  dVar1 = (double)lbl_803DE48C;
  FUN_80247a7c(dVar1,dVar1,dVar1,afStack_98);
  FUN_80247618(afStack_98,afStack_68,afStack_68);
  FUN_80247a48((double)lbl_803DE498,(double)lbl_803DE494,(double)lbl_803DE490,afStack_98);
  FUN_80247618(afStack_98,afStack_68,(float *)&DAT_803a95b0);
  FUN_80247a7c((double)lbl_803DC76C,-(double)lbl_803DC770,(double)lbl_803DC774,afStack_68);
  FUN_80247a48((double)lbl_803E2B18,(double)lbl_803E2AE8,(double)lbl_803E2ABC,afStack_98);
  FUN_80247618(afStack_98,afStack_68,afStack_98);
  FUN_80247618((float *)&DAT_803a95b0,afStack_98,(float *)&DAT_803a9490);
  FUN_80247d2c((double)lbl_803DC75C,(double)lbl_803DC760,(double)lbl_803DC764,
               (double)lbl_803DC768,(float *)&DAT_803a9450);
  dVar1 = FUN_800069f8();
  lbl_803DE47C = (float)dVar1;
  FUN_80006a00((double)lbl_803DC75C);
  FUN_800069d4();
  FUN_80006954(1);
  dVar1 = (double)lbl_803E2ABC;
  FUN_80006960(dVar1,dVar1,dVar1);
  FUN_8000695c(0x8000,0,0);
  FUN_80006984();
  *(float *)(DAT_803de4e0 + 6) = lbl_803DE498;
  *(float *)(DAT_803de4e0 + 8) = lbl_803DE494;
  *(float *)(DAT_803de4e0 + 10) = lbl_803DE490;
  *(float *)(DAT_803de4e0 + 0xc) = lbl_803DE498;
  *(float *)(DAT_803de4e0 + 0xe) = lbl_803DE494;
  *(float *)(DAT_803de4e0 + 0x10) = lbl_803DE490;
  *(float *)(DAT_803de4e0 + 4) = (float)param_4;
  DAT_803de4e0[2] = param_5;
  DAT_803de4e0[1] = param_6;
  *DAT_803de4e0 = param_7;
  *(float *)(puRam803de4e4 + 6) = lbl_803DE498;
  *(float *)(puRam803de4e4 + 8) = lbl_803DE494;
  *(float *)(puRam803de4e4 + 10) = lbl_803DE490;
  *(float *)(puRam803de4e4 + 0xc) = lbl_803DE498;
  *(float *)(puRam803de4e4 + 0xe) = lbl_803DE494;
  *(float *)(puRam803de4e4 + 0x10) = lbl_803DE490;
  *(float *)(puRam803de4e4 + 4) = (float)param_4;
  puRam803de4e4[2] = param_5;
  puRam803de4e4[1] = param_6;
  *puRam803de4e4 = param_7;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e7ac
 * EN v1.0 Address: 0x8011E7AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011F534
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e7ac(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011e7b0
 * EN v1.0 Address: 0x8011E7B0
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8011F628
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_8011e7b0(void)
{
  return DAT_803de400;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e7bc
 * EN v1.0 Address: 0x8011E7BC
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8011F630
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e7bc(undefined param_1)
{
  DAT_803de433 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e7c8
 * EN v1.0 Address: 0x8011E7C8
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x8011F638
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e7c8(byte param_1)
{
  DAT_803de44c = param_1 & 1;
  if (param_1 == 3) {
    DAT_803de4b8 = 0xff;
    return;
  }
  if (2 < param_1) {
    return;
  }
  if (param_1 < 2) {
    return;
  }
  DAT_803de4b8 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e800
 * EN v1.0 Address: 0x8011E800
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8011F670
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e800(undefined param_1)
{
  DAT_803de412 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e80c
 * EN v1.0 Address: 0x8011E80C
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x8011F678
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e80c(void)
{
  DAT_803de504 = 0;
  DAT_803de4f4 = 0xffff;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e824
 * EN v1.0 Address: 0x8011E824
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8011F68C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
short FUN_8011e824(undefined2 *param_1)
{
  if (DAT_803de504 != 0) {
    *param_1 = DAT_803de50a;
  }
  return DAT_803de504;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e844
 * EN v1.0 Address: 0x8011E844
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x8011F6AC
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e844(undefined param_1)
{
  if (DAT_803de42c != '\0') {
    return;
  }
  DAT_803de42c = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e85c
 * EN v1.0 Address: 0x8011E85C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8011F6C4
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e85c(undefined2 param_1)
{
  DAT_803de42a = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e868
 * EN v1.0 Address: 0x8011E868
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x8011F6D0
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e868(undefined2 param_1)
{
  if (DAT_803de42a != 0) {
    return;
  }
  DAT_803de42a = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011e880
 * EN v1.0 Address: 0x8011E880
 * EN v1.0 Size: 656b
 * EN v1.1 Address: 0x8011F6E8
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011e880(void)
{
  short sVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  undefined4 local_58;
  int local_54;
  int local_50;
  int local_4c;
  int local_48;
  undefined4 local_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar5 = (uint)*(ushort *)(DAT_803a9790 + 0xc);
  uVar3 = (uint)DAT_803dc6c1;
  uVar2 = (uint)DAT_803dc6c0;
  uVar4 = *(ushort *)(DAT_803a978c + 10) & 0xff;
  if (DAT_803de3ee == 0) {
    sVar1 = -((ushort)DAT_803dc758 * (ushort)DAT_803dc070);
  }
  else {
    sVar1 = (ushort)DAT_803dc758 * (ushort)DAT_803dc070;
  }
  DAT_803de3ec = DAT_803de3ec + sVar1;
  if (DAT_803de3ec < 0) {
    DAT_803de3ec = 0;
  }
  else if (0xff < DAT_803de3ec) {
    DAT_803de3ec = 0xff;
  }
  if (DAT_803de3ec != 0) {
    FUN_8025db38(&local_48,&local_4c,&local_50,&local_54);
    FUN_8025da88(0,0,0x280,0x1e0);
    uStack_3c = (0x140 - (uint)DAT_803dc6c0) - uVar4 ^ 0x80000000;
    local_40 = 0x43300000;
    FUN_800709e0((double)(f32)(s32)uStack_3c,
                 (double)lbl_803E2B1C,DAT_803a978c,(int)DAT_803de3ec & 0xff,0x100,uVar4,uVar5,1);
    uStack_34 = 0x140 - DAT_803dc6c1 ^ 0x80000000;
    local_38 = 0x43300000;
    FUN_800709e0((double)(f32)(s32)uStack_34,
                 (double)lbl_803E2B1C,DAT_803a9790,(int)DAT_803de3ec & 0xff,0x100,
                 (uint)DAT_803dc6c1 << 1,uVar5,0);
    uStack_2c = 0x140 - DAT_803dc6c0 ^ 0x80000000;
    local_30 = 0x43300000;
    FUN_800709e0((double)(f32)(s32)uStack_2c,
                 (double)lbl_803E2B1C,DAT_803a9794,(int)DAT_803de3ec & 0xff,0x100,uVar2 - uVar3,
                 uVar5,0);
    uStack_24 = DAT_803dc6c1 + 0x140 ^ 0x80000000;
    local_28 = 0x43300000;
    FUN_800709e0((double)(f32)(s32)uStack_24,
                 (double)lbl_803E2B1C,DAT_803a9794,(int)DAT_803de3ec & 0xff,0x100,uVar2 - uVar3,
                 uVar5,0);
    uStack_1c = DAT_803dc6c0 + 0x140 ^ 0x80000000;
    local_20 = 0x43300000;
    FUN_800709e8((double)(f32)(s32)uStack_1c,
                 (double)lbl_803E2B1C,DAT_803a978c,(int)DAT_803de3ec & 0xff,0x100);
    local_44 = CONCAT31(0xff0000,(char)DAT_803de3ec);
    local_58 = local_44;
    FUN_8006fd90((DAT_803dc6c2 + 0x140) - (uint)DAT_803dc757,DAT_803dc756 + 0x32,
                 (uint)DAT_803dc757 + DAT_803dc6c2 + 0x140,(uVar5 + 0x32) - (uint)DAT_803dc756,
                 &local_58);
    FUN_8025da88(local_48,local_4c,local_50,local_54);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011eb10
 * EN v1.0 Address: 0x8011EB10
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8011F9B8
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011eb10(ushort param_1)
{
  DAT_803de3ee = param_1 & 0xff;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011eb1c
 * EN v1.0 Address: 0x8011EB1C
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x8011F9C4
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011eb1c(undefined param_1,undefined param_2,undefined2 param_3)
{
  DAT_803dc6c0 = param_1;
  DAT_803dc6c1 = param_2;
  DAT_803dc6c2 = param_3;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011eb38
 * EN v1.0 Address: 0x8011EB38
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8011F9D4
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011eb38(undefined param_1)
{
  DAT_803de3da = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011eb44
 * EN v1.0 Address: 0x8011EB44
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x8011FA10
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011eb44(void)
{
  uint uVar1;
  int iVar2;
  
  uVar1 = DAT_803de450;
  if (DAT_803de450 != 0) {
    *(undefined *)(DAT_803de450 + 0x18) = 0;
    iVar2 = *(int *)(uVar1 + 0x40);
    if (iVar2 == 1) {
      FUN_80053754();
      FUN_80053754();
      FUN_80053754();
      FUN_80053754();
    }
    else if ((iVar2 < 1) && (-1 < iVar2)) {
      FUN_80053754();
      FUN_80053754();
    }
    FUN_80017814(DAT_803de450);
    DAT_803de450 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011ebb8
 * EN v1.0 Address: 0x8011EBB8
 * EN v1.0 Size: 1160b
 * EN v1.1 Address: 0x8011FAA8
 * EN v1.1 Size: 1176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011ebb8(void)
{
  byte bVar1;
  int iVar2;
  short sVar3;
  ushort uVar4;
  int iVar5;
  int iVar6;
  char cVar7;
  uint uVar8;
  double dVar9;
  double dVar10;
  int local_78;
  int local_74;
  int local_70;
  int local_6c [3];
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  
  iVar5 = FUN_80017a98();
  iVar2 = DAT_803de450;
  if (DAT_803de450 != 0) {
    bVar1 = *(byte *)(DAT_803de450 + 0x18);
    if ((((*(char *)(DAT_803de450 + 0x44) < '\0') || (DAT_803de400 != '\0')) ||
        (iVar6 = FUN_800176d0(), iVar6 != 0)) ||
       (((iVar5 != 0 && ((*(ushort *)(iVar5 + 0xb0) & 0x1000) != 0)) &&
        (*(short *)(iVar2 + 0x2c) != 0x5d5)))) {
      sVar3 = (ushort)bVar1 + (ushort)DAT_803dc070 * -4;
      if (sVar3 < 0) {
        sVar3 = 0;
      }
      *(char *)(iVar2 + 0x18) = (char)sVar3;
      if ((*(char *)(iVar2 + 0x18) == '\0') && ((char)*(byte *)(iVar2 + 0x44) < '\0')) {
        *(byte *)(iVar2 + 0x44) = *(byte *)(iVar2 + 0x44) & 0x7f;
        FUN_8011eb44();
        return;
      }
    }
    else {
      uVar4 = (ushort)bVar1 + (ushort)DAT_803dc070 * 4;
      if (0xff < uVar4) {
        uVar4 = 0xff;
      }
      *(char *)(iVar2 + 0x18) = (char)uVar4;
    }
    FUN_8025db38(local_6c,&local_70,&local_74,&local_78);
    FUN_8025da88(0,0,0x280,0x1e0);
    iVar5 = *(int *)(iVar2 + 0x40);
    if (iVar5 == 1) {
      uVar4 = *(ushort *)(iVar2 + 0x2c);
      if (uVar4 == 0x643) {
        cVar7 = -0xc;
      }
      else if ((uVar4 < 0x643) && (uVar4 == 0x63e)) {
        cVar7 = -10;
      }
      else {
        cVar7 = '\0';
      }
      uStack_5c = (int)DAT_803de479 + 0xb5U ^ 0x80000000;
      local_60 = 0x43300000;
      local_6c[2] = (0x1a4 - (uint)(*(ushort *)(*(int *)(iVar2 + 0x30) + 0xc) >> 1)) +
                    (int)DAT_803dc754 + (int)cVar7 + (int)DAT_803de478 ^ 0x80000000;
      local_6c[1] = 0x43300000;
      FUN_800709e8((double)(f32)(s32)uStack_5c,
                   (double)(float)((double)CONCAT44(0x43300000,local_6c[2]) - DOUBLE_803e2af8),
                   *(int *)(iVar2 + 0x30),(uint)*(byte *)(iVar2 + 0x18),0x100);
      uVar8 = *(ushort *)(*(int *)(iVar2 + 0x30) + 10) + 0xb4;
      uStack_4c = 0x1a4 - (*(ushort *)(*(int *)(iVar2 + 0x34) + 0xc) >> 1);
      if (*(int *)(iVar2 + 8) < 0x9e) {
        *(uint *)(iVar2 + 8) = *(int *)(iVar2 + 8) + (uint)DAT_803dc070 * (uint)DAT_803dc755;
      }
      iVar5 = *(int *)(iVar2 + 0xc);
      if (iVar5 < 0) {
        iVar5 = 0;
      }
      else if (*(int *)(iVar2 + 8) < iVar5) {
        iVar5 = *(int *)(iVar2 + 8);
      }
      *(int *)(iVar2 + 0xc) = iVar5;
      iVar5 = (int)(short)iVar5;
      uStack_5c = uVar8 + iVar5 ^ 0x80000000;
      local_60 = 0x43300000;
      local_6c[2] = uStack_4c ^ 0x80000000;
      local_6c[1] = 0x43300000;
      FUN_800709e0((double)(f32)(s32)uStack_5c,
                   (double)(float)((double)CONCAT44(0x43300000,local_6c[2]) - DOUBLE_803e2af8),
                   *(undefined4 *)(iVar2 + 0x3c),(uint)*(byte *)(iVar2 + 0x18),0x100,
                   *(int *)(iVar2 + 8) - iVar5,0x1a,0);
      uStack_54 = uVar8 ^ 0x80000000;
      local_58 = 0x43300000;
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      FUN_800709e0((double)(f32)(s32)uStack_54,
                   (double)(f32)(s32)uStack_4c,
                   *(undefined4 *)(iVar2 + 0x38),(uint)*(byte *)(iVar2 + 0x18),0x100,iVar5,0x1a,0);
      uStack_44 = uVar8 + *(int *)(iVar2 + 8) ^ 0x80000000;
      local_48 = 0x43300000;
      uStack_3c = 0x1a4 - (*(ushort *)(*(int *)(iVar2 + 0x34) + 0xc) >> 1) ^ 0x80000000;
      local_40 = 0x43300000;
      FUN_800709e8((double)(f32)(s32)uStack_44,
                   (double)(f32)(s32)uStack_3c,
                   *(int *)(iVar2 + 0x34),(uint)*(byte *)(iVar2 + 0x18),0x100);
    }
    else if ((iVar5 < 1) && (-1 < iVar5)) {
      uVar8 = 0x140 - ((uint)(*(int *)(iVar2 + 0x10) * *(int *)(iVar2 + 4)) >> 1);
      dVar9 = DOUBLE_803e2af8;
      dVar10 = DOUBLE_803e2b08;
      for (iVar5 = 0; iVar5 < *(int *)(iVar2 + 4); iVar5 = iVar5 + 1) {
        if (iVar5 < *(int *)(iVar2 + 0xc)) {
          iVar6 = *(int *)(iVar2 + 0x2c);
        }
        else {
          iVar6 = *(int *)(iVar2 + 0x30);
        }
        local_6c[2] = uVar8 ^ 0x80000000;
        local_6c[1] = 0x43300000;
        uStack_5c = 0x1a4 - *(int *)(iVar2 + 0x14);
        local_60 = 0x43300000;
        FUN_800709e8((double)(float)((double)CONCAT44(0x43300000,local_6c[2]) - dVar9),
                     (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - dVar10),iVar6,
                     (uint)*(byte *)(iVar2 + 0x18),0x100);
        uVar8 = uVar8 + *(int *)(iVar2 + 0x10);
      }
    }
    FUN_8025da88(local_6c[0],local_70,local_74,local_78);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011f040
 * EN v1.0 Address: 0x8011F040
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8011FF40
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011f040(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011f044
 * EN v1.0 Address: 0x8011F044
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80120028
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011f044(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011f048
 * EN v1.0 Address: 0x8011F048
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801200F0
 * EN v1.1 Size: 4988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011f048(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011f04c
 * EN v1.0 Address: 0x8011F04C
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x8012146C
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011f04c(undefined4 param_1,undefined4 *param_2)
{
  float fVar1;
  uint uVar2;
  
  if (-1 < (int)param_2[1]) {
    param_2[1] = param_2[1] - (uint)DAT_803dc070;
    fVar1 = lbl_803E2B40;
    if ((int)param_2[1] < 0) {
      FUN_80053754();
      *param_2 = 0;
    }
    else {
      uVar2 = param_2[1] ^ 0x80000000;
      if (lbl_803E2C1C <= (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e2af8)) {
        if (lbl_803E2B40 != (float)param_2[2]) {
          param_2[2] = lbl_803E2C20 *
                       (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e2b08) +
                       (float)param_2[2];
          if (fVar1 < (float)param_2[2]) {
            param_2[2] = fVar1;
          }
        }
      }
      else {
        param_2[2] = (lbl_803E2B40 * (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e2af8)
                     ) / lbl_803E2C1C;
      }
      FUN_800033a8(-0x7fc55f78,0,0xc);
      DAT_803aa088 = *param_2;
      DAT_803aa094 = 0;
      FUN_800709e8((double)lbl_803E2C24,
                   (double)(f32)(s32)(DAT_803de3c0 + 0xafU),-0x7fc55f78,(int)(float)param_2[2],0x100);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011f210
 * EN v1.0 Address: 0x8011F210
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x801215C8
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011f210(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  DAT_803a9ff8 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              (int)param_9,param_10,param_11,param_12,param_13,param_14,param_15,
                              param_16);
  if (DAT_803a9ff8 != 0) {
    DAT_803aa004 = (undefined2)param_11;
    DAT_803aa000 = lbl_803E2ABC;
    DAT_803a9ffc = param_10;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011f2c4
 * EN v1.0 Address: 0x8011F2C4
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x8012162C
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011f2c4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined **ppuVar1;
  short *psVar2;
  undefined *puVar3;
  undefined4 uVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  undefined6 uVar6;
  
  uVar6 = FUN_80286840();
  ppuVar1 = &PTR_DAT_8031c228;
  puVar3 = &DAT_803b0000;
  DAT_803a9ff8 = 0;
  uVar4 = param_11;
  uVar5 = extraout_f1;
  do {
    psVar2 = (short *)*ppuVar1;
    if (psVar2 == (short *)0x0) {
      if (DAT_803a9ff8 != 0) {
        DAT_803aa004 = (undefined2)param_11;
        DAT_803aa000 = lbl_803E2ABC;
        DAT_803a9ffc = (int)uVar6;
      }
      FUN_8028688c();
      return;
    }
    for (; *psVar2 != -1; psVar2 = psVar2 + 8) {
      if (*psVar2 == (short)((uint6)uVar6 >> 0x20)) {
        DAT_803a9ff8 = FUN_8005398c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    (int)psVar2[3],puVar3,uVar4,param_12,param_13,param_14,param_15,
                                    param_16);
        break;
      }
    }
    ppuVar1 = ppuVar1 + 4;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_8011f438
 * EN v1.0 Address: 0x8011F438
 * EN v1.0 Size: 2816b
 * EN v1.1 Address: 0x80121724
 * EN v1.1 Size: 2060b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011f438(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  uint uVar7;
  undefined4 in_r10;
  char cVar8;
  uint uVar9;
  double dVar10;
  undefined8 uVar11;
  double dVar12;
  double in_f31;
  double in_ps31_1;
  float local_a8 [4];
  int local_98 [2];
  undefined8 local_90;
  undefined8 local_88;
  longlong local_80;
  longlong local_78;
  longlong local_70;
  longlong local_68;
  longlong local_60;
  longlong local_58;
  longlong local_50;
  longlong local_48;
  longlong local_40;
  longlong local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  FUN_80286834();
  cVar8 = '\0';
  local_98[0] = 0;
  iVar2 = FUN_80017a98();
  iVar3 = FUN_80017a90();
  FUN_8025da88(0,0,0x280,0x1e0);
  dVar10 = (double)lbl_803E2ABC;
  if ((((dVar10 <= (double)DAT_803a9f4c) || (dVar10 <= (double)DAT_803a9f68)) ||
      (dVar10 <= (double)DAT_803a9f60)) || (DAT_803de418 != 0)) {
    dVar10 = (double)lbl_803E2B40;
  }
  dVar12 = (double)lbl_803DE4C4;
  if (dVar10 <= dVar12) {
    if ((dVar10 < dVar12) &&
       (lbl_803DE4C4 = -(float)((double)lbl_803E2C20 * (double)lbl_803DC074 - dVar12),
       lbl_803DE4C4 < lbl_803E2ABC)) {
      lbl_803DE4C4 = lbl_803E2ABC;
    }
  }
  else {
    lbl_803DE4C4 = (float)((double)lbl_803E2C20 * (double)lbl_803DC074 + dVar12);
    if (lbl_803E2B40 < lbl_803DE4C4) {
      lbl_803DE4C4 = lbl_803E2B40;
    }
  }
  uVar7 = (uint)lbl_803DE4BC;
  local_90 = (double)(longlong)(int)uVar7;
  if ((uVar7 & 0xff) != 0) {
    dVar12 = (double)*(float *)(iVar2 + 0x14);
    iVar4 = FUN_8005b024();
    if ((((DAT_803a9f4c <= lbl_803E2C1C) || (lbl_803E2C28 <= DAT_803a9f4c)) ||
        (local_90 = (double)(longlong)(int)DAT_803a9f4c, ((int)DAT_803a9f4c & 8U) == 0)) &&
       ((((DAT_803a9f68 <= lbl_803E2C1C || (lbl_803E2C28 <= DAT_803a9f68)) ||
         (local_90 = (double)(longlong)(int)DAT_803a9f68, ((int)DAT_803a9f68 & 8U) == 0)) &&
        ((iVar4 != 0 || (iVar4 = FUN_80294dbc(iVar2), iVar4 == 0)))))) {
      dVar10 = DOUBLE_803e2af8;
      for (uVar9 = 0; uVar5 = uVar9 & 0xff, (int)uVar5 < DAT_803a9fe0 >> 2; uVar9 = uVar9 + 1) {
        if ((int)uVar5 < (int)DAT_803a9fc4 >> 2) {
          iVar4 = 0x16;
        }
        else if ((int)DAT_803a9fc4 >> 2 < (int)uVar5) {
          iVar4 = 0x12;
        }
        else {
          iVar4 = (DAT_803a9fc4 & 3) + 0x12;
        }
        local_90 = (double)CONCAT44(0x43300000,uVar5 * 0x21 + 0x1e ^ 0x80000000);
        dVar12 = (double)lbl_803E2C2C;
        FUN_800709e8((double)(float)(local_90 - dVar10),dVar12,(&DAT_803a9610)[iVar4],uVar7,0x100);
      }
    }
  }
  if ((((uVar7 & 0xff) != 0) && (uVar9 = FUN_80294be4(iVar2), uVar9 != 0)) &&
     (uVar9 = GameBit_Get(0xeb1), uVar9 != 0)) {
    hudDrawMagicBar(uVar7,0x100,0);
  }
  iVar2 = 0;
  uVar9 = playerHasKrazoaSpirit('\x01',0);
  uVar5 = GameBit_Get(0x123);
  if ((uVar5 == 0) && (uVar5 = GameBit_Get(0x83b), uVar5 == 0)) {
    uVar5 = GameBit_Get(0x2e8);
    if ((uVar5 != 0) || (uVar5 = GameBit_Get(0x83c), uVar5 != 0)) {
      iVar2 = 100;
    }
  }
  else {
    iVar2 = 99;
  }
  if (iVar2 != 0) {
    if (uVar9 != 0) {
      sVar1 = 0x104;
    }
    else {
      sVar1 = 0x122;
    }
    dVar12 = (double)lbl_803E2C2C;
    FUN_800709e8((double)(f32)(s32)((int)sVar1),dVar12,(&DAT_803a9610)[iVar2],uVar7,
                 0x100);
  }
  if (uVar9 != 0) {
    if (iVar2 == 0) {
      sVar1 = 0x122;
    }
    else {
      sVar1 = 0x140;
    }
    dVar12 = (double)lbl_803E2C2C;
    FUN_800709e8((double)(f32)(s32)((int)sVar1),dVar12,DAT_803a9798,uVar7,0x100);
  }
  if (((uVar7 & 0xff) != 0) && (iVar3 != 0)) {
    cVar8 = '\x16';
    if ((DAT_803a9f70 <= lbl_803E2C1C) ||
       ((lbl_803E2C28 <= DAT_803a9f70 ||
        (local_90 = (double)(longlong)(int)DAT_803a9f70, ((int)DAT_803a9f70 & 8U) == 0)))) {
      dVar12 = (double)lbl_803E2C30;
      FUN_800709e8((double)lbl_803E2C1C,dVar12,DAT_803a9764,uVar7,0x100);
    }
    for (uVar9 = 0; (uVar9 & 0xff) < 0x14; uVar9 = uVar9 + 4) {
      uVar5 = uVar9 & 0xff;
      if (((DAT_803a9fe8 & 0xfc) == uVar5) && ((DAT_803a9fe8 & 2) != 0)) {
        iVar2 = (int)(uVar5 * 0xf) >> 2;
        FUN_800709e0((double)(f32)(s32)(iVar2 + 0x40U),(double)lbl_803E2C34,DAT_803a976c
                     ,uVar7,0x100,6,0x12,0);
        dVar12 = (double)lbl_803E2C34;
        FUN_800709d8((double)(f32)(s32)(iVar2 + 0x46U),dVar12,DAT_803a9768,uVar7,0x100,7,
                     0x12,6,0);
      }
      else {
        if ((int)uVar5 < (int)DAT_803a9fe8) {
          iVar2 = 0x57;
        }
        else {
          iVar2 = 0x56;
        }
        dVar12 = (double)lbl_803E2C34;
        FUN_800709e8((double)(f32)(s32)(((int)(uVar5 * 0xf) >> 2) + 0x40U),dVar12,(&DAT_803a9610)[iVar2],uVar7
                     ,0x100);
      }
    }
  }
  iVar2 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  if ((iVar2 < 0x49) && (0x46 < iVar2)) {
    dVar12 = (double)(f32)(s32)((int)cVar8 + 0x5fU);
    FUN_800709e8((double)lbl_803E2C1C,dVar12,DAT_803a97a4,uVar7,0x100);
  }
  uVar11 = FUN_8025da88(0,0,0x280,0x1e0);
  if (DAT_803de3da == '\0') {
    uVar7 = GameBit_Get(0x91b);
    if (uVar7 == 0) {
      uVar7 = GameBit_Get(0x91a);
      if (uVar7 == 0) {
        uVar7 = GameBit_Get(0x919);
        if (uVar7 == 0) {
          sVar1 = 10;
        }
        else {
          sVar1 = 0x32;
        }
      }
      else {
        sVar1 = 100;
      }
    }
    else {
      sVar1 = 200;
    }
    local_88 = (double)(longlong)(int)DAT_803a9f24;
    local_90 = (double)(longlong)(int)DAT_803a9f58;
    uVar11 = FUN_801225a8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1e,
                          (int)(short)DAT_803a9fd0,sVar1,(int)DAT_803a9f24,(int)DAT_803a9f58,
                          local_98,0,in_r10);
    local_80 = (longlong)(int)DAT_803a9f28;
    local_78 = (longlong)(int)DAT_803a9f5c;
    uVar11 = FUN_801225a8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x19,
                          (int)(short)DAT_803a9fd4,7,(int)DAT_803a9f28,(int)DAT_803a9f5c,local_98,0,
                          in_r10);
    local_70 = (longlong)(int)DAT_803a9f1c;
    local_68 = (longlong)(int)DAT_803a9f50;
    uVar11 = FUN_801225a8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1a,
                          (int)(short)DAT_803a9fc8,0xf,(int)DAT_803a9f1c,(int)DAT_803a9f50,local_98,
                          0,in_r10);
    local_60 = (longlong)(int)DAT_803a9f40;
    local_58 = (longlong)(int)DAT_803a9f74;
    uVar11 = FUN_801225a8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x18,
                          (int)(short)DAT_803a9fec,0x1f,(int)DAT_803a9f40,(int)DAT_803a9f74,local_98
                          ,0,in_r10);
    local_50 = (longlong)(int)DAT_803a9f44;
    local_48 = (longlong)(int)DAT_803a9f78;
    uVar11 = FUN_801225a8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1b,
                          (int)(short)DAT_803a9ff0,7,(int)DAT_803a9f44,(int)DAT_803a9f78,local_98,0,
                          in_r10);
    local_40 = (longlong)(int)DAT_803a9f48;
    local_38 = (longlong)(int)DAT_803a9f7c;
    FUN_801225a8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1c,
                 (int)(short)DAT_803a9ff4,0xff,(int)DAT_803a9f48,(int)DAT_803a9f7c,local_98,0,in_r10
                );
  }
  else {
    local_a8[3] = 0.0;
    local_a8[2] = 0.0;
    local_a8[1] = 0.0;
    local_a8[0] = lbl_803E2C18;
    uVar6 = FUN_80017a98();
    iVar2 = ObjGroup_FindNearestObject(9,uVar6,local_a8);
    if ((iVar2 != 0) && (DAT_803de400 == '\0')) {
      uVar11 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x54))
                         (iVar2,local_a8 + 3,local_a8 + 2,local_a8 + 1);
      local_98[0] = 0x118;
      FUN_801225a8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1e,
                   (int)(short)(SUB42(local_a8[2],0) - SUB42(local_a8[3],0)),SUB42(local_a8[1],0),
                   0xff,0,local_98,1,in_r10);
    }
  }
  FUN_80286880();
  return;
}

/* sda21 accessors. */
extern u8 pauseMenuState;
extern u8 lbl_803DD7B3;
extern u8 lbl_803DD792;
extern u8 lbl_803DD75A;
extern u8 lbl_803DBA88;
u8 pauseMenuGetState(void) { return pauseMenuState; }
void fn_8011F34C(u8 x) { lbl_803DD7B3 = x; }
void hudFn_8011f38c(u8 x) { lbl_803DD792 = x; }
void hudFn_8011f6f0(u8 x) { lbl_803DD75A = x; }
void GameUI_func0E(u8 x) { lbl_803DBA88 = x; }

/* sth (s16 store) of zero-extended u8 — extsh + sth pattern */
extern s16 lbl_803DD76E;
void fn_8011F6D4(u32 x) {
    lbl_803DD76E = (s16)(u8)x;
}

/* forceAButtonIcon: extsh + sth aButtonIcon */
extern s16 aButtonIcon;
#pragma peephole off
#pragma scheduling off
void forceAButtonIcon(int x) {
    aButtonIcon = (s16)x;
}
#pragma scheduling on
#pragma peephole on

/* resetYbutton: zero out two halfwords */
extern s16 yButtonItemTextureId;
extern u16 yButtonState;
#pragma scheduling off
void resetYbutton(void) {
    yButtonState = 0;
    yButtonItemTextureId = -1;
}
#pragma scheduling on

/* setBButtonIcon: stb if zero */
extern u8 bButtonIcon;
#pragma peephole off
#pragma scheduling off
void setBButtonIcon(int x) {
    if (bButtonIcon == 0) {
        bButtonIcon = (u8)x;
    }
}
#pragma scheduling on
#pragma peephole on

/* setAButtonIcon: sth if aButtonIcon == 0 */
#pragma peephole off
#pragma scheduling off
void setAButtonIcon(int x) {
    if (aButtonIcon == 0) {
        aButtonIcon = (s16)x;
    }
}
#pragma scheduling on
#pragma peephole on

/* fearTestMeterSetRange: store the outer/inner half-widths and marker X. */
extern u8 fearTestMeterOuterHalfWidth;
extern u8 fearTestMeterInnerHalfWidth;
extern s16 fearTestMeterMarkerX;
void fearTestMeterSetRange(u8 a, u8 b, s16 c) {
    fearTestMeterOuterHalfWidth = a;
    fearTestMeterInnerHalfWidth = b;
    fearTestMeterMarkerX = c;
}

/* GameUI_airMeterSetField24: store float at *p + 0x24 if p non-null */
extern void *airMeter;
void GameUI_airMeterSetField24(float v) {
    void *p = airMeter;
    if (p == 0) return;
    *(f32 *)((char *)p + 0x24) = v;
}

/* cutSceneFn_8011dd30: init / setup */
extern void cutsceneFadeInOut(int x);
extern void setTimeStop(int x);
extern void pauseMenuInit(void);
extern int getCurGameText(void);
extern void gameTextLoadDir(int x);
extern f32 lbl_803E1E60;
extern f32 lbl_803DD764;
extern int lbl_803DD8DC;
extern int lbl_803DD7D8;
#pragma scheduling off
void cutSceneFn_8011dd30(void) {
    cutsceneFadeInOut(1);
    setTimeStop(0xff);
    pauseMenuInit();
    pauseMenuState = 0xb;
    lbl_803DD8DC = getCurGameText();
    gameTextLoadDir(0xb);
    lbl_803DD764 = lbl_803E1E60;
    lbl_803DD7D8 = 1;
}
#pragma scheduling on

/* GameUI_setInputOverride */
extern int lbl_803DD8A0;
extern s16 lbl_803DD89E;
extern s16 lbl_803DD89C;
extern u8 lbl_803DD8AC;
#pragma scheduling off
void GameUI_setInputOverride(int x, s16 a, s16 b) {
    if (x == -1) {
        lbl_803DD8A0 = 0;
        lbl_803DD89E = 0;
        lbl_803DD89C = 0;
        lbl_803DD8AC = 0;
        return;
    }
    lbl_803DD8A0 = x;
    lbl_803DD89E = a;
    lbl_803DD89C = b;
    lbl_803DD8AC = 1;
}
#pragma scheduling on

/* arwingHudSetVisible */
extern u8 arwingHudVisible;
extern s16 arwingHudAlpha;
#pragma peephole off
#pragma scheduling off
void arwingHudSetVisible(u32 x) {
    u32 v = x & 0xff;
    arwingHudVisible = (u8)(v & 1);
    if ((s32)v != 3) {
        if ((s32)v >= 3) return;
        if ((s32)v < 2) return;
        arwingHudAlpha = 0;
        return;
    }
    arwingHudAlpha = (s16)0xff;
}
#pragma scheduling on
#pragma peephole on

/* getYButtonItem: read yButtonState; if non-zero, set *out = yButtonItem; return yButtonState */
extern u16 yButtonItem;
#pragma peephole off
u16 getYButtonItem(s16 *out) {
    s32 t;
    if (yButtonState != 0) {
        t = (s16)yButtonItem;
        *out = (s16)t;
    }
    return yButtonState;
}
#pragma peephole on

/* GameUI_airMeterSetShutdown: set bit 7 of (*p)+0x44 if p non-null — uses bitfield insert (rlwimi) */
typedef struct {
    char pad[0x44];
    u8 bit7 : 1;
    u8 bits_0to6 : 7;
} _Obj8011F70C;
#pragma scheduling off
#pragma peephole off
void GameUI_airMeterSetShutdown(void) {
    _Obj8011F70C *p = (_Obj8011F70C *)airMeter;
    if (p == 0) return;
    p->bit7 = 1;
}
#pragma peephole reset
#pragma scheduling reset

extern void *textureLoadAsset(int id);
extern const f32 lbl_803E1E3C;
extern int lbl_803A9398[];

extern void textureFree(int handle);
extern void mm_free(void *p);
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void GameUI_airMeterShutdown(void) {
    int *m = (int *)airMeter;
    if (m == NULL) return;
    *(u8 *)((char *)m + 0x18) = 0;
    switch (m[0x10]) {
        case 0:
            textureFree(m[0xb]);
            textureFree(m[0xc]);
            break;
        case 1:
            textureFree(m[0xc]);
            textureFree(m[0xd]);
            textureFree(m[0xe]);
            textureFree(m[0xf]);
            break;
    }
    mm_free(airMeter);
    airMeter = NULL;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

extern void *mmAlloc(int size, int type, int x);
extern void *memset(void *p, int v, int n);
extern const f32 lbl_803E1E68;

#pragma scheduling off
#pragma peephole off
void GameUI_initAirMeter(int a, int b) {
    int *m;
    if (airMeter == NULL) {
    } else if ((((_Obj8011F70C*)airMeter)->bit7) != 0) {
        GameUI_airMeterShutdown();
    } else {
        return;
    }
    m = (int*)mmAlloc(0x48, 0x19, 0);
    memset(m, 0, 0x48);
    m[0] = 0;
    m[1] = a;
    m[2] = 0;
    m[0xc] = (int)textureLoadAsset(b);
    *(u16*)((char*)m + 0x2c) = (u16)b;
    m[0xd] = (int)textureLoadAsset(0x5d4);
    m[0xe] = (int)textureLoadAsset(0x5d3);
    m[0xf] = (int)textureLoadAsset(0x5d2);
    airMeter = m;
    *(u8*)((char*)m + 0x18) = 0;
    *(f32*)((char*)m + 0x24) = lbl_803E1E68;
    m[0x10] = 1;
}
#pragma peephole reset
#pragma scheduling reset

extern int *gMapEventInterface;
extern u8 lbl_803DB424;
extern int lbl_803DD8DC;
extern int lbl_803DD7D8;
extern f32 lbl_803DD764;
extern f32 lbl_803E1E60;
extern void pauseMenuInit(void);
extern int getCurGameText(void);
extern void gameTextLoadDir(int);
#pragma scheduling off
#pragma peephole off
void showDeathMenu(void) {
    int *o = (int *)*gMapEventInterface;
    int *r = (int *)(*(int (*)(int *))(*(int *)((char *)o + 0x8c)))(o);
    pauseMenuInit();
    if (*((u8 *)r + 9) != 0) {
        pauseMenuState = 8;
    } else if (lbl_803DB424 != 0) {
        pauseMenuState = 9;
    } else {
        pauseMenuState = 0xa;
    }
    lbl_803DD8DC = getCurGameText();
    gameTextLoadDir(0xb);
    lbl_803DD764 = lbl_803E1E60;
    lbl_803DD7D8 = 1;
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void GameUI_func15(s16 a, int b, int c) {
    void *t = textureLoadAsset(a);
    lbl_803A9398[0] = (int)t;
    if (t == NULL) return;
    lbl_803A9398[1] = b;
    *(s16 *)((char *)lbl_803A9398 + 0xc) = (s16)c;
    *(f32 *)((char *)lbl_803A9398 + 0x8) = lbl_803E1E3C;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void GameUI_airMeterRun(int v) {
    int *m = (int *)airMeter;
    int clamped;
    if (m == NULL) return;
    clamped = (v < 0) ? 0 : ((v > m[1]) ? m[1] : v);
    v = clamped;
    if (m[0x10] == 1) {
        v = clamped * 0x9e / m[1];
    }
    m[3] = v;
}
#pragma peephole reset
#pragma scheduling reset

extern u8 cMenuEnabled;
extern u16 curGameText;
extern s16 lbl_803DD8D0;
extern u8 lbl_803DD7A8;
extern s16 lbl_803DD778;
extern int lbl_803DD730;
extern s16 lbl_803DD770;
extern f32 lbl_803DD760;
extern int lbl_803A9410[];
extern u8 lbl_803DD75B;
extern s16 lbl_803DD772;
extern u8 pauseMenuFrameCounter;
extern void Obj_FreeObject(int *obj);
#pragma scheduling off
#pragma peephole off
void gameUiResetMenuState(void) {
    int i;
    cMenuEnabled = 0;
    curGameText = 0xffff;
    lbl_803DD8D0 = 0;
    lbl_803DD7A8 = 0;
    GameUI_airMeterShutdown();
    pauseMenuState = 0;
    lbl_803DD778 = 0;
    lbl_803DD730 = 0;
    lbl_803DD770 = 0;
    lbl_803DD760 = lbl_803E1E3C;
    {
        int **p = (int **)lbl_803A9410;
        for (i = 0; i < 4; p++, i++) {
            if (*p != NULL) {
                ((int *)(*p)[0x19])[1] = 0;
                ((int *)(*p)[0x19])[2] = 0;
                if ((u32)(*p)[0x13] > 0x90000000) (*p)[0x13] = 0;
                Obj_FreeObject(*p);
                *p = NULL;
            }
        }
    }
    lbl_803DD75A = 0;
    lbl_803DD75B = 0;
    lbl_803DD772 = 0;
    pauseMenuFrameCounter = 0x3c;
    lbl_803DD792 = 0;
}
#pragma peephole reset
#pragma scheduling reset

extern const f32 lbl_803E1E68;
#pragma scheduling off
#pragma peephole off
void GameUI_airMeterInitType0(int a, int b, int c) {
    int *m;
    if (airMeter != NULL) return;
    m = (int *)mmAlloc(0x48, 0x19, 0);
    memset(m, 0, 0x48);
    m[0] = 0;
    m[1] = a;
    m[0xb] = (int)textureLoadAsset(b);
    m[0xc] = (int)textureLoadAsset(c);
    m[4] = *(u16 *)((char *)m[0xb] + 0xa);
    m[5] = *(u16 *)((char *)m[0xb] + 0xc);
    airMeter = m;
    *(u8 *)((char *)m + 0x18) = 0;
    *(f32 *)((char *)m + 0x24) = lbl_803E1E68;
    m[0x10] = 0;
}
#pragma peephole reset
#pragma scheduling reset

extern int lbl_8031B5D8[];
#pragma scheduling off
#pragma peephole off
void GameUI_func14(s16 a, int b, int c) {
    int *entry = lbl_8031B5D8;
    lbl_803A9398[0] = 0;
    while (*(void **)entry != NULL) {
        s16 *row = (s16 *)*entry;
        while (row[0] != -1) {
            if (row[0] == a) {
                lbl_803A9398[0] = (int)textureLoadAsset(row[3]);
                break;
            }
            row += 8;
        }
        entry = (int *)((char *)entry + 0x10);
    }
    if (*(void **)lbl_803A9398 != NULL) {
        lbl_803A9398[1] = b;
        *(s16 *)((char *)lbl_803A9398 + 0xc) = (s16)c;
        *(f32 *)((char *)lbl_803A9398 + 0x8) = lbl_803E1E3C;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern u8 framesThisStep;
extern const f32 hudElementOpacity;
extern f32 lbl_803E1F9C;
extern f32 lbl_803E1FA0;
extern f32 lbl_803E1FA4;
extern int lbl_803DD740;
extern int lbl_803A9428[];
extern void textureFree(int handle);
extern void drawTexture(void *p, f32 a, f32 b, int c, int d);
#pragma scheduling off
#pragma peephole off
void hudDrawTimedElement(int unused, int *e) {
    if (e[1] < 0) return;
    e[1] = e[1] - framesThisStep;
    if (e[1] < 0) {
        textureFree(e[0]);
        e[0] = 0;
        return;
    }
    if ((f32)e[1] < lbl_803E1F9C) {
        *(f32 *)((char *)e + 0x8) = hudElementOpacity * (f32)e[1] / lbl_803E1F9C;
    } else {
        f32 cur = *(f32 *)((char *)e + 0x8);
        if (hudElementOpacity != cur) {
            *(f32 *)((char *)e + 0x8) = lbl_803E1FA0 * (f32)(u32)framesThisStep + cur;
            if (*(f32 *)((char *)e + 0x8) > hudElementOpacity) {
                *(f32 *)((char *)e + 0x8) = hudElementOpacity;
            }
        }
    }
    memset(lbl_803A9428, 0, 0xc);
    lbl_803A9428[0] = e[0];
    lbl_803A9428[3] = 0;
    drawTexture(lbl_803A9428, lbl_803E1FA4, (f32)(lbl_803DD740 + 0xaf),
                (int)*(f32 *)((char *)e + 0x8), 0x100);
}
#pragma peephole reset
#pragma scheduling reset

typedef union {
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} PPCWGPipe;
volatile PPCWGPipe GXWGFifo : (0xCC008000);

extern void GXBegin(int type, int fmt, int n);
extern f32 lbl_803E1E80;
extern void pauseMenuMapFn_8011de20(void *this, int a, s16 b, int c);
#pragma scheduling off
#pragma peephole off
void pauseMenuDrawElement(void *this, f32 fx, f32 fy, int p4, int p5, int p6, int p7) {
    int dx, dy;
    f32 c0, c1;
    pauseMenuMapFn_8011de20(this, p5, (s16)p4, p7 & 4);
    dx = (*(u16 *)((char *)this + 0xa) << 2) * (u16)p6 / 256;
    dy = (*(u16 *)((char *)this + 0xc) << 2) * (u16)p6 / 256;
    fx = lbl_803E1E80 * fx;
    fy = lbl_803E1E80 * fy;
    GXBegin(0x80, 1, 4);
    c0 = lbl_803E1E3C;
    c1 = lbl_803E1E68;
    GXWGFifo.s16 = (s16)fx;
    GXWGFifo.s16 = (s16)fy;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = c0;
    GXWGFifo.f32 = c0;
    GXWGFifo.s16 = (s16)(fx + (f32)(u32)dx);
    GXWGFifo.s16 = (s16)fy;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = c1;
    GXWGFifo.f32 = c0;
    GXWGFifo.s16 = (s16)(fx + (f32)(u32)dx);
    GXWGFifo.s16 = (s16)(fy + (f32)(u32)dy);
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = c1;
    GXWGFifo.f32 = c1;
    GXWGFifo.s16 = (s16)fx;
    GXWGFifo.s16 = (s16)(fy + (f32)(u32)dy);
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = c0;
    GXWGFifo.f32 = c1;
}
#pragma peephole reset
#pragma scheduling reset

typedef struct { u8 r, g, b, a; } GXColor;
extern void GXSetTevColor(int id, GXColor c);
extern void GXSetTevKColor(int id, GXColor c);
extern void GXLoadPosMtxImm(void *m, int id);
extern void GXLoadNrmMtxImm(void *m, int id);
extern void GXSetCurrentMtx(int id);
extern void GXSetNumTexGens(int n);
extern void GXSetNumIndStages(int n);
extern void GXSetNumChans(int n);
extern void textureFn_8004c264(void *this, int x);
extern void GXSetTexCoordGen2(int a, int b, int c, int d, int e, int f);
extern void GXSetTevKColorSel(int stage, int sel);
extern void GXSetTevDirect(int stage);
extern void GXSetTevOrder(int stage, int a, int b, int c);
extern void GXSetTevColorIn(int stage, int a, int b, int c, int d);
extern void GXSetTevAlphaIn(int stage, int a, int b, int c, int d);
extern void GXSetTevSwapMode(int stage, int a, int b);
extern void GXSetTevColorOp(int stage, int a, int b, int c, int d, int e);
extern void GXSetTevAlphaOp(int stage, int a, int b, int c, int d, int e);
extern void GXSetNumTevStages(int n);
extern void GXSetCullMode(int m);
extern void GXSetAlphaCompare(int a, int b, int c, int d, int e);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int a, int b);
extern int lbl_803E1E34;
extern int lbl_803E1E38;
extern char lbl_803A8830[];
#pragma scheduling off
#pragma peephole off
void pauseMenuMapFn_8011de20(void *this, int a, s16 b, int c) {
    GXColor colA = *(GXColor *)&lbl_803E1E34;
    GXColor colB = *(GXColor *)&lbl_803E1E38;
    colA.a = (u8)a;
    GXSetTevColor(1, colA);
    GXLoadPosMtxImm(lbl_803A8830, 0);
    GXLoadNrmMtxImm(lbl_803A8830, 0);
    GXSetCurrentMtx(0);
    GXSetNumTexGens(1);
    GXSetNumIndStages(0);
    GXSetNumChans(0);
    textureFn_8004c264(this, 0);
    GXSetTexCoordGen2(0, 1, 4, 0x3c, 0, 0x7d);
    GXSetTevKColorSel(0, 0xc);
    GXSetTevKColor(0, colB);
    GXSetTevDirect(0);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 2, 8, 0xe, 0xf);
    GXSetTevAlphaIn(0, 7, 1, 4, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    if (*(void **)((char *)this + 0x50) != NULL) {
        GXSetTevDirect(1);
        GXSetTevOrder(1, 0, 1, 0xff);
        GXSetTevColorIn(1, 0xf, 0xf, 0xf, 0);
        GXSetTevAlphaIn(1, 7, 1, 4, 7);
        GXSetTevSwapMode(1, 0, 0);
        GXSetTevColorOp(1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
        GXSetNumTevStages(2);
    } else {
        GXSetNumTevStages(1);
    }
    GXSetCullMode(0);
    if ((u8)c != 0) {
        GXSetBlendMode(1, 4, 1, 5);
    } else {
        GXSetBlendMode(1, 4, 5, 5);
    }
    gxSetZMode_(0, 7, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
}
#pragma peephole reset
#pragma scheduling reset

extern s16 lbl_803DBA8A;
extern f32 lbl_803DBA8C;

#pragma scheduling off
#pragma peephole off
void pauseMenuTextDrawFn(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1) {
    s16 z;
    GXLoadPosMtxImm(lbl_803A8830, 0);
    GXLoadNrmMtxImm(lbl_803A8830, 0);
    GXSetCurrentMtx(0);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
    GXSetCullMode(0);
    x0 -= 0x500;
    y0 -= 0x3c0;
    x1 -= 0x500;
    y1 -= 0x3c0;
    x0 = (f32)x0 * lbl_803DBA8C;
    y0 = (f32)y0 * lbl_803DBA8C;
    x1 = (f32)x1 * lbl_803DBA8C;
    y1 = (f32)y1 * lbl_803DBA8C;
    GXBegin(0x80, 1, 4);
    z = (s16)(lbl_803DBA8A << 2);
    GXWGFifo.s16 = (s16)(x0 + 0x500);
    GXWGFifo.s16 = (s16)(y0 + 0x3c0);
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;
    z = (s16)(lbl_803DBA8A << 2);
    GXWGFifo.s16 = (s16)(x1 + 0x500);
    GXWGFifo.s16 = (s16)(y0 + 0x3c0);
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;
    z = (s16)(lbl_803DBA8A << 2);
    GXWGFifo.s16 = (s16)(x1 + 0x500);
    GXWGFifo.s16 = (s16)(y1 + 0x3c0);
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;
    z = (s16)(lbl_803DBA8A << 2);
    GXWGFifo.s16 = (s16)(x0 + 0x500);
    GXWGFifo.s16 = (s16)(y1 + 0x3c0);
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drawFn_8011e8d8(void *this, f32 f1, f32 f2, int p4, int p5, int p6, int p7, int p8, int p9) {
    f32 sx, sy, u0, v0, u1, v1;
    u32 w, h;
    pauseMenuMapFn_8011de20(this, p5, (s16)p4, 0);
    sx = lbl_803E1E80 * f1;
    sy = lbl_803E1E80 * f2;
    w = *(u16 *)((char *)this + 0xa);
    h = *(u16 *)((char *)this + 0xc);
    u0 = (f32)(u32)p8 / (f32)w;
    v0 = (f32)(u32)p9 / (f32)h;
    u1 = (f32)(u32)(p6 + p8) / (f32)w;
    v1 = (f32)(u32)(p7 + p9) / (f32)h;
    GXBegin(0x80, 1, 4);
    GXWGFifo.s16 = (s16)sx;
    GXWGFifo.s16 = (s16)sy;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)(p6 << 2));
    GXWGFifo.s16 = (s16)sy;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)(p6 << 2));
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)(p7 << 2));
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;
    GXWGFifo.s16 = (s16)sx;
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)(p7 << 2));
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drawFn_8011eb3c(void *this, f32 f1, f32 f2, int p4, int p5, int p6, int p7, int p8, int p9) {
    f32 sx, sy, ua, ub, va, vb, tu, tv;
    u32 dx, dy;
    u8 flags = (u8)p9;
    pauseMenuMapFn_8011de20(this, p5, (s16)p4, flags & 4);
    dx = ((u32)(p7 << 2) * (u16)p6) >> 8;
    dy = ((u32)(p8 << 2) * (u16)p6) >> 8;
    sx = lbl_803E1E80 * f1;
    sy = lbl_803E1E80 * f2;
    tu = (f32)(u32)p7 / (f32)(u32)*(u16 *)((char *)this + 0xa);
    tv = (f32)(u32)p8 / (f32)(u32)*(u16 *)((char *)this + 0xc);
    if (flags & 1) {
        ua = tu;
        ub = lbl_803E1E3C;
    } else {
        ua = lbl_803E1E3C;
        ub = tu;
    }
    if (flags & 2) {
        va = tv;
        vb = lbl_803E1E3C;
    } else {
        va = lbl_803E1E3C;
        vb = tv;
    }
    GXBegin(0x80, 1, 4);
    GXWGFifo.s16 = (s16)sx;
    GXWGFifo.s16 = (s16)sy;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = ua;
    GXWGFifo.f32 = va;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)dx);
    GXWGFifo.s16 = (s16)sy;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = ub;
    GXWGFifo.f32 = va;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)dx);
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)dy);
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = ub;
    GXWGFifo.f32 = vb;
    GXWGFifo.s16 = (s16)sx;
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)dy);
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = ua;
    GXWGFifo.f32 = vb;
}
#pragma peephole reset
#pragma scheduling reset

extern void PSMTXRotRad(f32 *m, int axis, f32 rad);
extern void PSMTXConcat(f32 *a, f32 *b, f32 *out);
extern void PSMTXScale(f32 *m, f32 x, f32 y, f32 z);
extern void PSMTXTrans(f32 *m, f32 x, f32 y, f32 z);
extern void C_MTXPerspective(f32 *m, f32 fovY, f32 aspect, f32 nearP, f32 farP);
extern f32 Camera_GetFovY(void);
extern void Camera_SetFovY(f32);
extern void Camera_RebuildProjectionMatrix(void);
extern void Camera_SetCurrentViewIndex(s32);
extern void Camera_SetCurrentViewPosition(f32, f32, f32);
extern void Camera_SetCurrentViewRotation(s32, s32, s32);
extern void Camera_UpdateViewMatrices(void);
extern f32 lbl_803DD818, lbl_803DD814, lbl_803DD810, lbl_803DD80C;
extern f32 lbl_803DD808, lbl_803DD804, lbl_803DD800, lbl_803DD7FC;
extern const f32 lbl_803E1E94;
extern f32 lbl_803E1E90, lbl_803E1E98;
extern f32 lbl_803DBB04, lbl_803DBB08, lbl_803DBB0C;
extern f32 lbl_803DBAF4, lbl_803DBAF8, lbl_803DBAFC, lbl_803DBB00;
extern char lbl_803A87F0[];
extern char *lbl_803DD860[];
#pragma scheduling off
#pragma peephole off
void fn_8011EF50(u16 a, u16 b, u16 c, f32 f1, f32 f2, f32 f3, f32 f4) {
    char *base = lbl_803A87F0;
    f32 mA[12];
    f32 mB[12];
    lbl_803DD818 = f1;
    lbl_803DD814 = f2;
    lbl_803DD810 = f3;
    lbl_803DD80C = f4;
    lbl_803DD808 = lbl_803E1E90 * (f32)(u32)a / lbl_803E1E94;
    lbl_803DD804 = lbl_803E1E90 * (f32)(u32)b / lbl_803E1E94;
    lbl_803DD800 = lbl_803E1E90 * (f32)(u32)c / lbl_803E1E94;
    PSMTXRotRad(mA, 0x79, lbl_803DD800);
    PSMTXRotRad(mB, 0x78, lbl_803DD804);
    PSMTXConcat(mB, mA, mA);
    PSMTXRotRad(mB, 0x7a, lbl_803DD808);
    PSMTXConcat(mB, mA, mA);
    PSMTXScale(mB, lbl_803DD80C, lbl_803DD80C, lbl_803DD80C);
    PSMTXConcat(mB, mA, mA);
    PSMTXTrans(mB, lbl_803DD818, lbl_803DD814, lbl_803DD810);
    PSMTXConcat(mB, mA, (f32 *)(base + 0x160));
    PSMTXScale(mA, lbl_803DBB04, -lbl_803DBB08, lbl_803DBB0C);
    PSMTXTrans(mB, lbl_803E1E98, lbl_803E1E68, lbl_803E1E3C);
    PSMTXConcat(mB, mA, mB);
    PSMTXConcat((f32 *)(base + 0x160), mB, (f32 *)(base + 0x40));
    C_MTXPerspective((f32 *)base, lbl_803DBAF4, lbl_803DBAF8, lbl_803DBAFC, lbl_803DBB00);
    lbl_803DD7FC = Camera_GetFovY();
    Camera_SetFovY(lbl_803DBAF4);
    Camera_RebuildProjectionMatrix();
    Camera_SetCurrentViewIndex(1);
    Camera_SetCurrentViewPosition(lbl_803E1E3C, lbl_803E1E3C, lbl_803E1E3C);
    Camera_SetCurrentViewRotation(0x8000, 0, 0);
    Camera_UpdateViewMatrices();
    *(f32 *)(lbl_803DD860[0] + 0xc) = lbl_803DD818;
    *(f32 *)(lbl_803DD860[0] + 0x10) = lbl_803DD814;
    *(f32 *)(lbl_803DD860[0] + 0x14) = lbl_803DD810;
    *(f32 *)(lbl_803DD860[0] + 0x18) = lbl_803DD818;
    *(f32 *)(lbl_803DD860[0] + 0x1c) = lbl_803DD814;
    *(f32 *)(lbl_803DD860[0] + 0x20) = lbl_803DD810;
    *(f32 *)(lbl_803DD860[0] + 0x8) = f4;
    *(s16 *)(lbl_803DD860[0] + 0x4) = (s16)a;
    *(s16 *)(lbl_803DD860[0] + 0x2) = (s16)b;
    *(s16 *)(lbl_803DD860[0] + 0x0) = (s16)c;
    *(f32 *)(lbl_803DD860[1] + 0xc) = lbl_803DD818;
    *(f32 *)(lbl_803DD860[1] + 0x10) = lbl_803DD814;
    *(f32 *)(lbl_803DD860[1] + 0x14) = lbl_803DD810;
    *(f32 *)(lbl_803DD860[1] + 0x18) = lbl_803DD818;
    *(f32 *)(lbl_803DD860[1] + 0x1c) = lbl_803DD814;
    *(f32 *)(lbl_803DD860[1] + 0x20) = lbl_803DD810;
    *(f32 *)(lbl_803DD860[1] + 0x8) = f4;
    *(s16 *)(lbl_803DD860[1] + 0x4) = (s16)a;
    *(s16 *)(lbl_803DD860[1] + 0x2) = (s16)b;
    *(s16 *)(lbl_803DD860[1] + 0x0) = (s16)c;
}
#pragma peephole reset
#pragma scheduling reset

extern char hudTextures[];
extern s16 lbl_803DD76C;
extern u8 lbl_803DBAF0;
extern f32 lbl_803E1E9C;
extern u8 lbl_803DBAEE;
extern u8 lbl_803DBAEF;
extern void drawScaledTexture(void *tex, f32 x, f32 y, int alpha, int p5, int p6, int p7, int p8);
extern void GXGetScissor(int *a, int *b, int *c, int *d);
extern void GXSetScissor(int a, int b, int c, int d);
extern void hudDrawRect(int x0, int y0, int x1, int y1, GXColor col);
#pragma scheduling off
#pragma peephole off
void fearTestMeterDraw(void) {
    int sc0, sc1, sc2, sc3;
    GXColor col;
    void *texB = *(void **)(hudTextures + 0x180);
    u16 hgt = *(u16 *)((char *)texB + 0xc);
    int gap = (u8)fearTestMeterOuterHalfWidth - (u8)fearTestMeterInnerHalfWidth;
    void *texA = *(void **)(hudTextures + 0x17c);
    int wid = (u8)*(u16 *)((char *)texA + 0xa);
    if (lbl_803DD76E != 0) {
        lbl_803DD76C = lbl_803DD76C + lbl_803DBAF0 * framesThisStep;
    } else {
        lbl_803DD76C = lbl_803DD76C - lbl_803DBAF0 * framesThisStep;
    }
    if (lbl_803DD76C < 0) {
        lbl_803DD76C = 0;
    } else if (lbl_803DD76C > 0xff) {
        lbl_803DD76C = 0xff;
    }
    if (lbl_803DD76C == 0) return;
    GXGetScissor(&sc0, &sc1, &sc2, &sc3);
    GXSetScissor(0, 0, 0x280, 0x1e0);
    drawScaledTexture(*(void **)(hudTextures + 0x17c),
                      (f32)(int)(0x140 - (u8)fearTestMeterOuterHalfWidth - wid), lbl_803E1E9C,
                      (u8)lbl_803DD76C, 0x100, wid, hgt, 1);
    drawScaledTexture(*(void **)(hudTextures + 0x180),
                      (f32)(int)(0x140 - (u8)fearTestMeterInnerHalfWidth), lbl_803E1E9C,
                      (u8)lbl_803DD76C, 0x100, (u8)fearTestMeterInnerHalfWidth << 1, hgt, 0);
    drawScaledTexture(*(void **)(hudTextures + 0x184),
                      (f32)(int)(0x140 - (u8)fearTestMeterOuterHalfWidth), lbl_803E1E9C,
                      (u8)lbl_803DD76C, 0x100, gap, hgt, 0);
    drawScaledTexture(*(void **)(hudTextures + 0x184),
                      (f32)(int)((u8)fearTestMeterInnerHalfWidth + 0x140), lbl_803E1E9C,
                      (u8)lbl_803DD76C, 0x100, gap, hgt, 0);
    drawTexture(*(void **)(hudTextures + 0x17c),
                (f32)(int)((u8)fearTestMeterOuterHalfWidth + 0x140), lbl_803E1E9C,
                (u8)lbl_803DD76C, 0x100);
    col.r = 0xff;
    col.g = 0;
    col.b = 0;
    col.a = (u8)lbl_803DD76C;
    hudDrawRect((fearTestMeterMarkerX + 0x140) - (u8)lbl_803DBAEF,
                (u8)lbl_803DBAEE + 0x32,
                (u8)lbl_803DBAEF + (fearTestMeterMarkerX + 0x140),
                (hgt + 0x32) - (u8)lbl_803DBAEE,
                col);
    GXSetScissor(sc0, sc1, sc2, sc3);
}
#pragma peephole reset
#pragma scheduling reset

extern int *Obj_GetPlayerObject(void);
extern int getHudHiddenFrameCount(void);
extern s8 lbl_803DBAEC;
extern u8 lbl_803DBAED;
extern s8 lbl_803DD7F8;
extern s8 lbl_803DD7F9;
#pragma scheduling off
#pragma peephole off
void hudDrawAirMeter(void) {
    int sc0, sc1, sc2, sc3;
    int *player = Obj_GetPlayerObject();
    int *m = (int *)airMeter;
    _Obj8011F70C *p = (_Obj8011F70C *)airMeter;
    s16 alpha;
    s16 clamped;
    if (m == NULL) return;
    alpha = *(u8 *)((char *)m + 0x18);
    if (p->bit7 || pauseMenuState != 0 || getHudHiddenFrameCount() != 0 ||
        (player != NULL && (*(u16 *)((char *)player + 0xb0) & 0x1000) != 0 &&
         *(u16 *)((char *)m + 0x2c) != 0x5d5)) {
        alpha = (s16)(alpha - (framesThisStep << 2));
        clamped = (alpha < 0) ? 0 : alpha;
        *(u8 *)((char *)m + 0x18) = (u8)clamped;
        if (*(u8 *)((char *)m + 0x18) == 0 && p->bit7) {
            p->bit7 = 0;
            GameUI_airMeterShutdown();
            return;
        }
    } else {
        alpha = (s16)(alpha + (framesThisStep << 2));
        clamped = (alpha > 0xff) ? 0xff : alpha;
        *(u8 *)((char *)m + 0x18) = (u8)clamped;
    }
    GXGetScissor(&sc0, &sc1, &sc2, &sc3);
    GXSetScissor(0, 0, 0x280, 0x1e0);
    switch (m[0x10]) {
    case 0: {
        int x = 0x140 - ((u32)(m[4] * m[1]) >> 1);
        int i;
        for (i = 0; i < m[1]; i++) {
            void *tex = (i < m[3]) ? (void *)m[0xb] : (void *)m[0xc];
            drawTexture(tex, (f32)(int)x, (f32)(u32)(0x1a4 - m[5]),
                        *(u8 *)((char *)m + 0x18), 0x100);
            x += m[4];
        }
        break;
    }
    case 1: {
        int off;
        int by;
        int cy;
        int clampedC;
        switch (*(u16 *)((char *)m + 0x2c)) {
        case 0x63e:
            off = -0xa;
            break;
        case 0x643:
            off = -0xc;
            break;
        default:
            off = 0;
            break;
        }
        {
            int base = (0x1a4 - (*(u16 *)((char *)m[0xc] + 0xc) >> 1)) + lbl_803DBAEC;
            drawTexture((void *)m[0xc], (f32)(int)(lbl_803DD7F9 + 0xb5),
                        (f32)(int)(base + ((s8)off + lbl_803DD7F8)),
                        *(u8 *)((char *)m + 0x18), 0x100);
        }
        by = *(u16 *)((char *)m[0xc] + 0xa) + 0xb4;
        cy = 0x1a4 - (*(u16 *)((char *)m[0xd] + 0xc) >> 1);
        if (m[2] < 0x9e) {
            m[2] = m[2] + framesThisStep * lbl_803DBAED;
        }
        clampedC = (m[3] < 0) ? 0 : ((m[3] > m[2]) ? m[2] : m[3]);
        m[3] = clampedC;
        clampedC = (s16)clampedC;
        drawScaledTexture((void *)m[0xf], (f32)(int)(by + clampedC), (f32)(int)cy,
                          *(u8 *)((char *)m + 0x18), 0x100, m[2] - clampedC, 0x1a, 0);
        drawScaledTexture((void *)m[0xe], (f32)(int)by, (f32)(int)cy,
                          *(u8 *)((char *)m + 0x18), 0x100, clampedC, 0x1a, 0);
        drawTexture((void *)m[0xd], (f32)(int)(by + m[2]),
                    (f32)(int)(0x1a4 - (*(u16 *)((char *)m[0xd] + 0xc) >> 1)),
                    *(u8 *)((char *)m + 0x18), 0x100);
        break;
    }
    }
    GXSetScissor(sc0, sc1, sc2, sc3);
}
#pragma peephole reset
#pragma scheduling reset

extern void PSMTXCopy(f32 *src, f32 *dst);
extern void GXLoadTexMtxImm(f32 *m, int id, int type);
extern void GXSetIndTexOrder(int stage, int a, int b);
extern void GXSetIndTexCoordScale(int stage, int a, int b);
extern void GXSetIndTexMtx(int id, f32 *m, int scale);
extern void GXSetTevIndirect(int stage, int a, int b, int c, int d, int e, int f, int g, int h, int i);
extern void GXSetChanCtrl(int chan, int a, int b, int c, int d, int e, int f);
extern void GXSetChanMatColor(int chan, GXColor c);
extern void GXSetTevKAlphaSel(int stage, int sel);
extern void *ObjModel_GetRenderOp(int op, int x);
extern void *Shader_getLayer(void *op, int idx);
extern void *textureIdxToPtr(int idx);
extern void selectTexture(void *tex, int x);
extern void fn_8006C5CC(int *out);
extern int lbl_803E1E30;
extern int lbl_802C21AC[];
extern f32 lbl_803A8950[];
extern f32 lbl_803E1E64, lbl_803E1E6C, lbl_803E1E70;
extern f32 lbl_803DD850;
extern f32 lbl_80396820[];
extern f32 lbl_803DBB14;
extern int lbl_803DBB10;
typedef struct { int w[6]; } _IndMtx;
#pragma scheduling off
#pragma peephole off
int fn_8011E0D8(int *this, int *p2, int p3) {
    f32 m1[12];
    f32 m2[12];
    f32 m3[12];
    f32 mtex[12];
    _IndMtx indmtx;
    GXColor chanCol;
    int kcolor;
    int tex2;
    void *op, *layer, *tex0;
    f32 sval;

    chanCol = *(GXColor *)&lbl_803E1E30;
    indmtx = *(_IndMtx *)lbl_802C21AC;
    op = ObjModel_GetRenderOp(*p2, p3);
    layer = Shader_getLayer(op, 0);
    tex0 = textureIdxToPtr(*(int *)layer);

    PSMTXCopy(lbl_803A8950, m1);
    m1[3] = lbl_803E1E3C;
    m1[7] = lbl_803E1E3C;
    m1[11] = lbl_803E1E3C;
    PSMTXScale(m2, lbl_803E1E64 / lbl_803DD80C, lbl_803E1E64 / lbl_803DD80C, lbl_803E1E68 / lbl_803DD80C);
    m2[2] = lbl_803E1E6C / lbl_803DD80C;
    m2[6] = lbl_803E1E6C / lbl_803DD80C;
    PSMTXConcat(m2, m1, m1);
    GXLoadTexMtxImm(m1, 0x1e, 1);
    GXSetNumTexGens(3);
    GXSetNumTevStages(3);
    GXSetNumIndStages(2);
    GXSetNumChans(1);
    GXSetIndTexOrder(0, 0, 2);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32 *)&indmtx, 0);
    GXSetTevIndirect(0, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    selectTexture(tex0, 0);
    GXSetTexCoordGen2(0, 1, 1, 0x1e, 0, 0x7d);
    GXSetTevOrder(0, 0, 0, 4);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 0xa);
    GXSetTevAlphaIn(0, 7, 7, 7, 5);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanMatColor(4, chanCol);
    GXSetIndTexOrder(1, 0, 2);
    GXSetIndTexCoordScale(1, 0, 0);
    GXSetTevIndirect(1, 1, 0, 7, 1, 0, 0, 1, 0, 0);
    PSMTXConcat(lbl_80396820, lbl_803A8950, m1);
    sval = lbl_803E1E70 * (lbl_803DD850 * lbl_803DD850);
    PSMTXScale(m3, sval, sval, lbl_803E1E68);
    PSMTXConcat(m3, m1, m1);
    PSMTXTrans(m3, lbl_803E1E70 * (lbl_803E1E68 - sval), lbl_803E1E70 * (lbl_803E1E68 - sval), lbl_803E1E3C);
    PSMTXConcat(m3, m1, m1);
    GXLoadTexMtxImm(m1, 0x21, 0);
    GXSetTexCoordGen2(1, 1, 0, 0x21, 0, 0x7d);
    GXSetTevOrder(1, 1, 0, 0xff);
    GXSetTevColorIn(1, 0xf, 0xf, 0xf, 8);
    GXSetTevAlphaIn(1, 7, 7, 7, 0);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
    mtex[0] = lbl_803DBB14;
    mtex[1] = lbl_803E1E3C;
    mtex[2] = lbl_803E1E3C;
    mtex[3] = lbl_803E1E70;
    mtex[4] = lbl_803E1E3C;
    mtex[5] = lbl_803DBB14;
    mtex[6] = lbl_803E1E3C;
    mtex[7] = lbl_803E1E70;
    mtex[8] = lbl_803E1E3C;
    mtex[9] = lbl_803E1E3C;
    mtex[10] = lbl_803E1E3C;
    mtex[11] = lbl_803E1E68;
    GXLoadTexMtxImm(mtex, 0x24, 1);
    GXSetTexCoordGen2(2, 1, 1, 0x24, 0, 0x7d);
    fn_8006C5CC(&tex2);
    selectTexture((void *)tex2, 1);
    GXSetTevKAlphaSel(2, 0x1c);
    kcolor = lbl_803DBB10;
    GXSetTevKColor(0, *(GXColor *)&kcolor);
    GXSetTevDirect(2);
    GXSetTevOrder(2, 2, 1, 0xff);
    GXSetTevColorIn(2, 0xf, 0xf, 0xf, 0);
    GXSetTevAlphaIn(2, 7, 4, 6, 0);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 1, 0, 0, 1, 0);
    if (*(s16 *)((char *)this + 0x46) == 0x755) {
        GXSetCullMode(1);
    } else {
        GXSetCullMode(2);
    }
    GXSetBlendMode(1, 4, 5, 5);
    gxSetZMode_(0, 7, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xa, 1);
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

extern void *getTrickyObject(void);
extern int objIsCurModelNotZero(int *obj);
extern int coordsToMapCell(f32 x, f32 z);
extern int fn_802972A8(int *player);
extern void drawPartialTexture(void *tex, f32 x, f32 y, int alpha, int p5, int p6, int p7, int p8, int p9);
extern void hudDrawCounter(int id, int a, int b, int c, int d, int *e, int f);
extern int *gCameraInterface;
extern s16 cMenuFadeCounter;
extern f32 lbl_803DD844, lbl_803DD83C;
extern const f32 lbl_803E1F98;
extern f32 lbl_803E1FA8, lbl_803E1FAC, lbl_803E1FB0, lbl_803E1FB4;
extern f32 timeDelta;
#pragma scheduling off
#pragma peephole off
void hudDrawFn_80121440(void) {
    char *base = lbl_803A87F0;
    int *player, *tricky;
    int itemTex = 0;
    int hcArg = 0;
    int krazoa = 0;
    int alpha;
    int magicId;
    int i;
    f32 op;
    player = (int *)Obj_GetPlayerObject();
    tricky = (int *)getTrickyObject();
    GXSetScissor(0, 0, 0x280, 0x1e0);
    if (*(f32 *)(base + 0xafc) >= lbl_803E1E3C || *(f32 *)(base + 0xb18) >= lbl_803E1E3C ||
        *(f32 *)(base + 0xb10) >= lbl_803E1E3C || cMenuFadeCounter != 0)
        op = hudElementOpacity;
    else
        op = lbl_803E1E3C;
    if (op > lbl_803DD844) {
        lbl_803DD844 = lbl_803E1FA0 * timeDelta + lbl_803DD844;
        if (lbl_803DD844 > hudElementOpacity) lbl_803DD844 = hudElementOpacity;
    } else if (op < lbl_803DD844) {
        lbl_803DD844 = lbl_803DD844 - lbl_803E1FA0 * timeDelta;
        if (lbl_803DD844 < lbl_803E1E3C) lbl_803DD844 = lbl_803E1E3C;
    }
    alpha = (int)lbl_803DD83C;
    if ((u8)alpha != 0) {
        int cell = coordsToMapCell(*(f32 *)((char *)player + 0xc), *(f32 *)((char *)player + 0x14));
        if (!(*(f32 *)(base + 0xafc) > lbl_803E1F9C && *(f32 *)(base + 0xafc) < lbl_803E1FA8 &&
              ((int)*(f32 *)(base + 0xafc) & 8)) &&
            !(*(f32 *)(base + 0xb18) > lbl_803E1F9C && *(f32 *)(base + 0xb18) < lbl_803E1FA8 &&
              ((int)*(f32 *)(base + 0xb18) & 8)) &&
            !(cell == 0 && fn_802972A8(player) != 0)) {
            for (i = 0; (int)(u8)i < (*(int *)(base + 0xb90) >> 2); i++) {
                int b74 = *(int *)(base + 0xb74);
                int sel;
                if ((int)(u8)i < (b74 >> 2)) sel = 0x16;
                else if ((int)(u8)i > (b74 >> 2)) sel = 0x12;
                else sel = (b74 & 3) + 0x12;
                drawTexture(*(void **)(base + 0x1c0 + (u8)sel * 4),
                            (f32)(int)((u8)i * 0x21 + 0x1e), lbl_803E1FAC, alpha, 0x100);
            }
        }
    }
    if ((u8)alpha != 0 && objIsCurModelNotZero(player) != 0 && GameBit_Get(0xeb1) != 0) {
        hudDrawMagicBar(alpha, 0x100, 0);
    }
    krazoa = 0;
    if (playerHasKrazoaSpirit(1, 0) != 0) krazoa = 1;
    magicId = 0;
    if (GameBit_Get(0x123) != 0 || GameBit_Get(0x83b) != 0) magicId = 0x63;
    else if (GameBit_Get(0x2e8) != 0 || GameBit_Get(0x83c) != 0) magicId = 0x64;
    if ((u8)magicId != 0) {
        drawTexture(*(void **)(base + 0x1c0 + (u8)magicId * 4),
                    (f32)(int)(s16)(krazoa ? 0x104 : 0x122), lbl_803E1FAC, alpha, 0x100);
    }
    if ((u8)krazoa != 0) {
        drawTexture(*(void **)(base + 0x348),
                    (f32)(int)(s16)((u8)magicId ? 0x140 : 0x122), lbl_803E1FAC, alpha, 0x100);
    }
    if ((u8)alpha != 0 && tricky != NULL) {
        itemTex = 0x16;
        if (!(*(f32 *)(base + 0xb20) > lbl_803E1F9C && *(f32 *)(base + 0xb20) < lbl_803E1FA8 &&
              ((int)*(f32 *)(base + 0xb20) & 8))) {
            drawTexture(*(void **)(base + 0x314), lbl_803E1F9C, lbl_803E1FB0, alpha, 0x100);
        }
        for (i = 0; (int)(u8)i < 0x14; i += 4) {
            int b98 = *(int *)(base + 0xb98);
            if ((b98 & 0xfc) == (int)(u8)i && (b98 & 2) != 0) {
                int yo = ((u8)i * 0xf) / 4;
                drawScaledTexture(*(void **)(base + 0x31c), (f32)(int)(yo + 0x40), lbl_803E1FB4,
                                  alpha, 0x100, 6, 0x12, 0);
                drawPartialTexture(*(void **)(base + 0x318), (f32)(int)(yo + 0x46), lbl_803E1FB4,
                                   alpha, 0x100, 7, 0x12, 6, 0);
            } else {
                int sel = (b98 > (int)(u8)i) ? 0x57 : 0x56;
                int yo = ((u8)i * 0xf) / 4;
                drawTexture(*(void **)(base + 0x1c0 + (u8)sel * 4), (f32)(int)(yo + 0x40),
                            lbl_803E1FB4, alpha, 0x100);
            }
        }
    }
    {
        int camMode = (*(int (**)(void))(*(int *)gCameraInterface + 0x10))();
        if (camMode >= 0x47 && camMode < 0x49) {
            drawTexture(*(void **)(base + 0x354), lbl_803E1F9C,
                        (f32)(int)((s8)itemTex + 0x5f), alpha, 0x100);
        }
    }
    GXSetScissor(0, 0, 0x280, 0x1e0);
    if (lbl_803DD75A != 0) {
        int c0 = 0, c1 = 0, c2 = 0;
        f32 radius = lbl_803E1F98;
        int *near;
        near = (int *)ObjGroup_FindNearestObject(9, Obj_GetPlayerObject(), &radius);
        if (near != NULL && pauseMenuState == 0) {
            (*(void (*)(int *, int *, int *))(*(int *)(*(int *)((char *)near + 0x68)) + 0x54))(&c2, &c1, &c0);
            hcArg = 0x118;
            hudDrawCounter(0x1e, (s16)(c1 - c2), (s16)c0, 0xff, 0, &hcArg, 1);
        }
    } else {
        int style;
        if (GameBit_Get(0x91b) != 0) style = 0xc8;
        else if (GameBit_Get(0x91a) != 0) style = 0x64;
        else if (GameBit_Get(0x919) != 0) style = 0x32;
        else style = 0xa;
        hudDrawCounter(0x1e, (s16)*(int *)(base + 0xb80), (s16)style, (int)*(f32 *)(base + 0xad4), (int)*(f32 *)(base + 0xb08), &hcArg, 0);
        hudDrawCounter(0x19, (s16)*(int *)(base + 0xb84), 7, (int)*(f32 *)(base + 0xad8), (int)*(f32 *)(base + 0xb0c), &hcArg, 0);
        hudDrawCounter(0x1a, (s16)*(int *)(base + 0xb78), 0xf, (int)*(f32 *)(base + 0xacc), (int)*(f32 *)(base + 0xb00), &hcArg, 0);
        hudDrawCounter(0x18, (s16)*(int *)(base + 0xb9c), 0x1f, (int)*(f32 *)(base + 0xaf0), (int)*(f32 *)(base + 0xb24), &hcArg, 0);
        hudDrawCounter(0x1b, (s16)*(int *)(base + 0xba0), 7, (int)*(f32 *)(base + 0xaf4), (int)*(f32 *)(base + 0xb28), &hcArg, 0);
        hudDrawCounter(0x1c, (s16)*(int *)(base + 0xba4), 0xff, (int)*(f32 *)(base + 0xaf8), (int)*(f32 *)(base + 0xb2c), &hcArg, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int Camera_GetCurrentViewSlot(void);
extern u8 Rcp_GetViewFinderHudEnabled(void);
extern int getAngle(f32, f32);
extern f32 fn_80293E80(f32);
extern f32 sin(f32);
extern void drawViewFinderLine(u8 *color, f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3, f32 x4, f32 y4);
extern f32 fn_8029454C(f32);
extern const f64 lbl_803E1EA0, lbl_803E1EA8, lbl_803E1EB0, lbl_803E1EB8;
extern f64 lbl_803E1E78;
extern const f64 lbl_803E1EF0, lbl_803E1EF8, lbl_803E1F00, lbl_803E1F20, lbl_803E1F28;
extern const f32 lbl_803E1EC4, lbl_803E1EC8, lbl_803E1ECC, lbl_803E1ED0;
extern f32 lbl_803DD7F0, lbl_803DD7F4;
extern const f32 lbl_803E1ED4, lbl_803E1ED8, lbl_803E1EDC, lbl_803E1EE0, lbl_803E1EE4, lbl_803E1EE8, lbl_803E1E94;
extern const f32 lbl_803E1F08, lbl_803E1F0C, lbl_803E1F10, lbl_803E1F14, lbl_803E1F18;
extern const f32 lbl_803E1F30, lbl_803E1F34, lbl_803E1F48, lbl_803E1F4C;
extern f32 lbl_803DBAE0, lbl_803DBAE4;
extern const double lbl_803E1F38, lbl_803E1F40;
extern const f32 lbl_803E1F94;
extern char lbl_803DBB40;
extern const f32 lbl_803E1F70, lbl_803E1F90;
extern const double lbl_803E1F50, lbl_803E1F58, lbl_803E1F60, lbl_803E1F68, lbl_803E1F78, lbl_803E1F80, lbl_803E1F88, lbl_803E1EF8;
extern int lbl_803DBAE8;
extern char lbl_803DBB18, lbl_803DBB1C, lbl_803DBB20, lbl_803DBB24, lbl_803DBB28, lbl_803DBB2C, lbl_803DBB30, lbl_803DBB34, lbl_803DBB38;
extern f32 Camera_GetFarPlane(void);
extern f32 Camera_GetNearPlane(void);
extern int maybeReadDepthBuffer(int x, int y, void *fn);
extern u16 lbl_803DD7EC;
extern int lbl_803E1E2C;
extern char sTrickyDebugXCoordFormat[];
extern void gameTextSetColor(int, int, int, int);
extern int sprintf(char *, ...);
#pragma scheduling off

#define VFTICK(gA1, gA2, A, B, C) do { \
    GXColor _c2; \
    GXColor _c; \
    s16 _a; \
    f32 _r, _cs, _sn, _cx, _sx; \
    *(int *)&_c = lbl_803E1E2C; \
    _c.a = hudElementOpacity * lbl_803DD7F0; \
    _a = (s16)getAngle(gA1, gA2); \
    _r = lbl_803E1EC8 * (f32)_a / lbl_803E1E94; \
    _cs = fn_80293E80(_r); \
    _sn = sin(_r); \
    _c2 = _c; \
    _cx = lbl_803E1E68 * _cs; \
    _sx = lbl_803E1E68 * _sn; \
    drawViewFinderLine((u8 *)&_c2, (B) + _sx, (A) - _cx, (B) - _sx, (A) + _cx, (C) - _sx, (A) + _cx, (C) + _sx, (A) - _cx); \
} while (0)

#define VBLK(gA1, gA2, A, B, C) do { \
    GXColor _c2; \
    GXColor _c; \
    s16 _a; \
    f32 _r, _cs, _sn, _cx, _sx; \
    *(int *)&_c = lbl_803E1E2C; \
    _c.a = hudElementOpacity * lbl_803DD7F0; \
    _a = (s16)getAngle(gA1, gA2); \
    _r = lbl_803E1EC8 * (f32)_a / lbl_803E1E94; \
    _cs = fn_80293E80(_r); \
    _sn = sin(_r); \
    _c2 = _c; \
    _cx = lbl_803E1E68 * _cs; \
    _sx = lbl_803E1E68 * _sn; \
    drawViewFinderLine((u8 *)&_c2, (A) + _sx, (B) - _cx, (A) - _sx, (B) + _cx, (A) - _sx, (C) + _cx, (A) + _sx, (C) - _cx); \
} while (0)

#pragma peephole off
void drawViewFinderHud(void) {
    f32 fovY;
    int slot;
    f32 v;

    fovY = Camera_GetFovY();
    slot = Camera_GetCurrentViewSlot();
    if (Rcp_GetViewFinderHudEnabled() && pauseMenuState == 0) {
        lbl_803DD7F0 = (f32)(lbl_803E1EA0 * timeDelta + lbl_803DD7F0);
    } else {
        lbl_803DD7F0 = (f32)(lbl_803DD7F0 - lbl_803E1EA8 * timeDelta);
    }
    v = (lbl_803DD7F0 < lbl_803E1E3C) ? lbl_803E1E3C
                                      : ((lbl_803DD7F0 > lbl_803E1E68) ? lbl_803E1E68 : lbl_803DD7F0);
    lbl_803DD7F0 = v;
    if (v == lbl_803E1E3C) return;
    lbl_803DD7F4 = (f32)(lbl_803E1EB0 - lbl_803E1EB8 * v);
    lbl_803DD7EC = -*(s16 *)slot;

    VFTICK(lbl_803E1EC4, lbl_803E1E3C, lbl_803E1ECC, lbl_803E1ED0, lbl_803E1ED4);
    VFTICK(lbl_803E1ED8, lbl_803E1E3C, lbl_803E1ECC, lbl_803E1EDC, lbl_803E1EE0);
    VFTICK(lbl_803E1EC4, lbl_803E1E3C, lbl_803E1EE4, lbl_803E1ED0, lbl_803E1ED4);
    VFTICK(lbl_803E1ED8, lbl_803E1E3C, lbl_803E1EE4, lbl_803E1EDC, lbl_803E1EE0);
    VBLK(lbl_803E1E3C, lbl_803E1EC4, lbl_803E1ED0, lbl_803E1ECC, lbl_803E1EE8);
    VBLK(lbl_803E1E3C, lbl_803E1ED8, lbl_803E1ED0, lbl_803E1EE4, lbl_803E1ED4);
    VBLK(lbl_803E1E3C, lbl_803E1EC4, lbl_803E1EDC, lbl_803E1ECC, lbl_803E1EE8);
    VBLK(lbl_803E1E3C, lbl_803E1ED8, lbl_803E1EDC, lbl_803E1EE4, lbl_803E1ED4);

    {
        char buf[56];
        f32 f15v = (f32)(lbl_803E1EF0 * ((fovY - lbl_803E1EF8) / lbl_803E1F00) + lbl_803E1EB0);
        f32 f18v = -(lbl_803E1F0C * lbl_803DD7F0) + lbl_803E1F08;
        f32 f19v;
        f32 xc;
        {
            GXColor _c2; GXColor _c; s16 _a; f32 _r, _cs, _sn, _cx, _sx;
            *(int *)&_c = lbl_803E1E2C;
            _c.a = hudElementOpacity * lbl_803DD7F0;
            _a = (s16)getAngle(lbl_803E1E3C, lbl_803E1F08 - f18v);
            _r = lbl_803E1EC8 * (f32)_a / lbl_803E1E94;
            _cs = fn_80293E80(_r); _sn = sin(_r);
            _c2 = _c;
            _cx = lbl_803E1E68 * _cs;
            _sx = lbl_803E1E68 * _sn;
            drawViewFinderLine((u8 *)&_c2, lbl_803E1F10 + _sx, f18v - _cx, lbl_803E1F10 - _sx, f18v + _cx, lbl_803E1F10 - _sx, lbl_803E1F08 + _cx, lbl_803E1F10 + _sx, lbl_803E1F08 - _cx);
        }
        {
            GXColor _c2; GXColor _c; s16 _a; f32 _r, _cs, _sn, _cx, _sx;
            *(int *)&_c = lbl_803E1E2C;
            _c.a = hudElementOpacity * lbl_803DD7F0;
            _a = (s16)getAngle(lbl_803E1E3C, (f19v = lbl_803E1F14 + f15v) - f15v);
            _r = lbl_803E1EC8 * (f32)_a / lbl_803E1E94;
            _cs = fn_80293E80(_r); _sn = sin(_r);
            _c2 = _c;
            _cx = lbl_803E1F18 * _cs;
            _sx = lbl_803E1F18 * _sn;
            drawViewFinderLine((u8 *)&_c2, lbl_803E1F10 + _sx, f15v - _cx, lbl_803E1F10 - _sx, f15v + _cx, lbl_803E1F10 - _sx, f19v + _cx, lbl_803E1F10 + _sx, f19v - _cx);
        }
        xc = lbl_803E1F20 / fn_8029454C((f32)(lbl_803E1EC8 * fovY / lbl_803E1F28));
        xc = (f32)xc;
        sprintf(buf, sTrickyDebugXCoordFormat, xc);
        gameTextSetColor(0, 0xff, 0, (int)(hudElementOpacity * lbl_803DD7F0));
        gameTextShowStr(buf, 0x93, 0x21c, 0x46);

        {
            f32 kOpac, kF4C;
            f32 kF30, kEC8, kF34, kEC4, kE94;
            f64 kF38;
            f32 kF48;
            f64 kF40;
            f32 kE68;
            f32 f27;
            f32 fdx, f29, f30, f31;
            f27 = lbl_803E1E3C;
            kF30 = lbl_803E1F30;
            kEC8 = lbl_803E1EC8;
            kF34 = lbl_803E1F34;
            kEC4 = lbl_803E1EC4;
            kE94 = lbl_803E1E94;
            kF38 = lbl_803E1F38;
            kE68 = lbl_803E1E68;
            kF40 = lbl_803E1F40;
            kOpac = hudElementOpacity;
            kF48 = lbl_803E1F48;
            kF4C = lbl_803E1F4C;
            for (; f27 < kF4C; f27 += kEC4) {
                {
                    GXColor _c2; GXColor _c; s16 _a; f32 _r, _cs, _sn, _cx, _sx;
                    f32 f15, f16;
                    u8 alpha = kF30 * lbl_803DD7F0;
                    f31 = kEC4 + f27;
                    f30 = kF34 - f31;
                    _sn = lbl_803DBAE4 * sin(kEC8 * (f30 * lbl_803DBAE0) / kE94);
                    f15 = (f32)(lbl_803DD7F4 + (kF38 + _sn));
                    f29 = kF34 - f27;
                    _sn = lbl_803DBAE4 * sin(kEC8 * (f29 * lbl_803DBAE0) / kE94);
                    f16 = (f32)(lbl_803DD7F4 + (kF38 + _sn));
                    *(int *)&_c = lbl_803E1E2C;
                    _c.a = alpha;
                    fdx = f31 - f27;
                    _a = (s16)getAngle(fdx, f15 - f16);
                    _r = kEC8 * (f32)_a / kE94;
                    _cs = fn_80293E80(_r);
                    _sn = sin(_r);
                    _c2 = _c;
                    _cx = kE68 * _cs;
                    _sx = kE68 * _sn;
                    drawViewFinderLine((u8 *)&_c2, f27 + _sx, f16 - _cx, f27 - _sx, f16 + _cx, f31 - _sx, f15 + _cx, f31 + _sx, f15 - _cx);
                }
                {
                    GXColor _c2; GXColor _c; s16 _a; f32 _r, _cs, _sn, _cx, _sx;
                    u8 alpha = kF30 * lbl_803DD7F0;
                    f32 f16, f15;
                    _sn = lbl_803DBAE4 * sin(kEC8 * (f30 * lbl_803DBAE0) / kE94);
                    f16 = (f32)(lbl_803DD7F4 + (kF40 + _sn));
                    _sn = lbl_803DBAE4 * sin(kEC8 * (f29 * lbl_803DBAE0) / kE94);
                    f15 = (f32)(lbl_803DD7F4 + (kF40 + _sn));
                    *(int *)&_c = lbl_803E1E2C;
                    _c.a = alpha;
                    _a = (s16)getAngle(fdx, f16 - f15);
                    _r = kEC8 * (f32)_a / kE94;
                    _cs = fn_80293E80(_r);
                    _sn = sin(_r);
                    _c2 = _c;
                    _cx = kE68 * _cs;
                    _sx = kE68 * _sn;
                    drawViewFinderLine((u8 *)&_c2, f27 + _sx, f15 - _cx, f27 - _sx, f15 + _cx, f31 - _sx, f16 + _cx, f31 + _sx, f16 - _cx);
                }
                {
                    GXColor _c2; GXColor _c; s16 _a; f32 _r, _cs, _sn, _cx, _sx;
                    u8 alpha = kOpac * lbl_803DD7F0;
                    f32 f16, f15;
                    _sn = lbl_803DBAE4 * sin(kEC8 * (f30 * lbl_803DBAE0) / kE94);
                    f16 = lbl_803DD7F4 + (kF48 + _sn);
                    _sn = lbl_803DBAE4 * sin(kEC8 * (f29 * lbl_803DBAE0) / kE94);
                    f15 = lbl_803DD7F4 + (kF48 + _sn);
                    *(int *)&_c = lbl_803E1E2C;
                    _c.a = alpha;
                    _a = (s16)getAngle(fdx, f16 - f15);
                    _r = kEC8 * (f32)_a / kE94;
                    _cs = fn_80293E80(_r);
                    _sn = sin(_r);
                    _c2 = _c;
                    _cx = kE68 * _cs;
                    _sx = kE68 * _sn;
                    drawViewFinderLine((u8 *)&_c2, f27 + _sx, f15 - _cx, f27 - _sx, f15 + _cx, f31 - _sx, f16 + _cx, f31 + _sx, f16 - _cx);
                }
            }
        }
        {
            int r30v, r29v, r5v, r28v;
            int t;
            f32 f18, f19, num;
            t = (int)((xc - lbl_803E1F50) * lbl_803E1F58);
            r30v = (t < 0) ? 0 : ((t > 0x8c) ? 0x8c : t);
            t = (int)((xc - lbl_803E1F60) * lbl_803E1F68);
            r29v = (t < 0) ? 0 : ((t > 0xc8) ? 0xc8 : t);
            r5v = (int)((f32)lbl_803DD7EC / lbl_803E1F70);
            num = (f32)lbl_803DD7EC - (f32)r5v * lbl_803E1F70;
            f19 = xc * (lbl_803E1F70 / (f32)lbl_803DBAE8);
            f18 = (f32)(lbl_803E1F78 + (num / (f32)lbl_803DBAE8) * xc);
            r28v = -r5v;
            while (f18 > lbl_803E1E3C) {
                f18 -= f19;
                r28v--;
            }
            f18 += f19;
            r28v++;
            if (r28v < 0) r28v += 0x168;
            for (; f18 < lbl_803E1F4C; f18 += f19) {
                int r27v = 0xff;
                int r26v = 0xff;
                int r25v = 0xf;
                f64 q;
                if (r28v >= 0x168) r28v -= 0x168;
                q = r28v / lbl_803E1F80;
                if (q != (int)q) {
                    r26v = 0xc8;
                    q = r28v / lbl_803E1EF8;
                    if (q != (int)q) {
                        r27v = (u8)r30v;
                        r25v = 7;
                    } else {
                        r27v = (u8)r29v;
                        r25v = 0xa;
                    }
                }
                switch (r28v) {
                case 0:     sprintf(buf, &lbl_803DBB18, r28v); break;
                case 0x5a:  sprintf(buf, &lbl_803DBB1C, r28v); break;
                case 0xb4:  sprintf(buf, &lbl_803DBB20, r28v); break;
                case 0x10e: sprintf(buf, &lbl_803DBB24, r28v); break;
                case 0x2d:  sprintf(buf, &lbl_803DBB28, r28v); break;
                case 0x87:  sprintf(buf, &lbl_803DBB2C, r28v); break;
                case 0xe1:  sprintf(buf, &lbl_803DBB30, r28v); break;
                case 0x13b: sprintf(buf, &lbl_803DBB34, r28v); break;
                default:    sprintf(buf, &lbl_803DBB38, r28v); break;
                }
                r28v++;
                if ((u8)r27v != 0) {
                    f32 sn;
                    gameTextSetColor(0, 0xff, 0, (int)((f32)(u8)r27v * lbl_803DD7F0));
                    sn = lbl_803DBAE4 * sin(lbl_803E1EC8 * ((lbl_803E1F34 - f18) * lbl_803DBAE0) / lbl_803E1E94);
                    gameTextShowStr(buf, 0x93,
                        (int)(lbl_803E1F88 * (f18 - lbl_803E1F78) + lbl_803E1F78),
                        (int)(lbl_803DD7F4 + (lbl_803E1F90 + sn)));
                }
                {
                    GXColor _c2; GXColor _c; s16 _a; f32 _r, _cs, _sn, _cx, _sx;
                    u8 alpha = (f32)(u8)r26v * lbl_803DD7F0;
                    f32 f15 = lbl_803E1F34 - f18;
                    f32 f16;
                    f64 fx;
                    _sn = lbl_803DBAE4 * sin(lbl_803E1EC8 * (f15 * lbl_803DBAE0) / lbl_803E1E94);
                    f16 = lbl_803DD7F4 + ((f32)((u8)r25v + 0x1e0) + _sn);
                    _sn = lbl_803DBAE4 * sin(lbl_803E1EC8 * (f15 * lbl_803DBAE0) / lbl_803E1E94);
                    f15 = lbl_803DD7F4 + (lbl_803E1F48 + _sn);
                    *(int *)&_c = lbl_803E1E2C;
                    _c.a = alpha;
                    fx = lbl_803E1F88 * (f18 - lbl_803E1F78) + lbl_803E1F78;
                    _a = (s16)getAngle((f32)fx - f18, f16 - f15);
                    _r = lbl_803E1EC8 * (f32)_a / lbl_803E1E94;
                    _cs = fn_80293E80(_r);
                    _sn = sin(_r);
                    _c2 = _c;
                    _cx = lbl_803E1E68 * _cs;
                    _sx = lbl_803E1E68 * _sn;
                    drawViewFinderLine((u8 *)&_c2, f18 + _sx, f15 - _cx, f18 - _sx, f15 + _cx, (f32)fx - _sx, f16 + _cx, (f32)fx + _sx, f16 - _cx);
                }
            }
        }
        {
            f32 farP = Camera_GetFarPlane();
            f32 nearP = Camera_GetNearPlane();
            int depth = maybeReadDepthBuffer(0x140, 0xf0, (void *)drawViewFinderHud);
            f32 dist = (-farP * nearP) / (((f32)(u32)depth / lbl_803E1F94 - lbl_803E1E68) * (farP - nearP) - nearP);
            if (dist > lbl_803E1E3C && dist < lbl_803E1F98) {
                sprintf(buf, &lbl_803DBB40, dist / lbl_803E1EC4);
                gameTextSetColor(0, 0xff, 0, (int)(hudElementOpacity * lbl_803DD7F0));
                gameTextShowStr(buf, 0x93, 0x32, 0x46);
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
