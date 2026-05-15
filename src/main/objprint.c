#include "ghidra_import.h"
#include "main/objprint.h"

extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_8000681c();
extern double FUN_80006a30();
extern undefined4 FUN_80017550();
extern undefined4 FUN_80017558();
extern int FUN_80017570();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175d4();
extern undefined4 FUN_800175fc();
extern undefined4 FUN_80017600();
extern undefined4 FUN_80017604();
extern undefined4 FUN_80017608();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern int FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017794();
extern undefined4 FUN_80017798();
extern int FUN_8001779c();
extern undefined4 FUN_800178e8();
extern int FUN_8001792c();
extern int FUN_80017970();
extern undefined4 FUN_80017978();
extern undefined4 FUN_80017a00();
extern undefined4 FUN_80017a04();
extern undefined4 FUN_80017a54();
extern undefined4 FUN_8003d6f8();
extern undefined4 FUN_800400b0();
extern undefined4 FUN_800406cc();
extern undefined4 FUN_80040a88();
extern undefined4 FUN_800480a0();
extern undefined4 FUN_8004812c();
extern uint FUN_80053078();
extern void newshadows_getShadowTextureTable4x8();
extern void newshadows_getShadowTextureTable16();
extern void newshadows_getShadowNoiseTexture(int *textureOut);
extern void newshadows_getShadowNoiseScroll(float *xOffsetOut,float *yOffsetOut);
extern undefined4 FUN_8006f8a4();
extern undefined4 FUN_8006f8fc();
extern void trackIntersect_drawColorBand(void);
extern undefined4 FUN_802420e0();
extern undefined4 FUN_80247618();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247a7c();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_80247ef8();
extern undefined4 FUN_80258674();
extern undefined4 FUN_80258944();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025a2ec();
extern undefined4 FUN_8025a454();
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
extern undefined4 FUN_8025c49c();
extern undefined4 FUN_8025c510();
extern undefined4 FUN_8025c584();
extern undefined4 FUN_8025c5f0();
extern undefined4 FUN_8025c65c();
extern undefined4 FUN_8025c828();
extern undefined4 FUN_8025ca04();
extern undefined4 FUN_8025ca38();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025d8c4();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802924c8();
extern undefined4 FUN_80292b24();
extern undefined4 FUN_80293900();
extern undefined4 FUN_802950c8();
extern undefined4 countLeadingZeros();

extern undefined4 DAT_802c2290;
extern undefined4 DAT_802c2294;
extern undefined4 DAT_802c2298;
extern undefined4 DAT_802c229c;
extern undefined4 DAT_802c22a0;
extern undefined4 DAT_802c22a4;
extern undefined4 DAT_802c22a8;
extern undefined4 DAT_802c22ac;
extern undefined4 DAT_802c22b0;
extern undefined4 DAT_802c22b4;
extern undefined4 DAT_802c22b8;
extern undefined4 DAT_802c22bc;
extern undefined4 DAT_802c22c0;
extern undefined4 DAT_802c22c4;
extern undefined4 DAT_802c22c8;
extern undefined4 DAT_802c22cc;
extern undefined4 DAT_802c22d0;
extern undefined4 DAT_802c22d4;
extern undefined4 DAT_802c22d8;
extern undefined4 DAT_802c22dc;
extern undefined4 DAT_802c22e0;
extern undefined4 DAT_802c22e4;
extern undefined4 DAT_802c22e8;
extern undefined4 DAT_802c22ec;
extern uint DAT_802cba60;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc0c0;
extern undefined4 DAT_803dc0c8;
extern undefined4 DAT_803dc0d0;
extern undefined4 DAT_803dc0ec;
extern undefined4 DAT_803dc0f0;
extern undefined4 DAT_803dc0f8;
extern undefined4 DAT_803dc0fc;
extern undefined4 DAT_803dd880;
extern undefined4 DAT_803dd888;
extern undefined4 DAT_803dd889;
extern undefined4 DAT_803dd88a;
extern undefined4 DAT_803dd88b;
extern undefined4 DAT_803dd88c;
extern undefined4 DAT_803dd88d;
extern undefined4 DAT_803dd890;
extern undefined4 DAT_803dd894;
extern undefined4 DAT_803dd896;
extern undefined4 DAT_803dd898;
extern undefined4 DAT_803dd8b5;
extern undefined4 DAT_803dd8b6;
extern undefined4 DAT_803dd8bc;
extern undefined4 DAT_803dd8bd;
extern undefined4 DAT_803dd8be;
extern undefined4 DAT_803dd8c4;
extern undefined4 DAT_803dd8c8;
extern undefined4 DAT_803dd8dc;
extern undefined4 DAT_803dd8e0;
extern undefined4 DAT_803dd8e4;
extern undefined4 DAT_803df674;
extern undefined4 DAT_803df678;
extern undefined4 DAT_803df67c;
extern undefined4 DAT_803df680;
extern f64 DOUBLE_803df650;
extern f64 DOUBLE_803df6a0;
extern f64 DOUBLE_803df6c0;
extern f32 lbl_803DC074;
extern f32 lbl_803DC0C4;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DF61C;
extern f32 lbl_803DF624;
extern f32 lbl_803DF648;
extern f32 lbl_803DF658;
extern f32 lbl_803DF65C;
extern f32 lbl_803DF660;
extern f32 lbl_803DF664;
extern f32 lbl_803DF668;
extern f32 lbl_803DF66C;
extern f32 lbl_803DF684;
extern f32 lbl_803DF688;
extern f32 lbl_803DF68C;
extern f32 lbl_803DF690;
extern f32 lbl_803DF694;
extern f32 lbl_803DF698;
extern f32 lbl_803DF69C;
extern f32 lbl_803DF6A8;
extern f32 lbl_803DF6AC;
extern f32 lbl_803DF6B0;
extern f32 lbl_803DF6B4;
extern f32 lbl_803DF6B8;
extern undefined4 _DAT_803dc0f4;

/*
 * --INFO--
 *
 * Function: FUN_80038f38
 * EN v1.0 Address: 0x80038F38
 * EN v1.0 Size: 504b
 * EN v1.1 Address: 0x80039030
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80038f38(int param_1,char *param_2)
{
  float fVar1;
  uint uVar2;
  bool bVar4;
  int *piVar3;
  int iVar5;
  int iVar6;
  int iVar7;
  short *psVar8;
  undefined8 local_18;
  
  fVar1 = *(float *)(param_2 + 0xc);
  psVar8 = (short *)0x0;
  iVar5 = *(int *)(param_1 + 0x50);
  if (iVar5 != 0) {
    iVar6 = 0;
    iVar7 = 0;
    for (uVar2 = (uint)*(byte *)(iVar5 + 0x5a); uVar2 != 0; uVar2 = uVar2 - 1) {
      if ((*(char *)(*(int *)(iVar5 + 0x10) + *(char *)(param_1 + 0xad) + iVar6 + 1) != -1) &&
         (*(char *)(*(int *)(iVar5 + 0x10) + iVar6) == '\x01')) {
        psVar8 = (short *)(*(int *)(param_1 + 0x6c) + iVar7);
      }
      iVar6 = *(char *)(iVar5 + 0x55) + iVar6 + 1;
      iVar7 = iVar7 + 0x12;
    }
  }
  if (*param_2 == '\0') {
    bVar4 = FUN_800067f0(param_1,0x10);
    if (bVar4) {
      if ((int)fVar1 != -1) {
        uVar2 = (int)fVar1 - (uint)DAT_803dc070;
        if ((int)uVar2 < 0) {
          FUN_8000680c(param_1,0x10);
          *(float *)(param_2 + 4) = lbl_803DF624;
          param_2[0x14] = '\0';
          param_2[0x15] = '\0';
        }
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        *(float *)(param_2 + 0xc) = (float)(local_18 - DOUBLE_803df650);
      }
    }
    else {
      *(float *)(param_2 + 0xc) = lbl_803DF648;
      param_2[0x14] = '\0';
      param_2[0x15] = '\0';
      if (lbl_803DF624 < *(float *)(param_2 + 4)) {
        *(float *)(param_2 + 4) = lbl_803DF624;
        piVar3 = *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
        if (*(char *)(*piVar3 + 0xf9) != '\0') {
          FUN_800178e8((double)(lbl_803DF61C / lbl_803DC0C4),piVar3,2,
                       (int)*(char *)(piVar3[10] + 0x2d),-1,0);
        }
      }
    }
  }
  else {
    *param_2 = '\0';
  }
  if (psVar8 != (short *)0x0) {
    *psVar8 = (short)((int)*psVar8 + (int)*(short *)(param_2 + 0x14) >> 1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80039130
 * EN v1.0 Address: 0x80039130
 * EN v1.0 Size: 432b
 * EN v1.1 Address: 0x80039210
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80039130(uint param_1,int *param_2)
{
  float fVar1;
  int *piVar2;
  int iVar3;
  
  if ((-1 < *param_2) &&
     (fVar1 = (float)param_2[2] - lbl_803DC074, param_2[2] = (int)fVar1, fVar1 < lbl_803DF624))
  {
    if (*param_2 < param_2[1]) {
      if (*param_2 == 1) {
        FUN_8000681c(param_1,0x10,*(ushort *)(param_2 + 5));
      }
      iVar3 = *param_2;
      *param_2 = iVar3 + 1;
      piVar2 = *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
      if (*(char *)(*piVar2 + 0xf9) != '\0') {
        FUN_800178e8((double)(lbl_803DF61C / lbl_803DC0C4),piVar2,2,
                     (int)*(char *)(piVar2[10] + 0x2d),*(int *)(param_2[4] + iVar3 * 4) + -1,0);
      }
      param_2[2] = (int)((float)param_2[2] + (float)param_2[3]);
    }
    else {
      *param_2 = -1;
      piVar2 = *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
      if (*(char *)(*piVar2 + 0xf9) != '\0') {
        FUN_800178e8((double)(lbl_803DF61C / lbl_803DC0C4),piVar2,2,
                     (int)*(char *)(piVar2[10] + 0x2d),-1,0);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800392e0
 * EN v1.0 Address: 0x800392E0
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8003935C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800392e0(undefined4 *param_1)
{
  *param_1 = 0xffffffff;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800392ec
 * EN v1.0 Address: 0x800392EC
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x80039368
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800392ec(uint param_1,undefined *param_2,ushort param_3)
{
  bool bVar1;
  
  bVar1 = FUN_800067f0(param_1,0x10);
  if (!bVar1) {
    FUN_8000681c(param_1,0x10,param_3);
    *(float *)(param_2 + 0xc) = lbl_803DF648;
    *(undefined2 *)(param_2 + 0x14) = 0xfb00;
    *param_2 = 1;
    *(float *)(param_2 + 4) = lbl_803DF61C;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80039370
 * EN v1.0 Address: 0x80039370
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x800393E8
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80039370(undefined4 param_1,undefined4 param_2,ushort *param_3,uint param_4)
{
  ushort uVar1;
  ushort uVar2;
  uint uVar3;
  bool bVar5;
  int *piVar4;
  undefined *puVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_80286840();
  uVar3 = (uint)((ulonglong)uVar7 >> 0x20);
  puVar6 = (undefined *)uVar7;
  uVar1 = param_3[1];
  uVar2 = *param_3;
  if (((param_4 & 0xff) != 0) || (bVar5 = FUN_800067f0(uVar3,0x10), !bVar5)) {
    FUN_8000681c(uVar3,0x10,uVar2);
    *(float *)(puVar6 + 0xc) = lbl_803DF648;
    *(ushort *)(puVar6 + 0x14) = -uVar1;
    *puVar6 = 1;
    *(float *)(puVar6 + 4) = lbl_803DF61C;
  }
  if ((*(byte *)(param_3 + 2) != 0) &&
     (piVar4 = *(int **)(*(int *)(uVar3 + 0x7c) + *(char *)(uVar3 + 0xad) * 4),
     *(char *)(*piVar4 + 0xf9) != '\0')) {
    FUN_800178e8((double)(lbl_803DF61C / lbl_803DC0C4),piVar4,2,
                 (int)*(char *)(piVar4[10] + 0x2d),*(byte *)(param_3 + 2) - 1,0);
    param_3[1] = 0;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80039468
 * EN v1.0 Address: 0x80039468
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x800394F0
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80039468(undefined4 param_1,undefined4 param_2,ushort param_3,short param_4,uint param_5,
                 uint param_6)
{
  uint uVar1;
  bool bVar2;
  undefined *puVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar4 >> 0x20);
  puVar3 = (undefined *)uVar4;
  if (((param_6 & 0xff) != 0) || (bVar2 = FUN_800067f0(uVar1,0x10), !bVar2)) {
    FUN_8000681c(uVar1,0x10,param_3);
    *(float *)(puVar3 + 0xc) =
         (float)((double)CONCAT44(0x43300000,param_5 ^ 0x80000000) - DOUBLE_803df650);
    *(short *)(puVar3 + 0x14) = -param_4;
    *puVar3 = 1;
    *(float *)(puVar3 + 4) = lbl_803DF61C;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80039518
 * EN v1.0 Address: 0x80039518
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80039598
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 * FUN_80039518(void)
{
  return &DAT_802cba60;
}

/*
 * --INFO--
 *
 * Function: FUN_80039520
 * EN v1.0 Address: 0x80039520
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x800395A4
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80039520(int param_1,uint param_2)
{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  int iVar4;
  int iVar5;
  
  iVar5 = 0;
  iVar2 = *(int *)(param_1 + 0x50);
  if (iVar2 != 0) {
    pbVar3 = *(byte **)(iVar2 + 0xc);
    if (pbVar3 == (byte *)0x0) {
      return 0;
    }
    iVar4 = 0;
    for (uVar1 = (uint)*(byte *)(iVar2 + 0x59); uVar1 != 0; uVar1 = uVar1 - 1) {
      if (param_2 == *pbVar3) {
        iVar5 = *(int *)(param_1 + 0x70) + iVar4;
      }
      pbVar3 = pbVar3 + 2;
      iVar4 = iVar4 + 0x10;
    }
  }
  return iVar5;
}

/*
 * --INFO--
 *
 * Function: FUN_80039580
 * EN v1.0 Address: 0x80039580
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x80039608
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80039580(int param_1,uint param_2,float *param_3)
{
  uint uVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  uint unaff_r31;
  
  iVar3 = *(int *)(param_1 + 0x50);
  iVar4 = 0;
  uVar1 = (uint)*(byte *)(iVar3 + 0x5a);
  do {
    if (uVar1 == 0) {
LAB_80039674:
      piVar2 = (int *)FUN_80017a54(param_1);
      iVar4 = FUN_80017970(piVar2,unaff_r31);
      *param_3 = *(float *)(iVar4 + 0xc);
      param_3[1] = *(float *)(iVar4 + 0x1c);
      param_3[2] = *(float *)(iVar4 + 0x2c);
      *param_3 = *param_3 + lbl_803DDA58;
      param_3[2] = param_3[2] + lbl_803DDA5C;
      return;
    }
    if (param_2 == *(byte *)(*(int *)(iVar3 + 0x10) + iVar4)) {
      unaff_r31 = (uint)*(byte *)(*(int *)(iVar3 + 0x10) + iVar4 + (int)*(char *)(param_1 + 0xad) +
                                 1);
      goto LAB_80039674;
    }
    iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
    uVar1 = uVar1 - 1;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_8003964c
 * EN v1.0 Address: 0x8003964C
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x800396D0
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8003964c(int param_1,uint param_2)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar5 = 0;
  iVar4 = *(int *)(param_1 + 0x50);
  if (iVar4 != 0) {
    iVar3 = 0;
    iVar2 = 0;
    for (uVar1 = (uint)*(byte *)(iVar4 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
      if ((*(char *)(*(int *)(iVar4 + 0x10) + *(char *)(param_1 + 0xad) + iVar3 + 1) != -1) &&
         (param_2 == *(byte *)(*(int *)(iVar4 + 0x10) + iVar3))) {
        iVar5 = *(int *)(param_1 + 0x6c) + iVar2;
      }
      iVar3 = *(char *)(iVar4 + 0x55) + iVar3 + 1;
      iVar2 = iVar2 + 0x12;
    }
  }
  return iVar5;
}

/*
 * --INFO--
 *
 * Function: FUN_800396cc
 * EN v1.0 Address: 0x800396CC
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x8003974C
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800396cc(int param_1,int param_2)
{
  bool bVar1;
  short sVar2;
  undefined2 uVar3;
  uint uVar4;
  char *pcVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  
  iVar9 = 0;
  iVar7 = *(int *)(param_1 + 0x50);
  if ((iVar7 != 0) && (pcVar5 = *(char **)(iVar7 + 0xc), pcVar5 != (char *)0x0)) {
    iVar8 = 0;
    for (uVar4 = (uint)*(byte *)(iVar7 + 0x59); uVar4 != 0; uVar4 = uVar4 - 1) {
      if (*pcVar5 == '\x01') {
        iVar9 = *(int *)(param_1 + 0x70) + iVar8;
      }
      pcVar5 = pcVar5 + 2;
      iVar8 = iVar8 + 0x10;
    }
  }
  iVar8 = 0;
  if ((iVar7 != 0) && (pcVar5 = *(char **)(iVar7 + 0xc), pcVar5 != (char *)0x0)) {
    iVar6 = 0;
    for (uVar4 = (uint)*(byte *)(iVar7 + 0x59); uVar4 != 0; uVar4 = uVar4 - 1) {
      if (*pcVar5 == '\0') {
        iVar8 = *(int *)(param_1 + 0x70) + iVar6;
      }
      pcVar5 = pcVar5 + 2;
      iVar6 = iVar6 + 0x10;
    }
  }
  if ((iVar9 != 0) && (iVar8 != 0)) {
    sVar2 = *(short *)(param_2 + 0x22);
    bVar1 = sVar2 == 0;
    if ((0 < sVar2) && (*(int *)(param_2 + 0x24) <= (int)*(short *)(iVar9 + 8))) {
      bVar1 = true;
    }
    if ((sVar2 < 0) && ((int)*(short *)(iVar9 + 8) <= *(int *)(param_2 + 0x24))) {
      bVar1 = true;
    }
    if (bVar1) {
      uVar4 = randomGetRange(0xfffffc18,1000);
      *(uint *)(param_2 + 0x24) = uVar4;
      if (*(int *)(param_2 + 0x24) < (int)*(short *)(iVar9 + 8)) {
        uVar3 = 0xff6a;
      }
      else {
        uVar3 = 0x96;
      }
      *(undefined2 *)(param_2 + 0x22) = uVar3;
      uVar4 = randomGetRange(0x1e,100);
      *(char *)(param_2 + 0x20) = (char)uVar4;
    }
    if (*(char *)(param_2 + 0x20) < '\x01') {
      *(ushort *)(iVar9 + 8) =
           *(short *)(iVar9 + 8) + *(short *)(param_2 + 0x22) * (ushort)DAT_803dc070;
      *(undefined2 *)(iVar9 + 10) = 0;
      *(undefined2 *)(iVar8 + 8) = *(undefined2 *)(iVar9 + 8);
      *(undefined2 *)(iVar8 + 10) = 0;
    }
    else {
      *(byte *)(param_2 + 0x20) = *(char *)(param_2 + 0x20) - DAT_803dc070;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003988c
 * EN v1.0 Address: 0x8003988C
 * EN v1.0 Size: 412b
 * EN v1.1 Address: 0x8003992C
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8003988c(double param_1,double param_2,int param_3,short *param_4)
{
  undefined4 uVar1;
  double dVar2;
  double dVar3;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  undefined4 local_20;
  uint uStack_1c;
  
  local_48 = (float)param_1;
  local_44 = (float)param_1;
  local_40 = (float)param_2;
  local_3c = (float)-param_2;
  if ((int)*(short *)(param_3 + 0x14) == (int)*(short *)(param_3 + 0x16)) {
    uVar1 = 1;
  }
  else {
    uStack_34 = (int)*param_4 ^ 0x80000000;
    local_38 = 0x43300000;
    uStack_2c = (int)*(short *)(param_3 + 0x16) ^ 0x80000000;
    local_30 = 0x43300000;
    local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x14) ^ 0x80000000);
    local_20 = 0x43300000;
    dVar3 = (double)(((float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803df650) -
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df650)) /
                    ((float)(local_28 - DOUBLE_803df650) -
                    (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df650)));
    dVar2 = (double)lbl_803DF61C;
    if ((dVar3 <= dVar2) && (dVar2 = dVar3, dVar3 < (double)lbl_803DF624)) {
      dVar2 = (double)lbl_803DF624;
    }
    uStack_1c = uStack_2c;
    dVar3 = FUN_80006a30(dVar2,&local_48,(float *)0x0);
    if (*(short *)(param_3 + 0x14) < *(short *)(param_3 + 0x16)) {
      dVar3 = -dVar3;
    }
    *param_4 = (short)(int)(dVar3 * (double)lbl_803DC074 +
                           (double)(float)((double)CONCAT44(0x43300000,(int)*param_4 ^ 0x80000000) -
                                          DOUBLE_803df650));
    if ((((double)lbl_803DF61C == dVar2) || (0x1ffe < *param_4)) || (*param_4 < -0x1ffe)) {
      *param_4 = *(short *)(param_3 + 0x14);
      uVar1 = 1;
    }
    else {
      uVar1 = 0;
    }
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_80039a28
 * EN v1.0 Address: 0x80039A28
 * EN v1.0 Size: 412b
 * EN v1.1 Address: 0x80039AB8
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80039a28(int param_1,int param_2)
{
  undefined4 uVar1;
  double dVar2;
  double dVar3;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  undefined4 local_20;
  uint uStack_1c;
  
  local_48 = lbl_803DF658;
  local_44 = lbl_803DF658;
  local_40 = lbl_803DF65C;
  local_3c = lbl_803DF660;
  if ((int)*(short *)(param_1 + 0x14) == (int)*(short *)(param_1 + 0x16)) {
    uVar1 = 1;
  }
  else {
    uStack_34 = (int)*(short *)(param_2 + 2) ^ 0x80000000;
    local_38 = 0x43300000;
    uStack_2c = (int)*(short *)(param_1 + 0x16) ^ 0x80000000;
    local_30 = 0x43300000;
    local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0x14) ^ 0x80000000);
    local_20 = 0x43300000;
    dVar3 = (double)(((float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803df650) -
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df650)) /
                    ((float)(local_28 - DOUBLE_803df650) -
                    (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df650)));
    dVar2 = (double)lbl_803DF61C;
    if ((dVar3 <= dVar2) && (dVar2 = dVar3, dVar3 < (double)lbl_803DF624)) {
      dVar2 = (double)lbl_803DF624;
    }
    uStack_1c = uStack_2c;
    dVar3 = FUN_80006a30(dVar2,&local_48,(float *)0x0);
    if (*(short *)(param_1 + 0x14) < *(short *)(param_1 + 0x16)) {
      dVar3 = -dVar3;
    }
    *(short *)(param_2 + 2) =
         (short)(int)(dVar3 * (double)lbl_803DC074 +
                     (double)(float)((double)CONCAT44(0x43300000,
                                                      (int)*(short *)(param_2 + 2) ^ 0x80000000) -
                                    DOUBLE_803df650));
    if ((((double)lbl_803DF61C == dVar2) || (0x1ffe < *(short *)(param_2 + 2))) ||
       (*(short *)(param_2 + 2) < -0x1ffe)) {
      *(undefined2 *)(param_2 + 2) = *(undefined2 *)(param_1 + 0x14);
      uVar1 = 1;
    }
    else {
      uVar1 = 0;
    }
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_80039bc4
 * EN v1.0 Address: 0x80039BC4
 * EN v1.0 Size: 680b
 * EN v1.1 Address: 0x80039C4C
 * EN v1.1 Size: 676b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80039bc4(double param_1,undefined4 param_2,char *param_3,int param_4)
{
  int iVar1;
  uint uVar2;
  bool bVar3;
  
  bVar3 = (double)lbl_803DF664 < param_1;
  if (((uint)(int)*(short *)(param_3 + 0x1a) >> 8 & 0xff) != (uint)bVar3) {
    *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8 | 4;
    *(undefined2 *)(param_3 + 0x16) = *(undefined2 *)(param_4 + 2);
    param_3[0x14] = '\0';
    param_3[0x15] = '\0';
    param_3[0x1c] = '\0';
    param_3[0x1d] = '\0';
  }
  switch(*(ushort *)(param_3 + 0x1a) & 0xff) {
  case 0:
    *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8;
    uVar2 = randomGetRange(0x32,200);
    *(short *)(param_3 + 0x1c) = (short)uVar2;
    break;
  case 1:
    *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803dc070;
    if ((*(short *)(param_3 + 0x1c) < 0) && (uVar2 = randomGetRange(0,100), 0x5a < (int)uVar2)) {
      *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8 | 5;
      if (*param_3 == '\0') {
        param_3[0x14] = '\x1f';
        param_3[0x15] = -1;
        uVar2 = randomGetRange(0,1);
        if (uVar2 == 0) {
          *(short *)(param_3 + 0x14) = -*(short *)(param_3 + 0x14);
        }
      }
      else {
        uVar2 = randomGetRange(0,100);
        if (0 < (int)uVar2) {
          param_3[0x14] = '\x1f';
          param_3[0x15] = -1;
          uVar2 = randomGetRange(0,1);
          if (uVar2 == 0) {
            *(short *)(param_3 + 0x14) = -*(short *)(param_3 + 0x14);
          }
        }
      }
    }
    break;
  case 4:
    if (*(short *)(param_3 + 0x1c) < 1) {
      iVar1 = FUN_80039a28((int)param_3,param_4);
      if (iVar1 != 0) {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8;
        *(undefined2 *)(param_4 + 2) = 0;
      }
    }
    else {
      *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803dc070;
    }
    break;
  case 5:
    if (*(short *)(param_3 + 0x1c) < 1) {
      iVar1 = FUN_80039a28((int)param_3,param_4);
      if (iVar1 != 0) {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8 | 6;
        *(short *)(param_3 + 0x14) = -*(short *)(param_3 + 0x14);
        uVar2 = randomGetRange(0x14,100);
        *(short *)(param_3 + 0x1c) = (short)uVar2;
      }
    }
    else {
      *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803dc070;
    }
    break;
  case 6:
    if (*(short *)(param_3 + 0x1c) < 1) {
      iVar1 = FUN_80039a28((int)param_3,param_4);
      if (iVar1 != 0) {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8 | 4;
        param_3[0x14] = '\0';
        param_3[0x15] = '\0';
        uVar2 = randomGetRange(0x14,100);
        *(short *)(param_3 + 0x1c) = (short)uVar2;
      }
    }
    else {
      *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803dc070;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80039e6c
 * EN v1.0 Address: 0x80039E6C
 * EN v1.0 Size: 856b
 * EN v1.1 Address: 0x80039EF0
 * EN v1.1 Size: 880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80039e6c(double param_1,short *param_2,char *param_3,int param_4)
{
  float fVar1;
  ushort uVar2;
  float fVar3;
  uint uVar4;
  int iVar5;
  bool bVar6;
  
  bVar6 = (double)lbl_803DF664 < param_1;
  if (((uint)(int)*(short *)(param_3 + 0x1a) >> 8 & 0xff) != (uint)bVar6) {
    *(ushort *)(param_3 + 0x1a) = (ushort)bVar6 << 8;
  }
  uVar2 = *(ushort *)(param_3 + 0x1a) & 0xff;
  if (uVar2 == 2) {
    if ((*param_3 != '\0') || (iVar5 = FUN_80039a28((int)param_3,param_4), iVar5 != 0)) {
      *(ushort *)(param_3 + 0x1a) = (ushort)bVar6 << 8;
    }
  }
  else if (uVar2 < 2) {
    if (uVar2 == 0) {
      if (*param_3 == '\0') {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar6 << 8 | 1;
        uVar4 = randomGetRange(100,400);
        *(short *)(param_3 + 0x1c) = (short)uVar4;
        *(undefined2 *)(param_3 + 0x14) = *(undefined2 *)(param_4 + 2);
      }
      else {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar6 << 8 | 3;
        *(undefined2 *)(param_3 + 0x16) = *(undefined2 *)(param_4 + 2);
        *(float *)(param_3 + 0x10) = lbl_803DF61C;
      }
    }
    else {
      *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803dc070;
      if (*(short *)(param_3 + 0x1c) < 0) {
        iVar5 = (int)*(short *)(param_3 + 0x14);
        uVar4 = randomGetRange(0,0x1fff);
        *(short *)(param_3 + 0x14) = (short)uVar4;
        if (iVar5 < 1) {
          if (*(short *)(param_3 + 0x14) - iVar5 < 0xe38) {
            *(short *)(param_3 + 0x14) = *(short *)(param_3 + 0x14) + 0xe38;
          }
          if (0x1fff < *(short *)(param_3 + 0x14)) {
            param_3[0x14] = '\x1f';
            param_3[0x15] = -1;
          }
        }
        else {
          if (iVar5 - *(short *)(param_3 + 0x14) < 0xe38) {
            *(short *)(param_3 + 0x14) = *(short *)(param_3 + 0x14) + 0xe38;
          }
          if (0x1fff < *(short *)(param_3 + 0x14)) {
            param_3[0x14] = '\x1f';
            param_3[0x15] = -1;
          }
          *(short *)(param_3 + 0x14) = -*(short *)(param_3 + 0x14);
        }
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar6 << 8 | 2;
        param_3[0x1c] = '\0';
        param_3[0x1d] = '\0';
        *(undefined2 *)(param_3 + 0x16) = *(undefined2 *)(param_4 + 2);
      }
    }
  }
  else if (uVar2 < 4) {
    if (*param_3 == '\0') {
      *(ushort *)(param_3 + 0x1a) = (ushort)bVar6 << 8;
    }
    else {
      iVar5 = FUN_80017730();
      *(short *)(param_3 + 0x14) = (short)iVar5 - *param_2;
      if (0x8000 < *(short *)(param_3 + 0x14)) {
        *(short *)(param_3 + 0x14) = *(short *)(param_3 + 0x14) + 1;
      }
      if (*(short *)(param_3 + 0x14) < -0x8000) {
        *(short *)(param_3 + 0x14) = *(short *)(param_3 + 0x14) + -1;
      }
      fVar3 = lbl_803DF624;
      uVar4 = (uint)*(short *)(param_3 + 0x14);
      if (((int)uVar4 < 0x2000) && (-0x2000 < (int)uVar4)) {
        if (*(float *)(param_3 + 0x10) <= lbl_803DF624) {
          *(short *)(param_4 + 2) = *(short *)(param_3 + 0x14);
        }
        else {
          *(short *)(param_4 + 2) =
               (short)(int)(*(float *)(param_3 + 0x10) *
                            (float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_3 + 0x16) - uVar4 ^
                                                     0x80000000) - DOUBLE_803df650) +
                           (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803df650
                                  ));
          fVar1 = -(lbl_803DF668 * lbl_803DC074 - *(float *)(param_3 + 0x10));
          *(float *)(param_3 + 0x10) = fVar1;
          if (fVar1 < fVar3) {
            *(float *)(param_3 + 0x10) = fVar3;
          }
        }
      }
      else {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar6 << 8;
      }
    }
  }
  if (*(short *)(param_4 + 2) < -0x1fff) {
    *(undefined2 *)(param_4 + 2) = 0xe001;
  }
  else if (0x1fff < *(short *)(param_4 + 2)) {
    *(undefined2 *)(param_4 + 2) = 0x1fff;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003a1c4
 * EN v1.0 Address: 0x8003A1C4
 * EN v1.0 Size: 260b
 * EN v1.1 Address: 0x8003A260
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003a1c4(int param_1,int param_2)
{
  uint uVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  psVar2 = (short *)0x0;
  iVar3 = *(int *)(param_1 + 0x50);
  if (iVar3 != 0) {
    iVar4 = 0;
    iVar5 = 0;
    for (uVar1 = (uint)*(byte *)(iVar3 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
      if ((*(char *)(*(int *)(iVar3 + 0x10) + *(char *)(param_1 + 0xad) + iVar4 + 1) != -1) &&
         (*(char *)(*(int *)(iVar3 + 0x10) + iVar4) == '\0')) {
        psVar2 = (short *)(*(int *)(param_1 + 0x6c) + iVar5);
      }
      iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
      iVar5 = iVar5 + 0x12;
    }
  }
  if (psVar2 != (short *)0x0) {
    if (*psVar2 != 0) {
      uVar1 = *psVar2 * 3;
      *psVar2 = (short)((int)uVar1 >> 2) + (ushort)((int)uVar1 < 0 && (uVar1 & 3) != 0);
    }
    if (psVar2[1] != 0) {
      uVar1 = psVar2[1] * 3;
      psVar2[1] = (short)((int)uVar1 >> 2) + (ushort)((int)uVar1 < 0 && (uVar1 & 3) != 0);
    }
    *(undefined2 *)(param_2 + 0x1a) = 0;
    return;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8003A328
 * EN v1.0 Address: 0x8003A2C8
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x8003A328
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8003A328(double param_1,short *param_2,char *param_3)
{
  uint uVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  psVar2 = (short *)0x0;
  iVar3 = *(int *)(param_2 + 0x28);
  if (iVar3 != 0) {
    iVar4 = 0;
    iVar5 = 0;
    for (uVar1 = (uint)*(byte *)(iVar3 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
      if ((*(char *)(*(int *)(iVar3 + 0x10) + *(char *)((int)param_2 + 0xad) + iVar4 + 1) != -1) &&
         (*(char *)(*(int *)(iVar3 + 0x10) + iVar4) == '\0')) {
        psVar2 = (short *)(*(int *)(param_2 + 0x36) + iVar5);
      }
      iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
      iVar5 = iVar5 + 0x12;
    }
  }
  if (psVar2 != (short *)0x0) {
    if (*psVar2 != 0) {
      uVar1 = *psVar2 * 3;
      *psVar2 = (short)((int)uVar1 >> 2) + (ushort)((int)uVar1 < 0 && (uVar1 & 3) != 0);
    }
    if (param_1 < (double)lbl_803DF624) {
      param_1 = -param_1;
    }
    if ((double)lbl_803DF664 < param_1) {
      FUN_80039bc4(param_1,(undefined4)(u32)param_2,param_3,(int)psVar2);
    }
    else {
      FUN_80039e6c(param_1,param_2,param_3,(int)psVar2);
    }
    *(ushort *)(param_3 + 0x1a) = *(ushort *)(param_3 + 0x1a) & 0xff;
    *(ushort *)(param_3 + 0x1a) =
         *(ushort *)(param_3 + 0x1a) | (ushort)((double)lbl_803DF664 < param_1) << 8;
  }
}

/*
 * --INFO--
 *
 * Function: FUN_8003a420
 * EN v1.0 Address: 0x8003A420
 * EN v1.0 Size: 1164b
 * EN v1.1 Address: 0x8003A478
 * EN v1.1 Size: 1332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003a420(undefined4 param_1,undefined4 param_2,float *param_3,int param_4,short *param_5,
                 undefined4 param_6,short param_7)
{
  short sVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  short *psVar5;
  int iVar6;
  short *psVar7;
  int iVar8;
  short *psVar9;
  int iVar10;
  int iVar11;
  short sVar12;
  int iVar13;
  short *psVar14;
  uint *puVar15;
  short *psVar16;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar17;
  short local_88 [6];
  uint uStack_7c;
  longlong local_78;
  undefined8 local_70;
  undefined8 local_68;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar17 = FUN_80286834();
  psVar5 = (short *)((ulonglong)uVar17 >> 0x20);
  psVar14 = param_5 + 0xf;
  fVar2 = *param_3 - *(float *)((int)uVar17 + 0xc);
  fVar3 = param_3[2] - *(float *)((int)uVar17 + 0x14);
  FUN_80293900((double)(fVar2 * fVar2 + fVar3 * fVar3));
  iVar6 = FUN_80017730();
  local_88[2] = (short)iVar6 - *psVar5;
  if (0x8000 < local_88[2]) {
    local_88[2] = local_88[2] + 1;
  }
  if (local_88[2] < -0x8000) {
    local_88[2] = local_88[2] + -1;
  }
  iVar6 = FUN_80017730();
  local_88[3] = param_7 + (short)iVar6;
  if (0x8000 < local_88[3]) {
    local_88[3] = local_88[3] + 1;
  }
  if (local_88[3] < -0x8000) {
    local_88[3] = local_88[3] + -1;
  }
  if ((char)DAT_803dd880 < '\0') {
    local_88[2] = local_88[2] + -0x8000;
    local_88[3] = -local_88[3];
    DAT_803dd880 = DAT_803dd880 & 0x7f;
  }
  iVar6 = 0;
  puVar15 = &DAT_802cba60;
  do {
    psVar16 = (short *)0x0;
    iVar8 = *(int *)(psVar5 + 0x28);
    if (iVar8 != 0) {
      iVar10 = 0;
      iVar11 = 0;
      for (uVar4 = (uint)*(byte *)(iVar8 + 0x5a); uVar4 != 0; uVar4 = uVar4 - 1) {
        if ((*(char *)(*(int *)(iVar8 + 0x10) + *(char *)((int)psVar5 + 0xad) + iVar10 + 1) != -1)
           && (*puVar15 == (uint)*(byte *)(*(int *)(iVar8 + 0x10) + iVar10))) {
          psVar16 = (short *)(*(int *)(psVar5 + 0x36) + iVar11);
        }
        iVar10 = *(char *)(iVar8 + 0x55) + iVar10 + 1;
        iVar11 = iVar11 + 0x12;
      }
    }
    if (psVar16 == (short *)0x0) break;
    uVar4 = 0;
    psVar7 = local_88 + 2;
    psVar9 = local_88;
    iVar8 = 2;
    do {
      if ((uVar4 & 1 ^ uVar4 >> 0x1f) == uVar4 >> 0x1f) {
        local_70 = (double)CONCAT44(0x43300000,(int)*param_5 ^ 0x80000000);
        iVar10 = (int)(lbl_803DF66C * (float)(local_70 - DOUBLE_803df650));
        local_68 = (double)(longlong)iVar10;
        sVar12 = (short)iVar10;
      }
      else {
        uStack_7c = (int)*psVar14 ^ 0x80000000U;
        local_88[4] = 0x4330;
        local_88[5] = 0;
        iVar10 = (int)(lbl_803DF66C *
                      (float)((double)CONCAT44(0x43300000,(int)*psVar14 ^ 0x80000000U) -
                             DOUBLE_803df650));
        local_78 = (longlong)iVar10;
        sVar12 = (short)iVar10;
      }
      sVar1 = *psVar7;
      *psVar9 = sVar1;
      if ((int)sVar12 < (int)sVar1) {
        *psVar9 = sVar12;
        *psVar7 = sVar1 - sVar12;
      }
      else {
        iVar10 = -(int)sVar12;
        if (sVar1 < iVar10) {
          *psVar9 = (short)iVar10;
          *psVar7 = sVar1 + sVar12;
        }
        else {
          *psVar7 = 0;
        }
      }
      psVar7 = psVar7 + 1;
      psVar9 = psVar9 + 1;
      uVar4 = uVar4 + 1;
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
    if (param_4 == 0) {
      iVar10 = (int)(short)((short)((int)psVar16[1] + (int)local_88[0] >> 1) - psVar16[1]);
      uVar4 = (uint)DAT_803dc070;
      local_68 = (double)CONCAT44(0x43300000,-(int)*param_5 ^ 0x80000000);
      iVar8 = uVar4 * ((int)(short)(int)(lbl_803DF66C * (float)(local_68 - DOUBLE_803df650)) /
                      DAT_803dc0c0);
      if (iVar8 <= iVar10) {
        local_68 = (double)CONCAT44(0x43300000,(int)*param_5 ^ 0x80000000);
        iVar11 = uVar4 * ((int)(short)(int)(lbl_803DF66C * (float)(local_68 - DOUBLE_803df650)) /
                         DAT_803dc0c0);
        iVar8 = iVar10;
        if (iVar11 < iVar10) {
          iVar8 = iVar11;
        }
      }
      iVar13 = (int)(short)((short)((int)*psVar16 + (int)local_88[1] >> 1) - *psVar16);
      local_68 = (double)CONCAT44(0x43300000,(int)*psVar14 ^ 0x80000000);
      iVar10 = (int)(lbl_803DF66C * (float)(local_68 - DOUBLE_803df650));
      local_70 = (double)(longlong)iVar10;
      iVar11 = (int)(short)iVar10;
      iVar10 = uVar4 * (-iVar11 / (DAT_803dc0c0 << 1));
      if ((iVar10 <= iVar13) &&
         (iVar11 = uVar4 * (iVar11 / (DAT_803dc0c0 << 1)), iVar10 = iVar13, iVar11 < iVar13)) {
        iVar10 = iVar11;
      }
      *psVar16 = *psVar16 + (short)iVar10;
      psVar16[1] = psVar16[1] + (short)iVar8;
    }
    else {
      *(short *)(param_4 + 0x14) = local_88[0];
      FUN_80039a28(param_4,(int)psVar16);
      *(short *)(param_4 + 0x44) = local_88[1];
      FUN_8003988c((double)lbl_803DF658,(double)lbl_803DF65C,param_4 + 0x30,psVar16);
      param_4 = param_4 + 0x60;
    }
    puVar15 = puVar15 + 1;
    psVar14 = psVar14 + 1;
    param_5 = param_5 + 1;
    iVar6 = iVar6 + 1;
  } while (iVar6 < 10);
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003a8ac
 * EN v1.0 Address: 0x8003A8AC
 * EN v1.0 Size: 284b
 * EN v1.1 Address: 0x8003A9AC
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003a8ac(undefined4 param_1,undefined4 param_2,int param_3,int param_4)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  int iVar7;
  int iVar8;
  uint *puVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286838();
  iVar2 = (int)((ulonglong)uVar10 >> 0x20);
  puVar9 = (uint *)uVar10;
  iVar7 = 0;
  for (iVar8 = 0; iVar8 < param_3; iVar8 = iVar8 + 1) {
    psVar6 = (short *)0x0;
    iVar3 = *(int *)(iVar2 + 0x50);
    if (iVar3 != 0) {
      iVar4 = 0;
      iVar5 = 0;
      for (uVar1 = (uint)*(byte *)(iVar3 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
        if ((*(char *)(*(int *)(iVar3 + 0x10) + *(char *)(iVar2 + 0xad) + iVar4 + 1) != -1) &&
           (*puVar9 == (uint)*(byte *)(*(int *)(iVar3 + 0x10) + iVar4))) {
          psVar6 = (short *)(*(int *)(iVar2 + 0x6c) + iVar5);
        }
        iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
        iVar5 = iVar5 + 0x12;
      }
    }
    iVar3 = FUN_80039a28(param_4,(int)psVar6);
    iVar4 = FUN_8003988c((double)lbl_803DF658,(double)lbl_803DF65C,param_4 + 0x30,psVar6);
    iVar7 = iVar7 + iVar3 + iVar4;
    puVar9 = puVar9 + 1;
    param_4 = param_4 + 0x60;
  }
  countLeadingZeros(param_3 * 2 - iVar7);
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003a9c8
 * EN v1.0 Address: 0x8003A9C8
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x8003AAB8
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003a9c8(int param_1,uint param_2,undefined2 param_3,undefined2 param_4)
{
  uint uVar1;
  
  if ((int)param_2 < 1) {
    return;
  }
  uVar1 = param_2 >> 3;
  if (uVar1 != 0) {
    do {
      *(undefined2 *)(param_1 + 0x14) = param_3;
      *(undefined2 *)(param_1 + 0x44) = param_4;
      *(undefined2 *)(param_1 + 0x74) = param_3;
      *(undefined2 *)(param_1 + 0xa4) = param_4;
      *(undefined2 *)(param_1 + 0xd4) = param_3;
      *(undefined2 *)(param_1 + 0x104) = param_4;
      *(undefined2 *)(param_1 + 0x134) = param_3;
      *(undefined2 *)(param_1 + 0x164) = param_4;
      *(undefined2 *)(param_1 + 0x194) = param_3;
      *(undefined2 *)(param_1 + 0x1c4) = param_4;
      *(undefined2 *)(param_1 + 500) = param_3;
      *(undefined2 *)(param_1 + 0x224) = param_4;
      *(undefined2 *)(param_1 + 0x254) = param_3;
      *(undefined2 *)(param_1 + 0x284) = param_4;
      *(undefined2 *)(param_1 + 0x2b4) = param_3;
      *(undefined2 *)(param_1 + 0x2e4) = param_4;
      param_1 = param_1 + 0x300;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
    param_2 = param_2 & 7;
    if (param_2 == 0) {
      return;
    }
  }
  do {
    *(undefined2 *)(param_1 + 0x14) = param_3;
    *(undefined2 *)(param_1 + 0x44) = param_4;
    param_1 = param_1 + 0x60;
    param_2 = param_2 - 1;
  } while (param_2 != 0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003aa48
 * EN v1.0 Address: 0x8003AA48
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x8003AB38
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003aa48(int param_1)
{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  
  uVar6 = 0;
  do {
    puVar2 = (undefined2 *)0x0;
    iVar3 = *(int *)(param_1 + 0x50);
    if (iVar3 != 0) {
      iVar4 = 0;
      iVar5 = 0;
      for (uVar1 = (uint)*(byte *)(iVar3 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
        if ((*(char *)(*(int *)(iVar3 + 0x10) + *(char *)(param_1 + 0xad) + iVar4 + 1) != -1) &&
           (uVar6 == *(byte *)(*(int *)(iVar3 + 0x10) + iVar4))) {
          puVar2 = (undefined2 *)(*(int *)(param_1 + 0x6c) + iVar5);
        }
        iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
        iVar5 = iVar5 + 0x12;
      }
    }
    if (puVar2 != (undefined2 *)0x0) {
      *puVar2 = 0;
      puVar2[1] = 0;
      puVar2[2] = 0;
    }
    uVar6 = uVar6 + 1;
  } while ((int)uVar6 < 0x16);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003aaf0
 * EN v1.0 Address: 0x8003AAF0
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x8003ABD8
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003aaf0(int param_1,uint *param_2,int param_3,int param_4,int param_5)
{
  short sVar1;
  uint uVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  int iVar6;
  short *psVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  
  for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
    psVar7 = (short *)0x0;
    iVar8 = *(int *)(param_1 + 0x50);
    if (iVar8 != 0) {
      iVar9 = 0;
      iVar10 = 0;
      for (uVar2 = (uint)*(byte *)(iVar8 + 0x5a); uVar2 != 0; uVar2 = uVar2 - 1) {
        if ((*(char *)(*(int *)(iVar8 + 0x10) + *(char *)(param_1 + 0xad) + iVar9 + 1) != -1) &&
           (*param_2 == (uint)*(byte *)(*(int *)(iVar8 + 0x10) + iVar9))) {
          psVar7 = (short *)(*(int *)(param_1 + 0x6c) + iVar10);
        }
        iVar9 = *(char *)(iVar8 + 0x55) + iVar9 + 1;
        iVar10 = iVar10 + 0x12;
      }
    }
    if (psVar7 != (short *)0x0) {
      sVar1 = *psVar7;
      sVar5 = (short)param_4;
      sVar3 = (short)param_5;
      sVar4 = sVar5;
      if ((param_4 <= sVar1) && (sVar4 = sVar1, param_5 < sVar1)) {
        sVar4 = sVar3;
      }
      *psVar7 = sVar4;
      sVar1 = psVar7[1];
      sVar4 = sVar5;
      if ((param_4 <= sVar1) && (sVar4 = sVar1, param_5 < sVar1)) {
        sVar4 = sVar3;
      }
      psVar7[1] = sVar4;
      sVar1 = psVar7[2];
      if ((param_4 <= sVar1) && (sVar5 = sVar1, param_5 < sVar1)) {
        sVar5 = sVar3;
      }
      psVar7[2] = sVar5;
    }
    param_2 = param_2 + 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003ac24
 * EN v1.0 Address: 0x8003AC24
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x8003AD0C
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003ac24(int param_1,uint *param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  for (iVar2 = 0; iVar2 < param_3; iVar2 = iVar2 + 1) {
    psVar3 = (short *)0x0;
    iVar4 = *(int *)(param_1 + 0x50);
    if (iVar4 != 0) {
      iVar5 = 0;
      iVar6 = 0;
      for (uVar1 = (uint)*(byte *)(iVar4 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
        if ((*(char *)(*(int *)(iVar4 + 0x10) + *(char *)(param_1 + 0xad) + iVar5 + 1) != -1) &&
           (*param_2 == (uint)*(byte *)(*(int *)(iVar4 + 0x10) + iVar5))) {
          psVar3 = (short *)(*(int *)(param_1 + 0x6c) + iVar6);
        }
        iVar5 = *(char *)(iVar4 + 0x55) + iVar5 + 1;
        iVar6 = iVar6 + 0x12;
      }
    }
    if (psVar3 != (short *)0x0) {
      psVar3[1] = (short)(psVar3[1] * 3 >> 2);
      *psVar3 = (short)(*psVar3 * 3 >> 2);
      psVar3[2] = (short)(psVar3[2] * 3 >> 2);
    }
    param_2 = param_2 + 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003ad08
 * EN v1.0 Address: 0x8003AD08
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x8003ADF4
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003ad08(int param_1,uint *param_2,int param_3,int param_4)
{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
    puVar2 = (undefined2 *)0x0;
    iVar3 = *(int *)(param_1 + 0x50);
    if (iVar3 != 0) {
      iVar4 = 0;
      iVar5 = 0;
      for (uVar1 = (uint)*(byte *)(iVar3 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
        if ((*(char *)(*(int *)(iVar3 + 0x10) + *(char *)(param_1 + 0xad) + iVar4 + 1) != -1) &&
           (*param_2 == (uint)*(byte *)(*(int *)(iVar3 + 0x10) + iVar4))) {
          puVar2 = (undefined2 *)(*(int *)(param_1 + 0x6c) + iVar5);
        }
        iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
        iVar5 = iVar5 + 0x12;
      }
    }
    if (puVar2 != (undefined2 *)0x0) {
      *(undefined2 *)(param_4 + 0x16) = puVar2[1];
      *(undefined2 *)(param_4 + 0x46) = *puVar2;
    }
    param_2 = param_2 + 1;
    param_4 = param_4 + 0x60;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003add8
 * EN v1.0 Address: 0x8003ADD8
 * EN v1.0 Size: 660b
 * EN v1.1 Address: 0x8003AEBC
 * EN v1.1 Size: 780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003add8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,uint param_5,
                 uint param_6)
{
  int iVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  short sVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  short *psVar9;
  int iVar10;
  int iVar11;
  short *psVar12;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar13;
  short local_88 [4];
  undefined4 local_80;
  uint uStack_7c;
  longlong local_78;
  undefined8 local_70;
  double local_68;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar13 = FUN_8028683c();
  psVar9 = (short *)((ulonglong)uVar13 >> 0x20);
  iVar7 = (int)uVar13;
  psVar12 = (short *)0x0;
  iVar8 = *(int *)(psVar9 + 0x28);
  if (iVar8 != 0) {
    iVar10 = 0;
    iVar11 = 0;
    for (uVar4 = (uint)*(byte *)(iVar8 + 0x5a); uVar4 != 0; uVar4 = uVar4 - 1) {
      if ((*(char *)(*(int *)(iVar8 + 0x10) + *(char *)((int)psVar9 + 0xad) + iVar10 + 1) != -1) &&
         (*(char *)(*(int *)(iVar8 + 0x10) + iVar10) == '\0')) {
        psVar12 = (short *)(*(int *)(psVar9 + 0x36) + iVar11);
      }
      iVar10 = *(char *)(iVar8 + 0x55) + iVar10 + 1;
      iVar11 = iVar11 + 0x12;
    }
  }
  if (psVar12 != (short *)0x0) {
    if (iVar7 == 0) {
      psVar12[1] = psVar12[1] >> 1;
      *psVar12 = *psVar12 >> 1;
    }
    else {
      fVar2 = *(float *)(psVar9 + 6) - *(float *)(iVar7 + 0xc);
      fVar3 = *(float *)(psVar9 + 10) - *(float *)(iVar7 + 0x14);
      FUN_80293900((double)(fVar2 * fVar2 + fVar3 * fVar3));
      iVar7 = FUN_80017730();
      local_88[0] = (short)iVar7 - *psVar9;
      if (0x8000 < local_88[0]) {
        local_88[0] = local_88[0] + 1;
      }
      if (local_88[0] < -0x8000) {
        local_88[0] = local_88[0] + -1;
      }
      if ((param_5 & 0xff) != 0) {
        local_88[0] = local_88[0] + -0x8000;
      }
      iVar7 = FUN_80017730();
      local_88[1] = (short)iVar7 + -0x3fff;
      uStack_7c = param_4 ^ 0x80000000;
      local_80 = 0x43300000;
      iVar7 = (int)(lbl_803DF66C *
                   (float)((double)CONCAT44(0x43300000,param_4 ^ 0x80000000) - DOUBLE_803df650));
      local_78 = (longlong)iVar7;
      sVar5 = (short)iVar7;
      psVar9 = local_88;
      local_70 = (double)CONCAT44(0x43300000,param_6 ^ 0x80000000);
      fVar2 = lbl_803DF66C * (float)(local_70 - DOUBLE_803df650);
      iVar7 = (int)fVar2;
      local_68 = (double)(longlong)iVar7;
      iVar8 = -(int)(short)iVar7;
      iVar10 = -(int)sVar5;
      iVar11 = 2;
      iVar7 = param_3;
      do {
        *psVar9 = *psVar9 - *(short *)(iVar7 + 0x14);
        sVar6 = *psVar9;
        if (sVar6 < iVar8) {
          sVar6 = (short)iVar8;
        }
        else {
          iVar1 = (int)fVar2;
          local_68 = (double)(longlong)iVar1;
          if ((int)(short)iVar1 < (int)sVar6) {
            local_70 = (double)(longlong)iVar1;
            sVar6 = (short)iVar1;
          }
        }
        *psVar9 = sVar6;
        *(short *)(iVar7 + 0x14) = *(short *)(iVar7 + 0x14) + *psVar9;
        if ((int)sVar5 < (int)*(short *)(iVar7 + 0x14)) {
          *(short *)(iVar7 + 0x14) = sVar5;
        }
        if (*(short *)(iVar7 + 0x14) < iVar10) {
          *(short *)(iVar7 + 0x14) = (short)iVar10;
        }
        iVar7 = iVar7 + 0x30;
        psVar9 = psVar9 + 1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      psVar12[1] = *(short *)(param_3 + 0x14);
      *psVar12 = *(short *)(param_3 + 0x44);
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003b06c
 * EN v1.0 Address: 0x8003B06C
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x8003B1C8
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003b06c(short *param_1,undefined4 param_2,int param_3,uint param_4)
{
  uint uVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar6 = 0;
  iVar3 = *(int *)(param_1 + 0x28);
  if (iVar3 != 0) {
    iVar4 = 0;
    iVar5 = 0;
    for (uVar1 = (uint)*(byte *)(iVar3 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
      if ((*(char *)(*(int *)(iVar3 + 0x10) + *(char *)((int)param_1 + 0xad) + iVar4 + 1) != -1) &&
         (*(char *)(*(int *)(iVar3 + 0x10) + iVar4) == '\0')) {
        iVar6 = *(int *)(param_1 + 0x36) + iVar5;
      }
      iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
      iVar5 = iVar5 + 0x12;
    }
  }
  if (iVar6 != 0) {
    iVar3 = FUN_80017730();
    *(short *)(param_3 + 0x14) = (short)iVar3 - *param_1;
    sVar2 = (short)(int)(lbl_803DF66C *
                        (float)((double)CONCAT44(0x43300000,param_4 ^ 0x80000000) - DOUBLE_803df650)
                        );
    if ((int)sVar2 < (int)*(short *)(param_3 + 0x14)) {
      *(short *)(param_3 + 0x14) = sVar2;
    }
    iVar3 = -(int)sVar2;
    if (*(short *)(param_3 + 0x14) < iVar3) {
      *(short *)(param_3 + 0x14) = (short)iVar3;
    }
    *(undefined2 *)(iVar6 + 2) = *(undefined2 *)(param_3 + 0x14);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003b1a4
 * EN v1.0 Address: 0x8003B1A4
 * EN v1.0 Size: 220b
 * EN v1.1 Address: 0x8003B320
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003b1a4(int param_1,int param_2)
{
  uint uVar1;
  int *piVar2;
  char *pcVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  
  piVar2 = (int *)0x0;
  iVar5 = *(int *)(param_1 + 0x50);
  if ((iVar5 != 0) && (pcVar3 = *(char **)(iVar5 + 0xc), pcVar3 != (char *)0x0)) {
    iVar6 = 0;
    for (uVar1 = (uint)*(byte *)(iVar5 + 0x59); uVar1 != 0; uVar1 = uVar1 - 1) {
      if (*pcVar3 == '\x05') {
        piVar2 = (int *)(*(int *)(param_1 + 0x70) + iVar6);
      }
      pcVar3 = pcVar3 + 2;
      iVar6 = iVar6 + 0x10;
    }
  }
  piVar4 = (int *)0x0;
  if ((iVar5 != 0) && (pcVar3 = *(char **)(iVar5 + 0xc), pcVar3 != (char *)0x0)) {
    iVar6 = 0;
    for (uVar1 = (uint)*(byte *)(iVar5 + 0x59); uVar1 != 0; uVar1 = uVar1 - 1) {
      if (*pcVar3 == '\x04') {
        piVar4 = (int *)(*(int *)(param_1 + 0x70) + iVar6);
      }
      pcVar3 = pcVar3 + 2;
      iVar6 = iVar6 + 0x10;
    }
  }
  if (piVar2 == (int *)0x0) {
    return;
  }
  if (piVar4 == (int *)0x0) {
    return;
  }
  iVar5 = *piVar4 + (uint)DAT_803dc070 * 0x30;
  if (0x1ff < iVar5) {
    iVar5 = 0x200;
  }
  *piVar2 = iVar5;
  *piVar4 = iVar5;
  *(undefined *)(param_2 + 0x1e) = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003b280
 * EN v1.0 Address: 0x8003B280
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x8003B408
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003b280(int param_1,int param_2)
{
  int *piVar1;
  uint uVar2;
  char *pcVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  
  piVar1 = (int *)0x0;
  iVar5 = *(int *)(param_1 + 0x50);
  if ((iVar5 != 0) && (pcVar3 = *(char **)(iVar5 + 0xc), pcVar3 != (char *)0x0)) {
    iVar6 = 0;
    for (uVar2 = (uint)*(byte *)(iVar5 + 0x59); uVar2 != 0; uVar2 = uVar2 - 1) {
      if (*pcVar3 == '\x05') {
        piVar1 = (int *)(*(int *)(param_1 + 0x70) + iVar6);
      }
      pcVar3 = pcVar3 + 2;
      iVar6 = iVar6 + 0x10;
    }
  }
  piVar4 = (int *)0x0;
  if ((iVar5 != 0) && (pcVar3 = *(char **)(iVar5 + 0xc), pcVar3 != (char *)0x0)) {
    iVar6 = 0;
    for (uVar2 = (uint)*(byte *)(iVar5 + 0x59); uVar2 != 0; uVar2 = uVar2 - 1) {
      if (*pcVar3 == '\x04') {
        piVar4 = (int *)(*(int *)(param_1 + 0x70) + iVar6);
      }
      pcVar3 = pcVar3 + 2;
      iVar6 = iVar6 + 0x10;
    }
  }
  if ((piVar1 != (int *)0x0) && (piVar4 != (int *)0x0)) {
    uVar2 = (int)*(char *)(param_2 + 0x1e) & 0xf;
    if (uVar2 == 1) {
      if (((int)*(char *)(param_2 + 0x1e) & 0x80U) == 0) {
        iVar5 = *piVar4 + (uint)DAT_803dc070 * 0x60;
        if (0x200 < iVar5) {
          if (iVar5 + -0x200 < 0) {
            iVar5 = 0;
            *(undefined *)(param_2 + 0x1e) = 0;
          }
          else {
            iVar5 = 0x2ff;
            *(undefined *)(param_2 + 0x1e) = 0x81;
          }
          *(undefined *)(param_2 + 0x1f) = 0x28;
        }
      }
      else {
        iVar5 = *piVar4 + (uint)DAT_803dc070 * -0x60;
        if (iVar5 < 0) {
          iVar5 = 0;
          *(undefined *)(param_2 + 0x1e) = 0;
          *(undefined *)(param_2 + 0x1f) = 0;
        }
      }
      *piVar1 = iVar5;
      *piVar4 = iVar5;
    }
    else if (uVar2 == 0) {
      if (*(char *)(param_2 + 0x1f) < '\x01') {
        uVar2 = randomGetRange(0,1000);
        if (0x3de < (int)uVar2) {
          *(undefined *)(param_2 + 0x1e) = 1;
          *(undefined *)(param_2 + 0x1f) = 0;
        }
      }
      else {
        *(byte *)(param_2 + 0x1f) = *(char *)(param_2 + 0x1f) - DAT_803dc070;
      }
    }
    FUN_800396cc(param_1,param_2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003b444
 * EN v1.0 Address: 0x8003B444
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x8003B5F8
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003b444(short *param_1,char *param_2)
{
  uint uVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  psVar2 = (short *)0x0;
  iVar3 = *(int *)(param_1 + 0x28);
  if (iVar3 != 0) {
    iVar4 = 0;
    iVar5 = 0;
    for (uVar1 = (uint)*(byte *)(iVar3 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
      if ((*(char *)(*(int *)(iVar3 + 0x10) + *(char *)((int)param_1 + 0xad) + iVar4 + 1) != -1) &&
         (*(char *)(*(int *)(iVar3 + 0x10) + iVar4) == '\0')) {
        psVar2 = (short *)(*(int *)(param_1 + 0x36) + iVar5);
      }
      iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
      iVar5 = iVar5 + 0x12;
    }
  }
  if (psVar2 != (short *)0x0) {
    if (*psVar2 != 0) {
      uVar1 = *psVar2 * 3;
      *psVar2 = (short)((int)uVar1 >> 2) + (ushort)((int)uVar1 < 0 && (uVar1 & 3) != 0);
    }
    FUN_80039e6c((double)lbl_803DF624,param_1,param_2,(int)psVar2);
    *(ushort *)(param_2 + 0x1a) = *(ushort *)(param_2 + 0x1a) & 0xff;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003b540
 * EN v1.0 Address: 0x8003B540
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8003B6D8
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003b540(undefined param_1,undefined param_2,undefined param_3,undefined param_4)
{
  DAT_803dd88d = param_1;
  DAT_803dd88c = param_2;
  DAT_803dd88b = param_3;
  DAT_803dd889 = 1;
  DAT_803dd88a = param_4;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003b56c
 * EN v1.0 Address: 0x8003B56C
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8003B700
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003b56c(undefined2 param_1,undefined2 param_2,undefined2 param_3)
{
  DAT_803dd898 = param_1;
  DAT_803dd896 = param_2;
  DAT_803dd894 = param_3;
  DAT_803dd888 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003b590
 * EN v1.0 Address: 0x8003B590
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x8003B718
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003b590(undefined4 param_1,undefined4 param_2,int *param_3)
{
  undefined2 *puVar1;
  float *pfVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  
  uVar9 = FUN_80286830();
  puVar1 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  if ((1 < *(byte *)(*(int *)(puVar1 + 0x28) + 0x58)) && (puVar1[0x22] == 0x2d)) {
    iVar6 = *(int *)(puVar1 + 0x5c);
    iVar8 = 1;
    iVar5 = 0x18;
    iVar3 = iVar6;
    for (iVar7 = 0; iVar7 < *(short *)(iVar6 + 0xb0); iVar7 = iVar7 + 1) {
      if (iVar8 < (int)(uint)*(byte *)(*(int *)(puVar1 + 0x28) + 0x58)) {
        pfVar2 = (float *)FUN_80017970(param_3,(int)*(char *)(*(int *)(*(int *)(puVar1 + 0x28) +
                                                                      0x2c) +
                                                             iVar5 + *(char *)((int)puVar1 + 0xad) +
                                                             0x2a));
        iVar4 = *(int *)(*(int *)(puVar1 + 0x28) + 0x2c);
        local_3c = *(float *)(iVar4 + iVar5 + 0x18);
        local_38 = *(float *)(iVar4 + iVar5 + 0x1c);
        local_34 = *(float *)(iVar4 + iVar5 + 0x20);
        FUN_80247bf8(pfVar2,&local_3c,&local_3c);
        local_3c = local_3c + lbl_803DDA58;
        local_34 = local_34 + lbl_803DDA5C;
        *(float *)(iVar3 + 0x6c) = local_3c;
        *(float *)(iVar3 + 0x74) = local_38;
        *(float *)(iVar3 + 0x7c) = local_34;
      }
      if (iVar8 < (int)(uint)*(byte *)(*(int *)(puVar1 + 0x28) + 0x58)) {
        iVar4 = *(int *)(*(int *)(puVar1 + 0x28) + 0x2c);
        local_48 = *(float *)(iVar4 + iVar5);
        local_44 = *(float *)(iVar4 + iVar5 + 4);
        local_40 = *(float *)(iVar4 + iVar5 + 8);
        FUN_80247bf8((float *)(param_3[(*(ushort *)(param_3 + 6) & 1) + 3] +
                              *(char *)(iVar4 + iVar5 + *(char *)((int)puVar1 + 0xad) + 0x12) * 0x40
                              ),&local_48,&local_48);
        local_48 = local_48 + lbl_803DDA58;
        local_40 = local_40 + lbl_803DDA5C;
        *(float *)(iVar3 + 0x54) = local_48;
        *(float *)(iVar3 + 0x5c) = local_44;
        *(float *)(iVar3 + 100) = local_40;
      }
      iVar8 = iVar8 + 2;
      iVar5 = iVar5 + 0x30;
      iVar3 = iVar3 + 4;
    }
    if (*(short *)(iVar6 + 0xb0) != 0) {
      iVar6 = iVar6 + *(short *)(iVar6 + 0xb2) * 4;
      local_3c = *(float *)(iVar6 + 0x6c);
      local_38 = *(float *)(iVar6 + 0x74);
      local_34 = *(float *)(iVar6 + 0x7c);
      (**(code **)(**(int **)(puVar1 + 0x34) + 0x28))(puVar1,(int)uVar9,&local_48);
      local_3c = local_3c - local_48;
      local_38 = local_38 - local_44;
      local_34 = local_34 - local_40;
      iVar3 = FUN_80017730();
      *puVar1 = (short)iVar3;
      FUN_80293900((double)(local_3c * local_3c + local_34 * local_34));
      iVar3 = FUN_80017730();
      puVar1[1] = 0x4000 - (short)iVar3;
      puVar1[2] = 0;
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003b7dc
 * EN v1.0 Address: 0x8003B7DC
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x8003B9B0
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003b7dc(int param_1)
{
  if (*(int *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4) != 0) {
    FUN_800406cc(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003b818
 * EN v1.0 Address: 0x8003B818
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x8003B9EC
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003b818(int param_1)
{
  if ((*(int *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4) != 0) &&
     (FUN_80040a88(param_1), *(int *)(param_1 + 0x74) != 0)) {
    FUN_800400b0();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003b870
 * EN v1.0 Address: 0x8003B870
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8003BA48
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003b870(undefined4 param_1)
{
  DAT_803dd890 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003b878
 * EN v1.0 Address: 0x8003B878
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x8003BA50
 * EN v1.1 Size: 540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003b878(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 int param_5,undefined4 param_6)
{
  short sVar1;
  undefined4 uVar2;
  int iVar3;
  code *pcVar4;
  int iVar5;
  char cVar7;
  int iVar6;
  undefined8 uVar8;
  
  uVar8 = FUN_8028683c();
  uVar2 = (undefined4)((ulonglong)uVar8 >> 0x20);
  if (((((*(ushort *)(param_5 + 0xb0) & 0x40) == 0) && (*(int *)(param_5 + 0xc4) == 0)) &&
      ((*(ushort *)(param_5 + 6) & 0x4000) == 0)) &&
     ((*(int *)(param_5 + 0x30) == 0 || ((*(ushort *)(*(int *)(param_5 + 0x30) + 6) & 0x4000) == 0))
     )) {
    FUN_80017a04();
    *(ushort *)(param_5 + 0xb0) = *(ushort *)(param_5 + 0xb0) | 0x800;
    cVar7 = (char)param_6;
    if (*(int **)(param_5 + 0x68) == (int *)0x0) {
      if (cVar7 != '\0') {
        sVar1 = *(short *)(param_5 + 0x46);
        if ((sVar1 == 0x1f) || ((sVar1 < 0x1f && (sVar1 == 0)))) {
          FUN_802950c8(param_5,uVar2,(int)uVar8,param_3,param_4,cVar7);
        }
        else if ((*(int *)(*(int *)(param_5 + 0x7c) + *(char *)(param_5 + 0xad) * 4) != 0) &&
                (FUN_80040a88(param_5), *(int *)(param_5 + 0x74) != 0)) {
          FUN_800400b0();
        }
      }
    }
    else if ((*(ushort *)(param_5 + 0xb0) & 0x4000) == 0) {
      pcVar4 = *(code **)(**(int **)(param_5 + 0x68) + 0x10);
      if (pcVar4 != (code *)0x0) {
        (*pcVar4)(param_5,uVar2,(int)uVar8,param_3,param_4,param_6);
      }
    }
    else if (((cVar7 != '\0') &&
             (*(int *)(*(int *)(param_5 + 0x7c) + *(char *)(param_5 + 0xad) * 4) != 0)) &&
            (FUN_80040a88(param_5), *(int *)(param_5 + 0x74) != 0)) {
      FUN_800400b0();
    }
    FUN_80017a00();
    iVar5 = param_5;
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_5 + 0xeb); iVar6 = iVar6 + 1) {
      iVar3 = *(int *)(iVar5 + 200);
      if (*(short *)(iVar3 + 0x44) == 0x2d) {
        FUN_8003b590(iVar3,param_5,*(int **)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4));
      }
      iVar5 = iVar5 + 4;
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003ba68
 * EN v1.0 Address: 0x8003BA68
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8003BC6C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_8003ba68(void)
{
  return DAT_803dd8bc;
}

/*
 * --INFO--
 *
 * Function: FUN_8003ba74
 * EN v1.0 Address: 0x8003BA74
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8003BC74
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003ba74(undefined param_1)
{
  DAT_803dd8bc = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003ba80
 * EN v1.0 Address: 0x8003BA80
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x8003BC7C
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8003ba80(float *param_1,float *param_2)
{
  float fVar1;
  undefined4 uVar2;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  local_2c = *param_1;
  local_28 = param_1[1];
  local_24 = param_1[2];
  local_38 = param_1[4];
  local_34 = param_1[5];
  local_30 = param_1[6];
  local_20 = param_1[8];
  local_1c = param_1[9];
  local_18 = param_1[10];
  if (((((local_2c == lbl_803DF684) && (local_28 == lbl_803DF684)) &&
       (local_24 == lbl_803DF684)) ||
      (((local_38 == lbl_803DF684 && (local_34 == lbl_803DF684)) && (local_30 == lbl_803DF684)
       ))) || (((local_20 == lbl_803DF684 && (local_1c == lbl_803DF684)) &&
               (local_18 == lbl_803DF684)))) {
    uVar2 = 0;
  }
  else {
    FUN_80247ef8(&local_2c,&local_2c);
    FUN_80247ef8(&local_38,&local_38);
    FUN_80247ef8(&local_20,&local_20);
    *param_2 = local_2c;
    param_2[1] = local_28;
    param_2[2] = local_24;
    fVar1 = lbl_803DF684;
    param_2[3] = lbl_803DF684;
    param_2[4] = local_38;
    param_2[5] = local_34;
    param_2[6] = local_30;
    param_2[7] = fVar1;
    param_2[8] = local_20;
    param_2[9] = local_1c;
    param_2[10] = local_18;
    param_2[0xb] = fVar1;
    uVar2 = 1;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_8003bbfc
 * EN v1.0 Address: 0x8003BBFC
 * EN v1.0 Size: 420b
 * EN v1.1 Address: 0x8003BDE0
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8003bbfc(float *param_1,undefined2 *param_2,undefined2 *param_3,undefined2 *param_4)
{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  float local_78 [19];
  
  iVar2 = FUN_8003ba80(param_1,local_78);
  if (iVar2 == 0) {
    uVar3 = 0;
  }
  else {
    dVar4 = (double)FUN_802924c8();
    if ((double)lbl_803DF688 <= dVar4) {
      dVar5 = (double)FUN_80292b24();
      dVar6 = (double)lbl_803DF684;
      dVar5 = (double)(float)(dVar5 - dVar6);
    }
    else if (dVar4 <= (double)lbl_803DF68C) {
      dVar5 = (double)FUN_80292b24();
      dVar6 = (double)lbl_803DF684;
      dVar5 = (double)(float)(dVar6 - dVar5);
    }
    else {
      dVar5 = (double)FUN_80292b24();
      dVar6 = (double)FUN_80292b24();
    }
    fVar1 = lbl_803DF694;
    dVar7 = (double)lbl_803DF690;
    *param_4 = (short)(int)((float)(dVar7 * dVar6) / lbl_803DF694);
    *param_3 = (short)(int)((float)(dVar7 * dVar4) / fVar1);
    *param_2 = (short)(int)((float)(dVar7 * dVar5) / fVar1);
    uVar3 = 1;
  }
  return uVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_8003bda0
 * EN v1.0 Address: 0x8003BDA0
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x8003BF30
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003bda0(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)
{
  byte bVar1;
  byte bVar2;
  int iVar3;
  float *pfVar4;
  float *pfVar5;
  float *pfVar6;
  double dVar7;
  
  iVar3 = FUN_80286838();
  pfVar4 = (float *)FUN_8001779c();
  bVar1 = *(byte *)(iVar3 + 0xf3);
  bVar2 = *(byte *)(iVar3 + 0xf4);
  pfVar5 = pfVar4 + 0x9c0;
  pfVar6 = pfVar4 + 0x4b0;
  FUN_80017794(0);
  dVar7 = (double)lbl_803DF684;
  for (iVar3 = 0; iVar3 < (int)((uint)bVar1 + (uint)bVar2); iVar3 = iVar3 + 1) {
    FUN_80247618(param_3,pfVar5,pfVar4);
    FUN_80247618(pfVar4,param_4,pfVar6);
    pfVar6[3] = (float)dVar7;
    pfVar6[7] = (float)dVar7;
    pfVar6[0xb] = (float)dVar7;
    pfVar5 = pfVar5 + 0x10;
    pfVar4 = pfVar4 + 0xc;
    pfVar6 = pfVar6 + 0xc;
  }
  DAT_803dd8c8 = 2;
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003be6c
 * EN v1.0 Address: 0x8003BE6C
 * EN v1.0 Size: 672b
 * EN v1.1 Address: 0x8003BFF4
 * EN v1.1 Size: 636b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003be6c(void)
{
  int iVar1;
  float *pfVar2;
  float *pfVar3;
  float *pfVar4;
  int *piVar5;
  int iVar6;
  byte *pbVar7;
  int iVar8;
  int iVar9;
  double in_f27;
  double dVar10;
  double in_f28;
  double dVar11;
  double in_f29;
  double dVar12;
  double in_f30;
  double dVar13;
  double in_f31;
  double dVar14;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar15;
  float afStack_118 [12];
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
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
  undefined4 local_88;
  uint uStack_84;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  uVar15 = FUN_80286830();
  iVar1 = (int)((ulonglong)uVar15 >> 0x20);
  piVar5 = (int *)uVar15;
  iVar9 = 0;
  dVar13 = (double)lbl_803DF698;
  dVar14 = (double)lbl_803DF69C;
  dVar12 = DOUBLE_803df6a0;
  for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(iVar1 + 0xf4); iVar8 = iVar8 + 1) {
    pbVar7 = (byte *)(*(int *)(iVar1 + 0x54) + iVar9);
    pfVar2 = (float *)FUN_80017970(piVar5,iVar8 + (uint)*(byte *)(iVar1 + 0xf3));
    pfVar3 = (float *)FUN_80017970(piVar5,(uint)*pbVar7);
    pfVar4 = (float *)FUN_80017970(piVar5,(uint)pbVar7[1]);
    uStack_84 = (uint)pbVar7[2];
    local_88 = 0x43300000;
    dVar11 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_84) - dVar12) *
                            dVar13);
    dVar10 = (double)(float)(dVar14 - dVar11);
    iVar6 = *(int *)(iVar1 + 0x3c) + (uint)*pbVar7 * 0x1c;
    FUN_80247a48(-(double)*(float *)(iVar6 + 0x10),-(double)*(float *)(iVar6 + 0x14),
                 -(double)*(float *)(iVar6 + 0x18),afStack_118);
    FUN_80247618(pfVar3,afStack_118,&local_b8);
    iVar6 = *(int *)(iVar1 + 0x3c) + (uint)pbVar7[1] * 0x1c;
    FUN_80247a48(-(double)*(float *)(iVar6 + 0x10),-(double)*(float *)(iVar6 + 0x14),
                 -(double)*(float *)(iVar6 + 0x18),afStack_118);
    FUN_80247618(pfVar4,afStack_118,&local_e8);
    *pfVar2 = (float)((double)local_b8 * dVar11 + (double)(float)((double)local_e8 * dVar10));
    pfVar2[1] = (float)((double)local_b4 * dVar11 + (double)(float)((double)local_e4 * dVar10));
    pfVar2[2] = (float)((double)local_b0 * dVar11 + (double)(float)((double)local_e0 * dVar10));
    pfVar2[3] = (float)((double)local_ac * dVar11 + (double)(float)((double)local_dc * dVar10));
    pfVar2[4] = (float)((double)local_a8 * dVar11 + (double)(float)((double)local_d8 * dVar10));
    pfVar2[5] = (float)((double)local_a4 * dVar11 + (double)(float)((double)local_d4 * dVar10));
    pfVar2[6] = (float)((double)local_a0 * dVar11 + (double)(float)((double)local_d0 * dVar10));
    pfVar2[7] = (float)((double)local_9c * dVar11 + (double)(float)((double)local_cc * dVar10));
    pfVar2[8] = (float)((double)local_98 * dVar11 + (double)(float)((double)local_c8 * dVar10));
    pfVar2[9] = (float)((double)local_94 * dVar11 + (double)(float)((double)local_c4 * dVar10));
    pfVar2[10] = (float)((double)local_90 * dVar11 + (double)(float)((double)local_c0 * dVar10));
    pfVar2[0xb] = (float)((double)local_8c * dVar11 + (double)(float)((double)local_bc * dVar10));
    iVar9 = iVar9 + 4;
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003c10c
 * EN v1.0 Address: 0x8003C10C
 * EN v1.0 Size: 236b
 * EN v1.1 Address: 0x8003C270
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003c10c(int param_1,int *param_2)
{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  
  iVar2 = FUN_8001779c();
  if (*(char *)(param_1 + 0xf4) != '\0') {
    FUN_8003be6c();
  }
  uVar4 = (uint)*(byte *)(param_1 + 0xf3) + (uint)*(byte *)(param_1 + 0xf4);
  if ((uVar4 < 2) || (100 < uVar4)) {
    DAT_803dd8c8 = 3;
  }
  else {
    uVar3 = FUN_80017970(param_2,0);
    FUN_802420e0(uVar3,uVar4 * 0x40);
    uVar5 = iVar2 + 0x2700;
    for (uVar4 = uVar4 * 2 & 0xfe; uVar1 = uVar4 & 0xff, 0x7f < uVar1; uVar4 = uVar4 - 0x80) {
      FUN_80017798(uVar5,uVar3,0);
      uVar3 = uVar3 + 0x1000;
      uVar5 = uVar5 + 0x1000;
    }
    if (uVar1 != 0) {
      FUN_80017798(uVar5,uVar3,uVar1);
    }
    DAT_803dd8c8 = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8003c1f8
 * EN v1.0 Address: 0x8003C1F8
 * EN v1.0 Size: 2384b
 * EN v1.1 Address: 0x8003C360
 * EN v1.1 Size: 2484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8003c1f8(int param_1,int *param_2,int param_3)
{
  undefined uVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  uint *puVar5;
  uint uVar6;
  int *piVar7;
  double dVar8;
  uint local_190;
  undefined4 local_18c;
  uint local_188;
  uint local_184;
  undefined4 local_180;
  undefined4 uStack_17c;
  int local_178;
  int local_174;
  undefined4 local_170;
  float local_16c;
  float local_168;
  int local_164;
  uint local_160;
  int local_15c;
  undefined4 local_158;
  float local_154;
  float local_150;
  undefined4 local_14c;
  undefined4 local_148;
  undefined4 local_144;
  float local_140;
  float local_13c;
  undefined4 local_138;
  undefined4 local_134;
  undefined4 local_130;
  float local_12c;
  undefined4 local_128;
  float afStack_124 [12];
  float local_f4 [5];
  float local_e0;
  float afStack_c4 [12];
  float afStack_94 [12];
  float afStack_64 [13];
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  local_158 = DAT_803df67c;
  local_13c = DAT_802c22c0;
  local_138 = DAT_802c22c4;
  local_134 = DAT_802c22c8;
  local_130 = DAT_802c22cc;
  local_12c = (float)DAT_802c22d0;
  local_128 = DAT_802c22d4;
  local_154 = DAT_802c22d8;
  local_150 = (float)DAT_802c22dc;
  local_14c = DAT_802c22e0;
  local_148 = DAT_802c22e4;
  local_144 = DAT_802c22e8;
  local_140 = (float)DAT_802c22ec;
  iVar3 = FUN_8001792c(*param_2,param_3);
  if ((*(uint *)(iVar3 + 0x3c) & 0x200) == 0) {
    if ((DAT_803dd8c4 & 3) == 0) {
      DAT_803dd8be = 1;
      FUN_8003d6f8(param_1);
      uVar4 = 1;
    }
    else {
      DAT_803dd8be = 0;
      uVar4 = 0;
    }
  }
  else {
    DAT_803dd8be = 1;
    newshadows_getShadowTextureTable16(&local_15c,&local_160);
    uStack_2c = DAT_803dd8c4 ^ 0x80000000;
    local_30 = 0x43300000;
    uStack_24 = local_160 ^ 0x80000000;
    local_28 = 0x43300000;
    fVar2 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df6c0) /
            (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df6c0);
    dVar8 = (double)(fVar2 * fVar2 * lbl_803DF6A8);
    puVar5 = (uint *)FUN_800480a0(iVar3,0);
    uVar6 = FUN_80053078(*puVar5);
    FUN_8004812c(uVar6,0);
    FUN_80258674(2,1,4,0x3c,0,0x7d);
    FUN_8025be80(0);
    FUN_8025c828(0,2,0,0xff);
    FUN_8025c1a4(0,0xf,0xf,0xf,8);
    FUN_8025c224(0,7,7,7,7);
    FUN_8025c65c(0,0,0);
    FUN_8025c2a8(0,0,0,0,0,0);
    FUN_8025c368(0,0,0,0,1,0);
    uVar1 = *(undefined *)(param_1 + 0xf1);
    local_158 = CONCAT13(uVar1,CONCAT12(uVar1,CONCAT11(uVar1,(undefined)local_158)));
    local_180 = local_158;
    FUN_8025c510(0,(byte *)&local_180);
    FUN_8025c5f0(1,0x1c);
    FUN_8025c584(1,0xc);
    FUN_80247a7c((double)lbl_803DF6AC,(double)lbl_803DF6AC,(double)lbl_803DF684,afStack_94);
    FUN_80247a48((double)lbl_803DF6A8,(double)lbl_803DF6A8,(double)lbl_803DF69C,afStack_c4);
    FUN_80247618(afStack_c4,afStack_94,afStack_94);
    FUN_8025d8c4(afStack_94,0x43,0);
    FUN_80258674(0,1,1,0x1e,0,0x43);
    piVar7 = (int *)FUN_80017978((int)param_2,param_3);
    FUN_8004812c(*piVar7,1);
    FUN_8025be80(1);
    FUN_8025c828(1,0,1,4);
    FUN_8025c65c(1,0,0);
    FUN_8025c1a4(1,0xf,8,0xe,10);
    FUN_8025c224(1,7,7,7,7);
    FUN_8025c2a8(1,0,0,0,1,2);
    FUN_8025c368(1,0,0,0,1,0);
    newshadows_getShadowNoiseTexture(&local_164);
    FUN_8004812c(local_164,4);
    newshadows_getShadowNoiseScroll(&local_168,&local_16c);
    FUN_80247a48((double)(lbl_803DF6A8 * local_168),(double)(lbl_803DF6A8 * local_16c),
                 (double)lbl_803DF684,local_f4);
    local_f4[0] = lbl_803DF69C;
    local_e0 = lbl_803DF69C;
    FUN_8025d8c4(local_f4,0x46,0);
    FUN_80258674(1,1,4,0x3c,0,0x46);
    FUN_8025bd1c(0,1,4);
    FUN_8025bb48(0,0,0);
    local_13c = (float)dVar8;
    local_12c = (float)dVar8;
    FUN_8025b9e8(1,&local_13c,(char)DAT_803dc0f8);
    FUN_8025b94c(2,0,0,7,1,6,6,0,0,0);
    FUN_8025c828(2,0xff,0xff,0xff);
    FUN_8025c65c(2,0,0);
    FUN_8025c1a4(2,0xf,0,4,0xf);
    FUN_8025c224(2,7,7,7,7);
    FUN_8025c2a8(2,0,0,0,1,0);
    FUN_8025c368(2,0,0,0,1,0);
    uVar6 = FUN_80053078(*(uint *)(iVar3 + 0x38));
    FUN_8004812c(uVar6,2);
    FUN_80258674(3,1,4,0x3c,0,0x7d);
    FUN_8025bd1c(1,3,2);
    FUN_8025bb48(1,0,0);
    local_150 = (float)dVar8;
    local_140 = (float)dVar8;
    FUN_8025b9e8(2,&local_154,(char)DAT_803dc0fc);
    FUN_8025b94c(3,1,0,7,2,0,0,1,0,1);
    FUN_8004812c(*(int *)(local_15c + DAT_803dd8c4 * 4),3);
    FUN_80247a7c((double)lbl_803DF6B0,(double)lbl_803DF6B0,(double)lbl_803DF69C,afStack_64);
    FUN_8025d8c4(afStack_64,0x40,0);
    FUN_80258674(4,1,4,0x3c,1,0x40);
    FUN_8025c584(3,4);
    FUN_8025c828(3,4,3,8);
    FUN_8025c1a4(3,8,0xe,0,0);
    FUN_8025c224(3,7,4,5,7);
    FUN_8025c65c(3,0,0);
    FUN_8025c2a8(3,1,1,0,1,0);
    FUN_8025c368(3,0,0,0,1,0);
    if ((int)DAT_803dd8c4 < 0xc) {
      FUN_8025ca04(4);
      FUN_8025be54(2);
      FUN_80258944(5);
    }
    else {
      local_170 = DAT_803df680;
      piVar7 = FUN_80017624(param_1,'\0');
      if (piVar7 != (int *)0x0) {
        FUN_800175b0((int)piVar7,4);
        FUN_800175d4((double)lbl_803DF684,(double)lbl_803DF6B4,(double)lbl_803DF684,piVar7);
        FUN_8001759c((int)piVar7,0xff,0xff,0xff,0xff);
        FUN_80017608(0);
        FUN_80017600(2,0,0);
        local_184 = DAT_803dc0d0;
        FUN_8025a2ec(2,&local_184);
        local_188 = DAT_803dc0c8;
        FUN_8025a454(2,&local_188);
        FUN_800175fc(2,piVar7,param_1);
        FUN_80017604();
        FUN_80017620((uint)piVar7);
      }
      local_18c = local_170;
      FUN_8025c510(0,(byte *)&local_18c);
      FUN_8025c5f0(5,0x1c);
      FUN_8025c584(5,0xc);
      newshadows_getShadowTextureTable4x8(&local_174,&local_178,&uStack_17c);
      FUN_8004812c(*(int *)(local_174 + (DAT_803dd8c4 + (uint)DAT_803dd8bd * local_178 + -0xc) * 4),
                   5);
      FUN_80247a7c((double)lbl_803DF6B8,(double)lbl_803DF6B8,(double)lbl_803DF69C,afStack_124)
      ;
      FUN_8025d8c4(afStack_124,0x49,0);
      FUN_80258674(5,1,4,0x3c,1,0x49);
      FUN_8025be80(4);
      FUN_8025c828(4,5,5,4);
      FUN_8025c1a4(4,0xf,0xf,0xf,0);
      FUN_8025c224(4,7,4,5,7);
      FUN_8025c65c(4,0,0);
      FUN_8025c2a8(4,0,0,0,1,0);
      FUN_8025c368(4,0,0,0,1,2);
      FUN_8025be80(5);
      FUN_8025c828(5,0xff,0xff,0xff);
      FUN_8025c1a4(5,0,0xe,5,0xf);
      FUN_8025c224(5,0,2,2,7);
      FUN_8025c65c(5,0,0);
      FUN_8025c2a8(5,0,0,0,1,0);
      FUN_8025c368(5,0,0,0,1,0);
      FUN_8025ca04(6);
      FUN_8025be54(2);
      FUN_80258944(6);
    }
    FUN_80259288(2);
    local_190 = DAT_803dc0c8;
    dVar8 = (double)lbl_803DF684;
    FUN_8025ca38(dVar8,dVar8,dVar8,dVar8,0,(uint3 *)&local_190);
    FUN_8006f8fc(1,3,0);
    FUN_8006f8a4(1);
    FUN_8025cce8(1,4,5,5);
    uVar4 = 1;
  }
  return uVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_8003cb48
 * EN v1.0 Address: 0x8003CB48
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8003CD14
 * EN v1.1 Size: 2780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8003cb48(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/* sda21 accessors. */
extern u32 lbl_803DCC10;
extern u8 lbl_803DCC3C;
void fn_8003B950(u32 x) { lbl_803DCC10 = x; }
u8 fn_8003BB74(void) { return lbl_803DCC3C; }
void fn_8003BB7C(u8 x) { lbl_803DCC3C = x; }

extern s16 lbl_803DCC18, lbl_803DCC16, lbl_803DCC14;
extern u8 lbl_803DCC08;
#pragma scheduling off
#pragma peephole off
void fn_8003B608(s16 a, s16 b, s16 c) {
    lbl_803DCC18 = a;
    lbl_803DCC16 = b;
    lbl_803DCC14 = c;
    lbl_803DCC08 = 1;
}
#pragma peephole reset
#pragma scheduling reset
