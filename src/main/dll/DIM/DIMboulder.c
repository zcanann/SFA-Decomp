#include "ghidra_import.h"
#include "main/dll/DIM/DIMboulder.h"

extern undefined4 FUN_800066e0();
extern undefined4 FUN_80006724();
extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_80006c88();
extern undefined8 FUN_80017484();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_80035d58();
extern undefined4 ObjHits_DisableObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_800614c4();
extern int FUN_800632f4();
extern undefined8 FUN_80080f14();
extern undefined4 FUN_80080f18();
extern undefined4 FUN_8008112c();
extern int FUN_800e8b98();
extern undefined4 FUN_800ea9b8();
extern undefined4 FUN_801abf38();
extern undefined4 FUN_801d8308();
extern uint FUN_8028683c();
extern undefined4 FUN_80286888();
extern int FUN_80294dbc();

extern undefined4 DAT_802c2a88;
extern undefined4 DAT_802c2a8c;
extern undefined4 DAT_802c2a90;
extern undefined4 DAT_80324188;
extern undefined4 DAT_803241c0;
extern undefined4 DAT_803241f8;
extern undefined4 DAT_80324230;
extern undefined4 DAT_803242f8;
extern undefined4 DAT_80324304;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6e4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de7c0;
extern f64 DOUBLE_803e5390;
extern f64 DOUBLE_803e53c0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e536c;
extern f32 FLOAT_803e5374;
extern f32 FLOAT_803e5378;
extern f32 FLOAT_803e5380;
extern f32 FLOAT_803e5384;
extern f32 FLOAT_803e5388;
extern f32 FLOAT_803e5398;
extern f32 FLOAT_803e539c;
extern f32 FLOAT_803e53a0;
extern f32 FLOAT_803e53a4;
extern f32 FLOAT_803e53a8;
extern f32 FLOAT_803e53ac;
extern f32 FLOAT_803e53b0;
extern f32 FLOAT_803e53b4;
extern f32 FLOAT_803e53b8;
extern f32 FLOAT_803e53c8;
extern f32 FLOAT_803e53d0;
extern f32 FLOAT_803e53d8;
extern f32 FLOAT_803e53dc;
extern f32 FLOAT_803e53e0;
extern f32 FLOAT_803e53f0;

/*
 * --INFO--
 *
 * Function: FUN_801ac248
 * EN v1.0 Address: 0x801AC248
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AC4FC
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ac248(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801ac24c
 * EN v1.0 Address: 0x801AC24C
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x801AC5D0
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ac24c(int param_1)
{
  int iVar1;
  undefined4 uVar2;
  undefined *puVar3;
  
  puVar3 = *(undefined **)(param_1 + 0xb8);
  FUN_80017698(0x3a3,0);
  FUN_80017698(0x3a2,0);
  iVar1 = FUN_80017a98();
  iVar1 = FUN_80294dbc(iVar1);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x48))();
  }
  uVar2 = FUN_80044404(0x17);
  FUN_80042bec(uVar2,1);
  if (iVar1 == 1) {
    (**(code **)(*DAT_803dd6e8 + 0x40))(1);
    *puVar3 = 5;
    FUN_80017698(0x37b,1);
  }
  else {
    *puVar3 = 6;
    FUN_80017698(0xce,1);
  }
  FUN_80017698(0x378,0);
  FUN_80017698(0x3b9,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ac340
 * EN v1.0 Address: 0x801AC340
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x801AC6BC
 * EN v1.1 Size: 320b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ac340(int param_1,undefined *param_2)
{
  uint uVar1;
  int iVar2;
  
  (**(code **)(*DAT_803dd6e8 + 0x40))(0);
  uVar1 = FUN_80017690(0x3a3);
  if (uVar1 != 0) {
    FUN_80017698(0x3a3,0);
    FUN_80017698(0x3a2,0);
    FUN_80017698(0x378,0);
    FUN_80017698(0x3b9,0);
    iVar2 = FUN_80017a98();
    iVar2 = FUN_80294dbc(iVar2);
    if (iVar2 == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x48))();
    }
    FUN_80017698(0x4e5,1);
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),1,1);
    if (iVar2 == 1) {
      (**(code **)(*DAT_803dd6e8 + 0x40))(1);
      *param_2 = 5;
      FUN_80017698(0x379,1);
    }
    else {
      *param_2 = 6;
      FUN_80017698(0xcb,1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ac490
 * EN v1.0 Address: 0x801AC490
 * EN v1.0 Size: 2148b
 * EN v1.1 Address: 0x801AC7FC
 * EN v1.1 Size: 1148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ac490(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  char cVar1;
  uint uVar2;
  undefined *puVar3;
  undefined8 uVar4;
  
  puVar3 = *(undefined **)(param_9 + 0xb8);
  switch(*puVar3) {
  case 1:
    uVar2 = FUN_80017690(0xadc);
    if ((uVar2 == 0) || (uVar2 = FUN_80017690(0xadd), uVar2 == 0)) {
      uVar2 = FUN_80017690(0x70);
      if (uVar2 != 0) {
        *puVar3 = 2;
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0xb,1);
      }
    }
    else {
      FUN_80017698(0xade,1);
      *puVar3 = 2;
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0xb,1);
    }
    break;
  case 2:
    uVar2 = FUN_80017690(0x70);
    if (uVar2 != 0) {
      *puVar3 = 3;
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),6,1);
    }
    break;
  case 3:
    uVar2 = FUN_80017690(0x72);
    if (uVar2 != 0) {
      param_1 = (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0,0);
    }
    uVar2 = FUN_80017690(0x3a2);
    if (uVar2 != 0) {
      *puVar3 = 4;
      FUN_80017698(0xe5d,1);
      FUN_80017698(0xe5e,1);
      FUN_80017698(0xe5f,1);
      FUN_80017698(0xe60,1);
      FUN_80017698(0xe61,1);
      FUN_80017698(0xe62,1);
      FUN_80017698(0xe63,1);
      FUN_80017698(0xe64,1);
      FUN_80017698(0xe65,1);
      FUN_80017698(0xe66,1);
      FUN_80017698(0xe67,1);
      FUN_80017698(0xe68,1);
      FUN_80017698(0xe69,1);
      FUN_80017698(0xe6a,1);
      param_1 = FUN_80017698(0xe6b,1);
    }
    if (*(int *)(param_9 + 0xf4) == 0) {
      uVar4 = FUN_80006728(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0xa3,0,param_13,param_14,param_15,param_16);
      uVar4 = FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x9e,0,param_13,param_14,param_15,param_16);
      uVar4 = FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x119,0,param_13,param_14,param_15,param_16);
      FUN_800066e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x15b,0,0,0,param_15,param_16);
      FUN_800066e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x15c,0,0,0,param_15,param_16);
      FUN_800066e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x17c,0,0,0,param_15,param_16);
      FUN_800066e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x17b,0,0,0,param_15,param_16);
      (**(code **)(*DAT_803dd6e4 + 0x1c))(1);
      *(undefined4 *)(param_9 + 0xf4) = 1;
    }
    break;
  case 4:
    FUN_801ac340(param_9,puVar3);
    break;
  case 5:
    if ((*(uint *)(puVar3 + 4) & 1) != 0) {
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),3,0);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),4,0);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),6,0);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),7,0);
      *puVar3 = 0;
      (**(code **)(*DAT_803dd72c + 0x44))((int)*(char *)(param_9 + 0xac),2);
    }
    break;
  case 6:
    if ((*(uint *)(puVar3 + 4) & 1) != 0) {
      puVar3[8] = 2;
    }
    if (('\0' < (char)puVar3[8]) && (cVar1 = puVar3[8] + -1, puVar3[8] = cVar1, cVar1 == '\0')) {
      uVar4 = FUN_80017698(0x4e5,0);
      FUN_80053c98(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1a,'\0',param_11,
                   param_12,param_13,param_14,param_15,param_16);
    }
    break;
  case 7:
    uVar2 = FUN_80017690(0x6e);
    if (uVar2 != 0) {
      *puVar3 = 1;
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),2,0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801accf4
 * EN v1.0 Address: 0x801ACCF4
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801ACC78
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801accf4(int param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  
  *(uint *)(*(int *)(param_1 + 0xb8) + 4) = *(uint *)(*(int *)(param_1 + 0xb8) + 4) | 1;
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar1 = iVar1 + 1) {
    if (*(char *)(param_3 + iVar1 + 0x81) == '\x02') {
      FUN_80017698(0x378,0);
      FUN_80017698(0x3b9,0);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801acd7c
 * EN v1.0 Address: 0x801ACD7C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801ACD10
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801acd7c(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801acda4
 * EN v1.0 Address: 0x801ACDA4
 * EN v1.0 Size: 1188b
 * EN v1.1 Address: 0x801ACD44
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801acda4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  uint uVar2;
  int iVar3;
  undefined4 extraout_r4;
  int iVar4;
  undefined8 uVar5;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  if (*(int *)(param_9 + 0xf4) == 0) {
    uVar5 = FUN_80006728(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_9,0xa3,0,param_13,param_14,param_15,param_16);
    uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_9,0x9e,0,param_13,param_14,param_15,param_16);
    param_11 = 0x104;
    param_12 = 0;
    FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,0x104
                 ,0,param_13,param_14,param_15,param_16);
    param_1 = (**(code **)(*DAT_803dd6e4 + 0x1c))(1);
    *(undefined4 *)(param_9 + 0xf4) = 1;
    param_10 = extraout_r4;
  }
  bVar1 = *(byte *)(iVar4 + 0xc);
  if (bVar1 == 2) {
    uVar2 = FUN_80017690(0x3a3);
    if (uVar2 != 0) {
      FUN_801ac24c(param_9);
    }
  }
  else if ((bVar1 < 2) && (bVar1 != 0)) {
    FUN_801ac490(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
                 param_11,param_12,param_13,param_14,param_15,param_16);
  }
  *(uint *)(iVar4 + 4) = *(uint *)(iVar4 + 4) & 0xfffffffe;
  if (FLOAT_803e5374 < *(float *)(iVar4 + 0x10)) {
    uVar5 = FUN_80017484(0xff,0xff,0xff,0xff);
    FUN_80006c88(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x351);
    *(float *)(iVar4 + 0x10) = *(float *)(iVar4 + 0x10) - FLOAT_803dc074;
    if (*(float *)(iVar4 + 0x10) < FLOAT_803e5374) {
      *(float *)(iVar4 + 0x10) = FLOAT_803e5374;
    }
  }
  iVar3 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if (iVar3 == 0) {
    if ((*(short *)(iVar4 + 10) != 0x1a) &&
       (*(undefined2 *)(iVar4 + 10) = 0x1a, (*(uint *)(iVar4 + 4) & 8) != 0)) {
      FUN_800067c0((int *)0x1a,1);
    }
  }
  else if ((*(short *)(iVar4 + 10) != -1) &&
          (*(undefined2 *)(iVar4 + 10) = 0xffff, (*(uint *)(iVar4 + 4) & 8) != 0)) {
    FUN_800067c0((int *)0x1a,0);
  }
  FUN_801d8308(iVar4 + 4,2,0x2c1,0x238,0x1ed,(int *)0xb2);
  FUN_801d8308(iVar4 + 4,0x10,0x1ba,0x1b9,0x1d6,(int *)0xb4);
  FUN_801d8308(iVar4 + 4,4,-1,-1,0x3a0,(int *)0xe9);
  FUN_801d8308(iVar4 + 4,8,-1,-1,0x3a1,(int *)(int)*(short *)(iVar4 + 10));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ad248
 * EN v1.0 Address: 0x801AD248
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801ACF74
 * EN v1.1 Size: 828b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ad248(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801ad24c
 * EN v1.0 Address: 0x801AD24C
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x801AD2B0
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_801ad24c(int param_1)
{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 *local_18 [4];
  
  iVar7 = *(int *)(param_1 + 0xb8);
  iVar3 = FUN_800632f4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                       (double)*(float *)(param_1 + 0x14),param_1,local_18,0,0);
  iVar6 = -1;
  iVar5 = 0;
  puVar4 = local_18[0];
  fVar1 = FLOAT_803e5398;
  if (0 < iVar3) {
    do {
      fVar2 = *(float *)(param_1 + 0x10) - *(float *)*puVar4;
      if ((FLOAT_803e539c < fVar2) && (fVar2 < fVar1)) {
        iVar6 = iVar5;
        fVar1 = fVar2;
      }
      puVar4 = puVar4 + 1;
      iVar5 = iVar5 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if (iVar6 == -1) {
    fVar1 = *(float *)(param_1 + 0x10);
  }
  else {
    *(undefined *)(iVar7 + 0xe) = 1;
    fVar1 = *(float *)local_18[0][iVar6];
  }
  return (double)fVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_801ad318
 * EN v1.0 Address: 0x801AD318
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801AD390
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ad318(int param_1)
{
  char in_r8;
  
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 0xc) != '\x03') && (in_r8 != '\0')) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ad350
 * EN v1.0 Address: 0x801AD350
 * EN v1.0 Size: 1580b
 * EN v1.1 Address: 0x801AD3D4
 * EN v1.1 Size: 1124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ad350(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  byte bVar1;
  short sVar2;
  float fVar3;
  float fVar4;
  ushort uVar5;
  bool bVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int *piVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  undefined8 local_30;
  
  uVar7 = FUN_8028683c();
  piVar13 = *(int **)(uVar7 + 0xb8);
  iVar12 = *(int *)(uVar7 + 0x54);
  iVar10 = *(int *)(uVar7 + 100);
  iVar11 = *(int *)(uVar7 + 0x4c);
  if (DAT_803de7c0 == 0) {
    DAT_803de7c0 = FUN_80006b14(0x5b);
  }
  if (*(char *)((int)piVar13 + 0xe) == '\0') {
    dVar15 = FUN_801ad24c(uVar7);
    piVar13[1] = (int)(float)dVar15;
    if ((*(char *)((int)piVar13 + 0xe) != '\0') && (iVar10 != 0)) {
      *(int *)(iVar10 + 0x24) = piVar13[1];
      FUN_800614c4();
    }
  }
  else {
    if (iVar10 != 0) {
      fVar3 = (*(float *)(uVar7 + 0x10) - (float)piVar13[1]) /
              ((float)piVar13[2] - (float)piVar13[1]);
      fVar4 = FLOAT_803e53a0;
      if ((fVar3 <= FLOAT_803e53a0) && (fVar4 = fVar3, fVar3 < FLOAT_803e5380)) {
        fVar4 = FLOAT_803e5380;
      }
      dVar15 = (double)(FLOAT_803e53a0 - fVar4);
      iVar8 = FUN_80017a98();
      if (iVar8 == 0) {
        dVar14 = (double)FLOAT_803e53a4;
      }
      else {
        dVar16 = (double)FUN_8001771c((float *)(uVar7 + 0x18),(float *)(iVar8 + 0x18));
        dVar14 = (double)FLOAT_803e53a4;
        if ((dVar16 <= dVar14) && (dVar14 = dVar16, dVar16 < (double)FLOAT_803e53a8)) {
          dVar14 = (double)FLOAT_803e53a8;
        }
      }
      param_3 = (double)(FLOAT_803e53a0 - (float)(dVar14 - (double)FLOAT_803e53a8) / FLOAT_803e53ac)
      ;
      param_2 = (double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(uVar7 + 0x37)) -
                                DOUBLE_803e5390) / FLOAT_803e53b4);
      *(char *)(iVar10 + 0x40) =
           (char)(int)(param_2 *
                      (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                       (int)((double)FLOAT_803e53b0
                                                                            * dVar15) + 0x40U ^
                                                                       0x80000000) - DOUBLE_803e53c0
                                                     ) * param_3));
    }
    uVar9 = (uint)*(short *)(iVar11 + 0x1c);
    if ((uVar9 == 0xffffffff) || (uVar9 = FUN_80017690(uVar9), uVar9 != 0)) {
      bVar1 = *(byte *)(piVar13 + 3);
      if (bVar1 == 2) {
        *(undefined4 *)(iVar12 + 0x48) = 0x10;
        *(undefined4 *)(iVar12 + 0x4c) = 0x10;
        *(undefined *)(iVar12 + 0x6f) = 1;
        *(undefined *)(iVar12 + 0x6e) = 0xd;
      }
      else if (bVar1 < 2) {
        if (bVar1 == 0) {
          iVar10 = FUN_80017a98();
          if (iVar10 == 0) {
            bVar6 = false;
          }
          else {
            iVar8 = *(int *)(uVar7 + 0x4c);
            dVar15 = (double)FUN_80017710((float *)(uVar7 + 0x18),(float *)(iVar10 + 0x18));
            param_4 = (double)(*(float *)(uVar7 + 0x10) - *(float *)(iVar10 + 0x10));
            if (param_4 < (double)FLOAT_803e5380) {
              param_4 = (double)FLOAT_803e5380;
            }
            param_3 = (double)FLOAT_803e5384;
            local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar8 + 0x1a));
            param_2 = DOUBLE_803e5390;
            if (((double)(float)(param_3 * (double)(float)(local_30 - DOUBLE_803e5390)) <= dVar15)
               || ((double)FLOAT_803e5388 <= param_4)) {
              bVar6 = false;
            }
            else {
              bVar6 = true;
            }
          }
          if ((bVar6) &&
             (sVar2 = *(short *)(piVar13 + 4), uVar5 = (ushort)DAT_803dc070,
             *(ushort *)(piVar13 + 4) = sVar2 - uVar5, (short)(sVar2 - uVar5) < 1)) {
            *(undefined *)(piVar13 + 3) = 1;
          }
        }
        else {
          if (*(char *)((int)piVar13 + 0xd) == '\0') {
            *(undefined *)((int)piVar13 + 0xd) = 1;
            *(float *)(uVar7 + 0x28) = FLOAT_803e5380;
            if (*(short *)(uVar7 + 0x46) == 0x67) {
              FUN_80006824(uVar7,0x155);
            }
            FUN_80006824(uVar7,0xa5);
            *(ushort *)(iVar12 + 0x60) = *(ushort *)(iVar12 + 0x60) | 1;
          }
          *(undefined4 *)(iVar12 + 0x48) = 0x10;
          *(undefined4 *)(iVar12 + 0x4c) = 0x10;
          *(undefined *)(iVar12 + 0x6f) = 1;
          *(undefined *)(iVar12 + 0x6e) = 0xd;
          *(float *)(uVar7 + 0x28) = FLOAT_803e53b8 * FLOAT_803dc074 + *(float *)(uVar7 + 0x28);
          *(float *)(uVar7 + 0x10) =
               *(float *)(uVar7 + 0x28) * FLOAT_803dc074 + *(float *)(uVar7 + 0x10);
          param_3 = (double)(float)piVar13[1];
          param_2 = (double)*(float *)(*piVar13 + 8);
          if (*(float *)(uVar7 + 0x10) < (float)(param_3 + param_2)) {
            *(float *)(uVar7 + 0x10) = (float)(param_2 * (double)*(float *)(uVar7 + 8) + param_3);
            *(undefined *)(piVar13 + 3) = 2;
            if (*(int *)(*piVar13 + 4) != 0) {
              FUN_80006824(uVar7,(ushort)*(int *)(*piVar13 + 4));
            }
          }
        }
      }
      if (*(int *)(iVar12 + 0x50) != 0) {
        *(ushort *)(iVar12 + 0x60) = *(ushort *)(iVar12 + 0x60) & 0xfffe;
        *(undefined *)(piVar13 + 3) = 3;
        FUN_8000680c(uVar7,8);
        if (*(short *)(uVar7 + 0x46) == 0x67) {
          FUN_80006824(uVar7,0x156);
        }
        else {
          FUN_80006824(uVar7,0x3bb);
          local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar11 + 0x1b));
          FUN_8008112c((double)(float)(local_30 - DOUBLE_803e5390),param_2,param_3,param_4,param_5,
                       param_6,param_7,param_8,uVar7,1,1,0,1,1,1,1);
        }
      }
      fVar3 = FLOAT_803e5380;
      *(float *)(uVar7 + 0x24) = FLOAT_803e5380;
      *(float *)(uVar7 + 0x2c) = fVar3;
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ad97c
 * EN v1.0 Address: 0x801AD97C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AD838
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ad97c(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801ad980
 * EN v1.0 Address: 0x801AD980
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AD9B4
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ad980(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801ad984
 * EN v1.0 Address: 0x801AD984
 * EN v1.0 Size: 420b
 * EN v1.1 Address: 0x801AD9F4
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801ad984(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)
{
  int iVar1;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar2;
  double dVar3;
  double dVar4;
  
  if (*(short *)(param_9 + 0x46) != 0x172) {
    pfVar2 = *(float **)(param_9 + 0xb8);
    iVar1 = FUN_80017a98();
    dVar3 = (double)FUN_8001771c((float *)(iVar1 + 0x18),(float *)(param_9 + 0x18));
    dVar4 = (double)*pfVar2;
    if ((dVar4 <= dVar3) || (*(char *)((int)pfVar2 + 0xb) != '\0')) {
      if (((double)(float)((double)FLOAT_803e53d0 + dVar4) < dVar3) &&
         (*(char *)((int)pfVar2 + 0xb) != '\0')) {
        *(undefined *)((int)pfVar2 + 0xb) = 0;
        FUN_800066e0(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                     (uint)*(ushort *)(pfVar2 + 2),0,0,0,in_r9,in_r10);
      }
    }
    else {
      *(undefined *)((int)pfVar2 + 0xb) = 1;
      FUN_800066e0(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   (uint)*(ushort *)((int)pfVar2 + 6),0,0,0,in_r9,in_r10);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801adb28
 * EN v1.0 Address: 0x801ADB28
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x801ADB04
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801adb28(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  undefined4 in_r9;
  undefined4 in_r10;
  
  if (*(short *)(param_9 + 0x46) != 0x172) {
    if (*(char *)(*(int *)(param_9 + 0xb8) + 0xb) != '\0') {
      FUN_800066e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   (uint)*(ushort *)(*(int *)(param_9 + 0xb8) + 8),0,0,0,in_r9,in_r10);
    }
    (**(code **)(*DAT_803dd6f8 + 0x18))(param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801adbec
 * EN v1.0 Address: 0x801ADBEC
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801ADB80
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801adbec(int param_1)
{
  char in_r8;
  
  if ((*(short *)(param_1 + 0x46) == 0x172) && (in_r8 != '\0')) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801adc20
 * EN v1.0 Address: 0x801ADC20
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x801ADBC0
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801adc20(undefined2 *param_1)
{
  if ((param_1[0x23] != 0x172) && (*(int *)(param_1 + 0x7a) == 0)) {
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    *(undefined4 *)(param_1 + 0x7a) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801adc9c
 * EN v1.0 Address: 0x801ADC9C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801ADC38
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801adc9c(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801adca0
 * EN v1.0 Address: 0x801ADCA0
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x801ADD98
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801adca0(undefined2 *param_1,undefined2 *param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,char param_7,int param_8,int param_9)
{
  undefined uVar1;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20 [5];
  
  if (((param_9 != 0) && (param_7 != '\0')) && (0 < param_8)) {
    uVar1 = *(undefined *)((int)param_2 + 0x37);
    *(char *)((int)param_2 + 0x37) = (char)param_8;
    (**(code **)(**(int **)(param_2 + 0x34) + 0x10))
              (param_2,param_3,param_4,param_5,param_6,0xffffffff);
    *(undefined *)((int)param_2 + 0x37) = uVar1;
  }
  *(undefined4 *)(param_1 + 0x46) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0x48) = *(undefined4 *)(param_1 + 0xe);
  *(undefined4 *)(param_1 + 0x4a) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 10);
  (**(code **)(**(int **)(param_2 + 0x34) + 0x28))(param_2,local_20,&local_24,&local_28);
  *(undefined4 *)(param_1 + 6) = local_20[0];
  *(undefined4 *)(param_1 + 8) = local_24;
  *(undefined4 *)(param_1 + 10) = local_28;
  *param_1 = *param_2;
  param_1[1] = param_2[1];
  param_1[2] = param_2[2];
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 10);
  *(undefined4 *)(param_1 + 0x12) = *(undefined4 *)(param_2 + 0x12);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x14);
  *(undefined4 *)(param_1 + 0x16) = *(undefined4 *)(param_2 + 0x16);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801addec
 * EN v1.0 Address: 0x801ADDEC
 * EN v1.0 Size: 896b
 * EN v1.1 Address: 0x801ADEE4
 * EN v1.1 Size: 576b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801addec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,uint *param_13,undefined4 param_14,undefined4 param_15
            ,undefined4 param_16)
{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  undefined2 uStack_2a;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 local_20;
  
  piVar5 = *(int **)(param_9 + 0xb8);
  *(undefined *)(piVar5 + 8) = 0xff;
  iVar6 = *piVar5;
  if (*(char *)(param_11 + 0x80) == '\x03') {
    *(undefined *)((int)piVar5 + 0x21) = 0xff;
    *(undefined *)(param_11 + 0x80) = 0;
  }
  local_28 = DAT_802c2a88;
  local_24 = DAT_802c2a8c;
  local_20 = DAT_802c2a90;
  if (*(char *)((int)piVar5 + 0x21) != *(char *)((int)piVar5 + 0x22)) {
    if (*(int *)(param_9 + 200) != 0) {
      param_1 = FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             *(int *)(param_9 + 200));
      *(undefined4 *)(param_9 + 200) = 0;
      *(undefined *)(param_9 + 0xeb) = 0;
    }
    uVar1 = FUN_80017ae8();
    if ((uVar1 & 0xff) == 0) {
      *(undefined *)((int)piVar5 + 0x22) = 0;
    }
    else {
      if (0 < *(char *)((int)piVar5 + 0x21)) {
        puVar2 = FUN_80017aa4(0x18,(&uStack_2a)[*(char *)((int)piVar5 + 0x21)]);
        param_12 = 0xffffffff;
        param_13 = *(uint **)(param_9 + 0x30);
        uVar3 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,
                             4,0xff,0xffffffff,param_13,param_14,param_15,param_16);
        *(undefined4 *)(param_9 + 200) = uVar3;
        *(undefined *)(param_9 + 0xeb) = 1;
      }
      *(undefined *)((int)piVar5 + 0x22) = *(undefined *)((int)piVar5 + 0x21);
    }
  }
  *(undefined2 *)(param_11 + 0x6e) = *(undefined2 *)(param_11 + 0x70);
  if ((iVar6 == 0) || (*(char *)(param_11 + 0x80) != '\x02')) {
    if ((iVar6 != 0) && (*(char *)(param_11 + 0x80) == '\x01')) {
      (**(code **)(**(int **)(iVar6 + 0x68) + 0x3c))(iVar6,0);
      *(undefined *)(param_11 + 0x80) = 0;
    }
  }
  else {
    piVar5[1] = (int)FLOAT_803e53f0;
    piVar5[2] = piVar5[5];
    piVar5[3] = piVar5[6];
    piVar5[4] = piVar5[7];
    (**(code **)(**(int **)(iVar6 + 0x68) + 0x3c))(iVar6,2);
    FUN_800305f8((double)FLOAT_803e53e0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x100,1,param_12,param_13,param_14,param_15,param_16);
    iVar4 = *(int *)(param_9 + 100);
    if (iVar4 != 0) {
      *(uint *)(iVar4 + 0x30) = *(uint *)(iVar4 + 0x30) | 0x1000;
    }
    *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xfffb;
    *(undefined *)(param_11 + 0x80) = 0;
  }
  if ((iVar6 != 0) && (iVar6 = (**(code **)(**(int **)(iVar6 + 0x68) + 0x38))(iVar6), iVar6 == 2)) {
    *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xfffc;
  }
  return 0;
}


/* Trivial 4b 0-arg blr leaves. */
void imicemountain_free(void) {}
void imicemountain_hitDetect(void) {}
void crrockfall_free(void) {}
void crrockfall_hitDetect(void) {}
void magiclight_hitDetect(void) {}
void magiclight_release(void) {}
void magiclight_initialise(void) {}
void fn_801AE0E4(void) {}
void fn_801AE0E8(void) {}
void imicepillar_free(void) {}

/* 8b "li r3, N; blr" returners. */
int imicemountain_getExtraSize(void) { return 0x14; }
int imicemountain_func08(void) { return 0x0; }
int crrockfall_getExtraSize(void) { return 0x14; }
int crrockfall_func08(void) { return 0x0; }
int magiclight_func08(void) { return 0x0; }
int fn_801ADB70(void) { return 0x24; }
int fn_801ADB78(void) { return 0x3; }
int imicepillar_getExtraSize(void) { return 0x4; }
int imicepillar_func08(void) { return 0x0; }

/* Pattern wrappers. */
extern u32 lbl_803DDB40;
void crrockfall_initialise(void) { lbl_803DDB40 = 0x0; }
