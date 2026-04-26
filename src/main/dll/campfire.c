#include "ghidra_import.h"
#include "main/dll/campfire.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80017698();
extern uint FUN_80017760();
extern undefined4 FUN_80017a28();
extern undefined4 FUN_80017a98();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b540();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_80081120();
extern undefined4 FUN_801695e8();
extern int FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294c68();

extern undefined4 DAT_802c2990;
extern undefined4 DAT_802c2994;
extern undefined4 DAT_802c2998;
extern undefined4 DAT_802c299c;
extern undefined4 DAT_80321048;
extern undefined4 DAT_80321054;
extern undefined4 DAT_803ad2c8;
extern undefined4 DAT_803ad2ca;
extern undefined4 DAT_803ad2cc;
extern undefined4 DAT_803ad2d0;
extern undefined4 DAT_803ad2e0;
extern undefined4 DAT_803ad2f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd738;
extern undefined4* DAT_803de710;
extern f64 DOUBLE_803e3d00;
extern f64 DOUBLE_803e3d08;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de714;
extern f32 FLOAT_803de718;
extern f32 FLOAT_803e3cf8;
extern f32 FLOAT_803e3d10;
extern f32 FLOAT_803e3d14;
extern f32 FLOAT_803e3d24;
extern f32 FLOAT_803e3d2c;
extern f32 FLOAT_803e3d30;
extern f32 FLOAT_803e3d34;
extern f32 FLOAT_803e3d38;
extern f32 FLOAT_803e3d3c;
extern f32 FLOAT_803e3d40;
extern f32 FLOAT_803e3d44;
extern f32 FLOAT_803e3d48;
extern f32 FLOAT_803e3d4c;
extern f32 FLOAT_803e3d58;
extern f32 FLOAT_803e3d5c;
extern f32 FLOAT_803e3d60;

/*
 * --INFO--
 *
 * Function: FUN_8016821c
 * EN v1.0 Address: 0x8016821C
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x80168370
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8016821c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  
  if ((*(char *)(param_10 + 0x27a) != '\0') &&
     (ObjHits_EnableObject(param_9), *(char *)(param_10 + 0x27a) != '\0')) {
    uVar1 = FUN_80017760(6,7);
    FUN_800305f8((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,uVar1,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3d2c;
  *(undefined *)(param_10 + 0x34d) = 1;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80168358
 * EN v1.0 Address: 0x80168358
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x80168404
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80168358(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  bVar1 = *(char *)(param_10 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      uVar2 = FUN_80017760(0,4);
      FUN_800305f8((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,(int)*(short *)(&DAT_80321048 + uVar2 * 2),0,param_12,param_13,param_14,
                   param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    ObjHits_EnableObject(param_9);
    *(undefined *)(iVar3 + 0x4a) = 4;
  }
  *(undefined4 *)(param_10 + 0x2a0) =
       *(undefined4 *)(&DAT_80321054 + (uint)*(byte *)(iVar3 + 0x4a) * 4);
  *(undefined *)(param_10 + 0x34d) = 1;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801684c0
 * EN v1.0 Address: 0x801684C0
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x801684C4
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801684c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  bVar1 = *(char *)(param_10 + 0x27a) == '\0';
  if (bVar1) {
    if (*(char *)(param_10 + 0x346) != '\0') {
      FUN_80017698((int)*(short *)(iVar2 + 0x3f4),0);
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_800305f8((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,4,0,param_12,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
      *(undefined2 *)(iVar2 + 0x402) = 0;
    }
  }
  else {
    if (!bVar1) {
      FUN_800305f8((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,5,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    ObjHits_DisableObject(param_9);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e3d14;
    *(float *)(param_10 + 0x280) = FLOAT_803e3cf8;
  }
  if ((*(uint *)(param_10 + 0x314) & 0x1000) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xffffefff;
    FUN_801695e8(param_9,2);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801686b0
 * EN v1.0 Address: 0x801686B0
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801685C4
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801686b0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  bVar1 = *(char *)(param_10 + 0x27a) == '\0';
  if (bVar1) {
    if (*(char *)(param_10 + 0x346) != '\0') {
      *(undefined2 *)(iVar2 + 0x402) = 1;
    }
  }
  else {
    if (!bVar1) {
      FUN_800305f8((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,4,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    FUN_801695e8(param_9,1);
    *(undefined *)(param_10 + 0x25f) = 1;
    FUN_80017698((int)*(short *)(iVar2 + 0x3f4),1);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    *(undefined *)(param_9 + 0x36) = 0xff;
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         FLOAT_803e3d30 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e3d00) /
         FLOAT_803e3d34;
    ObjHits_EnableObject(param_9);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80168818
 * EN v1.0 Address: 0x80168818
 * EN v1.0 Size: 500b
 * EN v1.1 Address: 0x801686C8
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80168818(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int *param_10)
{
  uint uVar1;
  undefined2 *puVar2;
  float *pfVar3;
  int iVar4;
  undefined4 in_r10;
  int iVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  
  iVar6 = *(int *)(param_9 + 0x4c);
  dVar8 = (double)FLOAT_803e3d38;
  FLOAT_803de714 =
       (float)(dVar8 + (double)((float)((double)CONCAT44(0x43300000,
                                                         (int)*(char *)(iVar6 + 0x28) ^ 0x80000000)
                                       - DOUBLE_803e3d08) / FLOAT_803e3d3c));
  param_10[0x10] = (int)FLOAT_803e3d24;
  FUN_80006824(param_9,0x276);
  iVar5 = 0x28;
  do {
    pfVar3 = &FLOAT_803de714;
    iVar4 = *DAT_803dd708;
    (**(code **)(iVar4 + 8))(param_9,0x717,0,4,0xffffffff);
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  if ((*param_10 == 0) && (uVar1 = FUN_80017ae8(), (uVar1 & 0xff) != 0)) {
    puVar2 = FUN_80017aa4(0x24,0x55e);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
    dVar7 = (double)FLOAT_803e3d40;
    *(float *)(puVar2 + 6) = (float)(dVar7 + (double)*(float *)(param_9 + 0x10));
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar2 + 2) = *(undefined *)(iVar6 + 4);
    *(undefined *)((int)puVar2 + 5) = *(undefined *)(iVar6 + 5);
    *(undefined *)(puVar2 + 3) = *(undefined *)(iVar6 + 6);
    *(undefined *)((int)puVar2 + 7) = *(undefined *)(iVar6 + 7);
    iVar5 = FUN_80017ae4(dVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff,
                         0xffffffff,(uint *)0x0,pfVar3,iVar4,in_r10);
    *param_10 = iVar5;
    *(float *)(*param_10 + 8) = FLOAT_803de714;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80168a0c
 * EN v1.0 Address: 0x80168A0C
 * EN v1.0 Size: 640b
 * EN v1.1 Address: 0x80168820
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80168a0c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,char param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  iVar4 = *(int *)(param_10 + 0x40c);
  iVar3 = *(int *)(param_9 + 0x4c);
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) != 0) {
    dVar6 = (double)FLOAT_803e3d38;
    dVar5 = (double)(float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar3 + 0x28) ^ 0x80000000) -
                           DOUBLE_803e3d08);
    dVar7 = (double)(float)(dVar6 + (double)(float)(dVar5 / (double)FLOAT_803e3d3c));
    puVar2 = FUN_80017aa4(0x24,0x51b);
    if (param_11 == '\0') {
      *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 0x28);
      *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 0x2c);
      *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0x30);
    }
    else {
      *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 0x10);
      *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 0x14);
      *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0x18);
    }
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 4;
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    iVar3 = FUN_80017ae4(dVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff,
                         0xffffffff,(uint *)0x0,param_14,param_15,param_16);
    if (iVar3 != 0) {
      dVar5 = (double)(FLOAT_803e3d44 *
                      (*(float *)(param_10 + 0x2c0) /
                      (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x3fe)) -
                             DOUBLE_803e3d00)));
      *(float *)(iVar3 + 0x24) =
           (float)((double)(*(float *)(*(int *)(param_10 + 0x2d0) + 0xc) - *(float *)(puVar2 + 4)) /
                  dVar5);
      uVar1 = FUN_80017760(0xfffffff6,10);
      *(float *)(iVar3 + 0x28) =
           (float)((double)(((float)((double)FLOAT_803e3d40 * dVar7 +
                                    (double)*(float *)(*(int *)(param_10 + 0x2d0) + 0x10)) +
                            (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) -
                                   DOUBLE_803e3d08)) - *(float *)(puVar2 + 6)) / dVar5);
      *(float *)(iVar3 + 0x2c) =
           (float)((double)(*(float *)(*(int *)(param_10 + 0x2d0) + 0x14) - *(float *)(puVar2 + 8))
                  / dVar5);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80168c8c
 * EN v1.0 Address: 0x80168C8C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80168A08
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80168c8c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,int param_14,int param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80168c90
 * EN v1.0 Address: 0x80168C90
 * EN v1.0 Size: 1624b
 * EN v1.1 Address: 0x80168BF8
 * EN v1.1 Size: 1108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80168c90(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,int param_11)
{
  float fVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  double dVar8;
  undefined8 uVar9;
  undefined auStack_48 [2];
  undefined auStack_46 [2];
  short local_44 [2];
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  longlong local_20;
  
  uVar9 = FUN_80286840();
  puVar2 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  iVar6 = (int)uVar9;
  piVar7 = *(int **)(iVar6 + 0x40c);
  local_34 = DAT_802c2990;
  local_30 = DAT_802c2994;
  local_2c = DAT_802c2998;
  local_28 = DAT_802c299c;
  uVar3 = FUN_80017a98();
  iVar4 = *(int *)(param_11 + 0x2d0);
  if (iVar4 != 0) {
    local_40 = *(float *)(iVar4 + 0x18) - *(float *)(puVar2 + 0xc);
    param_4 = (double)local_40;
    local_3c = *(float *)(iVar4 + 0x1c) - *(float *)(puVar2 + 0xe);
    param_3 = (double)local_3c;
    local_38 = *(float *)(iVar4 + 0x20) - *(float *)(puVar2 + 0x10);
    param_2 = (double)(local_38 * local_38);
    dVar8 = FUN_80293900((double)(float)(param_2 +
                                        (double)((float)(param_4 * param_4) +
                                                (float)(param_3 * param_3))));
    *(float *)(param_11 + 0x2c0) = (float)dVar8;
  }
  (**(code **)(*DAT_803dd738 + 0x54))
            (puVar2,param_11,iVar6 + 0x35c,(int)*(short *)(iVar6 + 0x3f4),0,0,0,4);
  (**(code **)(*DAT_803dd738 + 0x14))(puVar2,uVar3,4,local_44,auStack_46,auStack_48);
  if ((local_44[0] == 1) || (local_44[0] == 2)) {
    iVar4 = (**(code **)(*DAT_803dd738 + 0x50))
                      (puVar2,param_11,iVar6 + 0x35c,(int)*(short *)(iVar6 + 0x3f4),0,0,1,
                       &DAT_803ad2c8);
    if (iVar4 != 0) {
      if ((iVar4 != 0x10) && (iVar4 != 0x11)) {
        FUN_80081120(puVar2,&DAT_803ad2c8,3,(int *)0x0);
        (**(code **)(*DAT_803dd70c + 0x14))(puVar2,param_11,4);
        *(char *)(param_11 + 0x354) = *(char *)(param_11 + 0x354) + -1;
        FUN_80017a28(puVar2,0xf,200,0,0,1);
        FUN_80006824((uint)puVar2,0x22);
      }
      if (*(char *)(param_11 + 0x354) < '\x01') {
        *(undefined2 *)(param_11 + 0x270) = 2;
      }
    }
  }
  else {
    iVar4 = (**(code **)(*DAT_803dd738 + 0x50))
                      (puVar2,param_11,iVar6 + 0x35c,(int)*(short *)(iVar6 + 0x3f4),0,0,1,
                       &DAT_803ad2c8);
    if (iVar4 != 0) {
      if (iVar4 == 0x11) {
        if (*(short *)(param_11 + 0x270) != 1) {
          (**(code **)(*DAT_803dd70c + 0x14))(puVar2,param_11,6);
          *(undefined *)(param_11 + 0x27b) = 1;
          *(undefined *)(param_11 + 0x27a) = 1;
          *(undefined2 *)(param_11 + 0x270) = 1;
          FUN_80081120(puVar2,&DAT_803ad2c8,1,(int *)0x0);
          FUN_80006824((uint)puVar2,0x22);
          FUN_80006824((uint)puVar2,0x3ac);
        }
      }
      else if ((iVar4 != 0x10) && ((double)(float)piVar7[0x10] < (double)FLOAT_803e3d58)) {
        FUN_80168818((double)(float)piVar7[0x10],param_2,param_3,param_4,param_5,param_6,param_7,
                     param_8,(uint)puVar2,piVar7);
        DAT_803ad2d0 = FLOAT_803e3d10;
        DAT_803ad2cc = 0;
        DAT_803ad2ca = 0;
        DAT_803ad2c8 = 0;
        (**(code **)(*DAT_803de710 + 4))(0,1,&DAT_803ad2c8,0x401,0xffffffff,&local_34);
        FUN_80294c68(uVar3,2);
        (**(code **)(*DAT_803dd70c + 0x14))(puVar2,param_11,5);
        FUN_80081120(puVar2,&DAT_803ad2c8,4,(int *)0x0);
        FUN_80006824((uint)puVar2,0x255);
      }
    }
    if (*(char *)(param_11 + 0x354) < '\x01') {
      *(undefined2 *)(param_11 + 0x270) = 2;
    }
  }
  fVar1 = FLOAT_803e3cf8;
  if (*piVar7 != 0) {
    if (FLOAT_803e3cf8 < (float)piVar7[0x10]) {
      uVar5 = (uint)(float)piVar7[0x10];
      local_20 = (longlong)(int)uVar5;
      uVar5 = FUN_80017760(0,uVar5 & 0xff);
      *(char *)(*piVar7 + 0x36) = (char)uVar5;
      *(undefined2 *)(*piVar7 + 4) = puVar2[2];
      *(undefined2 *)(*piVar7 + 2) = puVar2[1];
      *(undefined2 *)*piVar7 = *puVar2;
      piVar7[0x10] = (int)-(FLOAT_803e3d5c * FLOAT_803dc074 - (float)piVar7[0x10]);
    }
    else {
      *(undefined *)(*piVar7 + 0x36) = 0;
      piVar7[0x10] = (int)fVar1;
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801692e8
 * EN v1.0 Address: 0x801692E8
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x8016904C
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801692e8(int param_1)
{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  ObjGroup_RemoveObject(param_1,3);
  (**(code **)(*DAT_803dd738 + 0x40))(param_1,uVar1,0x20);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80169348
 * EN v1.0 Address: 0x80169348
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x801690A8
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80169348(void)
{
  int iVar1;
  char in_r8;
  int iVar2;
  
  iVar1 = FUN_8028683c();
  iVar2 = *(int *)(iVar1 + 0xb8);
  if ((in_r8 != '\0') && (*(int *)(iVar1 + 0xf4) == 0)) {
    if (*(float *)(iVar2 + 1000) != FLOAT_803e3cf8) {
      FUN_8003b540(200,0,0,(char)(int)*(float *)(iVar2 + 1000));
    }
    FUN_8003b818(iVar1);
    if ((*(ushort *)(iVar2 + 0x400) & 0x60) != 0) {
      FUN_8008111c((double)FLOAT_803e3d10,(double)*(float *)(iVar2 + 1000),iVar1,3,(int *)0x0);
    }
    iVar2 = *(int *)(iVar2 + 0x40c);
    ObjPath_GetPointWorldPosition(iVar1,2,(float *)(iVar2 + 0x10),(undefined4 *)(iVar2 + 0x14),
                 (float *)(iVar2 + 0x18),0);
    ObjPath_GetPointWorldPosition(iVar1,1,(float *)(iVar2 + 0x28),(undefined4 *)(iVar2 + 0x2c),
                 (float *)(iVar2 + 0x30),0);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80169430
 * EN v1.0 Address: 0x80169430
 * EN v1.0 Size: 1120b
 * EN v1.1 Address: 0x801691B8
 * EN v1.1 Size: 940b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80169430(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9)
{
  int iVar1;
  uint uVar2;
  int *piVar3;
  undefined4 uVar4;
  undefined4 in_r7;
  undefined4 uVar5;
  int in_r8;
  undefined4 uVar6;
  int in_r9;
  undefined4 uVar7;
  undefined4 in_r10;
  int iVar8;
  int iVar9;
  undefined8 extraout_f1;
  double dVar10;
  double dVar11;
  
  iVar9 = *(int *)(param_9 + 0xb8);
  iVar8 = *(int *)(param_9 + 0x4c);
  if (*(int *)(param_9 + 0xf4) == 0) {
    iVar1 = *DAT_803dd738;
    iVar8 = (**(code **)(iVar1 + 0x30))(param_9,iVar9,0);
    if (iVar8 == 0) {
      *(undefined2 *)(iVar9 + 0x402) = 0;
    }
    else {
      FUN_80168c90(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar9
                   ,iVar9);
      if (*(short *)(iVar9 + 0x402) == 0) {
        iVar8 = *(int *)(iVar9 + 0x40c);
        *(float *)(iVar8 + 0x34) = *(float *)(iVar8 + 0x34) - FLOAT_803dc074;
        if (*(float *)(iVar8 + 0x34) <= FLOAT_803e3cf8) {
          FUN_80006824(param_9,0x271);
          uVar2 = FUN_80017760(300,600);
          *(float *)(iVar8 + 0x34) =
               (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3d08);
        }
        uVar4 = FUN_80017a98();
        *(undefined4 *)(iVar9 + 0x2d0) = uVar4;
        if (*(short *)(iVar9 + 0x274) != 6) {
          (**(code **)(*DAT_803dd70c + 0x30))((double)FLOAT_803dc074,param_9,iVar9,5);
        }
        iVar8 = (**(code **)(*DAT_803dd738 + 0x48))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar9 + 0x3fe)) -
                                          DOUBLE_803e3d00),param_9,iVar9,0x8000);
        if (iVar8 != 0) {
          (**(code **)(*DAT_803dd738 + 0x28))
                    (param_9,iVar9,iVar9 + 0x35c,(int)*(short *)(iVar9 + 0x3f4),0,0,0,4,0xffffffff);
          *(undefined *)(iVar9 + 0x349) = 0;
          *(undefined2 *)(iVar9 + 0x402) = 1;
        }
      }
      else {
        iVar8 = *(int *)(iVar9 + 0x40c);
        piVar3 = (int *)FUN_80039520(param_9,0);
        *(short *)(iVar8 + 0x48) = *(short *)(iVar8 + 0x48) + 0x1000;
        dVar11 = (double)FLOAT_803e3d4c;
        dVar10 = (double)FUN_80293f90();
        dVar10 = (double)(float)((double)FLOAT_803e3d10 + dVar10);
        *piVar3 = (int)((double)FLOAT_803e3d48 * dVar10);
        uVar4 = FUN_80017a98();
        *(undefined4 *)(iVar9 + 0x2d0) = uVar4;
        FUN_80168c8c(dVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar9,
                     iVar9,iVar1,in_r7,in_r8,in_r9,in_r10);
        (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e3cf8,param_9,iVar9,0xffffffff);
        if (*(short *)(iVar9 + 0x274) != 6) {
          (**(code **)(*DAT_803dd70c + 0x30))((double)FLOAT_803dc074,param_9,iVar9,5);
        }
        *(undefined4 *)(iVar9 + 0x3e0) = *(undefined4 *)(param_9 + 0xc0);
        *(undefined4 *)(param_9 + 0xc0) = 0;
        (**(code **)(*DAT_803dd70c + 8))
                  ((double)FLOAT_803dc074,(double)FLOAT_803dc074,param_9,iVar9,&DAT_803ad2f8,
                   &DAT_803ad2e0);
        *(undefined4 *)(param_9 + 0xc0) = *(undefined4 *)(iVar9 + 0x3e0);
      }
    }
  }
  else if ((*(short *)(iVar9 + 0x270) != 3) &&
          (iVar1 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar8 + 0x14)), iVar1 != 0))
  {
    uVar4 = 8;
    uVar5 = 6;
    uVar6 = 0;
    uVar7 = 0x26;
    iVar1 = *DAT_803dd738;
    (**(code **)(iVar1 + 0x58))((double)FLOAT_803e3d60,param_9,iVar8,iVar9);
    *(undefined2 *)(iVar9 + 0x402) = 0;
    FUN_80006824(param_9,0x270);
    FUN_800305f8((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,4,0x10,uVar4,uVar5,uVar6,uVar7,iVar1);
    *(undefined *)(iVar9 + 0x346) = 0;
    *(undefined *)(param_9 + 0x36) = 0xff;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  return;
}
