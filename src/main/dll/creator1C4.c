#include "ghidra_import.h"
#include "main/dll/creator1C4.h"

extern undefined8 FUN_80008cbc();
extern undefined4 FUN_80009a94();
extern undefined4 FUN_8000a538();
extern undefined4 FUN_8000bb38();
extern byte FUN_8001469c();
extern undefined4 FUN_800146a8();
extern undefined4 FUN_800146c8();
extern undefined4 FUN_800146e8();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern uint FUN_80022264();
extern int FUN_8002bac4();
extern undefined4 FUN_8002cc9c();
extern void* FUN_80037048();
extern undefined4 FUN_80043604();
extern int FUN_8004832c();
extern undefined8 FUN_80088f20();
extern undefined4 FUN_801c76a4();
extern undefined4 FUN_801d84c4();
extern undefined4 FUN_801d8650();
extern undefined4 FUN_80286834();
extern undefined4 FUN_80286880();
extern uint FUN_80296cb4();

extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e5cc8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5cd4;
extern f32 FLOAT_803e5cd8;

/*
 * --INFO--
 *
 * Function: FUN_801c7cd8
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C7CD8
 * EN v1.1 Size: 2124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c7cd8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  ushort *puVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  int iVar10;
  byte bVar12;
  undefined4 *puVar11;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar13;
  undefined8 uVar14;
  double dVar15;
  double dVar16;
  int local_38 [2];
  undefined4 local_30;
  uint uStack_2c;
  
  puVar2 = (ushort *)FUN_80286834();
  iVar13 = *(int *)(puVar2 + 0x5c);
  iVar3 = FUN_8002bac4();
  local_38[0] = 0;
  if (iVar3 != 0) {
    uVar4 = FUN_80020078(0x149);
    uVar5 = FUN_80020078(0x14c);
    uVar6 = FUN_80020078(0x14d);
    uVar7 = FUN_80020078(0x14e);
    uVar8 = FUN_80020078(0x14a);
    uVar9 = FUN_80020078(0x14b);
    if ((((((uVar4 & 0xff) == 0) || ((uVar5 & 0xff) == 0)) || ((uVar6 & 0xff) == 0)) ||
        (((uVar7 & 0xff) == 0 || ((uVar8 & 0xff) == 0)))) || ((uVar9 & 0xff) == 0)) {
      if (((*(byte *)(iVar13 + 0x15) >> 6 & 1) == 0) && ((uVar4 & 0xff) != 0)) {
        *(byte *)(iVar13 + 0x15) = *(byte *)(iVar13 + 0x15) & 0xbf | 0x40;
        FUN_8000bb38(0,0x109);
      }
      else if (((*(byte *)(iVar13 + 0x15) >> 5 & 1) == 0) && ((uVar5 & 0xff) != 0)) {
        *(byte *)(iVar13 + 0x15) = *(byte *)(iVar13 + 0x15) & 0xdf | 0x20;
        FUN_8000bb38(0,0x109);
      }
      else if (((*(byte *)(iVar13 + 0x15) >> 4 & 1) == 0) && ((uVar6 & 0xff) != 0)) {
        *(byte *)(iVar13 + 0x15) = *(byte *)(iVar13 + 0x15) & 0xef | 0x10;
        FUN_8000bb38(0,0x109);
      }
      else if (((*(byte *)(iVar13 + 0x15) >> 3 & 1) == 0) && ((uVar7 & 0xff) != 0)) {
        *(byte *)(iVar13 + 0x15) = *(byte *)(iVar13 + 0x15) & 0xf7 | 8;
        FUN_8000bb38(0,0x109);
      }
      else if (((*(byte *)(iVar13 + 0x15) >> 2 & 1) == 0) && ((uVar8 & 0xff) != 0)) {
        *(byte *)(iVar13 + 0x15) = *(byte *)(iVar13 + 0x15) & 0xfb | 4;
        FUN_8000bb38(0,0x109);
      }
      else if (((*(byte *)(iVar13 + 0x15) >> 1 & 1) == 0) && ((uVar9 & 0xff) != 0)) {
        *(byte *)(iVar13 + 0x15) = *(byte *)(iVar13 + 0x15) & 0xfd | 2;
        FUN_8000bb38(0,0x109);
      }
    }
    if ((*(int *)(puVar2 + 0x7a) != 0) &&
       (*(int *)(puVar2 + 0x7a) = *(int *)(puVar2 + 0x7a) + -1, *(int *)(puVar2 + 0x7a) == 0)) {
      uVar14 = FUN_80088f20(7,'\x01');
      uVar14 = FUN_80008cbc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,
                            iVar3,0xcc,0,in_r7,in_r8,in_r9,in_r10);
      uVar14 = FUN_80008cbc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,
                            iVar3,0xcd,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80008cbc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,iVar3,0x222
                   ,0,in_r7,in_r8,in_r9,in_r10);
    }
    FUN_801c76a4(puVar2);
    iVar10 = FUN_8004832c(0x22);
    FUN_80043604(iVar10,1,0);
    FUN_801d84c4(iVar13 + 0x13,2,-1,-1,0xdd2,(int *)0xb);
    FUN_801d8650(iVar13 + 0x13,1,-1,-1,0xcbb,(int *)0x8);
    FUN_801d84c4(iVar13 + 0x13,4,-1,-1,0xcbb,(int *)0xc4);
    fVar1 = FLOAT_803e5cd4;
    dVar15 = (double)*(float *)(iVar13 + 4);
    dVar16 = (double)FLOAT_803e5cd4;
    if (dVar15 <= dVar16) {
      switch(*(undefined *)(iVar13 + 0x14)) {
      case 0:
        puVar2[3] = puVar2[3] & 0xbfff;
        fVar1 = *(float *)(iVar13 + 8) - FLOAT_803dc074;
        *(float *)(iVar13 + 8) = fVar1;
        if ((double)fVar1 <= dVar16) {
          FUN_8000bb38((uint)puVar2,0x343);
          uStack_2c = FUN_80022264(500,1000);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          *(float *)(iVar13 + 8) = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e5cc8)
          ;
        }
        if ((*(byte *)((int)puVar2 + 0xaf) & 1) != 0) {
          *(undefined *)(iVar13 + 0x14) = 5;
          FUN_800201ac(0x129,0);
          FUN_800201ac(0x5af,0);
          FUN_800201ac(0xdd2,1);
          (**(code **)(*DAT_803dd6d4 + 0x48))(0,puVar2,0xffffffff);
          FUN_8000a538((int *)0xd8,1);
        }
        break;
      case 1:
        if (*(char *)(iVar13 + 0x15) < '\0') {
          FUN_800201ac(0x148,1);
          *(undefined *)(iVar13 + 0x14) = 2;
          FUN_800146e8(0x1d,0x4e);
          FUN_800146c8();
        }
        break;
      case 2:
        *(undefined *)(iVar13 + 0x12) = 0;
        uVar4 = FUN_80020078(0x149);
        if (uVar4 != 0) {
          *(char *)(iVar13 + 0x12) = *(char *)(iVar13 + 0x12) + '\x01';
        }
        uVar4 = FUN_80020078(0x14b);
        if (uVar4 != 0) {
          *(char *)(iVar13 + 0x12) = *(char *)(iVar13 + 0x12) + '\x01';
        }
        uVar4 = FUN_80020078(0x14e);
        if (uVar4 != 0) {
          *(char *)(iVar13 + 0x12) = *(char *)(iVar13 + 0x12) + '\x01';
        }
        uVar4 = FUN_80020078(0x14d);
        if (uVar4 != 0) {
          *(char *)(iVar13 + 0x12) = *(char *)(iVar13 + 0x12) + '\x01';
        }
        uVar4 = FUN_80020078(0x14c);
        if (uVar4 != 0) {
          *(char *)(iVar13 + 0x12) = *(char *)(iVar13 + 0x12) + '\x01';
        }
        uVar4 = FUN_80020078(0x14a);
        if (uVar4 != 0) {
          *(char *)(iVar13 + 0x12) = *(char *)(iVar13 + 0x12) + '\x01';
        }
        if (*(char *)(iVar13 + 0x12) == '\x06') {
          *(undefined *)(iVar13 + 0x14) = 6;
          FUN_800146a8();
          FUN_800201ac(0xdd2,0);
          *(float *)(iVar13 + 4) = FLOAT_803e5cd8;
          (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
          FUN_8000bb38(0,0x7e);
        }
        else {
          bVar12 = FUN_8001469c();
          if (bVar12 == 0) {
            *(undefined *)(iVar13 + 0x12) = 0;
          }
          else {
            *(undefined *)(iVar13 + 0x14) = 7;
            puVar11 = FUN_80037048(0x10,local_38);
            for (; local_38[0] != 0; local_38[0] = local_38[0] + -1) {
              dVar15 = (double)FUN_8002cc9c(dVar15,dVar16,param_3,param_4,param_5,param_6,param_7,
                                            param_8,puVar11[local_38[0] + -1]);
            }
            *(float *)(iVar13 + 4) = FLOAT_803e5cd8;
            (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
          }
        }
        break;
      case 3:
        uVar4 = FUN_80296cb4(iVar3,0x80);
        if (uVar4 == 0) {
          FUN_80009a94(3);
          (**(code **)(*DAT_803dd6d4 + 0x48))(1,puVar2,0xffffffff);
          *(undefined *)(iVar13 + 0x14) = 4;
          FUN_800201ac(0x36a,0);
          (**(code **)(*DAT_803dd72c + 0x50))(0xd,0,1);
          (**(code **)(*DAT_803dd72c + 0x50))(0xd,1,1);
          (**(code **)(*DAT_803dd72c + 0x50))(0xd,5,1);
          (**(code **)(*DAT_803dd72c + 0x50))(0xd,10,1);
          (**(code **)(*DAT_803dd72c + 0x50))(0xd,0xb,1);
          FUN_800201ac(0xc91,1);
          FUN_800201ac(0xe05,0);
        }
        else {
          FUN_800201ac(0x129,1);
          *(undefined *)(iVar13 + 0x14) = 4;
        }
        break;
      case 4:
        *(undefined *)(iVar13 + 0x14) = 0;
        *(byte *)(iVar13 + 0x15) = *(byte *)(iVar13 + 0x15) & 0x7f;
        FUN_800201ac(0xdd2,0);
        FUN_800201ac(0x129,1);
        FUN_800201ac(0x149,0);
        FUN_800201ac(0x14c,0);
        FUN_800201ac(0x14d,0);
        FUN_800201ac(0x14e,0);
        FUN_800201ac(0x14a,0);
        FUN_800201ac(0x14b,0);
        FUN_800201ac(0x14b,0);
        FUN_800201ac(0x5af,1);
        FUN_800201ac(0x148,0);
        FUN_800201ac(0xe37,0);
        FUN_800201ac(0xe3a,0);
        *(byte *)(iVar13 + 0x15) = *(byte *)(iVar13 + 0x15) & 0xbf;
        *(byte *)(iVar13 + 0x15) = *(byte *)(iVar13 + 0x15) & 0xdf;
        *(byte *)(iVar13 + 0x15) = *(byte *)(iVar13 + 0x15) & 0xef;
        *(byte *)(iVar13 + 0x15) = *(byte *)(iVar13 + 0x15) & 0xf7;
        *(byte *)(iVar13 + 0x15) = *(byte *)(iVar13 + 0x15) & 0xfb;
        *(byte *)(iVar13 + 0x15) = *(byte *)(iVar13 + 0x15) & 0xfd;
        break;
      case 5:
        *(float *)(iVar13 + 4) = FLOAT_803e5cd8;
        (**(code **)(*DAT_803dd6cc + 0xc))(0x1e,1);
        *(undefined *)(iVar13 + 0x14) = 1;
        puVar2[3] = puVar2[3] | 0x4000;
        break;
      case 6:
        *(undefined *)(iVar13 + 0x14) = 3;
        break;
      case 7:
        *(undefined *)(iVar13 + 0x14) = 4;
        FUN_800201ac(0xdd2,0);
        FUN_800201ac(0xe37,1);
      }
    }
    else {
      *(float *)(iVar13 + 4) = (float)(dVar15 - (double)FLOAT_803dc074);
      if ((double)*(float *)(iVar13 + 4) <= dVar16) {
        *(float *)(iVar13 + 4) = fVar1;
      }
    }
  }
  FUN_80286880();
  return;
}
