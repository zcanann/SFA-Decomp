#include "ghidra_import.h"
#include "main/dll/objfsa.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80003494();
extern undefined4 FUN_80006a10();
extern undefined4 FUN_80006a18();
extern undefined4 FUN_80006a1c();
extern undefined4 FUN_80006a30();
extern char FUN_80006a64();
extern undefined8 FUN_80006a68();
extern byte FUN_80006b20();
extern undefined4 FUN_80006b28();
extern undefined4 FUN_80006b30();
extern uint FUN_80017690();
extern double FUN_80017714();
extern uint FUN_80017730();
extern undefined4 FUN_80017754();
extern uint FUN_80017760();
extern undefined4 FUN_80017778();
extern undefined FUN_8002fc3c();
extern undefined4 FUN_800571f8();
extern int FUN_8005b398();
extern int FUN_800620e8();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_800d8088();
extern undefined4 FUN_800d8240();
extern int FUN_800e1b24();
extern int FUN_800e1c00();
extern int RomCurve_findByIdWithIndex();
extern undefined4 RomCurve_getAdjacentWindow();
extern f32 RomCurve_distanceToSegment(f32 x,f32 y,f32 z,float *segment);
extern int FUN_80286818();
extern undefined4 FUN_80286824();
extern undefined8 FUN_8028682c();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286864();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint countLeadingZeros();

extern char DAT_803120d8;
extern undefined2 DAT_8039d748;
extern undefined4 DAT_8039d74a;
extern undefined4 DAT_8039d758;
extern undefined4 DAT_8039d768;
extern undefined4 DAT_8039d76a;
extern undefined4 DAT_8039d76c;
extern undefined4 DAT_8039d76e;
extern undefined4 DAT_8039d770;
extern undefined4 DAT_8039d772;
extern undefined4 DAT_8039d774;
extern short DAT_8039d778;
extern short DAT_803a0748;
extern undefined4 DAT_803a074a;
extern undefined4 DAT_803a074c;
extern undefined4 DAT_803a074e;
extern undefined4 DAT_803a0750;
extern undefined4 DAT_803a0752;
extern undefined4 DAT_803a0754;
extern undefined4 DAT_803a0756;
extern undefined4 DAT_803a0758;
extern undefined4 DAT_803a075c;
extern undefined4 DAT_803a0760;
extern undefined4 DAT_803a0764;
extern undefined4 DAT_803a0768;
extern undefined4 DAT_803a076a;
extern undefined4 DAT_803a076c;
extern undefined4 DAT_803a2390;
extern int DAT_803a2448;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd728;
extern undefined4 DAT_803de0b0;
extern undefined4 DAT_803de0b4;
extern undefined4 DAT_803de0c0;
extern undefined4 DAT_803de0ce;
extern undefined4 DAT_803de0cf;
extern undefined4 DAT_803de0d0;
extern undefined4 DAT_803de0e0;
extern undefined4 DAT_803de0e4;
extern undefined4 DAT_803de0f0;
extern f64 DOUBLE_803e1218;
extern f64 DOUBLE_803e1260;
extern f64 DOUBLE_803e1268;
extern f64 DOUBLE_803e12a8;
extern f32 lbl_803DC074;
extern f32 lbl_803DE0C4;
extern f32 lbl_803DE0C8;
extern f32 lbl_803E11F0;
extern f32 lbl_803E1204;
extern f32 lbl_803E1208;
extern f32 lbl_803E1234;
extern f32 lbl_803E1238;
extern f32 lbl_803E123C;
extern f32 lbl_803E1240;
extern f32 lbl_803E1244;
extern f32 lbl_803E1248;
extern f32 lbl_803E124C;
extern f32 lbl_803E1250;
extern f32 lbl_803E1270;
extern f32 lbl_803E1274;
extern f32 lbl_803E1278;
extern f32 lbl_803E127C;
extern f32 lbl_803E1280;
extern f32 lbl_803E1284;
extern f32 lbl_803E1288;
extern f32 lbl_803E128C;
extern f32 lbl_803E1290;
extern f32 lbl_803E12B0;
extern f32 lbl_803E12B4;
extern f32 lbl_803E12B8;
extern f32 lbl_803E12BC;
extern f32 lbl_803E12C0;
extern f32 lbl_803E12C4;
extern f32 lbl_803E12C8;
extern f32 lbl_803E12CC;
extern f32 lbl_803E12D0;
extern f32 lbl_803E12D4;

/*
 * --INFO--
 *
 * Function: FUN_800d8f90
 * EN v1.0 Address: 0x800D8F90
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x800D8FE0
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8f90(ushort *param_1,int param_2,uint param_3)
{
  uint uVar1;
  
  if (*(int *)(param_2 + 0x2d0) != 0) {
    uVar1 = FUN_80017730();
    uVar1 = (uVar1 & 0xffff) - (uint)*param_1;
    if (0x8000 < (int)uVar1) {
      uVar1 = uVar1 - 0xffff;
    }
    if ((int)uVar1 < -0x8000) {
      uVar1 = uVar1 + 0xffff;
    }
    *param_1 = *param_1 +
               (short)(int)(((float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) -
                                    DOUBLE_803e1218) * lbl_803DC074) /
                           (lbl_803E1204 *
                           (float)((double)CONCAT44(0x43300000,param_3 ^ 0x80000000) -
                                  DOUBLE_803e1218)));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d9090
 * EN v1.0 Address: 0x800D9090
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x800D9108
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d9090(double param_1,double param_2,short *param_3,int param_4)
{
  float fVar1;
  double dVar2;
  
  dVar2 = (double)(float)(param_2 * param_1 + (double)*(float *)(param_4 + 0x2a8));
  if ((double)lbl_803E1208 < dVar2) {
    dVar2 = (double)lbl_803E1208;
  }
  fVar1 = (float)(dVar2 - (double)*(float *)(param_4 + 0x2a8));
  if (lbl_803E11F0 < fVar1) {
    *param_3 = *param_3 + (short)(int)(*(float *)(param_4 + 0x300) * fVar1);
    *(float *)(param_4 + 0x2a8) = (float)dVar2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d90f8
 * EN v1.0 Address: 0x800D90F8
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x800D91C0
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d90f8(double param_1,double param_2,double param_3,short *param_4,int param_5)
{
  if (lbl_803E1234 < *(float *)(param_5 + 0x298)) {
    *param_4 = (short)(int)(lbl_803E1238 * (float)((double)(float)(param_2 * param_1) / param_3) +
                           (float)((double)CONCAT44(0x43300000,(int)*param_4 ^ 0x80000000) -
                                  DOUBLE_803e1218));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d91b0
 * EN v1.0 Address: 0x800D91B0
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x800D921C
 * EN v1.1 Size: 460b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d91b0(double param_1,short *param_2,uint *param_3,uint param_4)
{
  float fVar1;
  undefined uVar2;
  float *pfVar3;
  int iVar4;
  float local_48;
  float local_44;
  float local_40;
  short local_3a;
  char local_36;
  char local_35 [8];
  char local_2d;
  
  local_36 = '\0';
  uVar2 = FUN_8002fc3c((double)(float)param_3[0xa8],param_1);
  *(undefined *)((int)param_3 + 0x346) = uVar2;
  param_3[0xc5] = 0;
  pfVar3 = &local_48;
  for (iVar4 = 0; iVar4 < local_2d; iVar4 = iVar4 + 1) {
    param_3[0xc5] = param_3[0xc5] | 1 << (int)*(char *)((int)pfVar3 + 0x13);
    pfVar3 = (float *)((int)pfVar3 + 1);
  }
  *param_3 = *param_3 & 0xfffeffff;
  fVar1 = lbl_803E11F0;
  if (local_36 == '\0') {
    param_3[0xa0] = (uint)lbl_803E11F0;
    param_3[0xa1] = (uint)fVar1;
  }
  else if ((param_4 & 0x10) == 0) {
    if ((param_4 & 1) != 0) {
      param_3[0xa0] = (uint)(float)(-(double)local_40 / param_1);
    }
    if ((param_4 & 2) != 0) {
      param_3[0xa1] = (uint)(float)((double)local_48 / param_1);
    }
    if ((param_4 & 8) != 0) {
      *param_2 = *param_2 + local_3a;
    }
    if ((param_4 & 4) != 0) {
      param_3[0xa2] = (uint)(float)((double)local_44 / param_1);
      *param_3 = *param_3 | 0x10000;
    }
  }
  else {
    if ((param_4 & 1) != 0) {
      param_3[0xad] = (uint)-local_40;
    }
    if ((param_4 & 2) != 0) {
      param_3[0xad] = (uint)local_48;
    }
    if ((param_4 & 4) != 0) {
      param_3[0xad] = (uint)local_44;
    }
    if ((param_4 & 8) != 0) {
      *param_2 = *param_2 + local_3a;
    }
  }
  DAT_803de0c0 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d9384
 * EN v1.0 Address: 0x800D9384
 * EN v1.0 Size: 364b
 * EN v1.1 Address: 0x800D93E8
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d9384(undefined4 param_1,undefined4 param_2,int param_3)
{
  short sVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_80286838();
  iVar5 = (int)uVar8;
  bVar3 = false;
  iVar6 = 0;
  uVar7 = extraout_f1;
  if (*(short *)(iVar5 + 0x270) != *(short *)(iVar5 + 0x272)) {
    *(undefined *)(iVar5 + 0x27b) = 1;
    *(undefined2 *)(iVar5 + 0x32e) = 0;
  }
  do {
    bVar2 = false;
    sVar1 = *(short *)(iVar5 + 0x270);
    iVar4 = (**(code **)(param_3 + sVar1 * 4))(uVar7,(int)((ulonglong)uVar8 >> 0x20),iVar5);
    if (iVar4 < 1) {
      if (iVar4 < 0) {
        if (-iVar4 == (int)sVar1) {
          *(undefined *)(iVar5 + 0x27b) = 0;
        }
        else {
          *(short *)(iVar5 + 0x272) = sVar1;
          *(undefined *)(iVar5 + 0x27b) = 1;
          *(undefined2 *)(iVar5 + 0x32e) = 0;
        }
        *(short *)(iVar5 + 0x270) = (short)-iVar4;
        bVar2 = true;
        bVar3 = true;
      }
      else {
        bVar2 = true;
      }
    }
    else {
      *(undefined2 *)(iVar5 + 0x272) = *(undefined2 *)(iVar5 + 0x270);
      *(short *)(iVar5 + 0x270) = (short)iVar4 + -1;
      *(undefined *)(iVar5 + 0x27b) = 1;
      *(undefined2 *)(iVar5 + 0x32e) = 0;
    }
    iVar6 = iVar6 + 1;
    if (0xff < iVar6) {
      bVar2 = true;
    }
  } while (!bVar2);
  *(undefined2 *)(iVar5 + 0x272) = *(undefined2 *)(iVar5 + 0x270);
  if ((!bVar3) &&
     (*(undefined *)(iVar5 + 0x27b) = 0,
     lbl_803E123C <
     (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x338) ^ 0x80000000) -
            DOUBLE_803e1218))) {
    *(undefined *)(iVar5 + 0x27b) = 0;
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d94f0
 * EN v1.0 Address: 0x800D94F0
 * EN v1.0 Size: 740b
 * EN v1.1 Address: 0x800D955C
 * EN v1.1 Size: 760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d94f0(undefined4 param_1,undefined4 param_2,int param_3)
{
  short sVar1;
  bool bVar2;
  bool bVar3;
  double dVar4;
  float fVar5;
  int iVar6;
  int iVar7;
  undefined uVar8;
  uint *puVar9;
  undefined *puVar10;
  int iVar11;
  double extraout_f1;
  double in_f31;
  double dVar12;
  double in_ps31_1;
  undefined8 uVar13;
  undefined auStack_78 [19];
  char local_65 [8];
  char local_5d;
  undefined4 local_58;
  uint uStack_54;
  longlong local_50;
  undefined4 local_48;
  uint uStack_44;
  longlong local_40;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar13 = FUN_80286838();
  iVar6 = (int)((ulonglong)uVar13 >> 0x20);
  puVar9 = (uint *)uVar13;
  bVar3 = false;
  iVar11 = 0;
  DAT_803de0d0 = 0;
  DAT_803de0c0 = '\0';
  dVar12 = extraout_f1;
  if (*(short *)(puVar9 + 0x9d) != *(short *)((int)puVar9 + 0x276)) {
    *(undefined *)((int)puVar9 + 0x27a) = 1;
    *(undefined2 *)(puVar9 + 0xce) = 0;
  }
  do {
    bVar2 = false;
    sVar1 = *(short *)(puVar9 + 0x9d);
    iVar7 = (**(code **)(param_3 + sVar1 * 4))(dVar12,iVar6,puVar9);
    if (iVar7 < 1) {
      if (iVar7 < 0) {
        *(short *)(puVar9 + 0x9d) = (short)-iVar7;
        if (-iVar7 != (int)sVar1) {
          *(short *)((int)puVar9 + 0x276) = sVar1;
          if ((code *)puVar9[0xc1] != (code *)0x0) {
            (*(code *)puVar9[0xc1])(iVar6,puVar9);
            puVar9[0xc1] = 0;
          }
          puVar9[0xc1] = puVar9[0xc2];
          *(undefined *)((int)puVar9 + 0x27a) = 1;
          *(undefined2 *)(puVar9 + 0xce) = 0;
          *(undefined *)((int)puVar9 + 0x34d) = 0;
          *(undefined *)(puVar9 + 0xd3) = 0;
          *(undefined *)((int)puVar9 + 0x356) = 0;
          *(undefined2 *)(puVar9 + 0x9e) = 0;
          if (*(int *)(iVar6 + 0x54) != 0) {
            *(undefined *)(*(int *)(iVar6 + 0x54) + 0x70) = 0;
          }
        }
        bVar2 = true;
        bVar3 = true;
      }
      else {
        bVar2 = true;
      }
    }
    else {
      *(undefined2 *)((int)puVar9 + 0x276) = *(undefined2 *)(puVar9 + 0x9d);
      *(short *)(puVar9 + 0x9d) = (short)iVar7 + -1;
      if ((code *)puVar9[0xc1] != (code *)0x0) {
        (*(code *)puVar9[0xc1])(iVar6,puVar9);
        puVar9[0xc1] = 0;
      }
      puVar9[0xc1] = puVar9[0xc2];
      *(undefined *)((int)puVar9 + 0x27a) = 1;
      *(undefined2 *)(puVar9 + 0xce) = 0;
      *(undefined *)((int)puVar9 + 0x34d) = 0;
      *(undefined *)(puVar9 + 0xd3) = 0;
      *(undefined *)((int)puVar9 + 0x356) = 0;
      *(undefined2 *)(puVar9 + 0x9e) = 0;
      if (*(int *)(iVar6 + 0x54) != 0) {
        *(undefined *)(*(int *)(iVar6 + 0x54) + 0x70) = 0;
      }
    }
    iVar11 = iVar11 + 1;
    if (0xff < iVar11) {
      bVar2 = true;
    }
  } while (!bVar2);
  if (!bVar3) {
    *(undefined *)((int)puVar9 + 0x27a) = 0;
  }
  *(undefined2 *)((int)puVar9 + 0x276) = *(undefined2 *)(puVar9 + 0x9d);
  if ((DAT_803de0c0 == '\0') && ((*(byte *)(puVar9 + 0xd3) & 1) == 0)) {
    local_5d = '\0';
    uVar8 = FUN_8002fc3c((double)(float)puVar9[0xa8],dVar12);
    *(undefined *)((int)puVar9 + 0x346) = uVar8;
    puVar9[0xc5] = 0;
    puVar10 = auStack_78;
    for (iVar11 = 0; iVar11 < local_5d; iVar11 = iVar11 + 1) {
      puVar9[0xc5] = puVar9[0xc5] | 1 << (int)(char)puVar10[0x13];
      puVar10 = puVar10 + 1;
    }
    *puVar9 = *puVar9 & 0xfffeffff;
  }
  fVar5 = lbl_803E1240;
  dVar4 = DOUBLE_803e1218;
  if ((*puVar9 & 0x4000) == 0) {
    uStack_54 = (int)*(short *)(iVar6 + 2) ^ 0x80000000;
    local_58 = 0x43300000;
    iVar11 = (int)((float)((double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e1218)
                          * dVar12) * lbl_803E1240);
    local_50 = (longlong)iVar11;
    *(short *)(iVar6 + 2) = *(short *)(iVar6 + 2) - (short)iVar11;
    uStack_44 = (int)*(short *)(iVar6 + 4) ^ 0x80000000;
    local_48 = 0x43300000;
    iVar11 = (int)((float)((double)(float)((double)CONCAT44(0x43300000,uStack_44) - dVar4) * dVar12)
                  * fVar5);
    local_40 = (longlong)iVar11;
    *(short *)(iVar6 + 4) = *(short *)(iVar6 + 4) - (short)iVar11;
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d97d4
 * EN v1.0 Address: 0x800D97D4
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x800D9854
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d97d4(int param_1,int param_2,int param_3)
{
  if (*(short *)(param_2 + 0x274) != param_3) {
    *(short *)(param_2 + 0x276) = *(short *)(param_2 + 0x274);
    *(short *)(param_2 + 0x274) = (short)param_3;
    if (*(code **)(param_2 + 0x304) != (code *)0x0) {
      (**(code **)(param_2 + 0x304))();
      *(undefined4 *)(param_2 + 0x304) = 0;
    }
    *(undefined4 *)(param_2 + 0x304) = *(undefined4 *)(param_2 + 0x308);
  }
  *(undefined2 *)(param_2 + 0x338) = 0;
  *(undefined *)(param_2 + 0x27a) = 1;
  *(undefined *)(param_2 + 0x34d) = 0;
  *(undefined *)(param_2 + 0x34c) = 0;
  *(undefined *)(param_2 + 0x356) = 0;
  *(undefined2 *)(param_2 + 0x278) = 0;
  if (*(int *)(param_1 + 0x54) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d9874
 * EN v1.0 Address: 0x800D9874
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800D98FC
 * EN v1.1 Size: 412b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d9874(int param_1,uint *param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800d9878
 * EN v1.0 Address: 0x800D9878
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800D9A98
 * EN v1.1 Size: 1328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d9878(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined4 param_4,
                 int param_5,int param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800d987c
 * EN v1.0 Address: 0x800D987C
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x800D9FC8
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d987c(undefined4 param_1,int param_2,undefined2 param_3,undefined2 param_4)
{
  FUN_800033a8(param_2,0,0x35c);
  *(undefined2 *)(param_2 + 0x26c) = param_3;
  *(undefined2 *)(param_2 + 0x26e) = param_4;
  *(undefined *)(param_2 + 0x27a) = 1;
  *(undefined *)(param_2 + 0x27b) = 1;
  *(float *)(param_2 + 0x2b8) = lbl_803E123C;
  *(undefined4 *)(param_2 + 0x33c) = 0xffffffff;
  *(undefined4 *)(param_2 + 0x340) = 0xffffffff;
  *(undefined *)(param_2 + 0x358) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d98fc
 * EN v1.0 Address: 0x800D98FC
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x800DA058
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d98fc(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11)
{
  byte bVar1;
  
  bVar1 = FUN_80006b20();
  if (bVar1 != 0) {
    param_1 = FUN_80006b30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  FUN_80006b28(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  (**(code **)(*DAT_803dd6e8 + 0xc))(param_9,param_10,param_11);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d9a30
 * EN v1.0 Address: 0x800D9A30
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x800DA0D8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d9a30(void)
{
  (**(code **)(*DAT_803dd6e8 + 8))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d9a64
 * EN v1.0 Address: 0x800D9A64
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x800DA108
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d9a64(void)
{
  (**(code **)(*DAT_803dd6e8 + 4))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d9a98
 * EN v1.0 Address: 0x800D9A98
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x800DA174
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d9a98(float *param_1)
{
  param_1[0x27] = (float)((uint)param_1[0x27] ^ (uint)param_1[0x29]);
  param_1[0x29] = (float)((uint)param_1[0x29] ^ (uint)param_1[0x27]);
  param_1[0x27] = (float)((uint)param_1[0x27] ^ (uint)param_1[0x29]);
  if (*param_1 < lbl_803E1248) {
    return;
  }
  *param_1 = lbl_803E124C;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d9b7c
 * EN v1.0 Address: 0x800D9B7C
 * EN v1.0 Size: 612b
 * EN v1.1 Address: 0x800DA1C4
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800d9b7c(int param_1,int param_2)
{
  undefined4 uVar1;
  double dVar2;
  
  if (((*(int *)(param_1 + 0xa0) == 0) || (*(int *)(param_1 + 0xa4) == 0)) || (param_2 == 0)) {
    uVar1 = 1;
  }
  else {
    *(int *)(param_1 + 0xa4) = param_2;
    if (*(int *)(param_1 + 0x80) == 0) {
      *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(param_2 + 8);
      dVar2 = (double)FUN_80293f90();
      *(float *)(param_1 + 0xc4) =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2e)) -
                                  DOUBLE_803e1268) * dVar2);
      *(undefined4 *)(param_1 + 0xdc) = *(undefined4 *)(param_2 + 0xc);
      dVar2 = (double)FUN_80293f90();
      *(float *)(param_1 + 0xe4) =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2e)) -
                                  DOUBLE_803e1268) * dVar2);
      *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(param_2 + 0x10);
      dVar2 = (double)FUN_80294964();
      *(float *)(param_1 + 0x104) =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2e)) -
                                  DOUBLE_803e1268) * dVar2);
    }
    else {
      *(undefined4 *)(param_1 + 0xa8) = *(undefined4 *)(param_2 + 8);
      dVar2 = (double)FUN_80293f90();
      *(float *)(param_1 + 0xb0) =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2e)) -
                                  DOUBLE_803e1268) * dVar2);
      *(undefined4 *)(param_1 + 200) = *(undefined4 *)(param_2 + 0xc);
      dVar2 = (double)FUN_80293f90();
      *(float *)(param_1 + 0xd0) =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2e)) -
                                  DOUBLE_803e1268) * dVar2);
      *(undefined4 *)(param_1 + 0xe8) = *(undefined4 *)(param_2 + 0x10);
      dVar2 = (double)FUN_80294964();
      *(float *)(param_1 + 0xf0) =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2e)) -
                                  DOUBLE_803e1268) * dVar2);
    }
    uVar1 = 0;
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_800d9de0
 * EN v1.0 Address: 0x800D9DE0
 * EN v1.0 Size: 1972b
 * EN v1.1 Address: 0x800DA4C8
 * EN v1.1 Size: 1772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800d9de0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9,float param_10,undefined4 param_11,undefined4 param_12,
            undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  undefined4 uVar2;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  double dVar3;
  double dVar4;
  
  fVar1 = param_9[0x28];
  if (((fVar1 == 0.0) || (param_9[0x29] == 0.0)) || (param_10 == 0.0)) {
    uVar2 = 1;
  }
  else {
    if (param_9[0x20] == 0.0) {
      param_9[0x27] = fVar1;
      param_9[0x28] = param_9[0x29];
      param_9[0x29] = param_10;
      FUN_80003494((uint)(param_9 + 0x2a),(uint)(param_9 + 0x2e),0x10);
      FUN_80003494((uint)(param_9 + 0x32),(uint)(param_9 + 0x36),0x10);
      uVar2 = 0x10;
      FUN_80003494((uint)(param_9 + 0x3a),(uint)(param_9 + 0x3e),0x10);
      param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
      param_9[0x2f] = *(float *)((int)param_9[0x29] + 8);
      dVar3 = (double)FUN_80293f90();
      param_9[0x30] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      dVar3 = (double)FUN_80293f90();
      param_9[0x31] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
      param_9[0x37] = *(float *)((int)param_9[0x29] + 0xc);
      dVar3 = (double)FUN_80293f90();
      param_9[0x38] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      dVar3 = (double)FUN_80293f90();
      param_9[0x39] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
      param_9[0x3f] = *(float *)((int)param_9[0x29] + 0x10);
      dVar3 = (double)FUN_80294964();
      param_9[0x40] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      dVar4 = (double)FUN_80294964();
      dVar3 = DOUBLE_803e1268;
      dVar4 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                               (uint)*(byte *)((int)param_9[0x29] +
                                                                              0x2e)) -
                                             DOUBLE_803e1268) * dVar4);
      param_9[0x41] = (float)((double)lbl_803E1250 * dVar4);
      if (param_9[0x24] != 0.0) {
        FUN_80006a18(dVar4,dVar3,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                     extraout_r4_00,uVar2,param_12,param_13,param_14,param_15,param_16);
        if (lbl_803E1248 <= *param_9) {
          *param_9 = lbl_803E124C;
        }
      }
    }
    else {
      param_9[0x27] = fVar1;
      param_9[0x28] = param_9[0x29];
      param_9[0x29] = param_10;
      FUN_80003494((uint)(param_9 + 0x2e),(uint)(param_9 + 0x2a),0x10);
      FUN_80003494((uint)(param_9 + 0x36),(uint)(param_9 + 0x32),0x10);
      uVar2 = 0x10;
      FUN_80003494((uint)(param_9 + 0x3e),(uint)(param_9 + 0x3a),0x10);
      param_9[0x2a] = *(float *)((int)param_9[0x29] + 8);
      param_9[0x2b] = *(float *)((int)param_9[0x28] + 8);
      dVar3 = (double)FUN_80293f90();
      param_9[0x2c] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      dVar3 = (double)FUN_80293f90();
      param_9[0x2d] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      param_9[0x32] = *(float *)((int)param_9[0x29] + 0xc);
      param_9[0x33] = *(float *)((int)param_9[0x28] + 0xc);
      dVar3 = (double)FUN_80293f90();
      param_9[0x34] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      dVar3 = (double)FUN_80293f90();
      param_9[0x35] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      param_9[0x3a] = *(float *)((int)param_9[0x29] + 0x10);
      param_9[0x3b] = *(float *)((int)param_9[0x28] + 0x10);
      dVar3 = (double)FUN_80294964();
      param_9[0x3c] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      dVar4 = (double)FUN_80294964();
      dVar3 = DOUBLE_803e1268;
      dVar4 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                               (uint)*(byte *)((int)param_9[0x28] +
                                                                              0x2e)) -
                                             DOUBLE_803e1268) * dVar4);
      param_9[0x3d] = (float)((double)lbl_803E1250 * dVar4);
      if (param_9[0x24] != 0.0) {
        FUN_80006a18(dVar4,dVar3,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                     extraout_r4,uVar2,param_12,param_13,param_14,param_15,param_16);
        if (*param_9 <= lbl_803E1270) {
          *param_9 = lbl_803E1274;
        }
      }
    }
    uVar2 = 0;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_800da594
 * EN v1.0 Address: 0x800DA594
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x800DABB4
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800da594(double param_1,float *param_2)
{
  if (lbl_803E1270 < *param_2) {
    if (lbl_803E1248 <= *param_2) {
      *param_2 = lbl_803E124C;
    }
  }
  else {
    *param_2 = lbl_803E1274;
  }
  FUN_80006a10(param_1,param_2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800da5e8
 * EN v1.0 Address: 0x800DA5E8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DAC0C
 * EN v1.1 Size: 1628b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_800da5e8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 float *param_9,float param_10,float param_11,float param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800da5f0
 * EN v1.0 Address: 0x800DA5F0
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x800DB268
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800da5f0(float *param_1,uint param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  int local_18 [3];
  
  piVar5 = (int *)(**(code **)(*DAT_803dd71c + 0x10))(local_18);
  iVar7 = 0;
  fVar1 = lbl_803E1278;
  if (0 < local_18[0]) {
    do {
      iVar6 = *piVar5;
      if ((((iVar6 != 0) && (*(char *)(iVar6 + 0x19) == '$')) &&
          ((param_2 == 0xffffffff || (*(byte *)(iVar6 + 3) == param_2)))) &&
         (((param_3 == -1 || (*(char *)(iVar6 + 0x1a) == param_3)) &&
          (fVar2 = *param_1 - *(float *)(iVar6 + 8), fVar3 = param_1[1] - *(float *)(iVar6 + 0xc),
          fVar4 = param_1[2] - *(float *)(iVar6 + 0x10),
          fVar2 = fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3, fVar2 < fVar1)))) {
        iVar7 = iVar6;
        fVar1 = fVar2;
      }
      piVar5 = piVar5 + 1;
      local_18[0] = local_18[0] + -1;
    } while (local_18[0] != 0);
  }
  return iVar7;
}

/*
 * --INFO--
 *
 * Function: FUN_800da700
 * EN v1.0 Address: 0x800DA700
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x800DB36C
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800da700(undefined4 param_1,undefined4 param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float *pfVar4;
  int *piVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps31_1;
  undefined8 uVar11;
  int local_38 [12];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar11 = FUN_80286838();
  pfVar4 = (float *)((ulonglong)uVar11 >> 0x20);
  piVar5 = (int *)(**(code **)(*DAT_803dd71c + 0x10))(local_38);
  dVar10 = (double)lbl_803E1278;
  for (iVar8 = 0; iVar8 < local_38[0]; iVar8 = iVar8 + 1) {
    iVar7 = *piVar5;
    if ((((((iVar7 != 0) && (*(char *)(iVar7 + 0x19) == '$')) &&
          (((uint)uVar11 == 0xffffffff || ((uint)*(byte *)(iVar7 + 3) == (uint)uVar11)))) &&
         ((param_3 == -1 || (*(char *)(iVar7 + 0x1a) == param_3)))) &&
        (((int)*(short *)(iVar7 + 0x30) == 0xffffffff ||
         (uVar6 = FUN_80017690((int)*(short *)(iVar7 + 0x30)), uVar6 != 0)))) &&
       ((((int)*(short *)(iVar7 + 0x32) == 0xffffffff ||
         (uVar6 = FUN_80017690((int)*(short *)(iVar7 + 0x32)), uVar6 == 0)) &&
        (fVar1 = *pfVar4 - *(float *)(iVar7 + 8), fVar2 = pfVar4[1] - *(float *)(iVar7 + 0xc),
        fVar3 = pfVar4[2] - *(float *)(iVar7 + 0x10),
        dVar9 = (double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2), dVar9 < dVar10)))) {
      dVar10 = dVar9;
    }
    piVar5 = piVar5 + 1;
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800da850
 * EN v1.0 Address: 0x800DA850
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x800DB4B0
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800da850(uint param_1,undefined *param_2)
{
  *param_2 = (char)(param_1 & 0xffff);
  param_2[1] = (char)((param_1 & 0xffff) >> 8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800da860
 * EN v1.0 Address: 0x800DA860
 * EN v1.0 Size: 420b
 * EN v1.1 Address: 0x800DB4CC
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800da860(undefined4 param_1,undefined4 param_2,uint param_3)
{
  double dVar1;
  float *pfVar2;
  float *pfVar3;
  uint uVar4;
  double dVar5;
  double dVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_80286840();
  dVar1 = DOUBLE_803e1260;
  pfVar2 = (float *)((ulonglong)uVar7 >> 0x20);
  pfVar3 = (float *)uVar7;
  uVar4 = 0;
  while (((uVar4 & 0xff) < 0x100 &&
         ((param_3 & 0xffff) != (uint)(ushort)(&DAT_8039d76c)[(uVar4 & 0xff) * 0x18]))) {
    uVar4 = uVar4 + 1;
  }
  uVar4 = uVar4 & 0xff;
  *pfVar3 = (float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039d76e)[uVar4 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e1260);
  pfVar3[1] = pfVar2[1];
  pfVar3[2] = (float)((double)CONCAT44(0x43300000,
                                       (int)(short)(&DAT_8039d770)[uVar4 * 0x18] ^ 0x80000000) -
                     dVar1);
  dVar5 = FUN_80017714(pfVar2,pfVar3);
  dVar1 = DOUBLE_803e1260;
  *pfVar3 = (float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039d772)[uVar4 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e1260);
  pfVar3[2] = (float)((double)CONCAT44(0x43300000,
                                       (int)(short)(&DAT_8039d774)[uVar4 * 0x18] ^ 0x80000000) -
                     dVar1);
  dVar6 = FUN_80017714(pfVar2,pfVar3);
  dVar1 = DOUBLE_803e1260;
  if (dVar5 <= dVar6) {
    *pfVar3 = (float)((double)CONCAT44(0x43300000,
                                       (int)(short)(&DAT_8039d76e)[uVar4 * 0x18] ^ 0x80000000) -
                     DOUBLE_803e1260);
    pfVar3[2] = (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_8039d770)[uVar4 * 0x18] ^ 0x80000000) -
                       dVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800daa04
 * EN v1.0 Address: 0x800DAA04
 * EN v1.0 Size: 1332b
 * EN v1.1 Address: 0x800DB670
 * EN v1.1 Size: 1268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800daa04(undefined4 param_1,undefined4 param_2,int param_3)
{
  ushort uVar1;
  uint uVar2;
  float *pfVar3;
  float *pfVar4;
  byte bVar6;
  uint uVar5;
  undefined2 *in_r10;
  byte bVar8;
  uint uVar7;
  byte bVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_8028683c();
  pfVar3 = (float *)((ulonglong)uVar10 >> 0x20);
  pfVar4 = (float *)uVar10;
  for (bVar6 = 0; bVar6 < 4; bVar6 = bVar6 + 1) {
    uVar5 = (uint)*(byte *)((int)&DAT_803a0748 + bVar6 + 0x24 + param_3 * 0x28);
    if (uVar5 != 0) {
      in_r10 = &DAT_8039d748 + uVar5 * 0x18;
      if ((pfVar3[1] <
           (float)((double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_8039d768)[uVar5 * 0x18] ^ 0x80000000) -
                  DOUBLE_803e1260)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)(&DAT_8039d76a)[uVar5 * 0x18] ^ 0x80000000
                                  ) - DOUBLE_803e1260) < pfVar3[1])) {
        bVar8 = 0;
        uVar2 = 0;
        while ((bVar8 < 4 &&
               (*(float *)(in_r10 + (uint)bVar8 * 2 + 8) +
                *pfVar3 * (float)((double)CONCAT44(0x43300000,
                                                   (int)(short)in_r10[uVar2 & 0xff] ^ 0x80000000) -
                                 DOUBLE_803e1260) +
                pfVar3[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)in_r10[(uVar2 & 0xff) + 1] ^ 0x80000000) -
                       DOUBLE_803e1260) <= lbl_803E1270))) {
          bVar8 = bVar8 + 1;
          uVar2 = uVar2 + 2;
        }
        if (((bVar8 == 4) &&
            (pfVar4[1] <
             (float)((double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_8039d768)[uVar5 * 0x18] ^ 0x80000000) -
                    DOUBLE_803e1260))) &&
           ((float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039d76a)[uVar5 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e1260) < pfVar4[1])) {
          bVar8 = 0;
          uVar5 = 0;
          while ((bVar8 < 4 &&
                 (*(float *)(in_r10 + (uint)bVar8 * 2 + 8) +
                  *pfVar4 * (float)((double)CONCAT44(0x43300000,
                                                     (int)(short)in_r10[uVar5 & 0xff] ^ 0x80000000)
                                   - DOUBLE_803e1260) +
                  pfVar4[2] *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)in_r10[(uVar5 & 0xff) + 1] ^ 0x80000000) -
                         DOUBLE_803e1260) <= lbl_803E1270))) {
            bVar8 = bVar8 + 1;
            uVar5 = uVar5 + 2;
          }
          if (bVar8 == 4) goto LAB_800dbb4c;
        }
      }
    }
  }
  for (bVar6 = 0; bVar6 < 4; bVar6 = bVar6 + 1) {
    uVar5 = (uint)*(byte *)((int)&DAT_803a0748 + bVar6 + 0x24 + param_3 * 0x28);
    if (uVar5 != 0) {
      uVar2 = countLeadingZeros(0xff - param_3);
      uVar1 = (&DAT_8039d76c)[uVar5 * 0x18];
      if ((uVar2 >> 5 & (uint)uVar1) == 0) {
        uVar5 = uVar1 & 0xff;
      }
      else {
        uVar5 = (int)(uVar1 & 0xff00) >> 8;
      }
      for (bVar8 = 0; bVar8 < 4; bVar8 = bVar8 + 1) {
        uVar2 = (uint)(byte)(&DAT_803a076c)[uVar5 * 0x28 + (uint)bVar8];
        if (uVar2 != 0) {
          if ((&DAT_8039d76c)[uVar2 * 0x18] != in_r10[0x12]) {
            if ((pfVar3[1] <
                 (float)((double)CONCAT44(0x43300000,
                                          (int)(short)(&DAT_8039d768)[uVar2 * 0x18] ^ 0x80000000) -
                        DOUBLE_803e1260)) &&
               ((float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_8039d76a)[uVar2 * 0x18] ^ 0x80000000) -
                       DOUBLE_803e1260) < pfVar3[1])) {
              bVar9 = 0;
              uVar7 = 0;
              while ((bVar9 < 4 &&
                     (*(float *)(&DAT_8039d748 + uVar2 * 0x18 + (uint)bVar9 * 2 + 8) +
                      *pfVar3 * (float)((double)CONCAT44(0x43300000,
                                                         (int)(short)(&DAT_8039d748)
                                                                     [uVar2 * 0x18 + (uVar7 & 0xff)]
                                                         ^ 0x80000000) - DOUBLE_803e1260) +
                      pfVar3[2] *
                      (float)((double)CONCAT44(0x43300000,
                                               (int)(short)(&DAT_8039d748)
                                                           [uVar2 * 0x18 + (uVar7 & 0xff) + 1] ^
                                               0x80000000) - DOUBLE_803e1260) <= lbl_803E1270))) {
                bVar9 = bVar9 + 1;
                uVar7 = uVar7 + 2;
              }
              if (((bVar9 == 4) &&
                  (pfVar4[1] <
                   (float)((double)CONCAT44(0x43300000,
                                            (int)(short)(&DAT_8039d768)[uVar2 * 0x18] ^ 0x80000000)
                          - DOUBLE_803e1260))) &&
                 ((float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039d76a)[uVar2 * 0x18] ^ 0x80000000) -
                         DOUBLE_803e1260) < pfVar4[1])) {
                bVar9 = 0;
                uVar7 = 0;
                while ((bVar9 < 4 &&
                       (*(float *)(&DAT_8039d748 + uVar2 * 0x18 + (uint)bVar9 * 2 + 8) +
                        *pfVar4 * (float)((double)CONCAT44(0x43300000,
                                                           (int)(short)(&DAT_8039d748)
                                                                       [uVar2 * 0x18 +
                                                                        (uVar7 & 0xff)] ^ 0x80000000
                                                          ) - DOUBLE_803e1260) +
                        pfVar4[2] *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_8039d748)
                                                             [uVar2 * 0x18 + (uVar7 & 0xff) + 1] ^
                                                 0x80000000) - DOUBLE_803e1260) <= lbl_803E1270)))
                {
                  bVar9 = bVar9 + 1;
                  uVar7 = uVar7 + 2;
                }
                if (bVar9 == 4) {
                  FUN_800723a0();
                  goto LAB_800dbb4c;
                }
              }
            }
          }
        }
      }
    }
  }
LAB_800dbb4c:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800daf38
 * EN v1.0 Address: 0x800DAF38
 * EN v1.0 Size: 472b
 * EN v1.1 Address: 0x800DBB64
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800daf38(float *param_1,uint param_2,uint param_3)
{
  uint uVar1;
  uint uVar2;
  byte bVar3;
  
  bVar3 = 0;
  do {
    if (3 < bVar3) {
      FUN_800723a0();
      return 0;
    }
    uVar1 = (uint)(byte)(&DAT_803a076c)[param_2 * 0x28 + (uint)bVar3];
    if (uVar1 != 0) {
      if ((ushort)(&DAT_8039d76c)[uVar1 * 0x18] == param_3) {
        if ((param_1[1] <
             (float)((double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_8039d768)[uVar1 * 0x18] ^ 0x80000000) -
                    DOUBLE_803e1260)) &&
           ((float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039d76a)[uVar1 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e1260) < param_1[1])) {
          param_2 = 0;
          uVar2 = 0;
          while (((param_2 & 0xff) < 4 &&
                 (*(float *)(&DAT_8039d748 + uVar1 * 0x18 + (param_2 & 0xff) * 2 + 8) +
                  *param_1 *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039d748)
                                                       [uVar1 * 0x18 + (uVar2 & 0xff)] ^ 0x80000000)
                         - DOUBLE_803e1260) +
                  param_1[2] *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039d748)
                                                       [uVar1 * 0x18 + (uVar2 & 0xff) + 1] ^
                                           0x80000000) - DOUBLE_803e1260) <= lbl_803E1270))) {
            param_2 = param_2 + 1;
            uVar2 = uVar2 + 2;
          }
        }
        uVar1 = countLeadingZeros(4 - (param_2 & 0xff));
        return uVar1 >> 5;
      }
    }
    bVar3 = bVar3 + 1;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_800db110
 * EN v1.0 Address: 0x800DB110
 * EN v1.0 Size: 480b
 * EN v1.1 Address: 0x800DBCD8
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2
FUN_800db110(float *param_1,int param_2,undefined4 param_3,undefined4 param_4,byte param_5)
{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  
  bVar1 = 0;
  do {
    if (3 < bVar1) {
      return 0;
    }
    if (((&DAT_803a2390)[param_2] != '\0') &&
       (uVar2 = (uint)(byte)(&DAT_803a076c)[param_2 * 0x28 + (uint)bVar1], uVar2 != 0)) {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_8039d768)[uVar2 * 0x18] ^ 0x80000000) -
                  DOUBLE_803e1260)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)(&DAT_8039d76a)[uVar2 * 0x18] ^ 0x80000000
                                  ) - DOUBLE_803e1260) < param_1[1])) {
        param_5 = 0;
        uVar3 = 0;
        while ((param_5 < 4 &&
               (*(float *)(&DAT_8039d748 + uVar2 * 0x18 + (uint)param_5 * 2 + 8) +
                *param_1 *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_8039d748)[uVar2 * 0x18 + (uVar3 & 0xff)]
                                         ^ 0x80000000) - DOUBLE_803e1260) +
                param_1[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_8039d748)
                                                     [uVar2 * 0x18 + (uVar3 & 0xff) + 1] ^
                                         0x80000000) - DOUBLE_803e1260) <= lbl_803E1270))) {
          param_5 = param_5 + 1;
          uVar3 = uVar3 + 2;
        }
      }
      if (param_5 == 4) {
        return (&DAT_8039d76c)[uVar2 * 0x18];
      }
    }
    bVar1 = bVar1 + 1;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_800db2f0
 * EN v1.0 Address: 0x800DB2F0
 * EN v1.0 Size: 396b
 * EN v1.1 Address: 0x800DBE30
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800db2f0(float *param_1)
{
  int iVar1;
  undefined4 uVar2;
  short *psVar3;
  short *psVar4;
  short *psVar5;
  short *psVar6;
  short sVar7;
  short sVar8;
  
  iVar1 = FUN_800db820(param_1);
  if (iVar1 == 0) {
    psVar6 = &DAT_8039d778;
    for (sVar8 = 1; sVar8 < DAT_803de0e4; sVar8 = sVar8 + 1) {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,(int)psVar6[0x10] ^ 0x80000000) - DOUBLE_803e1260))
         && ((float)((double)CONCAT44(0x43300000,(int)psVar6[0x11] ^ 0x80000000) - DOUBLE_803e1260)
             < param_1[1])) {
        sVar7 = 0;
        psVar3 = psVar6;
        psVar4 = psVar6;
        for (psVar5 = psVar6;
            (sVar7 < 4 &&
            (*(float *)(psVar5 + 8) +
             *param_1 *
             (float)((double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000) - DOUBLE_803e1260) +
             param_1[2] *
             (float)((double)CONCAT44(0x43300000,(int)psVar3[1] ^ 0x80000000) - DOUBLE_803e1260) <=
             lbl_803E1270)); psVar5 = psVar5 + 2) {
          sVar7 = sVar7 + 1;
          psVar3 = psVar3 + 2;
          psVar4 = psVar4 + 2;
        }
        if (sVar7 == 4) {
          return 1;
        }
      }
      psVar6 = psVar6 + 0x18;
    }
    uVar2 = 0;
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_800db47c
 * EN v1.0 Address: 0x800DB47C
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x800DBF88
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800db47c(float *param_1,undefined *param_2)
{
  uint uVar1;
  uint uVar2;
  byte bVar3;
  uint uVar4;
  uint uVar5;
  byte unaff_r31;
  
  uVar2 = FUN_800db820(param_1);
  if ((param_2 != (undefined *)0x0) && ((uVar2 & 0xff) != 0)) {
    *param_2 = (char)uVar2;
    param_2[1] = 0;
    uVar1 = 1;
    for (bVar3 = 0; bVar3 < 4; bVar3 = bVar3 + 1) {
      uVar5 = (uint)bVar3;
      uVar4 = (uint)(byte)(&DAT_803a076c)[(uVar2 & 0xff) * 0x28 + uVar5];
      if (uVar4 == 0) {
        *(undefined2 *)(param_2 + uVar5 * 2 + 2) = 0;
      }
      else {
        *(undefined2 *)(param_2 + uVar5 * 2 + 2) = (&DAT_8039d76c)[uVar4 * 0x18];
        if (param_1[1] <
            (float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039d768)[uVar4 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e1260)) {
          if ((float)((double)CONCAT44(0x43300000,
                                       (int)(short)(&DAT_8039d76a)[uVar4 * 0x18] ^ 0x80000000) -
                     DOUBLE_803e1260) < param_1[1]) {
            uVar5 = 0;
            for (unaff_r31 = 0; unaff_r31 < 4; unaff_r31 = unaff_r31 + 1) {
              if (lbl_803E1270 <
                  *(float *)(&DAT_8039d748 + uVar4 * 0x18 + (uint)unaff_r31 * 2 + 8) +
                  *param_1 *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039d748)
                                                       [uVar4 * 0x18 + (uVar5 & 0xff)] ^ 0x80000000)
                         - DOUBLE_803e1260) +
                  param_1[2] *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039d748)
                                                       [uVar4 * 0x18 + (uVar5 & 0xff) + 1] ^
                                           0x80000000) - DOUBLE_803e1260)) break;
              uVar5 = uVar5 + 2;
            }
          }
        }
        if (unaff_r31 == 4) {
          param_2[1] = param_2[1] | (byte)uVar1;
        }
      }
      uVar1 = (uVar1 & 0x7f) << 1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800db690
 * EN v1.0 Address: 0x800DB690
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x800DC158
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 FUN_800db690(float *param_1)
{
  uint uVar1;
  byte bVar2;
  undefined2 *puVar3;
  int iVar4;
  
  puVar3 = &DAT_8039d748;
  iVar4 = DAT_803de0e4;
  if (0 < DAT_803de0e4) {
    do {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,(int)(short)puVar3[0x10] ^ 0x80000000) -
                  DOUBLE_803e1260)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)puVar3[0x11] ^ 0x80000000) -
                 DOUBLE_803e1260) < param_1[1])) {
        bVar2 = 0;
        uVar1 = 0;
        while ((bVar2 < 4 &&
               (*(float *)(puVar3 + (uint)bVar2 * 2 + 8) +
                *param_1 *
                (float)((double)CONCAT44(0x43300000,(int)(short)puVar3[uVar1 & 0xff] ^ 0x80000000) -
                       DOUBLE_803e1260) +
                param_1[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)puVar3[(uVar1 & 0xff) + 1] ^ 0x80000000) -
                       DOUBLE_803e1260) <= lbl_803E1270))) {
          bVar2 = bVar2 + 1;
          uVar1 = uVar1 + 2;
        }
        if (bVar2 == 4) {
          return puVar3[0x12];
        }
      }
      puVar3 = puVar3 + 0x18;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800db820
 * EN v1.0 Address: 0x800DB820
 * EN v1.0 Size: 1096b
 * EN v1.1 Address: 0x800DC27C
 * EN v1.1 Size: 936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800db820(float *param_1)
{
  short sVar1;
  short sVar2;
  uint uVar3;
  int iVar4;
  byte bVar5;
  
  sVar2 = (short)DAT_803de0e0;
  if (DAT_803de0e0 == 0xb4) {
    sVar1 = 0;
  }
  else {
    sVar1 = sVar2 + 1;
  }
  do {
    iVar4 = (int)sVar2;
    if (iVar4 == sVar1) {
      if ((&DAT_803a2390)[iVar4] != '\0') {
        if ((param_1[1] <
             (float)((double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0768)[iVar4 * 0x14] ^ 0x80000000) -
                    DOUBLE_803e1260)) &&
           ((float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_803a076a)[iVar4 * 0x14] ^ 0x80000000) -
                   DOUBLE_803e1260) < param_1[1])) {
          bVar5 = 0;
          uVar3 = 0;
          while ((bVar5 < 4 &&
                 (*(float *)(&DAT_803a0748 + iVar4 * 0x14 + (uint)bVar5 * 2 + 8) +
                  *param_1 *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_803a0748)
                                                       [iVar4 * 0x14 + (uVar3 & 0xff)] ^ 0x80000000)
                         - DOUBLE_803e1260) +
                  param_1[2] *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_803a0748)
                                                       [iVar4 * 0x14 + (uVar3 & 0xff) + 1] ^
                                           0x80000000) - DOUBLE_803e1260) <= lbl_803E1270))) {
            bVar5 = bVar5 + 1;
            uVar3 = uVar3 + 2;
          }
          if (bVar5 == 4) {
            DAT_803de0e0 = (int)sVar2;
            return (int)sVar2;
          }
        }
      }
      return 0;
    }
    iVar4 = (int)sVar2;
    if ((&DAT_803a2390)[iVar4] != '\0') {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_803a0768)[iVar4 * 0x14] ^ 0x80000000) -
                  DOUBLE_803e1260)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)(&DAT_803a076a)[iVar4 * 0x14] ^ 0x80000000
                                  ) - DOUBLE_803e1260) < param_1[1])) {
        bVar5 = 0;
        uVar3 = 0;
        while ((bVar5 < 4 &&
               (*(float *)(&DAT_803a0748 + iVar4 * 0x14 + (uint)bVar5 * 2 + 8) +
                *param_1 *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_803a0748)[iVar4 * 0x14 + (uVar3 & 0xff)]
                                         ^ 0x80000000) - DOUBLE_803e1260) +
                param_1[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_803a0748)
                                                     [iVar4 * 0x14 + (uVar3 & 0xff) + 1] ^
                                         0x80000000) - DOUBLE_803e1260) <= lbl_803E1270))) {
          bVar5 = bVar5 + 1;
          uVar3 = uVar3 + 2;
        }
        if (bVar5 == 4) {
          DAT_803de0e0 = (int)sVar2;
          return (int)sVar2;
        }
      }
    }
    iVar4 = (int)sVar1;
    if ((&DAT_803a2390)[iVar4] != '\0') {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_803a0768)[iVar4 * 0x14] ^ 0x80000000) -
                  DOUBLE_803e1260)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)(&DAT_803a076a)[iVar4 * 0x14] ^ 0x80000000
                                  ) - DOUBLE_803e1260) < param_1[1])) {
        bVar5 = 0;
        uVar3 = 0;
        while ((bVar5 < 4 &&
               (*(float *)(&DAT_803a0748 + iVar4 * 0x14 + (uint)bVar5 * 2 + 8) +
                *param_1 *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_803a0748)[iVar4 * 0x14 + (uVar3 & 0xff)]
                                         ^ 0x80000000) - DOUBLE_803e1260) +
                param_1[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_803a0748)
                                                     [iVar4 * 0x14 + (uVar3 & 0xff) + 1] ^
                                         0x80000000) - DOUBLE_803e1260) <= lbl_803E1270))) {
          bVar5 = bVar5 + 1;
          uVar3 = uVar3 + 2;
        }
        if (bVar5 == 4) {
          DAT_803de0e0 = (int)sVar1;
          return (int)sVar1;
        }
      }
    }
    sVar2 = sVar2 + -1;
    if (sVar2 == -1) {
      sVar2 = 0xb4;
    }
    sVar1 = sVar1 + 1;
    if (sVar1 == 0xb5) {
      sVar1 = 0;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_800dbc68
 * EN v1.0 Address: 0x800DBC68
 * EN v1.0 Size: 6004b
 * EN v1.1 Address: 0x800DC624
 * EN v1.1 Size: 4768b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800dbc68(void)
{
  bool bVar1;
  byte bVar2;
  byte bVar3;
  float fVar4;
  float fVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int *piVar10;
  int iVar11;
  undefined2 *puVar12;
  char *pcVar13;
  char cVar15;
  uint uVar14;
  int iVar16;
  byte bVar17;
  int iVar18;
  byte *pbVar19;
  int iVar20;
  char *pcVar21;
  short *psVar22;
  int iVar23;
  int iVar24;
  double in_f25;
  double in_f26;
  double in_f27;
  double dVar25;
  double dVar26;
  double in_f28;
  double dVar27;
  double in_f29;
  double dVar28;
  double dVar29;
  double in_f30;
  double dVar30;
  double dVar31;
  double in_f31;
  double dVar32;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_2c8;
  char local_2c4 [52];
  char local_290;
  byte abStack_24c [364];
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
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
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  FUN_80286824();
  pcVar21 = &DAT_803120d8;
  FUN_800571f8(local_2c4);
  iVar16 = 0;
  pcVar13 = local_2c4;
  iVar24 = 0xf;
  do {
    iVar7 = iVar16;
    if ((((*pcVar13 != *pcVar21) || (iVar7 = iVar16 + 1, pcVar13[1] != pcVar21[1])) ||
        (iVar7 = iVar16 + 2, pcVar13[2] != pcVar21[2])) ||
       (((iVar7 = iVar16 + 3, pcVar13[3] != pcVar21[3] ||
         (iVar7 = iVar16 + 4, pcVar13[4] != pcVar21[4])) ||
        ((iVar7 = iVar16 + 5, pcVar13[5] != pcVar21[5] ||
         ((iVar7 = iVar16 + 6, pcVar13[6] != pcVar21[6] ||
          (iVar7 = iVar16 + 7, pcVar13[7] != pcVar21[7])))))))) break;
    pcVar21 = pcVar21 + 8;
    pcVar13 = pcVar13 + 8;
    iVar16 = iVar16 + 8;
    iVar24 = iVar24 + -1;
    iVar7 = iVar16;
  } while (iVar24 != 0);
  if (iVar7 != 0x78) {
    FUN_80003494(0x803120d8,(uint)local_2c4,0x78);
    fVar4 = lbl_803E1280;
    if ((local_2c4[2] == '\0') && (local_290 == '\0')) {
      fVar4 = lbl_803E1284;
    }
    dVar25 = (double)fVar4;
    piVar10 = (int *)(**(code **)(*DAT_803dd71c + 0x10))(&local_2c8);
    FUN_800033a8(-0x7fc5dc70,0,0xb5);
    iVar16 = 8;
    puVar12 = &DAT_8039d748;
    do {
      puVar12[0x12] = 0;
      puVar12[0x2a] = 0;
      puVar12[0x42] = 0;
      puVar12[0x5a] = 0;
      puVar12[0x72] = 0;
      puVar12[0x8a] = 0;
      puVar12[0xa2] = 0;
      puVar12[0xba] = 0;
      puVar12[0xd2] = 0;
      puVar12[0xea] = 0;
      puVar12[0x102] = 0;
      puVar12[0x11a] = 0;
      puVar12[0x132] = 0;
      puVar12[0x14a] = 0;
      puVar12[0x162] = 0;
      puVar12[0x17a] = 0;
      puVar12[0x192] = 0;
      puVar12[0x1aa] = 0;
      puVar12[0x1c2] = 0;
      puVar12[0x1da] = 0;
      puVar12[0x1f2] = 0;
      puVar12[0x20a] = 0;
      puVar12[0x222] = 0;
      puVar12[0x23a] = 0;
      puVar12[0x252] = 0;
      puVar12[0x26a] = 0;
      puVar12[0x282] = 0;
      puVar12[0x29a] = 0;
      puVar12[0x2b2] = 0;
      puVar12[0x2ca] = 0;
      puVar12[0x2e2] = 0;
      puVar12[0x2fa] = 0;
      puVar12 = puVar12 + 0x300;
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    DAT_803de0e4 = 1;
    for (iVar16 = 0; iVar16 < local_2c8; iVar16 = iVar16 + 1) {
      iVar24 = *piVar10;
      if (*(char *)(iVar24 + 0x19) == '&') {
        uVar14 = (uint)*(byte *)(iVar24 + 3);
        iVar7 = uVar14 * 0x28;
        psVar22 = &DAT_803a0748 + uVar14 * 0x14;
        (&DAT_803a2390)[uVar14] = 1;
        local_e0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 4) ^ 0x80000000);
        dVar30 = (double)(float)((double)(float)(local_e0 - DOUBLE_803e1260) * dVar25 +
                                (double)*(float *)(iVar24 + 8));
        local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 5) ^ 0x80000000);
        dVar32 = (double)(float)((double)(float)(local_d8 - DOUBLE_803e1260) * dVar25 +
                                (double)*(float *)(iVar24 + 0x10));
        local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 6) ^ 0x80000000);
        dVar28 = (double)(float)((double)(float)(local_d0 - DOUBLE_803e1260) * dVar25 +
                                (double)*(float *)(iVar24 + 8));
        local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 7) ^ 0x80000000);
        dVar29 = (double)(float)((double)(float)(local_c8 - DOUBLE_803e1260) * dVar25 +
                                (double)*(float *)(iVar24 + 0x10));
        dVar31 = (double)(float)(dVar29 - dVar32);
        dVar27 = (double)(float)(dVar30 - dVar28);
        dVar26 = FUN_80293900((double)(float)(dVar31 * dVar31 + (double)(float)(dVar27 * dVar27)));
        if (dVar26 != (double)lbl_803E1270) {
          dVar31 = (double)(float)(dVar31 / dVar26);
          dVar27 = (double)(float)(dVar27 / dVar26);
        }
        dVar26 = (double)lbl_803E127C;
        iVar23 = (int)(dVar26 * dVar31);
        local_c8 = (double)(longlong)iVar23;
        *psVar22 = (short)iVar23;
        iVar23 = (int)(dVar26 * dVar27);
        local_d0 = (double)(longlong)iVar23;
        (&DAT_803a074a)[uVar14 * 0x14] = (short)iVar23;
        dVar26 = DOUBLE_803e1260;
        local_d8 = (double)CONCAT44(0x43300000,(int)*psVar22 ^ 0x80000000);
        local_e0 = (double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_803a074a)[uVar14 * 0x14] ^ 0x80000000);
        (&DAT_803a0758)[uVar14 * 10] =
             -(float)((double)(float)(local_d8 - DOUBLE_803e1260) * dVar30 +
                     (double)(float)((double)(float)(local_e0 - DOUBLE_803e1260) * dVar32));
        local_c0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x30) ^ 0x80000000);
        dVar30 = (double)(float)((double)(float)(local_c0 - dVar26) * dVar25 +
                                (double)*(float *)(iVar24 + 8));
        local_b8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x31) ^ 0x80000000);
        dVar32 = (double)(float)((double)(float)(local_b8 - dVar26) * dVar25 +
                                (double)*(float *)(iVar24 + 0x10));
        dVar27 = (double)(float)(dVar32 - dVar29);
        dVar31 = (double)(float)(dVar28 - dVar30);
        dVar26 = FUN_80293900((double)(float)(dVar27 * dVar27 + (double)(float)(dVar31 * dVar31)));
        if (dVar26 != (double)lbl_803E1270) {
          dVar27 = (double)(float)(dVar27 / dVar26);
          dVar31 = (double)(float)(dVar31 / dVar26);
        }
        dVar26 = (double)lbl_803E127C;
        iVar23 = (int)(dVar26 * dVar27);
        local_b8 = (double)(longlong)iVar23;
        *(short *)(&DAT_803a074c + iVar7) = (short)iVar23;
        iVar23 = (int)(dVar26 * dVar31);
        local_c0 = (double)(longlong)iVar23;
        *(short *)(&DAT_803a074e + iVar7) = (short)iVar23;
        dVar26 = DOUBLE_803e1260;
        local_c8 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_803a074c + iVar7) ^ 0x80000000);
        local_d0 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_803a074e + iVar7) ^ 0x80000000);
        *(float *)(&DAT_803a075c + iVar7) =
             -(float)((double)(float)(local_c8 - DOUBLE_803e1260) * dVar28 +
                     (double)(float)((double)(float)(local_d0 - DOUBLE_803e1260) * dVar29));
        local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x32) ^ 0x80000000);
        dVar29 = (double)(float)((double)(float)(local_d8 - dVar26) * dVar25 +
                                (double)*(float *)(iVar24 + 8));
        local_e0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x33) ^ 0x80000000);
        dVar28 = (double)(float)((double)(float)(local_e0 - dVar26) * dVar25 +
                                (double)*(float *)(iVar24 + 0x10));
        dVar27 = (double)(float)(dVar28 - dVar32);
        dVar31 = (double)(float)(dVar30 - dVar29);
        dVar26 = FUN_80293900((double)(float)(dVar27 * dVar27 + (double)(float)(dVar31 * dVar31)));
        if (dVar26 != (double)lbl_803E1270) {
          dVar27 = (double)(float)(dVar27 / dVar26);
          dVar31 = (double)(float)(dVar31 / dVar26);
        }
        dVar26 = (double)lbl_803E127C;
        iVar23 = (int)(dVar26 * dVar27);
        local_b8 = (double)(longlong)iVar23;
        *(short *)(&DAT_803a0750 + iVar7) = (short)iVar23;
        iVar23 = (int)(dVar26 * dVar31);
        local_c0 = (double)(longlong)iVar23;
        *(short *)(&DAT_803a0752 + iVar7) = (short)iVar23;
        dVar26 = DOUBLE_803e1260;
        local_c8 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_803a0750 + iVar7) ^ 0x80000000);
        local_d0 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_803a0752 + iVar7) ^ 0x80000000);
        *(float *)(&DAT_803a0760 + iVar7) =
             -(float)((double)(float)(local_c8 - DOUBLE_803e1260) * dVar30 +
                     (double)(float)((double)(float)(local_d0 - DOUBLE_803e1260) * dVar32));
        local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 5) ^ 0x80000000);
        dVar27 = (double)(float)((double)(float)((double)(float)(local_d8 - dVar26) * dVar25 +
                                                (double)*(float *)(iVar24 + 0x10)) - dVar28);
        local_e0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 4) ^ 0x80000000);
        dVar31 = (double)(float)(dVar29 - (double)(float)((double)(float)(local_e0 - dVar26) *
                                                          dVar25 + (double)*(float *)(iVar24 + 8)));
        dVar26 = FUN_80293900((double)(float)(dVar27 * dVar27 + (double)(float)(dVar31 * dVar31)));
        if (dVar26 != (double)lbl_803E1270) {
          dVar27 = (double)(float)(dVar27 / dVar26);
          dVar31 = (double)(float)(dVar31 / dVar26);
        }
        dVar26 = (double)lbl_803E127C;
        iVar23 = (int)(dVar26 * dVar27);
        local_b8 = (double)(longlong)iVar23;
        *(short *)(&DAT_803a0754 + iVar7) = (short)iVar23;
        iVar23 = (int)(dVar26 * dVar31);
        local_c0 = (double)(longlong)iVar23;
        *(short *)(&DAT_803a0756 + iVar7) = (short)iVar23;
        dVar26 = DOUBLE_803e1260;
        local_c8 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_803a0754 + iVar7) ^ 0x80000000);
        local_d0 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_803a0756 + iVar7) ^ 0x80000000);
        *(float *)(&DAT_803a0764 + iVar7) =
             -(float)((double)(float)(local_c8 - DOUBLE_803e1260) * dVar29 +
                     (double)(float)((double)(float)(local_d0 - DOUBLE_803e1260) * dVar28));
        fVar4 = lbl_803E1250;
        local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x18) ^ 0x80000000);
        iVar7 = (int)(lbl_803E1250 * (float)(local_d8 - dVar26) + *(float *)(iVar24 + 0xc));
        local_e0 = (double)(longlong)iVar7;
        (&DAT_803a0768)[uVar14 * 0x14] = (short)iVar7;
        local_b0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x1a) ^ 0x80000000);
        iVar7 = (int)-(fVar4 * (float)(local_b0 - dVar26) - *(float *)(iVar24 + 0xc));
        local_a8 = (double)(longlong)iVar7;
        (&DAT_803a076a)[uVar14 * 0x14] = (short)iVar7;
        iVar23 = 0;
        iVar7 = iVar24;
        do {
          iVar20 = iVar23 + 0x24;
          *(undefined *)((int)psVar22 + iVar20) = 0;
          if ((-1 < *(int *)(iVar7 + 0x1c)) &&
             (iVar11 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar11 != 0)) {
            bVar2 = *(byte *)(iVar24 + 3);
            bVar3 = *(byte *)(iVar11 + 3);
            if (bVar2 < bVar3) {
              sVar6 = CONCAT11(bVar3,bVar2);
            }
            else {
              sVar6 = CONCAT11(bVar2,bVar3);
            }
            cVar15 = '\x01';
            iVar8 = DAT_803de0e4 + -1;
            puVar12 = &DAT_8039d748;
            if (1 < DAT_803de0e4) {
              do {
                if (sVar6 == puVar12[0x2a]) {
                  *(char *)((int)psVar22 + iVar20) = cVar15;
                  break;
                }
                cVar15 = cVar15 + '\x01';
                iVar8 = iVar8 + -1;
                puVar12 = puVar12 + 0x18;
              } while (iVar8 != 0);
            }
            iVar8 = DAT_803de0e4;
            if (*(char *)((int)psVar22 + iVar20) == '\0') {
              iVar18 = 0;
              iVar9 = *(int *)(iVar24 + 0x14);
              if ((((*(int *)(iVar11 + 0x1c) != iVar9) &&
                   (iVar18 = 1, *(int *)(iVar11 + 0x20) != iVar9)) &&
                  (iVar18 = 2, *(int *)(iVar11 + 0x24) != iVar9)) &&
                 (iVar18 = 3, *(int *)(iVar11 + 0x28) != iVar9)) {
                iVar18 = 4;
              }
              *(char *)((int)psVar22 + iVar20) = (char)DAT_803de0e4;
              (&DAT_8039d76c)[iVar8 * 0x18] = sVar6;
              fVar4 = lbl_803E1288;
              abStack_24c[iVar8 * 2] = *(byte *)(iVar24 + 3);
              abStack_24c[iVar8 * 2 + 1] = *(byte *)(iVar11 + 3);
              local_a8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x34) ^ 0x80000000);
              dVar29 = (double)(float)((double)(float)(local_a8 - DOUBLE_803e1260) * dVar25 +
                                      (double)*(float *)(iVar24 + 8));
              local_b0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x35) ^ 0x80000000);
              dVar28 = (double)(float)((double)(float)(local_b0 - DOUBLE_803e1260) * dVar25 +
                                      (double)*(float *)(iVar24 + 0x10));
              local_b8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x36) ^ 0x80000000);
              dVar30 = (double)(float)((double)(float)(local_b8 - DOUBLE_803e1260) * dVar25 +
                                      (double)*(float *)(iVar24 + 8));
              local_c0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x37) ^ 0x80000000);
              dVar32 = (double)(float)((double)(float)(local_c0 - DOUBLE_803e1260) * dVar25 +
                                      (double)*(float *)(iVar24 + 0x10));
              iVar20 = (int)((float)(dVar29 + dVar30) * lbl_803E1288);
              local_c8 = (double)(longlong)iVar20;
              (&DAT_8039d76e)[iVar8 * 0x18] = (short)iVar20;
              iVar20 = (int)((float)(dVar28 + dVar32) * fVar4);
              local_d0 = (double)(longlong)iVar20;
              (&DAT_8039d770)[iVar8 * 0x18] = (short)iVar20;
              dVar27 = (double)(float)(dVar32 - dVar28);
              dVar31 = (double)(float)(dVar29 - dVar30);
              dVar26 = FUN_80293900((double)(float)(dVar27 * dVar27 +
                                                   (double)(float)(dVar31 * dVar31)));
              if (dVar26 != (double)lbl_803E1270) {
                dVar27 = (double)(float)(dVar27 / dVar26);
                dVar31 = (double)(float)(dVar31 / dVar26);
              }
              dVar26 = (double)lbl_803E127C;
              iVar20 = (int)(dVar26 * dVar27);
              local_a8 = (double)(longlong)iVar20;
              (&DAT_8039d748)[iVar8 * 0x18] = (short)iVar20;
              iVar20 = (int)(dVar26 * dVar31);
              local_b0 = (double)(longlong)iVar20;
              (&DAT_8039d74a)[iVar8 * 0x18] = (short)iVar20;
              dVar26 = DOUBLE_803e1260;
              local_b8 = (double)CONCAT44(0x43300000,
                                          (int)(short)(&DAT_8039d748)[iVar8 * 0x18] ^ 0x80000000);
              local_c0 = (double)CONCAT44(0x43300000,
                                          (int)(short)(&DAT_8039d74a)[iVar8 * 0x18] ^ 0x80000000);
              (&DAT_8039d758)[iVar8 * 0xc] =
                   -(float)((double)(float)(local_b8 - DOUBLE_803e1260) * dVar29 +
                           (double)(float)((double)(float)(local_c0 - DOUBLE_803e1260) * dVar28));
              iVar8 = iVar11 + iVar18 * 4;
              local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar8 + 0x34) ^ 0x80000000);
              dVar29 = (double)(float)((double)(float)(local_c8 - dVar26) * dVar25 +
                                      (double)*(float *)(iVar11 + 8));
              local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar8 + 0x35) ^ 0x80000000);
              dVar28 = (double)(float)((double)(float)(local_d0 - dVar26) * dVar25 +
                                      (double)*(float *)(iVar11 + 0x10));
              iVar20 = DAT_803de0e4 * 0x30;
              dVar27 = (double)(float)(dVar28 - dVar32);
              dVar31 = (double)(float)(dVar30 - dVar29);
              dVar26 = FUN_80293900((double)(float)(dVar27 * dVar27 +
                                                   (double)(float)(dVar31 * dVar31)));
              if (dVar26 != (double)lbl_803E1270) {
                dVar27 = (double)(float)(dVar27 / dVar26);
                dVar31 = (double)(float)(dVar31 / dVar26);
              }
              dVar26 = (double)lbl_803E127C;
              iVar9 = (int)(dVar26 * dVar27);
              local_a8 = (double)(longlong)iVar9;
              *(short *)(iVar20 + -0x7fc628b4) = (short)iVar9;
              iVar9 = (int)(dVar26 * dVar31);
              local_b0 = (double)(longlong)iVar9;
              *(short *)(iVar20 + -0x7fc628b2) = (short)iVar9;
              dVar26 = DOUBLE_803e1260;
              local_b8 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(iVar20 + -0x7fc628b4) ^ 0x80000000);
              local_c0 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(iVar20 + -0x7fc628b2) ^ 0x80000000);
              *(float *)(iVar20 + -0x7fc628a4) =
                   -(float)((double)(float)(local_b8 - DOUBLE_803e1260) * dVar30 +
                           (double)(float)((double)(float)(local_c0 - DOUBLE_803e1260) * dVar32));
              fVar4 = lbl_803E1288;
              iVar9 = DAT_803de0e4;
              local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar8 + 0x36) ^ 0x80000000);
              dVar30 = (double)(float)((double)(float)(local_c8 - dVar26) * dVar25 +
                                      (double)*(float *)(iVar11 + 8));
              local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar8 + 0x37) ^ 0x80000000);
              dVar32 = (double)(float)((double)(float)(local_d0 - dVar26) * dVar25 +
                                      (double)*(float *)(iVar11 + 0x10));
              iVar20 = (int)((float)(dVar29 + dVar30) * lbl_803E1288);
              local_d8 = (double)(longlong)iVar20;
              iVar8 = DAT_803de0e4 * 0x30;
              (&DAT_8039d772)[DAT_803de0e4 * 0x18] = (short)iVar20;
              iVar20 = (int)((float)(dVar28 + dVar32) * fVar4);
              local_e0 = (double)(longlong)iVar20;
              (&DAT_8039d774)[iVar9 * 0x18] = (short)iVar20;
              dVar27 = (double)(float)(dVar32 - dVar28);
              dVar31 = (double)(float)(dVar29 - dVar30);
              dVar26 = FUN_80293900((double)(float)(dVar27 * dVar27 +
                                                   (double)(float)(dVar31 * dVar31)));
              if (dVar26 != (double)lbl_803E1270) {
                dVar27 = (double)(float)(dVar27 / dVar26);
                dVar31 = (double)(float)(dVar31 / dVar26);
              }
              dVar26 = (double)lbl_803E127C;
              iVar20 = (int)(dVar26 * dVar27);
              local_a8 = (double)(longlong)iVar20;
              *(short *)(iVar8 + -0x7fc628b0) = (short)iVar20;
              iVar20 = (int)(dVar26 * dVar31);
              local_b0 = (double)(longlong)iVar20;
              *(short *)(iVar8 + -0x7fc628ae) = (short)iVar20;
              dVar26 = DOUBLE_803e1260;
              local_b8 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(iVar8 + -0x7fc628b0) ^ 0x80000000);
              local_c0 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(iVar8 + -0x7fc628ae) ^ 0x80000000);
              *(float *)(iVar8 + -0x7fc628a0) =
                   -(float)((double)(float)(local_b8 - DOUBLE_803e1260) * dVar29 +
                           (double)(float)((double)(float)(local_c0 - DOUBLE_803e1260) * dVar28));
              iVar20 = DAT_803de0e4 * 0x30;
              local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x35) ^ 0x80000000);
              dVar27 = (double)(float)((double)(float)((double)(float)(local_c8 - dVar26) * dVar25 +
                                                      (double)*(float *)(iVar24 + 0x10)) - dVar32);
              local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x34) ^ 0x80000000);
              dVar31 = (double)(float)(dVar30 - (double)(float)((double)(float)(local_d0 - dVar26) *
                                                                dVar25 + (double)*(float *)(iVar24 +
                                                                                           8)));
              dVar26 = FUN_80293900((double)(float)(dVar27 * dVar27 +
                                                   (double)(float)(dVar31 * dVar31)));
              if (dVar26 != (double)lbl_803E1270) {
                dVar27 = (double)(float)(dVar27 / dVar26);
                dVar31 = (double)(float)(dVar31 / dVar26);
              }
              dVar26 = (double)lbl_803E127C;
              *(short *)(iVar20 + -0x7fc628ac) = (short)(int)(dVar26 * dVar27);
              *(short *)(iVar20 + -0x7fc628aa) = (short)(int)(dVar26 * dVar31);
              dVar26 = DOUBLE_803e1260;
              local_b8 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(iVar20 + -0x7fc628ac) ^ 0x80000000);
              local_c0 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(iVar20 + -0x7fc628aa) ^ 0x80000000);
              *(float *)(iVar20 + -0x7fc6289c) =
                   -(float)((double)(float)(local_b8 - DOUBLE_803e1260) * dVar30 +
                           (double)(float)((double)(float)(local_c0 - DOUBLE_803e1260) * dVar32));
              local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x18) ^ 0x80000000);
              fVar5 = lbl_803E1250 * (float)(local_c8 - dVar26) + *(float *)(iVar24 + 0xc);
              local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x18) ^ 0x80000000);
              fVar4 = lbl_803E1250 * (float)(local_d0 - dVar26) + *(float *)(iVar11 + 0xc);
              if (fVar5 <= fVar4) {
                (&DAT_8039d768)[DAT_803de0e4 * 0x18] = (short)(int)fVar4;
              }
              else {
                (&DAT_8039d768)[DAT_803de0e4 * 0x18] = (short)(int)fVar5;
              }
              local_a8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x1a) ^ 0x80000000);
              fVar4 = -(lbl_803E1250 * (float)(local_a8 - DOUBLE_803e1260) -
                       *(float *)(iVar24 + 0xc));
              local_b0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x1a) ^ 0x80000000);
              fVar5 = -(lbl_803E1250 * (float)(local_b0 - DOUBLE_803e1260) -
                       *(float *)(iVar11 + 0xc));
              if (fVar5 <= fVar4) {
                iVar20 = (int)fVar5;
                local_a8 = (double)(longlong)iVar20;
                (&DAT_8039d76a)[DAT_803de0e4 * 0x18] = (short)iVar20;
              }
              else {
                iVar20 = (int)fVar4;
                local_a8 = (double)(longlong)iVar20;
                (&DAT_8039d76a)[DAT_803de0e4 * 0x18] = (short)iVar20;
              }
              DAT_803de0e4 = DAT_803de0e4 + 1;
            }
          }
          iVar7 = iVar7 + 4;
          iVar23 = iVar23 + 1;
        } while (iVar23 < 4);
      }
      piVar10 = piVar10 + 1;
    }
    pbVar19 = abStack_24c;
    dVar26 = (double)lbl_803E1270;
    dVar31 = (double)lbl_803E128C;
    dVar25 = DOUBLE_803e1260;
    puVar12 = &DAT_8039d748;
    for (iVar16 = 1; pbVar19 = pbVar19 + 2, iVar16 < DAT_803de0e4; iVar16 = iVar16 + 1) {
      bVar2 = *pbVar19;
      bVar3 = pbVar19[1];
      local_a8 = (double)CONCAT44(0x43300000,
                                  (int)(short)puVar12[0x2d] - (int)(short)puVar12[0x2b] ^ 0x80000000
                                 );
      dVar27 = (double)(float)(local_a8 - dVar25);
      local_b0 = (double)CONCAT44(0x43300000,
                                  (int)(short)puVar12[0x2e] - (int)(short)puVar12[0x2c] ^ 0x80000000
                                 );
      dVar29 = (double)(float)(local_b0 - dVar25);
      iVar24 = 0;
      do {
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2c] ^ 0x80000000);
        dVar28 = local_a8 - dVar25;
        local_b0 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2b] ^ 0x80000000);
        dVar30 = local_b0 - dVar25;
        uVar14 = 0;
        for (bVar17 = 0; bVar17 < 4; bVar17 = bVar17 + 1) {
          local_a8 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar2 * 0x14 + (uVar14 & 0xff)] ^
                                      0x80000000);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar2 * 0x14 + (uVar14 & 0xff) + 1] ^
                                      0x80000000);
          if (dVar26 < (double)(*(float *)(&DAT_803a0748 + (uint)bVar2 * 0x14 + (uint)bVar17 * 2 + 8
                                          ) +
                               (float)dVar30 * (float)(local_a8 - dVar25) +
                               (float)dVar28 * (float)(local_b0 - dVar25))) break;
          uVar14 = uVar14 + 2;
        }
        if (bVar17 == 4) goto LAB_800dd65c;
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2c] ^ 0x80000000);
        dVar28 = local_a8 - dVar25;
        local_b0 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2b] ^ 0x80000000);
        dVar30 = local_b0 - dVar25;
        uVar14 = 0;
        for (bVar17 = 0; bVar17 < 4; bVar17 = bVar17 + 1) {
          local_a8 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar3 * 0x14 + (uVar14 & 0xff)] ^
                                      0x80000000);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar3 * 0x14 + (uVar14 & 0xff) + 1] ^
                                      0x80000000);
          if (dVar26 < (double)(*(float *)(&DAT_803a0748 + (uint)bVar3 * 0x14 + (uint)bVar17 * 2 + 8
                                          ) +
                               (float)dVar30 * (float)(local_a8 - dVar25) +
                               (float)dVar28 * (float)(local_b0 - dVar25))) break;
          uVar14 = uVar14 + 2;
        }
        if (bVar17 == 4) goto LAB_800dd65c;
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2b] ^ 0x80000000);
        iVar7 = (int)((float)(local_a8 - dVar25) + (float)(dVar27 / dVar31));
        local_b0 = (double)(longlong)iVar7;
        puVar12[0x2b] = (short)iVar7;
        local_b8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2c] ^ 0x80000000);
        iVar7 = (int)((float)(local_b8 - dVar25) + (float)(dVar29 / dVar31));
        local_c0 = (double)(longlong)iVar7;
        puVar12[0x2c] = (short)iVar7;
        bVar1 = iVar24 != 100;
        iVar24 = iVar24 + 1;
      } while (bVar1);
      FUN_800723a0();
LAB_800dd65c:
      iVar24 = 0;
      do {
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2e] ^ 0x80000000);
        dVar28 = local_a8 - dVar25;
        local_b0 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2d] ^ 0x80000000);
        dVar30 = local_b0 - dVar25;
        uVar14 = 0;
        for (bVar17 = 0; bVar17 < 4; bVar17 = bVar17 + 1) {
          local_a8 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar2 * 0x14 + (uVar14 & 0xff)] ^
                                      0x80000000);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar2 * 0x14 + (uVar14 & 0xff) + 1] ^
                                      0x80000000);
          if (dVar26 < (double)(*(float *)(&DAT_803a0748 + (uint)bVar2 * 0x14 + (uint)bVar17 * 2 + 8
                                          ) +
                               (float)dVar30 * (float)(local_a8 - dVar25) +
                               (float)dVar28 * (float)(local_b0 - dVar25))) break;
          uVar14 = uVar14 + 2;
        }
        if (bVar17 == 4) goto LAB_800dd85c;
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2e] ^ 0x80000000);
        dVar28 = local_a8 - dVar25;
        local_b0 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2d] ^ 0x80000000);
        dVar30 = local_b0 - dVar25;
        uVar14 = 0;
        for (bVar17 = 0; bVar17 < 4; bVar17 = bVar17 + 1) {
          local_a8 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar3 * 0x14 + (uVar14 & 0xff)] ^
                                      0x80000000);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar3 * 0x14 + (uVar14 & 0xff) + 1] ^
                                      0x80000000);
          if (dVar26 < (double)(*(float *)(&DAT_803a0748 + (uint)bVar3 * 0x14 + (uint)bVar17 * 2 + 8
                                          ) +
                               (float)dVar30 * (float)(local_a8 - dVar25) +
                               (float)dVar28 * (float)(local_b0 - dVar25))) break;
          uVar14 = uVar14 + 2;
        }
        if (bVar17 == 4) goto LAB_800dd85c;
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2d] ^ 0x80000000);
        iVar7 = (int)((float)(local_a8 - dVar25) - (float)(dVar27 / dVar31));
        local_b0 = (double)(longlong)iVar7;
        puVar12[0x2d] = (short)iVar7;
        local_b8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2e] ^ 0x80000000);
        iVar7 = (int)((float)(local_b8 - dVar25) - (float)(dVar29 / dVar31));
        local_c0 = (double)(longlong)iVar7;
        puVar12[0x2e] = (short)iVar7;
        bVar1 = iVar24 != 100;
        iVar24 = iVar24 + 1;
      } while (bVar1);
      FUN_800723a0();
LAB_800dd85c:
      puVar12 = puVar12 + 0x18;
    }
  }
  FUN_80286870();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800dd3dc
 * EN v1.0 Address: 0x800DD3DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800DD8C4
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800dd3dc(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800dd3e0
 * EN v1.0 Address: 0x800DD3E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800DD8C8
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800dd3e0(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800dd3e4
 * EN v1.0 Address: 0x800DD3E4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DD8CC
 * EN v1.1 Size: 2208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800dd3e4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9,undefined4 param_10,uint param_11)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800dd3ec
 * EN v1.0 Address: 0x800DD3EC
 * EN v1.0 Size: 288b
 * EN v1.1 Address: 0x800DE16C
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800dd3ec(int param_1,int param_2,uint param_3)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int local_18 [6];
  
  iVar3 = 0;
  iVar1 = *(int *)(param_1 + 0x1c);
  if (((-1 < iVar1) && ((*(byte *)(param_1 + 0x1b) & 1) != 0)) && (iVar1 != param_2)) {
    iVar3 = 1;
    local_18[0] = iVar1;
  }
  iVar2 = *(int *)(param_1 + 0x20);
  iVar1 = iVar3;
  if (((-1 < iVar2) && ((*(byte *)(param_1 + 0x1b) & 2) != 0)) && (iVar2 != param_2)) {
    iVar1 = iVar3 + 1;
    local_18[iVar3] = iVar2;
  }
  iVar2 = *(int *)(param_1 + 0x24);
  iVar3 = iVar1;
  if (((-1 < iVar2) && ((*(byte *)(param_1 + 0x1b) & 4) != 0)) && (iVar2 != param_2)) {
    iVar3 = iVar1 + 1;
    local_18[iVar1] = iVar2;
  }
  iVar2 = *(int *)(param_1 + 0x28);
  iVar1 = iVar3;
  if (((-1 < iVar2) && ((*(byte *)(param_1 + 0x1b) & 8) != 0)) && (iVar2 != param_2)) {
    iVar1 = iVar3 + 1;
    local_18[iVar3] = iVar2;
  }
  if (iVar1 == 0) {
    iVar1 = -1;
  }
  else {
    if ((int)(iVar1 - 1U) < (int)param_3) {
      param_3 = iVar1 - 1U;
    }
    if (param_3 == 0xffffffff) {
      param_3 = FUN_80017760(0,iVar1 - 1);
    }
    iVar1 = local_18[param_3];
  }
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_800dd50c
 * EN v1.0 Address: 0x800DD50C
 * EN v1.0 Size: 288b
 * EN v1.1 Address: 0x800DE2C4
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800dd50c(int param_1,int param_2,uint param_3)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int local_18 [6];
  
  iVar3 = 0;
  iVar1 = *(int *)(param_1 + 0x1c);
  if (((-1 < iVar1) && ((*(byte *)(param_1 + 0x1b) & 1) == 0)) && (iVar1 != param_2)) {
    iVar3 = 1;
    local_18[0] = iVar1;
  }
  iVar2 = *(int *)(param_1 + 0x20);
  iVar1 = iVar3;
  if (((-1 < iVar2) && ((*(byte *)(param_1 + 0x1b) & 2) == 0)) && (iVar2 != param_2)) {
    iVar1 = iVar3 + 1;
    local_18[iVar3] = iVar2;
  }
  iVar2 = *(int *)(param_1 + 0x24);
  iVar3 = iVar1;
  if (((-1 < iVar2) && ((*(byte *)(param_1 + 0x1b) & 4) == 0)) && (iVar2 != param_2)) {
    iVar3 = iVar1 + 1;
    local_18[iVar1] = iVar2;
  }
  iVar2 = *(int *)(param_1 + 0x28);
  iVar1 = iVar3;
  if (((-1 < iVar2) && ((*(byte *)(param_1 + 0x1b) & 8) == 0)) && (iVar2 != param_2)) {
    iVar1 = iVar3 + 1;
    local_18[iVar3] = iVar2;
  }
  if (iVar1 == 0) {
    iVar1 = -1;
  }
  else {
    if ((int)(iVar1 - 1U) < (int)param_3) {
      param_3 = iVar1 - 1U;
    }
    if (param_3 == 0xffffffff) {
      param_3 = FUN_80017760(0,iVar1 - 1);
    }
    iVar1 = local_18[param_3];
  }
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_800dd62c
 * EN v1.0 Address: 0x800DD62C
 * EN v1.0 Size: 2048b
 * EN v1.1 Address: 0x800DE41C
 * EN v1.1 Size: 1880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800dd62c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9,uint param_10,undefined4 param_11,int param_12,int param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  undefined4 uVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  
  if (((param_9 != (float *)0x0) && (param_9[0x28] != 0.0)) && (param_9[0x29] != 0.0)) {
    param_9[0x27] = param_9[0x28];
    param_9[0x28] = param_9[0x29];
    FUN_80003494((uint)(param_9 + 0x2a),(uint)(param_9 + 0x2e),0x10);
    FUN_80003494((uint)(param_9 + 0x32),(uint)(param_9 + 0x36),0x10);
    FUN_80003494((uint)(param_9 + 0x3a),(uint)(param_9 + 0x3e),0x10);
    if (param_9[0x20] == 0.0) {
      uVar1 = FUN_800dd50c((int)param_9[0x28],-1,param_10);
    }
    else {
      uVar1 = FUN_800dd3ec((int)param_9[0x28],-1,param_10);
    }
    if (uVar1 == 0xffffffff) {
      param_9[0x29] = 0.0;
    }
    else {
      if ((int)uVar1 < 0) {
        fVar3 = 0.0;
      }
      else {
        param_13 = DAT_803de0f0 + -1;
        param_12 = 0;
        while (param_12 <= param_13) {
          param_10 = param_13 + param_12 >> 1;
          fVar3 = (float)(&DAT_803a2448)[param_10];
          if (*(uint *)((int)fVar3 + 0x14) < uVar1) {
            param_12 = param_10 + 1;
          }
          else {
            if (*(uint *)((int)fVar3 + 0x14) <= uVar1) goto LAB_800de544;
            param_13 = param_10 - 1;
          }
        }
        fVar3 = 0.0;
      }
LAB_800de544:
      param_9[0x29] = fVar3;
      if (param_9[0x29] != 0.0) {
        if (param_9[0x20] == 0.0) {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x29] + 8);
          dVar4 = (double)FUN_80293f90();
          param_9[0x30] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar4 = (double)FUN_80293f90();
          param_9[0x31] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x29] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x29] + 0xc);
          dVar4 = (double)FUN_80293f90();
          param_9[0x38] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar4 = (double)FUN_80293f90();
          param_9[0x39] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x29] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x29] + 0x10);
          dVar4 = (double)FUN_80294964();
          param_9[0x40] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar5 = (double)FUN_80294964();
          dVar4 = DOUBLE_803e12a8;
          dVar5 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                   (uint)*(byte *)((int)param_9[0x29
                                                  ] + 0x2e)) - DOUBLE_803e12a8) * dVar5);
          param_9[0x41] = (float)((double)lbl_803E1290 * dVar5);
          uVar2 = extraout_r4_00;
        }
        else {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x27] + 8);
          dVar4 = (double)FUN_80293f90();
          param_9[0x30] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar4 = (double)FUN_80293f90();
          param_9[0x31] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x27] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x27] + 0xc);
          dVar4 = (double)FUN_80293f90();
          param_9[0x38] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar4 = (double)FUN_80293f90();
          param_9[0x39] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x27] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x27] + 0x10);
          dVar4 = (double)FUN_80294964();
          param_9[0x40] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar5 = (double)FUN_80294964();
          dVar4 = DOUBLE_803e12a8;
          dVar5 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                   (uint)*(byte *)((int)param_9[0x27
                                                  ] + 0x2e)) - DOUBLE_803e12a8) * dVar5);
          param_9[0x41] = (float)((double)lbl_803E1290 * dVar5);
          uVar2 = extraout_r4;
        }
        if (param_9[0x24] != 0.0) {
          FUN_80006a18(dVar5,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                       uVar2,param_10,param_12,param_13,fVar3,param_15,param_16);
        }
        if (param_9[0x20] == 0.0) {
          FUN_80006a10((double)lbl_803E12B4,param_9);
        }
        else {
          FUN_80006a10((double)lbl_803E12B0,param_9);
        }
        return 0;
      }
    }
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_800dde2c
 * EN v1.0 Address: 0x800DDE2C
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x800DEB74
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800dde2c(int param_1,int param_2)
{
  double dVar1;
  
  if ((param_2 != 0) && (param_2 != *(int *)(param_1 + 0xa4))) {
    *(int *)(param_1 + 0xa4) = param_2;
    *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 8);
    dVar1 = (double)FUN_80293f90();
    *(float *)(param_1 + 0xc4) =
         lbl_803E1290 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e12a8) * dVar1);
    *(undefined4 *)(param_1 + 0xdc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0xc);
    dVar1 = (double)FUN_80293f90();
    *(float *)(param_1 + 0xe4) =
         lbl_803E1290 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e12a8) * dVar1);
    *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0x10);
    dVar1 = (double)FUN_80294964();
    *(float *)(param_1 + 0x104) =
         lbl_803E1290 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e12a8) * dVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ddf84
 * EN v1.0 Address: 0x800DDF84
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DED20
 * EN v1.1 Size: 956b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800ddf84(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9,float param_10,undefined4 param_11,undefined4 param_12,
            undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800ddf8c
 * EN v1.0 Address: 0x800DDF8C
 * EN v1.0 Size: 2572b
 * EN v1.1 Address: 0x800DF0DC
 * EN v1.1 Size: 2428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800ddf8c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9)
{
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  float fVar4;
  uint uVar5;
  float fVar6;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar7;
  double dVar8;
  uint local_88 [4];
  uint local_78 [4];
  undefined4 local_68;
  uint uStack_64;
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
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;
  
  if (((param_9 != (float *)0x0) && (param_9[0x28] != 0.0)) && (param_9[0x29] != 0.0)) {
    param_9[0x27] = param_9[0x28];
    param_9[0x28] = param_9[0x29];
    FUN_80003494((uint)(param_9 + 0x2a),(uint)(param_9 + 0x2e),0x10);
    FUN_80003494((uint)(param_9 + 0x32),(uint)(param_9 + 0x36),0x10);
    FUN_80003494((uint)(param_9 + 0x3a),(uint)(param_9 + 0x3e),0x10);
    if (param_9[0x20] == 0.0) {
      fVar4 = param_9[0x28];
      iVar2 = 0;
      uVar5 = *(uint *)((int)fVar4 + 0x1c);
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 1) == 0)) && (uVar5 != 0xffffffff))
      {
        iVar2 = 1;
        local_88[0] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x20);
      iVar3 = iVar2;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 2) == 0)) && (uVar5 != 0xffffffff))
      {
        iVar3 = iVar2 + 1;
        local_88[iVar2] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x24);
      iVar2 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 4) == 0)) && (uVar5 != 0xffffffff))
      {
        iVar2 = iVar3 + 1;
        local_88[iVar3] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x28);
      iVar3 = iVar2;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 8) == 0)) && (uVar5 != 0xffffffff))
      {
        iVar3 = iVar2 + 1;
        local_88[iVar2] = uVar5;
      }
      if (iVar3 == 0) {
        uVar5 = 0xffffffff;
      }
      else {
        uVar5 = FUN_80017760(0,iVar3 - 1);
        uVar5 = local_88[uVar5];
      }
    }
    else {
      fVar4 = param_9[0x28];
      iVar2 = 0;
      uVar5 = *(uint *)((int)fVar4 + 0x1c);
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 1) != 0)) && (uVar5 != 0xffffffff))
      {
        iVar2 = 1;
        local_78[0] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x20);
      iVar3 = iVar2;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 2) != 0)) && (uVar5 != 0xffffffff))
      {
        iVar3 = iVar2 + 1;
        local_78[iVar2] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x24);
      iVar2 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 4) != 0)) && (uVar5 != 0xffffffff))
      {
        iVar2 = iVar3 + 1;
        local_78[iVar3] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x28);
      iVar3 = iVar2;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 8) != 0)) && (uVar5 != 0xffffffff))
      {
        iVar3 = iVar2 + 1;
        local_78[iVar2] = uVar5;
      }
      if (iVar3 == 0) {
        uVar5 = 0xffffffff;
      }
      else {
        uVar5 = FUN_80017760(0,iVar3 - 1);
        uVar5 = local_78[uVar5];
      }
    }
    if (uVar5 == 0xffffffff) {
      param_9[0x29] = 0.0;
    }
    else {
      if ((int)uVar5 < 0) {
        fVar6 = 0.0;
      }
      else {
        fVar4 = (float)(DAT_803de0f0 + -1);
        iVar3 = 0;
        while (iVar3 <= (int)fVar4) {
          iVar2 = (int)fVar4 + iVar3 >> 1;
          fVar6 = (float)(&DAT_803a2448)[iVar2];
          if (*(uint *)((int)fVar6 + 0x14) < uVar5) {
            iVar3 = iVar2 + 1;
          }
          else {
            if (*(uint *)((int)fVar6 + 0x14) <= uVar5) goto LAB_800df42c;
            fVar4 = (float)(iVar2 + -1);
          }
        }
        fVar6 = 0.0;
      }
LAB_800df42c:
      param_9[0x29] = fVar6;
      if (param_9[0x29] != 0.0) {
        if (param_9[0x20] == 0.0) {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x29] + 8);
          uStack_c = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
          local_10 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_14 = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_18 = 0x43300000;
          param_9[0x30] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_1c = (int)*(char *)((int)param_9[0x29] + 0x2c) << 8 ^ 0x80000000;
          local_20 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_24 = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
          local_28 = 0x43300000;
          param_9[0x31] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e12a8) *
                      dVar7);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x29] + 0xc);
          uStack_2c = (int)*(char *)((int)param_9[0x28] + 0x2d) << 8 ^ 0x80000000;
          local_30 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_34 = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_38 = 0x43300000;
          param_9[0x38] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_3c = (int)*(char *)((int)param_9[0x29] + 0x2d) << 8 ^ 0x80000000;
          local_40 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_44 = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
          local_48 = 0x43300000;
          param_9[0x39] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e12a8) *
                      dVar7);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x29] + 0x10);
          uStack_4c = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
          local_50 = 0x43300000;
          dVar7 = (double)FUN_80294964();
          uStack_54 = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_58 = 0x43300000;
          param_9[0x40] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_5c = (int)*(char *)((int)param_9[0x29] + 0x2c) << 8 ^ 0x80000000;
          local_60 = 0x43300000;
          dVar8 = (double)FUN_80294964();
          dVar7 = DOUBLE_803e12a8;
          uStack_64 = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
          local_68 = 0x43300000;
          dVar8 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_64) -
                                                 DOUBLE_803e12a8) * dVar8);
          param_9[0x41] = (float)((double)lbl_803E1290 * dVar8);
          uVar1 = extraout_r4_00;
        }
        else {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x27] + 8);
          uStack_64 = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
          local_68 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_5c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_60 = 0x43300000;
          param_9[0x30] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_54 = (int)*(char *)((int)param_9[0x27] + 0x2c) << 8 ^ 0x80000000;
          local_58 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_4c = (uint)*(byte *)((int)param_9[0x27] + 0x2e);
          local_50 = 0x43300000;
          param_9[0x31] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e12a8) *
                      dVar7);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x27] + 0xc);
          uStack_44 = (int)*(char *)((int)param_9[0x28] + 0x2d) << 8 ^ 0x80000000;
          local_48 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_3c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_40 = 0x43300000;
          param_9[0x38] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_34 = (int)*(char *)((int)param_9[0x27] + 0x2d) << 8 ^ 0x80000000;
          local_38 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_2c = (uint)*(byte *)((int)param_9[0x27] + 0x2e);
          local_30 = 0x43300000;
          param_9[0x39] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e12a8) *
                      dVar7);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x27] + 0x10);
          uStack_24 = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
          local_28 = 0x43300000;
          dVar7 = (double)FUN_80294964();
          uStack_1c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_20 = 0x43300000;
          param_9[0x40] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_14 = (int)*(char *)((int)param_9[0x27] + 0x2c) << 8 ^ 0x80000000;
          local_18 = 0x43300000;
          dVar8 = (double)FUN_80294964();
          dVar7 = DOUBLE_803e12a8;
          uStack_c = (uint)*(byte *)((int)param_9[0x27] + 0x2e);
          local_10 = 0x43300000;
          dVar8 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_c) -
                                                 DOUBLE_803e12a8) * dVar8);
          param_9[0x41] = (float)((double)lbl_803E1290 * dVar8);
          uVar1 = extraout_r4;
        }
        if (param_9[0x24] != 0.0) {
          FUN_80006a18(dVar8,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                       uVar1,iVar3,fVar4,fVar6,uVar5,in_r9,in_r10);
        }
        if (param_9[0x20] == 0.0) {
          FUN_80006a10((double)lbl_803E12B4,param_9);
        }
        else {
          FUN_80006a10((double)lbl_803E12B0,param_9);
        }
        return 0;
      }
    }
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_800de998
 * EN v1.0 Address: 0x800DE998
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DFA58
 * EN v1.1 Size: 2400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800de998(double param_1,undefined8 param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,float *param_9,int param_10,
            undefined4 param_11,int param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800de9a0
 * EN v1.0 Address: 0x800DE9A0
 * EN v1.0 Size: 832b
 * EN v1.1 Address: 0x800E03B8
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800de9a0(undefined4 param_1,undefined4 param_2,int param_3,int param_4,char param_5)
{
  float fVar1;
  int *piVar2;
  char cVar4;
  int iVar3;
  int iVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  double dVar9;
  undefined8 uVar10;
  double dVar11;
  double dVar12;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar13;
  double dVar14;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar15;
  char local_d0 [4];
  short asStack_cc [4];
  short asStack_c4 [4];
  float local_bc;
  float local_b8;
  int local_b4;
  int aiStack_b0 [34];
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
  uVar15 = FUN_8028682c();
  piVar2 = (int *)((ulonglong)uVar15 >> 0x20);
  dVar13 = (double)lbl_803E12BC;
  local_bc = (float)piVar2[3];
  local_b8 = lbl_803E12C0 + (float)piVar2[4];
  local_b4 = piVar2[5];
  dVar14 = dVar13;
  FUN_80006a68(&local_bc,asStack_cc);
  piVar8 = &DAT_803a2448;
  for (iVar7 = 0; iVar7 < DAT_803de0f0; iVar7 = iVar7 + 1) {
    iVar6 = *piVar8;
    iVar5 = 0;
    do {
      if (((int)*(char *)(iVar6 + 0x19) == *(int *)((int)uVar15 + iVar5 * 4)) || (param_3 < 1)) {
        dVar11 = (double)(*(float *)(iVar6 + 8) - (float)piVar2[3]);
        dVar12 = (double)(*(float *)(iVar6 + 0xc) - (float)piVar2[4]);
        fVar1 = *(float *)(iVar6 + 0x10) - (float)piVar2[5];
        dVar9 = FUN_80293900((double)(fVar1 * fVar1 +
                                     (float)(dVar11 * dVar11 + (double)(float)(dVar12 * dVar12))));
        if (dVar9 < dVar14) {
          local_bc = *(float *)(iVar6 + 8);
          local_b8 = lbl_803E12C0 + *(float *)(iVar6 + 0xc);
          local_b4 = *(int *)(iVar6 + 0x10);
          uVar10 = FUN_80006a68(&local_bc,asStack_c4);
          cVar4 = FUN_80006a64(uVar10,dVar11,dVar12,in_f4,in_f5,in_f6,in_f7,in_f8,asStack_c4,
                               asStack_cc,(undefined4 *)0x0,local_d0,0);
          if (((local_d0[0] == '\x01') || (cVar4 != '\0')) &&
             (iVar5 = FUN_800620e8(piVar2 + 3,&local_bc,(float *)0x0,aiStack_b0,piVar2,(int)param_5,
                                   0xffffffff,0,0), iVar5 == 0)) {
            dVar14 = dVar9;
          }
        }
        iVar5 = param_3;
        if ((*(char *)(iVar6 + 0x18) == param_4) && (dVar9 < dVar13)) {
          local_bc = *(float *)(iVar6 + 8);
          local_b8 = lbl_803E12C0 + *(float *)(iVar6 + 0xc);
          local_b4 = *(int *)(iVar6 + 0x10);
          uVar10 = FUN_80006a68(&local_bc,asStack_c4);
          cVar4 = FUN_80006a64(uVar10,dVar11,dVar12,in_f4,in_f5,in_f6,in_f7,in_f8,asStack_c4,
                               asStack_cc,(undefined4 *)0x0,local_d0,0);
          if (((local_d0[0] == '\x01') || (cVar4 != '\0')) &&
             (iVar3 = FUN_800620e8(piVar2 + 3,&local_bc,(float *)0x0,aiStack_b0,piVar2,(int)param_5,
                                   0xffffffff,0,0), iVar3 == 0)) {
            dVar13 = dVar9;
          }
        }
      }
      iVar5 = iVar5 + 1;
    } while (iVar5 < param_3);
    piVar8 = piVar8 + 1;
  }
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800dece0
 * EN v1.0 Address: 0x800DECE0
 * EN v1.0 Size: 1476b
 * EN v1.1 Address: 0x800E0670
 * EN v1.1 Size: 1572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800dece0(void)
{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  float *pfVar8;
  char *pcVar9;
  undefined *puVar10;
  undefined4 *puVar11;
  uint uVar12;
  uint uVar13;
  int iVar14;
  undefined4 *puVar15;
  int *in_r6;
  int *piVar16;
  int iVar17;
  int iVar18;
  int iVar19;
  float *pfVar20;
  float *pfVar21;
  int iVar22;
  int iVar23;
  float *pfVar24;
  int iVar25;
  uint uVar26;
  double in_f31;
  double dVar27;
  double in_ps31_1;
  int local_6d8;
  int local_6d4;
  float local_6d0 [4];
  int local_6c0 [4];
  float local_6b0 [40];
  int local_610 [40];
  char local_570 [48];
  undefined local_540 [1336];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar5 = FUN_80286818();
  if ((iVar5 != 0) && (iVar6 = RomCurve_findByIdWithIndex(*(uint *)(iVar5 + 0x14),&local_6d8), iVar6 != 0)) {
    iVar6 = 0;
    iVar18 = 0;
    pfVar20 = local_6d0;
    pfVar21 = pfVar20;
    iVar22 = iVar5;
    do {
      if (-1 < *(int *)(iVar22 + 0x1c)) {
        pcVar9 = local_570;
        iVar25 = 0x1b;
        iVar14 = 0;
        do {
          iVar19 = iVar14;
          *pcVar9 = '\0';
          pcVar9[1] = '\0';
          pcVar9[2] = '\0';
          pcVar9[3] = '\0';
          pcVar9[4] = '\0';
          pcVar9[5] = '\0';
          pcVar9[6] = '\0';
          pcVar9[7] = '\0';
          pcVar9[8] = '\0';
          pcVar9[9] = '\0';
          pcVar9[10] = '\0';
          pcVar9[0xb] = '\0';
          pcVar9[0xc] = '\0';
          pcVar9[0xd] = '\0';
          pcVar9[0xe] = '\0';
          pcVar9[0xf] = '\0';
          pcVar9[0x10] = '\0';
          pcVar9[0x11] = '\0';
          pcVar9[0x12] = '\0';
          pcVar9[0x13] = '\0';
          pcVar9[0x14] = '\0';
          pcVar9[0x15] = '\0';
          pcVar9[0x16] = '\0';
          pcVar9[0x17] = '\0';
          pcVar9[0x18] = '\0';
          pcVar9[0x19] = '\0';
          pcVar9[0x1a] = '\0';
          pcVar9[0x1b] = '\0';
          pcVar9[0x1c] = '\0';
          pcVar9[0x1d] = '\0';
          pcVar9[0x1e] = '\0';
          pcVar9[0x1f] = '\0';
          pcVar9[0x20] = '\0';
          pcVar9[0x21] = '\0';
          pcVar9[0x22] = '\0';
          pcVar9[0x23] = '\0';
          pcVar9[0x24] = '\0';
          pcVar9[0x25] = '\0';
          pcVar9[0x26] = '\0';
          pcVar9[0x27] = '\0';
          pcVar9[0x28] = '\0';
          pcVar9[0x29] = '\0';
          pcVar9[0x2a] = '\0';
          pcVar9[0x2b] = '\0';
          pcVar9[0x2c] = '\0';
          pcVar9[0x2d] = '\0';
          pcVar9[0x2e] = '\0';
          pcVar9[0x2f] = '\0';
          pcVar9 = pcVar9 + 0x30;
          iVar14 = iVar19 + 0x30;
          iVar25 = iVar25 + -1;
        } while (iVar25 != 0);
        puVar10 = local_540 + iVar19;
        iVar25 = 0x514 - iVar14;
        if (iVar14 < 0x514) {
          do {
            *puVar10 = 0;
            puVar10 = puVar10 + 1;
            iVar25 = iVar25 + -1;
          } while (iVar25 != 0);
        }
        local_570[local_6d8] = '\x01';
        iVar14 = RomCurve_findByIdWithIndex(*(uint *)(iVar22 + 0x1c),&local_6d4);
        if (iVar14 != 0) {
          fVar1 = *(float *)(iVar14 + 0x10) - *(float *)(iVar5 + 0x10);
          fVar2 = *(float *)(iVar14 + 8) - *(float *)(iVar5 + 8);
          fVar3 = *(float *)(iVar14 + 0xc) - *(float *)(iVar5 + 0xc);
          local_6b0[0] = fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3;
          iVar14 = 1;
          local_610[0] = local_6d4;
          local_570[local_6d4] = '\x01';
          bVar4 = false;
          pfVar24 = pfVar21;
          do {
            if (iVar14 < 1) {
              bVar4 = true;
            }
            else {
              iVar14 = iVar14 + -1;
              iVar25 = iVar14 * 4;
              local_6d4 = local_610[iVar14];
              iVar19 = (&DAT_803a2448)[local_610[iVar14]];
              dVar27 = (double)local_6b0[iVar14];
              if (*(char *)(iVar19 + 0x34) == '\x01') {
                bVar4 = true;
                *pfVar24 = local_6b0[iVar14];
                pfVar21 = pfVar21 + 1;
                pfVar24 = pfVar24 + 1;
                local_6b0[iVar6 + -4] = *(float *)(iVar22 + 0x1c);
                iVar6 = iVar6 + 1;
              }
              else {
                iVar17 = 0;
                iVar23 = iVar19;
                do {
                  if ((((-1 < (int)*(uint *)(iVar23 + 0x1c)) &&
                       (iVar7 = RomCurve_findByIdWithIndex(*(uint *)(iVar23 + 0x1c),&local_6d4), iVar7 != 0)) &&
                      (local_570[local_6d4] == '\0')) && (iVar14 < 0x28)) {
                    fVar1 = *(float *)(iVar19 + 0x10) - *(float *)(iVar7 + 0x10);
                    fVar2 = *(float *)(iVar19 + 8) - *(float *)(iVar7 + 8);
                    fVar3 = *(float *)(iVar19 + 0xc) - *(float *)(iVar7 + 0xc);
                    fVar1 = fVar1 * fVar1 +
                            (float)(dVar27 + (double)(fVar2 * fVar2)) + fVar3 * fVar3;
                    iVar7 = 0;
                    for (pfVar8 = local_6b0; (iVar7 < iVar14 && (fVar1 < *pfVar8));
                        pfVar8 = pfVar8 + 1) {
                      iVar7 = iVar7 + 1;
                    }
                    puVar11 = (undefined4 *)((int)local_610 + iVar25);
                    puVar15 = (undefined4 *)((int)local_6b0 + iVar25);
                    uVar12 = iVar14 - iVar7;
                    if (iVar7 < iVar14) {
                      uVar26 = uVar12 >> 3;
                      if (uVar26 != 0) {
                        do {
                          *puVar11 = puVar11[-1];
                          *puVar15 = puVar15[-1];
                          puVar11[-1] = puVar11[-2];
                          puVar15[-1] = puVar15[-2];
                          puVar11[-2] = puVar11[-3];
                          puVar15[-2] = puVar15[-3];
                          puVar11[-3] = puVar11[-4];
                          puVar15[-3] = puVar15[-4];
                          puVar11[-4] = puVar11[-5];
                          puVar15[-4] = puVar15[-5];
                          puVar11[-5] = puVar11[-6];
                          puVar15[-5] = puVar15[-6];
                          puVar11[-6] = puVar11[-7];
                          puVar15[-6] = puVar15[-7];
                          puVar11[-7] = puVar11[-8];
                          puVar15[-7] = puVar15[-8];
                          puVar11 = puVar11 + -8;
                          puVar15 = puVar15 + -8;
                          uVar26 = uVar26 - 1;
                        } while (uVar26 != 0);
                        uVar12 = uVar12 & 7;
                        if (uVar12 == 0) goto LAB_800e0a70;
                      }
                      do {
                        *puVar11 = puVar11[-1];
                        *puVar15 = puVar15[-1];
                        puVar11 = puVar11 + -1;
                        puVar15 = puVar15 + -1;
                        uVar12 = uVar12 - 1;
                      } while (uVar12 != 0);
                    }
LAB_800e0a70:
                    iVar14 = iVar14 + 1;
                    iVar25 = iVar25 + 4;
                    local_6b0[iVar7] = fVar1;
                    local_610[iVar7] = local_6d4;
                    local_570[local_6d4] = '\x01';
                  }
                  iVar23 = iVar23 + 4;
                  iVar17 = iVar17 + 1;
                } while (iVar17 < 4);
              }
            }
          } while (!bVar4);
        }
      }
      iVar22 = iVar22 + 4;
      iVar18 = iVar18 + 1;
    } while (iVar18 < 4);
    if (iVar6 != 0) {
      if (iVar6 == 1) {
        *in_r6 = *(int *)(iVar5 + 0x14);
      }
      else if (1 < iVar6) {
        iVar22 = 0;
        for (iVar18 = 0; iVar18 < iVar6; iVar18 = iVar18 + 1) {
          piVar16 = (int *)((int)local_6c0 + iVar22);
          if (*in_r6 == *piVar16) {
            puVar11 = (undefined4 *)((int)local_6d0 + iVar22);
            uVar12 = (iVar6 + -1) - iVar18;
            if (iVar18 < iVar6 + -1) {
              uVar26 = uVar12 >> 3;
              uVar13 = uVar12;
              if (uVar26 == 0) goto LAB_800e0be4;
              do {
                *piVar16 = piVar16[1];
                *puVar11 = puVar11[1];
                piVar16[1] = piVar16[2];
                puVar11[1] = puVar11[2];
                piVar16[2] = piVar16[3];
                puVar11[2] = puVar11[3];
                piVar16[3] = piVar16[4];
                puVar11[3] = puVar11[4];
                piVar16[4] = piVar16[5];
                puVar11[4] = puVar11[5];
                piVar16[5] = piVar16[6];
                puVar11[5] = puVar11[6];
                piVar16[6] = piVar16[7];
                puVar11[6] = puVar11[7];
                piVar16[7] = piVar16[8];
                puVar11[7] = puVar11[8];
                piVar16 = piVar16 + 8;
                puVar11 = puVar11 + 8;
                iVar22 = iVar22 + 0x20;
                uVar26 = uVar26 - 1;
              } while (uVar26 != 0);
              for (uVar13 = uVar12 & 7; uVar13 != 0; uVar13 = uVar13 - 1) {
LAB_800e0be4:
                *piVar16 = piVar16[1];
                *puVar11 = puVar11[1];
                piVar16 = piVar16 + 1;
                puVar11 = puVar11 + 1;
                iVar22 = iVar22 + 4;
              }
              iVar18 = iVar18 + uVar12;
            }
            iVar6 = iVar6 + -1;
          }
          iVar22 = iVar22 + 4;
        }
        *in_r6 = *(int *)(iVar5 + 0x14);
        iVar5 = 0;
        iVar22 = 0;
        if (0 < iVar6) {
          do {
            if (*pfVar20 < local_6d0[iVar5]) {
              iVar5 = iVar22;
            }
            pfVar20 = pfVar20 + 1;
            iVar22 = iVar22 + 1;
            iVar6 = iVar6 + -1;
          } while (iVar6 != 0);
        }
      }
    }
  }
  FUN_80286864();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800df2a4
 * EN v1.0 Address: 0x800DF2A4
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x800E0C94
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800df2a4(double param_1,double param_2,double param_3,int param_4,int param_5)
{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  float local_78 [2];
  int local_70 [2];
  float local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  float local_50;
  float local_4c;
  float local_48;
  
  local_70[1] = -1;
  local_70[0] = -1;
  local_78[1] = lbl_803E12C4;
  local_78[0] = lbl_803E12C4;
  local_68 = *(float *)(param_4 + 8);
  local_64 = *(undefined4 *)(param_4 + 0xc);
  local_60 = *(undefined4 *)(param_4 + 0x10);
  iVar7 = 0;
  do {
    uVar6 = *(uint *)(param_4 + 0x1c);
    if (-1 < (int)uVar6) {
      if ((int)uVar6 < 0) {
        iVar5 = 0;
      }
      else {
        iVar4 = DAT_803de0f0 + -1;
        iVar3 = 0;
        while (iVar3 <= iVar4) {
          iVar2 = iVar4 + iVar3 >> 1;
          iVar5 = (&DAT_803a2448)[iVar2];
          if (*(uint *)(iVar5 + 0x14) < uVar6) {
            iVar3 = iVar2 + 1;
          }
          else {
            if (*(uint *)(iVar5 + 0x14) <= uVar6) goto LAB_800e0d84;
            iVar4 = iVar2 + -1;
          }
        }
        iVar5 = 0;
      }
LAB_800e0d84:
      if (iVar5 != 0) {
        local_5c = *(undefined4 *)(iVar5 + 8);
        local_58 = *(undefined4 *)(iVar5 + 0xc);
        local_54 = *(undefined4 *)(iVar5 + 0x10);
        RomCurve_distanceToSegment(param_1,param_2,param_3,&local_68);
        fVar1 = (float)((double)local_48 - param_3) * (float)((double)local_48 - param_3) +
                (float)((double)local_50 - param_1) * (float)((double)local_50 - param_1) +
                (float)((double)local_4c - param_2) * (float)((double)local_4c - param_2);
        uVar6 = countLeadingZeros(param_5 - uVar6);
        uVar6 = uVar6 >> 5;
        if (fVar1 < local_78[uVar6]) {
          local_78[uVar6] = fVar1;
          local_70[uVar6] = *(int *)(param_4 + 0x1c);
        }
      }
    }
    param_4 = param_4 + 4;
    iVar7 = iVar7 + 1;
    if (3 < iVar7) {
      if ((local_70[0] == -1) && (local_70[0] = local_70[1], local_70[1] == -1)) {
        local_70[0] = -1;
      }
      return local_70[0];
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_800df46c
 * EN v1.0 Address: 0x800DF46C
 * EN v1.0 Size: 500b
 * EN v1.1 Address: 0x800E0E78
 * EN v1.1 Size: 548b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800df46c(undefined8 param_1,double param_2,double param_3)
{
  char cVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  uint *puVar8;
  uint *puVar9;
  int iVar10;
  int iVar11;
  uint *puVar12;
  uint local_84 [24];
  
  iVar5 = 0;
  piVar2 = &DAT_803a2448;
  iVar11 = 0;
  while ((iVar5 < DAT_803de0f0 && (iVar11 < 0x14))) {
    iVar4 = iVar11;
    if (*(char *)(*piVar2 + 0x19) == '\x17') {
      iVar4 = iVar11 + 1;
      local_84[iVar11] = *(uint *)(*piVar2 + 0x14);
    }
    piVar2 = piVar2 + 1;
    iVar5 = iVar5 + 1;
    iVar11 = iVar4;
  }
  puVar12 = local_84 + iVar11;
  do {
    puVar9 = puVar12;
    if (iVar11 == 0) {
      return 0xffffffff;
    }
    iVar5 = FUN_800e1c00(param_1,param_2,param_3);
    if (iVar5 != 0) {
      return local_84[0];
    }
    if ((int)local_84[0] < 0) {
      iVar7 = 0;
    }
    else {
      iVar4 = DAT_803de0f0 + -1;
      iVar5 = 0;
      while (iVar5 <= iVar4) {
        iVar3 = iVar4 + iVar5 >> 1;
        iVar7 = (&DAT_803a2448)[iVar3];
        if (*(uint *)(iVar7 + 0x14) < local_84[0]) {
          iVar5 = iVar3 + 1;
        }
        else {
          if (*(uint *)(iVar7 + 0x14) <= local_84[0]) goto LAB_800e0fa8;
          iVar4 = iVar3 + -1;
        }
      }
      iVar7 = 0;
    }
LAB_800e0fa8:
    cVar1 = *(char *)(iVar7 + 0x18);
    iVar5 = 0;
    puVar8 = local_84;
    puVar12 = puVar9;
    while (iVar5 < iVar11) {
      uVar6 = *puVar8;
      if ((int)uVar6 < 0) {
        iVar10 = 0;
      }
      else {
        iVar3 = 0;
        iVar4 = DAT_803de0f0 + -1;
        while (iVar3 <= iVar4) {
          iVar7 = iVar4 + iVar3 >> 1;
          iVar10 = (&DAT_803a2448)[iVar7];
          if (*(uint *)(iVar10 + 0x14) < uVar6) {
            iVar3 = iVar7 + 1;
          }
          else {
            if (*(uint *)(iVar10 + 0x14) <= uVar6) goto LAB_800e1030;
            iVar4 = iVar7 + -1;
          }
        }
        iVar10 = 0;
      }
LAB_800e1030:
      if (*(char *)(iVar10 + 0x18) == cVar1) {
        puVar9 = puVar9 + -1;
        puVar12 = puVar12 + -1;
        iVar11 = iVar11 + -1;
        *puVar8 = *puVar9;
      }
      else {
        puVar8 = puVar8 + 1;
        iVar5 = iVar5 + 1;
      }
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_800df660
 * EN v1.0 Address: 0x800DF660
 * EN v1.0 Size: 1516b
 * EN v1.1 Address: 0x800E109C
 * EN v1.1 Size: 1888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800df660(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)
{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  bool bVar5;
  bool bVar6;
  undefined8 uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  uint uVar12;
  float *pfVar13;
  int iVar14;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar15;
  uint local_78 [4];
  uint local_68 [4];
  uint local_58 [12];
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
  uVar15 = FUN_8028683c();
  iVar8 = (int)((ulonglong)uVar15 >> 0x20);
  iVar10 = (int)uVar15;
  uVar7 = CONCAT44(iVar10,iVar8);
  if (iVar8 == iVar10) {
    FUN_80293900((double)((param_4[2] - param_3[2]) * (param_4[2] - param_3[2]) +
                         (*param_4 - *param_3) * (*param_4 - *param_3) +
                         (param_4[1] - param_3[1]) * (param_4[1] - param_3[1])));
  }
  else {
    bVar6 = false;
    bVar5 = false;
    while (!bVar5) {
      bVar4 = false;
      if ((*(int *)(iVar8 + 0x1c) == -1) || ((*(byte *)(iVar8 + 0x1b) & 1) != 0)) {
        if ((*(int *)(iVar8 + 0x20) == -1) || ((*(byte *)(iVar8 + 0x1b) & 2) != 0)) {
          if ((*(int *)(iVar8 + 0x24) == -1) || ((*(byte *)(iVar8 + 0x1b) & 4) != 0)) {
            if ((*(int *)(iVar8 + 0x28) == -1) || ((*(byte *)(iVar8 + 0x1b) & 8) != 0)) {
              bVar4 = true;
            }
            else {
              bVar4 = false;
            }
          }
          else {
            bVar4 = false;
          }
        }
        else {
          bVar4 = false;
        }
      }
      if (bVar4) {
        bVar5 = true;
        bVar6 = false;
      }
      else {
        iVar9 = 0;
        uVar12 = *(uint *)(iVar8 + 0x1c);
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar8 + 0x1b) & 1) == 0)) && (uVar12 != 0)) {
          iVar9 = 1;
          local_58[0] = uVar12;
        }
        uVar12 = *(uint *)(iVar8 + 0x20);
        iVar11 = iVar9;
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar8 + 0x1b) & 2) == 0)) && (uVar12 != 0)) {
          iVar11 = iVar9 + 1;
          local_58[iVar9] = uVar12;
        }
        uVar12 = *(uint *)(iVar8 + 0x24);
        iVar9 = iVar11;
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar8 + 0x1b) & 4) == 0)) && (uVar12 != 0)) {
          iVar9 = iVar11 + 1;
          local_58[iVar11] = uVar12;
        }
        uVar12 = *(uint *)(iVar8 + 0x28);
        iVar11 = iVar9;
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar8 + 0x1b) & 8) == 0)) && (uVar12 != 0)) {
          iVar11 = iVar9 + 1;
          local_58[iVar9] = uVar12;
        }
        if (iVar11 == 0) {
          uVar12 = 0xffffffff;
        }
        else {
          uVar12 = FUN_80017760(0,iVar11 - 1);
          uVar12 = local_58[uVar12];
        }
        if ((int)uVar12 < 0) {
          iVar8 = 0;
        }
        else {
          iVar11 = DAT_803de0f0 + -1;
          iVar9 = 0;
          while (iVar9 <= iVar11) {
            iVar14 = iVar11 + iVar9 >> 1;
            iVar8 = (&DAT_803a2448)[iVar14];
            if (*(uint *)(iVar8 + 0x14) < uVar12) {
              iVar9 = iVar14 + 1;
            }
            else {
              if (*(uint *)(iVar8 + 0x14) <= uVar12) goto LAB_800e13a0;
              iVar11 = iVar14 + -1;
            }
          }
          iVar8 = 0;
        }
LAB_800e13a0:
        if (iVar8 == iVar10) {
          bVar5 = true;
          bVar6 = true;
        }
      }
    }
    pfVar13 = param_3;
    if (!bVar6) {
      pfVar13 = param_4;
      param_4 = param_3;
      uVar15 = uVar7;
    }
    iVar10 = (int)((ulonglong)uVar15 >> 0x20);
    iVar8 = 0;
    uVar12 = *(uint *)(iVar10 + 0x1c);
    if (((-1 < (int)uVar12) && ((*(byte *)(iVar10 + 0x1b) & 1) == 0)) && (uVar12 != 0)) {
      iVar8 = 1;
      local_68[0] = uVar12;
    }
    uVar12 = *(uint *)(iVar10 + 0x20);
    iVar9 = iVar8;
    if (((-1 < (int)uVar12) && ((*(byte *)(iVar10 + 0x1b) & 2) == 0)) && (uVar12 != 0)) {
      iVar9 = iVar8 + 1;
      local_68[iVar8] = uVar12;
    }
    uVar12 = *(uint *)(iVar10 + 0x24);
    iVar8 = iVar9;
    if (((-1 < (int)uVar12) && ((*(byte *)(iVar10 + 0x1b) & 4) == 0)) && (uVar12 != 0)) {
      iVar8 = iVar9 + 1;
      local_68[iVar9] = uVar12;
    }
    uVar12 = *(uint *)(iVar10 + 0x28);
    iVar9 = iVar8;
    if (((-1 < (int)uVar12) && ((*(byte *)(iVar10 + 0x1b) & 8) == 0)) && (uVar12 != 0)) {
      iVar9 = iVar8 + 1;
      local_68[iVar8] = uVar12;
    }
    if (iVar9 == 0) {
      uVar12 = 0xffffffff;
    }
    else {
      uVar12 = FUN_80017760(0,iVar9 - 1);
      uVar12 = local_68[uVar12];
    }
    if ((int)uVar12 < 0) {
      iVar9 = 0;
    }
    else {
      iVar10 = DAT_803de0f0 + -1;
      iVar8 = 0;
      while (iVar8 <= iVar10) {
        iVar11 = iVar10 + iVar8 >> 1;
        iVar9 = (&DAT_803a2448)[iVar11];
        if (*(uint *)(iVar9 + 0x14) < uVar12) {
          iVar8 = iVar11 + 1;
        }
        else {
          if (*(uint *)(iVar9 + 0x14) <= uVar12) goto LAB_800e1564;
          iVar10 = iVar11 + -1;
        }
      }
      iVar9 = 0;
    }
LAB_800e1564:
    fVar1 = *(float *)(iVar9 + 8) - *pfVar13;
    fVar2 = *(float *)(iVar9 + 0xc) - pfVar13[1];
    fVar3 = *(float *)(iVar9 + 0x10) - pfVar13[2];
    FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    bVar5 = false;
    while (!bVar5) {
      if (iVar9 == (int)uVar15) {
        bVar5 = true;
        fVar1 = *param_4 - *(float *)(iVar9 + 8);
        fVar2 = param_4[1] - *(float *)(iVar9 + 0xc);
        fVar3 = param_4[2] - *(float *)(iVar9 + 0x10);
        FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
      }
      else {
        iVar8 = 0;
        uVar12 = *(uint *)(iVar9 + 0x1c);
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar9 + 0x1b) & 1) == 0)) && (uVar12 != 0)) {
          iVar8 = 1;
          local_78[0] = uVar12;
        }
        uVar12 = *(uint *)(iVar9 + 0x20);
        iVar10 = iVar8;
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar9 + 0x1b) & 2) == 0)) && (uVar12 != 0)) {
          iVar10 = iVar8 + 1;
          local_78[iVar8] = uVar12;
        }
        uVar12 = *(uint *)(iVar9 + 0x24);
        iVar8 = iVar10;
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar9 + 0x1b) & 4) == 0)) && (uVar12 != 0)) {
          iVar8 = iVar10 + 1;
          local_78[iVar10] = uVar12;
        }
        uVar12 = *(uint *)(iVar9 + 0x28);
        iVar10 = iVar8;
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar9 + 0x1b) & 8) == 0)) && (uVar12 != 0)) {
          iVar10 = iVar8 + 1;
          local_78[iVar8] = uVar12;
        }
        if (iVar10 == 0) {
          uVar12 = 0xffffffff;
        }
        else {
          uVar12 = FUN_80017760(0,iVar10 - 1);
          uVar12 = local_78[uVar12];
        }
        if ((int)uVar12 < 0) {
          iVar14 = 0;
        }
        else {
          iVar10 = DAT_803de0f0 + -1;
          iVar8 = 0;
          while (iVar8 <= iVar10) {
            iVar11 = iVar10 + iVar8 >> 1;
            iVar14 = (&DAT_803a2448)[iVar11];
            if (*(uint *)(iVar14 + 0x14) < uVar12) {
              iVar8 = iVar11 + 1;
            }
            else {
              if (*(uint *)(iVar14 + 0x14) <= uVar12) goto LAB_800e1778;
              iVar10 = iVar11 + -1;
            }
          }
          iVar14 = 0;
        }
LAB_800e1778:
        fVar1 = *(float *)(iVar14 + 8) - *(float *)(iVar9 + 8);
        fVar2 = *(float *)(iVar14 + 0xc) - *(float *)(iVar9 + 0xc);
        fVar3 = *(float *)(iVar14 + 0x10) - *(float *)(iVar9 + 0x10);
        FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
        iVar9 = iVar14;
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800dfc4c
 * EN v1.0 Address: 0x800DFC4C
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x800E17FC
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800dfc4c(double param_1,int param_2,float *param_3,float *param_4,float *param_5)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  uint local_38 [6];
  
  iVar5 = 0;
  uVar8 = *(uint *)(param_2 + 0x1c);
  if (((-1 < (int)uVar8) && ((*(byte *)(param_2 + 0x1b) & 1) == 0)) && (uVar8 != 0)) {
    iVar5 = 1;
    local_38[0] = uVar8;
  }
  uVar8 = *(uint *)(param_2 + 0x20);
  iVar6 = iVar5;
  if (((-1 < (int)uVar8) && ((*(byte *)(param_2 + 0x1b) & 2) == 0)) && (uVar8 != 0)) {
    iVar6 = iVar5 + 1;
    local_38[iVar5] = uVar8;
  }
  uVar8 = *(uint *)(param_2 + 0x24);
  iVar5 = iVar6;
  if (((-1 < (int)uVar8) && ((*(byte *)(param_2 + 0x1b) & 4) == 0)) && (uVar8 != 0)) {
    iVar5 = iVar6 + 1;
    local_38[iVar6] = uVar8;
  }
  uVar8 = *(uint *)(param_2 + 0x28);
  iVar6 = iVar5;
  if (((-1 < (int)uVar8) && ((*(byte *)(param_2 + 0x1b) & 8) == 0)) && (uVar8 != 0)) {
    iVar6 = iVar5 + 1;
    local_38[iVar5] = uVar8;
  }
  if (iVar6 == 0) {
    uVar8 = 0xffffffff;
  }
  else {
    uVar8 = FUN_80017760(0,iVar6 - 1);
    uVar8 = local_38[uVar8];
  }
  if ((int)uVar8 < 0) {
    iVar9 = 0;
  }
  else {
    iVar6 = DAT_803de0f0 + -1;
    iVar5 = 0;
    while (iVar5 <= iVar6) {
      iVar7 = iVar6 + iVar5 >> 1;
      iVar9 = (&DAT_803a2448)[iVar7];
      if (*(uint *)(iVar9 + 0x14) < uVar8) {
        iVar5 = iVar7 + 1;
      }
      else {
        if (*(uint *)(iVar9 + 0x14) <= uVar8) goto LAB_800e19bc;
        iVar6 = iVar7 + -1;
      }
    }
    iVar9 = 0;
  }
LAB_800e19bc:
  if (iVar9 == 0) {
    *param_3 = *(float *)(param_2 + 8);
    *param_4 = *(float *)(param_2 + 0xc);
    *param_5 = *(float *)(param_2 + 0x10);
  }
  else {
    fVar1 = *(float *)(iVar9 + 0xc);
    fVar2 = *(float *)(param_2 + 0xc);
    fVar3 = *(float *)(iVar9 + 0x10);
    fVar4 = *(float *)(param_2 + 0x10);
    *param_3 = (float)((double)(float)((double)*(float *)(iVar9 + 8) -
                                      (double)*(float *)(param_2 + 8)) * param_1 +
                      (double)*(float *)(param_2 + 8));
    *param_4 = (float)((double)(fVar1 - fVar2) * param_1 + (double)*(float *)(param_2 + 0xc));
    *param_5 = (float)((double)(fVar3 - fVar4) * param_1 + (double)*(float *)(param_2 + 0x10));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800dfe64
 * EN v1.0 Address: 0x800DFE64
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x800E1A4C
 * EN v1.1 Size: 860b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800dfe64(double param_1,double param_2,double param_3,int param_4,float *param_5)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  float local_78;
  float local_74;
  float local_70;
  uint local_6c [4];
  uint auStack_5c [8];
  
LAB_800e1c9c:
  do {
    while( true ) {
      bVar1 = false;
      if ((*(int *)(param_4 + 0x1c) == -1) || ((*(byte *)(param_4 + 0x1b) & 1) != 0)) {
        if ((*(int *)(param_4 + 0x20) == -1) || ((*(byte *)(param_4 + 0x1b) & 2) != 0)) {
          if ((*(int *)(param_4 + 0x24) == -1) || ((*(byte *)(param_4 + 0x1b) & 4) != 0)) {
            if ((*(int *)(param_4 + 0x28) == -1) || ((*(byte *)(param_4 + 0x1b) & 8) != 0)) {
              bVar1 = true;
            }
            else {
              bVar1 = false;
            }
          }
          else {
            bVar1 = false;
          }
        }
        else {
          bVar1 = false;
        }
      }
      if (bVar1) {
        *param_5 = lbl_803E12B8;
        return param_4;
      }
      RomCurve_getAdjacentWindow(param_4,(int *)auStack_5c);
      iVar2 = FUN_800e1b24(param_1,param_2,param_3,auStack_5c,&local_70,&local_74,&local_78);
      if ((((iVar2 != 0) && (lbl_803E12C8 < local_70)) && (local_70 < lbl_803E12CC)) &&
         ((lbl_803E12D0 < local_74 && (local_74 < lbl_803E12D4)))) {
        *param_5 = local_78;
        return param_4;
      }
      iVar2 = 0;
      uVar4 = *(uint *)(param_4 + 0x1c);
      if (((-1 < (int)uVar4) && ((*(byte *)(param_4 + 0x1b) & 1) == 0)) && (uVar4 != 0)) {
        iVar2 = 1;
        local_6c[0] = uVar4;
      }
      uVar4 = *(uint *)(param_4 + 0x20);
      iVar3 = iVar2;
      if (((-1 < (int)uVar4) && ((*(byte *)(param_4 + 0x1b) & 2) == 0)) && (uVar4 != 0)) {
        iVar3 = iVar2 + 1;
        local_6c[iVar2] = uVar4;
      }
      uVar4 = *(uint *)(param_4 + 0x24);
      iVar2 = iVar3;
      if (((-1 < (int)uVar4) && ((*(byte *)(param_4 + 0x1b) & 4) == 0)) && (uVar4 != 0)) {
        iVar2 = iVar3 + 1;
        local_6c[iVar3] = uVar4;
      }
      uVar4 = *(uint *)(param_4 + 0x28);
      iVar3 = iVar2;
      if (((-1 < (int)uVar4) && ((*(byte *)(param_4 + 0x1b) & 8) == 0)) && (uVar4 != 0)) {
        iVar3 = iVar2 + 1;
        local_6c[iVar2] = uVar4;
      }
      if (iVar3 == 0) {
        uVar4 = 0xffffffff;
      }
      else {
        uVar4 = FUN_80017760(0,iVar3 - 1);
        uVar4 = local_6c[uVar4];
      }
      if (-1 < (int)uVar4) break;
      param_4 = 0;
    }
    iVar3 = DAT_803de0f0 + -1;
    iVar2 = 0;
    while (iVar2 <= iVar3) {
      iVar5 = iVar3 + iVar2 >> 1;
      param_4 = (&DAT_803a2448)[iVar5];
      if (*(uint *)(param_4 + 0x14) < uVar4) {
        iVar2 = iVar5 + 1;
      }
      else {
        if (*(uint *)(param_4 + 0x14) <= uVar4) goto LAB_800e1c9c;
        iVar3 = iVar5 + -1;
      }
    }
    param_4 = 0;
  } while( true );
}


/* Trivial 4b 0-arg blr leaves. */
void player_release(void) {}
void player_initialise(void) {}
void UIController_release(void) {}
void UIController_initialise(void) {}
void fn_800D9EB4(void) {}
void fn_800D9EC4(void) {}
void fn_800D9EC8(void) {}
void fn_800D9ED4(void) {}
void fn_800D9ED8(void) {}
void fn_800D9EDC(void) {}
void Dummy12_release(void) {}
void Dummy12_initialise(void) {}
void fn_800DD640(void) {}
void fn_800DD644(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_800D9ECC(void) { return 0x0; }

/* sda21 accessors. */
extern u32 lbl_803DD430;
void fn_800D9668(u32 x) { lbl_803DD430 = x; }

/* Pattern wrappers. */
extern u32 lbl_803DD458;
void fn_800D9EB8(void) { lbl_803DD458 = 0x3; }
