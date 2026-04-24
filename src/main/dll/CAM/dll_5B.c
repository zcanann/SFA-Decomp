#include "ghidra_import.h"
#include "main/dll/CAM/camshipbattle5C.h"
#include "main/dll/CAM/dll_5B.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068f4();
extern double FUN_800069f8();
extern int FUN_80006a10();
extern undefined4 FUN_80006a1c();
extern undefined4 FUN_80006a30();
extern undefined4 FUN_80006ba8();
extern char FUN_80006bb8();
extern char FUN_80006bc0();
extern char FUN_80006bc8();
extern char FUN_80006bd0();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern uint FUN_80017690();
extern double FUN_800176f4();
extern uint FUN_80017730();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern int FUN_80017a98();
extern int FUN_800369d0();
extern void* FUN_80037134();
extern undefined4 FUN_80053bf0();
extern undefined4 FUN_800810d8();
extern undefined4 FUN_80101980();
extern undefined4 FUN_80107ee4();
extern undefined4 FUN_80108074();
extern double FUN_8010aea8();
extern undefined4 FUN_80135814();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80294c64();
extern undefined4 FUN_80294d00();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803de1c0;
extern undefined4* DAT_803de1c8;
extern undefined4* DAT_803de1d0;
extern f64 DOUBLE_803e2458;
extern f64 DOUBLE_803e24b8;
extern f64 DOUBLE_803e2500;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e2440;
extern f32 FLOAT_803e2444;
extern f32 FLOAT_803e2448;
extern f32 FLOAT_803e244c;
extern f32 FLOAT_803e2450;
extern f32 FLOAT_803e2460;
extern f32 FLOAT_803e2464;
extern f32 FLOAT_803e2468;
extern f32 FLOAT_803e246c;
extern f32 FLOAT_803e2470;
extern f32 FLOAT_803e2474;
extern f32 FLOAT_803e2478;
extern f32 FLOAT_803e247c;
extern f32 FLOAT_803e2480;
extern f32 FLOAT_803e2484;
extern f32 FLOAT_803e2488;
extern f32 FLOAT_803e248c;
extern f32 FLOAT_803e2490;
extern f32 FLOAT_803e2494;
extern f32 FLOAT_803e2498;
extern f32 FLOAT_803e249c;
extern f32 FLOAT_803e24a0;
extern f32 FLOAT_803e24a4;
extern f32 FLOAT_803e24a8;
extern f32 FLOAT_803e24ac;
extern f32 FLOAT_803e24b0;
extern f32 FLOAT_803e24c0;
extern f32 FLOAT_803e24c4;
extern f32 FLOAT_803e24c8;
extern f32 FLOAT_803e24cc;
extern f32 FLOAT_803e24d0;
extern f32 FLOAT_803e24d4;
extern f32 FLOAT_803e24d8;
extern f32 FLOAT_803e24f0;
extern f32 FLOAT_803e24f8;
extern f32 FLOAT_803e2508;
extern f32 FLOAT_803e250c;

/*
 * --INFO--
 *
 * Function: FUN_8010847c
 * EN v1.0 Address: 0x8010847C
 * EN v1.0 Size: 1012b
 * EN v1.1 Address: 0x80108718
 * EN v1.1 Size: 1024b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010847c(short *param_1)
{
  float fVar1;
  short sVar2;
  char cVar3;
  char cVar4;
  short *psVar5;
  double dVar6;
  double dVar7;
  undefined8 local_38;
  
  psVar5 = *(short **)(param_1 + 0x52);
  cVar3 = FUN_80006bd0(0);
  cVar4 = FUN_80006bc8(0);
  dVar6 = (double)((FLOAT_803e2460 - *(float *)(param_1 + 0x5a)) / FLOAT_803e2464);
  dVar7 = (double)FLOAT_803e2444;
  if ((dVar7 <= dVar6) && (dVar7 = dVar6, (double)FLOAT_803e2468 < dVar6)) {
    dVar7 = (double)FLOAT_803e2468;
  }
  dVar6 = FUN_800176f4((double)((float)((double)CONCAT44(0x43300000,(int)cVar3 ^ 0x80000000) -
                                       DOUBLE_803e2458) *
                                -(float)((double)FLOAT_803e2470 * dVar7 - (double)FLOAT_803e246c) -
                               *(float *)(DAT_803de1c0 + 0x11c)),(double)FLOAT_803e2474,
                       (double)FLOAT_803dc074);
  *(float *)(DAT_803de1c0 + 0x11c) = (float)((double)*(float *)(DAT_803de1c0 + 0x11c) + dVar6);
  if ((FLOAT_803e2478 < *(float *)(DAT_803de1c0 + 0x11c)) &&
     (*(float *)(DAT_803de1c0 + 0x11c) < FLOAT_803e247c)) {
    *(float *)(DAT_803de1c0 + 0x11c) = FLOAT_803e2444;
  }
  fVar1 = FLOAT_803e2480 *
          ((float)((double)CONCAT44(0x43300000,(int)cVar4 ^ 0x80000000) - DOUBLE_803e2458) /
          FLOAT_803e2484);
  *param_1 = (short)(int)(*(float *)(DAT_803de1c0 + 0x11c) * FLOAT_803dc074 +
                         (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                DOUBLE_803e2458));
  sVar2 = (short)(int)fVar1 - param_1[1];
  if (0x8000 < sVar2) {
    sVar2 = sVar2 + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  dVar7 = FUN_800176f4((double)(float)((double)CONCAT44(0x43300000,(int)sVar2 ^ 0x80000000) -
                                      DOUBLE_803e2458),
                       (double)(FLOAT_803e2468 /
                               (float)((double)FLOAT_803e248c * dVar7 + (double)FLOAT_803e2488)),
                       (double)FLOAT_803dc074);
  param_1[1] = (short)(int)((double)(float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000
                                                            ) - DOUBLE_803e2458) + dVar7);
  if (0x3c00 < param_1[1]) {
    param_1[1] = 0x3c00;
  }
  if (param_1[1] < -0x3c00) {
    param_1[1] = -0x3c00;
  }
  *psVar5 = -0x8000 - *param_1;
  if (psVar5[0x22] == 1) {
    FUN_80294c64(psVar5,*psVar5);
  }
  if (*(float *)(DAT_803de1c0 + 0x124) < *(float *)(DAT_803de1c0 + 0x130)) {
    *(float *)(DAT_803de1c0 + 0x130) = *(float *)(DAT_803de1c0 + 0x124);
  }
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(DAT_803de1c0 + 0x120);
  *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(DAT_803de1c0 + 0x130);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(DAT_803de1c0 + 0x128);
  if (*(char *)(DAT_803de1c0 + 0x12d) < '\0') {
    dVar7 = (double)*(float *)(param_1 + 0x5a);
    cVar3 = FUN_80006bb8(0);
    local_38 = (double)CONCAT44(0x43300000,-(int)cVar3 ^ 0x80000000);
    dVar6 = (double)(float)((double)(FLOAT_803e2490 * (float)(local_38 - DOUBLE_803e2458)) *
                            (double)FLOAT_803dc074 + dVar7);
    dVar7 = FUN_800069f8();
    FUN_800810d8(dVar7);
    dVar7 = (double)FLOAT_803e247c;
    if ((dVar7 <= dVar6) && (dVar7 = dVar6, (double)FLOAT_803e2460 < dVar6)) {
      dVar7 = (double)FLOAT_803e2460;
    }
    if ((*(byte *)(DAT_803de1c0 + 0x12d) >> 6 & 1) != 0) {
      if ((dVar7 == (double)*(float *)(param_1 + 0x5a)) &&
         ((*(byte *)(DAT_803de1c0 + 0x12d) >> 5 & 1) != 0)) {
        FUN_80006810(0,0x3d8);
        *(byte *)(DAT_803de1c0 + 0x12d) = *(byte *)(DAT_803de1c0 + 0x12d) & 0xdf;
      }
      if ((dVar7 != (double)*(float *)(param_1 + 0x5a)) &&
         ((*(byte *)(DAT_803de1c0 + 0x12d) >> 5 & 1) == 0)) {
        FUN_80006824(0,0x3d8);
        *(byte *)(DAT_803de1c0 + 0x12d) = *(byte *)(DAT_803de1c0 + 0x12d) & 0xdf | 0x20;
      }
    }
    *(float *)(param_1 + 0x5a) = (float)dVar7;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80108870
 * EN v1.0 Address: 0x80108870
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80108B18
 * EN v1.1 Size: 596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80108870(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80108874
 * EN v1.0 Address: 0x80108874
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x80108D6C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80108874(undefined2 *param_1)
{
  undefined2 *puVar1;
  
  puVar1 = (undefined2 *)(**(code **)(*DAT_803dd6d0 + 0xc))();
  if ((puVar1 != (undefined2 *)0x0) && (param_1 != (undefined2 *)0x0)) {
    *puVar1 = *param_1;
    puVar1[1] = param_1[1];
    puVar1[2] = param_1[2];
    *(undefined4 *)(puVar1 + 6) = *(undefined4 *)(param_1 + 4);
    *(undefined4 *)(puVar1 + 8) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(puVar1 + 10) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(puVar1 + 0xc) = *(undefined4 *)(param_1 + 4);
    *(undefined4 *)(puVar1 + 0xe) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(puVar1 + 0x10) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(puVar1 + 0x5a) = *(undefined4 *)(param_1 + 10);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80108914
 * EN v1.0 Address: 0x80108914
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x80108E08
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80108914(int param_1)
{
  int iVar1;
  int iVar2;
  int local_18 [5];
  
  *(ushort *)(*(int *)(param_1 + 0xa4) + 6) = *(ushort *)(*(int *)(param_1 + 0xa4) + 6) & 0xbfff;
  FUN_80053bf0(0);
  iVar2 = *(int *)(param_1 + 0xa4);
  if (iVar2 != 0) {
    *(undefined *)(iVar2 + 0x36) = 0xff;
    iVar1 = FUN_80017a98();
    if (iVar1 == iVar2) {
      FUN_80294d00(iVar2,local_18);
      if (local_18[0] != 0) {
        *(undefined *)(local_18[0] + 0x36) = 0xff;
        if (*(char *)(local_18[0] + 0x36) == '\x01') {
          *(undefined *)(local_18[0] + 0x36) = 0;
        }
      }
    }
  }
  FUN_80006810(0,0x3d8);
  FUN_80017814(DAT_803de1c0);
  DAT_803de1c0 = 0;
  FUN_800810d8((double)FLOAT_803e2460);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801089d0
 * EN v1.0 Address: 0x801089D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80108EC8
 * EN v1.1 Size: 1452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801089d0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801089d4
 * EN v1.0 Address: 0x801089D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80109474
 * EN v1.1 Size: 1396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801089d4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 *param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801089d8
 * EN v1.0 Address: 0x801089D8
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x801099E8
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801089d8(void)
{
  FUN_80017814(DAT_803de1c8);
  DAT_803de1c8 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80108a04
 * EN v1.0 Address: 0x80108A04
 * EN v1.0 Size: 848b
 * EN v1.1 Address: 0x80109A14
 * EN v1.1 Size: 816b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80108a04(short *param_1)
{
  float fVar1;
  uint uVar2;
  uint uVar3;
  char cVar4;
  char cVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  
  dVar10 = (double)FLOAT_803e24c0;
  iVar6 = *(int *)(param_1 + 0x52);
  uVar2 = FUN_80006c10(0);
  uVar3 = FUN_80006c00(0);
  if ((uVar3 & 2) == 0) {
    if ((uVar2 & 8) != 0) {
      dVar10 = (double)(FLOAT_803e24c4 * *DAT_803de1c8);
    }
    if ((uVar2 & 4) != 0) {
      dVar10 = (double)(FLOAT_803e24c8 * *DAT_803de1c8);
    }
    dVar7 = dVar10;
    if (dVar10 < (double)FLOAT_803e24c0) {
      dVar7 = -dVar10;
    }
    dVar9 = (double)DAT_803de1c8[1];
    dVar8 = dVar9;
    if (dVar9 < (double)FLOAT_803e24c0) {
      dVar8 = -dVar9;
    }
    fVar1 = FLOAT_803e24d0;
    if (dVar7 < dVar8) {
      fVar1 = FLOAT_803e24cc;
    }
    DAT_803de1c8[1] = fVar1 * (float)(dVar10 - dVar9) + DAT_803de1c8[1];
    *DAT_803de1c8 = *DAT_803de1c8 + DAT_803de1c8[1];
    if (*DAT_803de1c8 < FLOAT_803e24d4) {
      *DAT_803de1c8 = FLOAT_803e24d4;
    }
    if (FLOAT_803e24d8 < *DAT_803de1c8) {
      *DAT_803de1c8 = FLOAT_803e24d8;
    }
    cVar4 = FUN_80006bc0(0);
    cVar5 = FUN_80006bb8(0);
    *param_1 = *param_1 + cVar4 * -3;
    param_1[1] = param_1[1] + cVar5 * 3;
    dVar10 = (double)FUN_80293f90();
    dVar7 = (double)FUN_80294964();
    dVar8 = (double)FUN_80294964();
    dVar9 = (double)FUN_80293f90();
    fVar1 = *DAT_803de1c8;
    dVar8 = (double)(float)((double)fVar1 * dVar8);
    *(float *)(param_1 + 0xc) = *(float *)(iVar6 + 0x18) + (float)(dVar8 * dVar7);
    *(float *)(param_1 + 0xe) =
         FLOAT_803e24d4 + *(float *)(iVar6 + 0x1c) + (float)((double)fVar1 * dVar9);
    *(float *)(param_1 + 0x10) = *(float *)(iVar6 + 0x20) + (float)(dVar8 * dVar10);
    FUN_800068f4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  else {
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80108d54
 * EN v1.0 Address: 0x80108D54
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80109D44
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80108d54(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80108d58
 * EN v1.0 Address: 0x80108D58
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x80109DA0
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80108d58(undefined8 param_1,double param_2,double param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  double extraout_f1;
  double dVar7;
  double in_f28;
  double dVar8;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar9;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar10;
  int local_68 [12];
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
  uVar10 = FUN_8028683c();
  dVar9 = (double)FLOAT_803e24f8;
  dVar8 = extraout_f1;
  piVar4 = FUN_80037134(7,local_68);
  for (iVar6 = 0; iVar6 < local_68[0]; iVar6 = iVar6 + 1) {
    iVar5 = *piVar4;
    if ((((int)*(short *)(iVar5 + 0x44) == (int)uVar10) &&
        ((uint)*(byte *)(*(int *)(iVar5 + 0x4c) + 0x18) == (uint)((ulonglong)uVar10 >> 0x20))) &&
       (fVar1 = (float)(dVar8 - (double)*(float *)(iVar5 + 0x18)),
       fVar2 = (float)(param_2 - (double)*(float *)(iVar5 + 0x1c)),
       fVar3 = (float)(param_3 - (double)*(float *)(iVar5 + 0x20)),
       dVar7 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2)), dVar7 < dVar9)
       ) {
      dVar9 = dVar7;
    }
    piVar4 = piVar4 + 1;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80108e7c
 * EN v1.0 Address: 0x80108E7C
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80109EB4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80108e7c(void)
{
  FUN_80017814(DAT_803de1d0);
  DAT_803de1d0 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80108ea8
 * EN v1.0 Address: 0x80108EA8
 * EN v1.0 Size: 608b
 * EN v1.1 Address: 0x80109EE0
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80108ea8(short *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  
  if (*(char *)((int)DAT_803de1d0 + 0xf5) == '\0') {
    iVar3 = *(int *)(param_1 + 0x52);
    iVar4 = *(int *)(*DAT_803de1d0 + 0x4c);
    if ((*(byte *)(iVar4 + 0x1b) & 1) == 0) {
      *param_1 = *(short *)(iVar4 + 0x1c) + -0x8000;
    }
    if ((*(byte *)(iVar4 + 0x1b) & 2) == 0) {
      param_1[1] = *(short *)(iVar4 + 0x1e);
    }
    if ((*(byte *)(iVar4 + 0x1b) & 4) == 0) {
      param_1[2] = *(short *)(iVar4 + 0x20);
    }
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*DAT_803de1d0 + 0x18);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(*DAT_803de1d0 + 0x1c);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*DAT_803de1d0 + 0x20);
    *(float *)(param_1 + 0x5a) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x1a)) - DOUBLE_803e2500);
    dVar6 = (double)(*(float *)(param_1 + 0xc) - *(float *)(iVar3 + 0x18));
    dVar5 = (double)(*(float *)(param_1 + 0x10) - *(float *)(iVar3 + 0x20));
    if ((*(byte *)(iVar4 + 0x1b) & 1) != 0) {
      iVar1 = FUN_80017730();
      *param_1 = -0x8000 - (short)iVar1;
    }
    if ((*(byte *)(iVar4 + 0x1b) & 2) != 0) {
      FUN_80293900((double)(float)(dVar6 * dVar6 + (double)(float)(dVar5 * dVar5)));
      uVar2 = FUN_80017730();
      iVar1 = ((uVar2 & 0xffff) - (int)*(short *)(iVar4 + 0x1e)) - (uint)(ushort)param_1[1];
      if (0x8000 < iVar1) {
        iVar1 = iVar1 + -0xffff;
      }
      if (iVar1 < -0x8000) {
        iVar1 = iVar1 + 0xffff;
      }
      param_1[1] = param_1[1] + (short)((int)(iVar1 * (uint)DAT_803dc070) >> 3);
    }
    if ((*(byte *)(iVar4 + 0x1b) & 4) != 0) {
      iVar3 = (int)param_1[2] - (uint)*(ushort *)(iVar3 + 4);
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      param_1[2] = param_1[2] + (short)((int)(iVar3 * (uint)DAT_803dc070) >> 3);
    }
    FUN_800068f4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  else {
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80109108
 * EN v1.0 Address: 0x80109108
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010A198
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80109108(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8010910c
 * EN v1.0 Address: 0x8010910C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010A3A0
 * EN v1.1 Size: 888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010910c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80109110
 * EN v1.0 Address: 0x80109110
 * EN v1.0 Size: 280b
 * EN v1.1 Address: 0x8010A718
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80109110(undefined4 param_1,undefined4 param_2,uint param_3)
{
  bool bVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_80286840();
  iVar4 = (int)((ulonglong)uVar6 >> 0x20);
  piVar3 = (int *)uVar6;
  bVar1 = false;
  *piVar3 = 0;
  while (!bVar1) {
    bVar1 = true;
    if ((*(char *)(iVar4 + 0x19) != '\x1b') && (*(char *)(iVar4 + 0x19) != '\x1a')) {
      for (iVar5 = 0; iVar5 < 5; iVar5 = iVar5 + 1) {
        if ((((-1 < *(int *)(iVar4 + iVar5 * 4 + 0x1c)) &&
             (((int)*(char *)(iVar4 + 0x1b) & 1 << iVar5) != 0)) &&
            (iVar2 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar2 != 0)) &&
           (((*(byte *)(iVar2 + 0x31) == param_3 || (*(byte *)(iVar2 + 0x32) == param_3)) ||
            (*(byte *)(iVar2 + 0x33) == param_3)))) {
          bVar1 = false;
          iVar5 = 5;
          iVar4 = iVar2;
        }
      }
    }
    if (!bVar1) {
      *piVar3 = *piVar3 + 1;
    }
  }
  FUN_8028688c();
  return;
}
