#include "ghidra_import.h"
#include "main/dll/CAM/camshipbattle5C.h"
#include "main/dll/CAM/dll_5B.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern undefined4 Obj_TransformWorldPointToLocal();
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
extern int ObjHits_GetPriorityHit();
extern void* ObjGroup_GetObjects();
extern undefined4 FUN_80053bf0();
extern undefined4 FUN_800810d8();
extern undefined4 FUN_80101980();
extern undefined4 fn_80108010();
extern undefined4 fn_80108194();
extern double fn_8010AEA8();
extern undefined4 FUN_80135814();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double sqrtf();
extern undefined4 fn_80293E80();
extern undefined4 sin();
extern undefined4 FUN_80294c64();
extern undefined4 FUN_80294d00();

extern undefined4 framesThisStep;
extern undefined4* lbl_803DCA50;
extern undefined4* lbl_803DCA9C;
extern undefined4* lbl_803DD548;
extern undefined4* lbl_803DD550;
extern undefined4* lbl_803DD558;
extern f64 lbl_803E17D8;
extern f64 lbl_803E1838;
extern f64 lbl_803E1880;
extern f32 timeDelta;
extern f32 lbl_803E17C0;
extern f32 lbl_803E17C4;
extern f32 lbl_803E17C8;
extern f32 lbl_803E17CC;
extern f32 lbl_803E17D0;
extern f32 lbl_803E17E0;
extern f32 lbl_803E17E4;
extern f32 lbl_803E17E8;
extern f32 lbl_803E17EC;
extern f32 lbl_803E17F0;
extern f32 lbl_803E17F4;
extern f32 lbl_803E17F8;
extern f32 lbl_803E17FC;
extern f32 lbl_803E1800;
extern f32 lbl_803E1804;
extern f32 lbl_803E1808;
extern f32 lbl_803E180C;
extern f32 lbl_803E1810;
extern f32 lbl_803E1814;
extern f32 lbl_803E1818;
extern f32 lbl_803E181C;
extern f32 lbl_803E1820;
extern f32 lbl_803E1824;
extern f32 lbl_803E1828;
extern f32 lbl_803E182C;
extern f32 lbl_803E1830;
extern f32 lbl_803E1840;
extern f32 lbl_803E1844;
extern f32 lbl_803E1848;
extern f32 lbl_803E184C;
extern f32 lbl_803E1850;
extern f32 lbl_803E1854;
extern f32 lbl_803E1858;
extern f32 lbl_803E1870;
extern f32 lbl_803E1878;
extern f32 lbl_803E1888;
extern f32 lbl_803E188C;

/*
 * --INFO--
 *
 * Function: fn_8010847C
 * EN v1.0 Address: 0x8010847C
 * EN v1.0 Size: 1012b
 * EN v1.1 Address: 0x80108718
 * EN v1.1 Size: 1024b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8010847C(short *param_1)
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
  dVar6 = (double)((lbl_803E17E0 - *(float *)(param_1 + 0x5a)) / lbl_803E17E4);
  dVar7 = (double)lbl_803E17C4;
  if ((dVar7 <= dVar6) && (dVar7 = dVar6, (double)lbl_803E17E8 < dVar6)) {
    dVar7 = (double)lbl_803E17E8;
  }
  dVar6 = FUN_800176f4((double)((float)((double)CONCAT44(0x43300000,(int)cVar3 ^ 0x80000000) -
                                       lbl_803E17D8) *
                                -(float)((double)lbl_803E17F0 * dVar7 - (double)lbl_803E17EC) -
                               *(float *)(lbl_803DD548 + 0x11c)),(double)lbl_803E17F4,
                       (double)timeDelta);
  *(float *)(lbl_803DD548 + 0x11c) = (float)((double)*(float *)(lbl_803DD548 + 0x11c) + dVar6);
  if ((lbl_803E17F8 < *(float *)(lbl_803DD548 + 0x11c)) &&
     (*(float *)(lbl_803DD548 + 0x11c) < lbl_803E17FC)) {
    *(float *)(lbl_803DD548 + 0x11c) = lbl_803E17C4;
  }
  fVar1 = lbl_803E1800 *
          ((float)((double)CONCAT44(0x43300000,(int)cVar4 ^ 0x80000000) - lbl_803E17D8) /
          lbl_803E1804);
  *param_1 = (short)(int)(*(float *)(lbl_803DD548 + 0x11c) * timeDelta +
                         (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                lbl_803E17D8));
  sVar2 = (short)(int)fVar1 - param_1[1];
  if (0x8000 < sVar2) {
    sVar2 = sVar2 + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  dVar7 = FUN_800176f4((double)(float)((double)CONCAT44(0x43300000,(int)sVar2 ^ 0x80000000) -
                                      lbl_803E17D8),
                       (double)(lbl_803E17E8 /
                               (float)((double)lbl_803E180C * dVar7 + (double)lbl_803E1808)),
                       (double)timeDelta);
  param_1[1] = (short)(int)((double)(float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000
                                                            ) - lbl_803E17D8) + dVar7);
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
  if (*(float *)(lbl_803DD548 + 0x124) < *(float *)(lbl_803DD548 + 0x130)) {
    *(float *)(lbl_803DD548 + 0x130) = *(float *)(lbl_803DD548 + 0x124);
  }
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(lbl_803DD548 + 0x120);
  *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(lbl_803DD548 + 0x130);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(lbl_803DD548 + 0x128);
  if (*(char *)(lbl_803DD548 + 0x12d) < '\0') {
    dVar7 = (double)*(float *)(param_1 + 0x5a);
    cVar3 = FUN_80006bb8(0);
    local_38 = (double)CONCAT44(0x43300000,-(int)cVar3 ^ 0x80000000);
    dVar6 = (double)(float)((double)(lbl_803E1810 * (float)(local_38 - lbl_803E17D8)) *
                            (double)timeDelta + dVar7);
    dVar7 = FUN_800069f8();
    FUN_800810d8(dVar7);
    dVar7 = (double)lbl_803E17FC;
    if ((dVar7 <= dVar6) && (dVar7 = dVar6, (double)lbl_803E17E0 < dVar6)) {
      dVar7 = (double)lbl_803E17E0;
    }
    if ((*(byte *)(lbl_803DD548 + 0x12d) >> 6 & 1) != 0) {
      if ((dVar7 == (double)*(float *)(param_1 + 0x5a)) &&
         ((*(byte *)(lbl_803DD548 + 0x12d) >> 5 & 1) != 0)) {
        FUN_80006810(0,0x3d8);
        *(byte *)(lbl_803DD548 + 0x12d) = *(byte *)(lbl_803DD548 + 0x12d) & 0xdf;
      }
      if ((dVar7 != (double)*(float *)(param_1 + 0x5a)) &&
         ((*(byte *)(lbl_803DD548 + 0x12d) >> 5 & 1) == 0)) {
        FUN_80006824(0,0x3d8);
        *(byte *)(lbl_803DD548 + 0x12d) = *(byte *)(lbl_803DD548 + 0x12d) & 0xdf | 0x20;
      }
    }
    *(float *)(param_1 + 0x5a) = (float)dVar7;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8010887C
 * EN v1.0 Address: 0x80108870
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80108B18
 * EN v1.1 Size: 596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8010887C(void)
{
}

/*
 * --INFO--
 *
 * Function: fn_80108AD0
 * EN v1.0 Address: 0x80108874
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x80108D6C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80108AD0(undefined2 *param_1)
{
  undefined2 *puVar1;
  
  puVar1 = (undefined2 *)(**(code **)(*lbl_803DCA50 + 0xc))();
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
 * Function: fn_80108B6C
 * EN v1.0 Address: 0x80108914
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x80108E08
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80108B6C(int param_1)
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
  FUN_80017814(lbl_803DD548);
  lbl_803DD548 = 0;
  FUN_800810d8((double)lbl_803E17E0);
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80108C2C
 * EN v1.0 Address: 0x801089D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80108EC8
 * EN v1.1 Size: 1452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80108C2C(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: fn_801091D8
 * EN v1.0 Address: 0x801089D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80109474
 * EN v1.1 Size: 1396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801091D8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
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
  FUN_80017814(lbl_803DD550);
  lbl_803DD550 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80109778
 * EN v1.0 Address: 0x80108A04
 * EN v1.0 Size: 848b
 * EN v1.1 Address: 0x80109A14
 * EN v1.1 Size: 816b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80109778(short *param_1)
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
  
  dVar10 = (double)lbl_803E1840;
  iVar6 = *(int *)(param_1 + 0x52);
  uVar2 = FUN_80006c10(0);
  uVar3 = FUN_80006c00(0);
  if ((uVar3 & 2) == 0) {
    if ((uVar2 & 8) != 0) {
      dVar10 = (double)(lbl_803E1844 * *lbl_803DD550);
    }
    if ((uVar2 & 4) != 0) {
      dVar10 = (double)(lbl_803E1848 * *lbl_803DD550);
    }
    dVar7 = dVar10;
    if (dVar10 < (double)lbl_803E1840) {
      dVar7 = -dVar10;
    }
    dVar9 = (double)lbl_803DD550[1];
    dVar8 = dVar9;
    if (dVar9 < (double)lbl_803E1840) {
      dVar8 = -dVar9;
    }
    fVar1 = lbl_803E1850;
    if (dVar7 < dVar8) {
      fVar1 = lbl_803E184C;
    }
    lbl_803DD550[1] = fVar1 * (float)(dVar10 - dVar9) + lbl_803DD550[1];
    *lbl_803DD550 = *lbl_803DD550 + lbl_803DD550[1];
    if (*lbl_803DD550 < lbl_803E1854) {
      *lbl_803DD550 = lbl_803E1854;
    }
    if (lbl_803E1858 < *lbl_803DD550) {
      *lbl_803DD550 = lbl_803E1858;
    }
    cVar4 = FUN_80006bc0(0);
    cVar5 = FUN_80006bb8(0);
    *param_1 = *param_1 + cVar4 * -3;
    param_1[1] = param_1[1] + cVar5 * 3;
    dVar10 = (double)fn_80293E80();
    dVar7 = (double)sin();
    dVar8 = (double)sin();
    dVar9 = (double)fn_80293E80();
    fVar1 = *lbl_803DD550;
    dVar8 = (double)(float)((double)fVar1 * dVar8);
    *(float *)(param_1 + 0xc) = *(float *)(iVar6 + 0x18) + (float)(dVar8 * dVar7);
    *(float *)(param_1 + 0xe) =
         lbl_803E1854 + *(float *)(iVar6 + 0x1c) + (float)((double)fVar1 * dVar9);
    *(float *)(param_1 + 0x10) = *(float *)(iVar6 + 0x20) + (float)(dVar8 * dVar10);
    Obj_TransformWorldPointToLocal((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  else {
    (**(code **)(*lbl_803DCA50 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80109AA8
 * EN v1.0 Address: 0x80108D54
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80109D44
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80109AA8(void)
{
}

/*
 * --INFO--
 *
 * Function: fn_80109B04
 * EN v1.0 Address: 0x80108D58
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x80109DA0
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80109B04(undefined8 param_1,double param_2,double param_3)
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
  dVar9 = (double)lbl_803E1878;
  dVar8 = extraout_f1;
  piVar4 = ObjGroup_GetObjects(7,local_68);
  for (iVar6 = 0; iVar6 < local_68[0]; iVar6 = iVar6 + 1) {
    iVar5 = *piVar4;
    if ((((int)*(short *)(iVar5 + 0x44) == (int)uVar10) &&
        ((uint)*(byte *)(*(int *)(iVar5 + 0x4c) + 0x18) == (uint)((ulonglong)uVar10 >> 0x20))) &&
       (fVar1 = (float)(dVar8 - (double)*(float *)(iVar5 + 0x18)),
       fVar2 = (float)(param_2 - (double)*(float *)(iVar5 + 0x1c)),
       fVar3 = (float)(param_3 - (double)*(float *)(iVar5 + 0x20)),
       dVar7 = sqrtf((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2)), dVar7 < dVar9)
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
  FUN_80017814(lbl_803DD558);
  lbl_803DD558 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80109C44
 * EN v1.0 Address: 0x80108EA8
 * EN v1.0 Size: 608b
 * EN v1.1 Address: 0x80109EE0
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80109C44(short *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  
  if (*(char *)((int)lbl_803DD558 + 0xf5) == '\0') {
    iVar3 = *(int *)(param_1 + 0x52);
    iVar4 = *(int *)(*lbl_803DD558 + 0x4c);
    if ((*(byte *)(iVar4 + 0x1b) & 1) == 0) {
      *param_1 = *(short *)(iVar4 + 0x1c) + -0x8000;
    }
    if ((*(byte *)(iVar4 + 0x1b) & 2) == 0) {
      param_1[1] = *(short *)(iVar4 + 0x1e);
    }
    if ((*(byte *)(iVar4 + 0x1b) & 4) == 0) {
      param_1[2] = *(short *)(iVar4 + 0x20);
    }
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*lbl_803DD558 + 0x18);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(*lbl_803DD558 + 0x1c);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*lbl_803DD558 + 0x20);
    *(float *)(param_1 + 0x5a) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x1a)) - lbl_803E1880);
    dVar6 = (double)(*(float *)(param_1 + 0xc) - *(float *)(iVar3 + 0x18));
    dVar5 = (double)(*(float *)(param_1 + 0x10) - *(float *)(iVar3 + 0x20));
    if ((*(byte *)(iVar4 + 0x1b) & 1) != 0) {
      iVar1 = FUN_80017730();
      *param_1 = -0x8000 - (short)iVar1;
    }
    if ((*(byte *)(iVar4 + 0x1b) & 2) != 0) {
      sqrtf((double)(float)(dVar6 * dVar6 + (double)(float)(dVar5 * dVar5)));
      uVar2 = FUN_80017730();
      iVar1 = ((uVar2 & 0xffff) - (int)*(short *)(iVar4 + 0x1e)) - (uint)(ushort)param_1[1];
      if (0x8000 < iVar1) {
        iVar1 = iVar1 + -0xffff;
      }
      if (iVar1 < -0x8000) {
        iVar1 = iVar1 + 0xffff;
      }
      param_1[1] = param_1[1] + (short)((int)(iVar1 * (uint)framesThisStep) >> 3);
    }
    if ((*(byte *)(iVar4 + 0x1b) & 4) != 0) {
      iVar3 = (int)param_1[2] - (uint)*(ushort *)(iVar3 + 4);
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      param_1[2] = param_1[2] + (short)((int)(iVar3 * (uint)framesThisStep) >> 3);
    }
    Obj_TransformWorldPointToLocal((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  else {
    (**(code **)(*lbl_803DCA50 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80109EFC
 * EN v1.0 Address: 0x80109108
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010A198
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80109EFC(void)
{
}

/*
 * --INFO--
 *
 * Function: fn_8010A104
 * EN v1.0 Address: 0x8010910C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010A3A0
 * EN v1.1 Size: 888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8010A104(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: fn_8010A47C
 * EN v1.0 Address: 0x80109110
 * EN v1.0 Size: 280b
 * EN v1.1 Address: 0x8010A718
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8010A47C(undefined4 param_1,undefined4 param_2,uint param_3)
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
            (iVar2 = (**(code **)(*lbl_803DCA9C + 0x1c))(), iVar2 != 0)) &&
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


/* Trivial 4b 0-arg blr leaves. */
void CameraModeViewfinder_release(void) {}
void CameraModeViewfinder_initialise(void) {}
void fn_80109748(void) {}
void fn_80109AFC(void) {}
void fn_80109B00(void) {}
void fn_80109C14(void) {}
void CameraModeStatic_release(void) {}
void CameraModeStatic_initialise(void) {}

/* fn_X(lbl); lbl = 0; */
extern void fn_80023800(undefined4 *);
#pragma scheduling off
#pragma peephole off
void fn_8010974C(void) { fn_80023800(lbl_803DD550); lbl_803DD550 = 0; }
void fn_80109C18(void) { fn_80023800(lbl_803DD558); lbl_803DD558 = 0; }
#pragma peephole reset
#pragma scheduling reset
