#include "ghidra_import.h"
#include "main/dll/SH/SHrocketmushroom.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_80017688();
extern uint FUN_80017760();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjHits_GetPriorityHit();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_801d2e30();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd728;
extern f64 DOUBLE_803e6038;
extern f64 DOUBLE_803e6068;
extern f64 DOUBLE_803e6070;
extern f32 lbl_803DC074;
extern f32 lbl_803E6028;
extern f32 lbl_803E602C;
extern f32 lbl_803E6040;
extern f32 lbl_803E6044;
extern f32 lbl_803E6048;
extern f32 lbl_803E604C;
extern f32 lbl_803E6050;
extern f32 lbl_803E6054;
extern f32 lbl_803E6058;
extern f32 lbl_803E605C;
extern f32 lbl_803E6060;
extern f32 lbl_803E6078;
extern f32 lbl_803E607C;
extern f32 lbl_803E6080;
extern f32 lbl_803E6084;

/*
 * --INFO--
 *
 * Function: FUN_801d383c
 * EN v1.0 Address: 0x801D383C
 * EN v1.0 Size: 608b
 * EN v1.1 Address: 0x801D3B8C
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d383c(int param_1,int param_2)
{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  uVar1 = *(ushort *)(iVar4 + 0x1c);
  uVar2 = FUN_80017760(0,100);
  if ((int)uVar2 < 10) {
    if (*(float *)(param_2 + 0x2a0) <= lbl_803E602C) {
      uVar2 = FUN_80017760(2000,4000);
      *(short *)(param_2 + 0x2ac) = (short)uVar2;
      uVar2 = FUN_80017760(0,1);
      if (uVar2 != 0) {
        *(short *)(param_2 + 0x2ac) = -*(short *)(param_2 + 0x2ac);
      }
      *(short *)(param_2 + 0x2ac) = *(short *)(param_2 + 0x2ac) + *(short *)(param_2 + 0x2a8);
      iVar3 = (int)*(short *)(param_2 + 0x2ac) - (uint)uVar1;
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      if (*(short *)(iVar4 + 0x1a) < iVar3) {
        *(ushort *)(param_2 + 0x2ac) = uVar1 + *(short *)(iVar4 + 0x1a);
      }
      if (iVar3 < -(int)*(short *)(iVar4 + 0x1a)) {
        *(ushort *)(param_2 + 0x2ac) = uVar1 - *(short *)(iVar4 + 0x1a);
      }
      *(float *)(param_2 + 0x2a0) = lbl_803E6040;
    }
  }
  uVar2 = FUN_80017760(0,100);
  if ((int)uVar2 < 10) {
    if (*(float *)(param_2 + 0x2a0) <= lbl_803E602C) {
      uVar2 = FUN_80017760(0xffffff38,200);
      *(float *)(param_2 + 0x280) =
           *(float *)(param_2 + 0x278) +
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6038) /
           lbl_803E6028;
      if (lbl_803E6044 <= *(float *)(param_2 + 0x280)) {
        if (lbl_803E6048 < *(float *)(param_2 + 0x280)) {
          *(float *)(param_2 + 0x280) = lbl_803E6048;
        }
      }
      else {
        *(float *)(param_2 + 0x280) = lbl_803E6044;
      }
    }
  }
  iVar4 = (int)*(short *)(param_2 + 0x2ac) - (uint)*(ushort *)(param_2 + 0x2a8);
  if (0x8000 < iVar4) {
    iVar4 = iVar4 + -0xffff;
  }
  if (iVar4 < -0x8000) {
    iVar4 = iVar4 + 0xffff;
  }
  *(short *)(param_2 + 0x2a8) =
       *(short *)(param_2 + 0x2a8) + (short)((int)(iVar4 * (uint)DAT_803dc070) >> 4);
  *(float *)(param_2 + 0x278) =
       lbl_803E604C * (*(float *)(param_2 + 0x280) - *(float *)(param_2 + 0x278)) * lbl_803DC074
       + *(float *)(param_2 + 0x278);
  dVar5 = (double)FUN_80293f90();
  *(float *)(param_2 + 0x288) = (float)((double)*(float *)(param_2 + 0x278) * dVar5);
  dVar5 = (double)FUN_80294964();
  *(float *)(param_2 + 0x28c) = (float)((double)*(float *)(param_2 + 0x278) * dVar5);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d3a9c
 * EN v1.0 Address: 0x801D3A9C
 * EN v1.0 Size: 1840b
 * EN v1.1 Address: 0x801D3E2C
 * EN v1.1 Size: 1520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d3a9c(double param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  float fVar1;
  short sVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  uint in_r7;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  undefined2 *puVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined4 uStack_28;
  uint uStack_24;
  uint local_20 [2];
  longlong local_18;
  
  puVar8 = *(undefined2 **)(param_9 + 0x5c);
  if ((*(byte *)(puVar8 + 0x158) >> 6 & 1) != 0) {
    while (iVar5 = ObjMsg_Pop((int)param_9,local_20,&uStack_24,(uint *)0x0), iVar5 != 0) {
      if (local_20[0] == 0x7000b) {
        FUN_80017688(0x66c);
        FUN_80006824((uint)param_9,0xa7);
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_9);
        iVar5 = 0;
        do {
          FUN_800810f4((double)lbl_803E6048,(double)lbl_803E6050,param_9,5,7,1,0x3c,0,0);
          in_r7 = 0xffffffff;
          in_r8 = 0;
          in_r9 = *DAT_803dd708;
          (**(code **)(in_r9 + 8))(param_9,0x3f3,0,4);
          iVar5 = iVar5 + 1;
        } while (iVar5 < 10);
        FUN_800175cc((double)lbl_803E6044,*(int *)(puVar8 + 0x138),'\0');
        *(float *)(puVar8 + 0x152) = lbl_803E6054;
        param_9[3] = param_9[3] | 0x4000;
        param_1 = (double)ObjHits_DisableObject((int)param_9);
        *(byte *)(puVar8 + 0x158) = *(byte *)(puVar8 + 0x158) & 0xbf;
      }
    }
    if ((*(byte *)(puVar8 + 0x158) >> 6 & 1) != 0) {
      return;
    }
  }
  dVar9 = (double)lbl_803E602C;
  if ((double)*(float *)(puVar8 + 0x152) == dVar9) {
    dVar11 = (double)*(float *)(puVar8 + 0x13a);
    dVar10 = (double)lbl_803E6058;
    if (dVar11 < dVar10) {
      in_r7 = (uint)-(float)((double)lbl_803E6060 * dVar11 - (double)lbl_803E605C);
      local_18 = (longlong)(int)in_r7;
      in_r7 = in_r7 & 0xff;
      dVar9 = (double)(float)(DOUBLE_803e6070 * (double)(float)(dVar10 - dVar11) + DOUBLE_803e6068);
      in_r8 = 0;
      in_r9 = 0;
      param_3 = DOUBLE_803e6070;
      param_1 = (double)FUN_800810f4((double)lbl_803E6048,dVar9,param_9,5,7,1,in_r7,0,0);
    }
    ObjHits_GetPriorityHit((int)param_9,&uStack_28,(int *)0x0,(uint *)0x0);
    iVar5 = **(int **)(param_9 + 0x2a);
    if (-1 < *(char *)(puVar8 + 0x158)) {
      *(float *)(puVar8 + 0x142) = *(float *)(puVar8 + 0x142) - lbl_803DC074;
      if (*(float *)(puVar8 + 0x142) < lbl_803E602C) {
        *(float *)(puVar8 + 0x142) = lbl_803E602C;
      }
      *(float *)(puVar8 + 0x150) = *(float *)(puVar8 + 0x150) - lbl_803DC074;
      if (*(float *)(puVar8 + 0x150) < lbl_803E602C) {
        *(float *)(puVar8 + 0x150) = lbl_803E602C;
      }
      *param_9 = *param_9 + puVar8[0x157];
      *(float *)(param_9 + 0x14) = lbl_803E6078 * lbl_803DC074 + *(float *)(param_9 + 0x14);
      if (*(float *)(param_9 + 0x14) < lbl_803E607C) {
        *(float *)(param_9 + 0x14) = lbl_803E607C;
      }
      if (lbl_803E602C < *(float *)(param_9 + 0x14)) {
        *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) * lbl_803E6080;
      }
      if (*(float *)(param_9 + 0x14) < lbl_803E602C) {
        ObjHits_EnableObject((int)param_9);
      }
      FUN_801d383c((int)param_9,(int)puVar8);
      uVar6 = FUN_80017760(0,100);
      if (((int)uVar6 < 5) && (*(float *)(puVar8 + 0x142) <= lbl_803E602C)) {
        FUN_801d2e30((int)param_9,(int)puVar8);
      }
      fVar1 = *(float *)(puVar8 + 0x14c) - lbl_803DC074;
      *(float *)(puVar8 + 0x14c) = fVar1;
      fVar4 = lbl_803E6080;
      fVar3 = lbl_803E602C;
      if (lbl_803E602C < fVar1) {
        *(float *)(puVar8 + 0x13e) =
             lbl_803E6084 * (*(float *)(puVar8 + 0x14e) - *(float *)(puVar8 + 0x13e)) *
             lbl_803DC074 + *(float *)(puVar8 + 0x13e);
      }
      else {
        *(float *)(puVar8 + 0x148) = *(float *)(puVar8 + 0x148) * lbl_803E6080;
        *(float *)(puVar8 + 0x14a) = *(float *)(puVar8 + 0x14a) * fVar4;
        *(float *)(puVar8 + 0x14c) = fVar3;
      }
      *(float *)(param_9 + 0x12) =
           *(float *)(puVar8 + 0x148) * *(float *)(puVar8 + 0x13e) + *(float *)(puVar8 + 0x144);
      *(float *)(param_9 + 0x16) =
           *(float *)(puVar8 + 0x14a) * *(float *)(puVar8 + 0x13e) + *(float *)(puVar8 + 0x146);
      dVar9 = (double)(*(float *)(param_9 + 0x14) * lbl_803DC074);
      param_3 = (double)(*(float *)(param_9 + 0x16) * lbl_803DC074);
      FUN_80017a88((double)(*(float *)(param_9 + 0x12) * lbl_803DC074),dVar9,param_3,(int)param_9)
      ;
      (**(code **)(*DAT_803dd728 + 0x10))((double)lbl_803DC074,param_9,puVar8 + 4);
      (**(code **)(*DAT_803dd728 + 0x14))(param_9,puVar8 + 4);
      param_1 = (double)(**(code **)(*DAT_803dd728 + 0x18))
                                  ((double)lbl_803DC074,param_9,puVar8 + 4);
      if ((((iVar5 != 0) && (sVar2 = *(short *)(iVar5 + 0x46), sVar2 != 0x36d)) && (sVar2 != 0x198))
         && (sVar2 != 0x63c)) {
        FUN_80006824((uint)param_9,0x59);
        *(byte *)(puVar8 + 0x158) = *(byte *)(puVar8 + 0x158) & 0x7f | 0x80;
        param_1 = (double)*(float *)(puVar8 + 0x13a);
        if ((double)lbl_803E6058 < param_1) {
          *(float *)(puVar8 + 0x13a) = lbl_803E6058;
        }
      }
      if ((*(byte *)(puVar8 + 0x134) & 0x11) != 0) {
        *(byte *)(puVar8 + 0x158) = *(byte *)(puVar8 + 0x158) & 0x7f | 0x80;
        param_1 = (double)*(float *)(puVar8 + 0x13a);
        if ((double)lbl_803E6058 < param_1) {
          *(float *)(puVar8 + 0x13a) = lbl_803E6058;
        }
      }
    }
    iVar7 = FUN_80017a98();
    if (iVar5 == iVar7) {
      *puVar8 = 0x18e;
      ObjMsg_SendToObject(param_1,dVar9,param_3,dVar10,dVar11,param_6,param_7,param_8,iVar5,0x7000a,
                   (uint)param_9,(uint)puVar8,in_r7,in_r8,in_r9,in_r10);
      *(byte *)(puVar8 + 0x158) = *(byte *)(puVar8 + 0x158) & 0xbf | 0x40;
    }
    else {
      fVar1 = *(float *)(puVar8 + 0x13a) - lbl_803DC074;
      *(float *)(puVar8 + 0x13a) = fVar1;
      if (fVar1 <= lbl_803E602C) {
        FUN_80006824((uint)param_9,0xa2);
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_9);
        iVar5 = 0;
        do {
          FUN_800810f4((double)lbl_803E6048,(double)lbl_803E6050,param_9,5,7,1,0x3c,0,0);
          (**(code **)(*DAT_803dd708 + 8))(param_9,0x3f3,0,4,0xffffffff,0);
          iVar5 = iVar5 + 1;
        } while (iVar5 < 10);
        FUN_800175cc((double)lbl_803E6044,*(int *)(puVar8 + 0x138),'\0');
        *(float *)(puVar8 + 0x152) = lbl_803E6054;
        param_9[3] = param_9[3] | 0x4000;
        ObjHits_DisableObject((int)param_9);
      }
    }
  }
  else {
    *param_9 = *param_9 + (ushort)DAT_803dc070 * 0x40;
    fVar1 = *(float *)(puVar8 + 0x152);
    *(float *)(puVar8 + 0x152) = (float)((double)fVar1 - (double)lbl_803DC074);
    if ((double)*(float *)(puVar8 + 0x152) <= dVar9) {
      FUN_80017ac8((double)fVar1,dVar9,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9)
      ;
    }
  }
  return;
}
