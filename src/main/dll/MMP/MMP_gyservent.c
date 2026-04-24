#include "ghidra_import.h"
#include "main/dll/MMP/MMP_gyservent.h"

extern undefined4 FUN_80017704();
extern undefined4 FUN_8001774c();
extern undefined4 FUN_80017754();
extern undefined4 FUN_80017778();
extern undefined8 FUN_800723a0();
extern undefined4 FUN_801993b0();
extern undefined4 FUN_80247bf8();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern f64 DOUBLE_803e4d68;
extern f64 DOUBLE_803e4d88;
extern f32 FLOAT_803e4d70;
extern f32 FLOAT_803e4d74;
extern f32 FLOAT_803e4d78;
extern f32 FLOAT_803e4d7c;
extern f32 FLOAT_803e4d80;

/*
 * --INFO--
 *
 * Function: FUN_80198fa4
 * EN v1.0 Address: 0x80198FA4
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x801990E4
 * EN v1.1 Size: 640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80198fa4(int param_1,float *param_2)
{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  dVar12 = (double)*param_2;
  dVar11 = (double)param_2[1];
  dVar10 = (double)param_2[2];
  dVar6 = (double)FUN_80293f90();
  dVar7 = (double)FUN_80294964();
  dVar8 = (double)FUN_80293f90();
  dVar9 = (double)FUN_80294964();
  dVar12 = (double)(float)(dVar12 - (double)*(float *)(param_1 + 0x18));
  dVar11 = (double)(float)(dVar11 - (double)*(float *)(param_1 + 0x1c));
  dVar10 = (double)(float)(dVar10 - (double)*(float *)(param_1 + 0x20));
  fVar2 = (float)(dVar12 * dVar7 - (double)(float)(dVar10 * dVar6));
  dVar6 = (double)(float)(dVar12 * dVar6 + (double)(float)(dVar10 * dVar7));
  fVar3 = (float)(dVar11 * dVar9 - (double)(float)(dVar6 * dVar8));
  fVar1 = (float)(dVar11 * dVar8 + (double)(float)(dVar6 * dVar9));
  if (fVar2 < FLOAT_803e4d70) {
    fVar2 = -fVar2;
  }
  if (fVar3 < FLOAT_803e4d70) {
    fVar3 = -fVar3;
  }
  if (fVar1 < FLOAT_803e4d70) {
    fVar1 = -fVar1;
  }
  if ((((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x3a) << 1 ^ 0x80000000) -
               DOUBLE_803e4d68) < fVar2) ||
      ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x3b) << 1 ^ 0x80000000) -
              DOUBLE_803e4d68) < fVar3)) ||
     ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x3c) << 1 ^ 0x80000000) -
             DOUBLE_803e4d68) < fVar1)) {
    uVar4 = 0;
  }
  else {
    uVar4 = 1;
  }
  return uVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_801991bc
 * EN v1.0 Address: 0x801991BC
 * EN v1.0 Size: 644b
 * EN v1.1 Address: 0x80199364
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801991bc(void)
{
  float fVar1;
  float fVar2;
  char cVar3;
  int iVar4;
  int in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps31_1;
  undefined8 uVar17;
  float local_48;
  float local_44;
  float local_40;
  longlong local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar17 = FUN_80286840();
  iVar4 = (int)((ulonglong)uVar17 >> 0x20);
  iVar5 = *(int *)(iVar4 + 0xb8);
  fVar2 = *(float *)(iVar5 + 0x18);
  dVar10 = (double)*(float *)(iVar5 + 0x14);
  fVar1 = (float)(dVar10 * (double)*(float *)(iVar5 + 0x24));
  dVar9 = (double)*(float *)(iVar5 + 0xc);
  dVar11 = (double)*(float *)(iVar5 + 0x1c);
  dVar8 = (double)*(float *)(iVar5 + 0x10);
  dVar14 = (double)(float)(dVar8 * (double)*(float *)(iVar5 + 0x20));
  dVar15 = (double)(fVar2 + fVar1 + (float)(dVar9 * dVar11 + dVar14));
  dVar16 = (double)(fVar2 + (float)(dVar10 * (double)*(float *)(iVar5 + 0x30) +
                                   (double)(float)(dVar9 * (double)*(float *)(iVar5 + 0x28) +
                                                  (double)(float)(dVar8 * (double)*(float *)(iVar5 +
                                                                                            0x2c))))
                   );
  dVar6 = (double)FLOAT_803e4d70;
  if (dVar6 <= dVar16) {
    if (dVar6 <= dVar15) {
      cVar3 = -2;
    }
    else {
      cVar3 = -1;
    }
  }
  else if (dVar6 <= dVar15) {
    cVar3 = '\x01';
  }
  else {
    cVar3 = '\x02';
  }
  if ((cVar3 == '\x01') || (cVar3 == -1)) {
    dVar15 = (double)(float)((double)*(float *)(iVar5 + 0x28) - dVar11);
    dVar12 = (double)(float)((double)*(float *)(iVar5 + 0x2c) - (double)*(float *)(iVar5 + 0x20));
    dVar13 = (double)(float)((double)*(float *)(iVar5 + 0x30) - (double)*(float *)(iVar5 + 0x24));
    dVar6 = (double)((((float)(-dVar9 * dVar11 - dVar14) - fVar1) - fVar2) /
                    (float)(dVar10 * dVar13 +
                           (double)(float)(dVar9 * dVar15 + (double)(float)(dVar8 * dVar12))));
    local_48 = (float)(dVar6 * dVar15 + dVar11);
    local_44 = (float)(dVar6 * dVar12 + (double)*(float *)(iVar5 + 0x20));
    local_40 = (float)(dVar6 * dVar13 + (double)*(float *)(iVar5 + 0x24));
    FUN_80247bf8((float *)(iVar5 + 0x38),&local_48,&local_48);
    dVar6 = (double)*(float *)(iVar5 + 0x34);
    dVar8 = -dVar6;
    if ((dVar8 <= (double)local_48) &&
       ((((double)local_48 <= dVar6 && (dVar8 <= (double)local_44)) && ((double)local_44 <= dVar6)))
       ) {
      uVar7 = FUN_800723a0();
      local_38 = (longlong)(int)dVar16;
      FUN_801993b0(uVar7,dVar8,dVar9,dVar10,dVar11,dVar15,dVar12,dVar13,iVar4,(int)uVar17,(int)cVar3
                   ,(int)dVar16,in_r7,in_r8,in_r9,in_r10);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80199440
 * EN v1.0 Address: 0x80199440
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x80199520
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80199440(ushort *param_1,int param_2)
{
  int iVar1;
  float local_c8;
  float local_c4;
  float local_c0;
  ushort local_bc;
  ushort local_ba;
  ushort local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float afStack_a4 [17];
  float afStack_60 [16];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  *param_1 = (ushort)((*(byte *)(param_2 + 0x3d) & 0x3f) << 10);
  param_1[1] = (ushort)*(byte *)(param_2 + 0x3e) << 8;
  uStack_1c = (uint)*(byte *)(param_2 + 0x3a);
  local_20 = 0x43300000;
  *(float *)(param_1 + 4) =
       *(float *)(*(int *)(param_1 + 0x28) + 4) *
       (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4d88) * FLOAT_803e4d74;
  local_bc = *param_1;
  local_ba = param_1[1];
  local_b8 = param_1[2];
  local_b4 = FLOAT_803e4d78;
  local_b0 = FLOAT_803e4d70;
  local_ac = FLOAT_803e4d70;
  local_a8 = FLOAT_803e4d70;
  FUN_80017754(afStack_a4,&local_bc);
  FUN_80017778((double)FLOAT_803e4d70,(double)FLOAT_803e4d70,(double)FLOAT_803e4d78,afStack_a4,
               &local_c0,&local_c4,&local_c8);
  *(float *)(iVar1 + 0xc) = local_c0;
  *(float *)(iVar1 + 0x10) = local_c4;
  *(float *)(iVar1 + 0x14) = local_c8;
  *(float *)(iVar1 + 0x18) =
       -(*(float *)(param_1 + 0x10) * local_c8 +
        *(float *)(param_1 + 0xc) * local_c0 + *(float *)(param_1 + 0xe) * local_c4);
  local_bc = -*param_1;
  local_ba = -param_1[1];
  local_b8 = 0;
  local_b4 = FLOAT_803e4d78;
  local_b0 = -*(float *)(param_1 + 0xc);
  local_ac = -*(float *)(param_1 + 0xe);
  local_a8 = -*(float *)(param_1 + 0x10);
  FUN_8001774c(afStack_60,(int)&local_bc);
  FUN_80017704(afStack_60,(undefined4 *)(iVar1 + 0x38));
  *(float *)(iVar1 + 0x34) = FLOAT_803e4d7c * *(float *)(param_1 + 4);
  *(float *)(iVar1 + 4) =
       FLOAT_803e4d80 * *(float *)(param_1 + 4) * FLOAT_803e4d80 * *(float *)(param_1 + 4);
  if (*(int *)(param_2 + 0x14) == 0x46a31) {
    FUN_800723a0();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019959c
 * EN v1.0 Address: 0x8019959C
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x80199704
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019959c(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5,
                 undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
  float fVar1;
  float fVar2;
  bool bVar3;
  char cVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f8;
  undefined8 local_8;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  local_8 = (double)CONCAT44(0x43300000,
                             (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x3b) << 1 ^ 0x80000000);
  dVar13 = (double)(float)(local_8 - DOUBLE_803e4d68);
  fVar2 = *(float *)(iVar5 + 0x1c) - *(float *)(param_1 + 0x18);
  dVar12 = (double)(*(float *)(iVar5 + 0x20) - *(float *)(param_1 + 0x1c));
  dVar9 = (double)*(float *)(param_1 + 0x20);
  fVar1 = (float)((double)*(float *)(iVar5 + 0x24) - dVar9);
  dVar10 = (double)(fVar2 * fVar2 + fVar1 * fVar1);
  fVar2 = *(float *)(iVar5 + 0x28) - *(float *)(param_1 + 0x18);
  dVar11 = (double)(*(float *)(iVar5 + 0x2c) - *(float *)(param_1 + 0x1c));
  fVar1 = (float)((double)*(float *)(iVar5 + 0x30) - dVar9);
  fVar1 = fVar2 * fVar2 + fVar1 * fVar1;
  dVar8 = (double)fVar1;
  dVar7 = (double)*(float *)(iVar5 + 4);
  if (dVar8 < dVar7) {
    dVar6 = dVar11;
    if (dVar11 < (double)FLOAT_803e4d70) {
      dVar6 = -dVar11;
    }
    if (dVar6 < dVar13) {
      bVar3 = false;
      if (dVar10 < dVar7) {
        dVar6 = dVar12;
        if (dVar12 < (double)FLOAT_803e4d70) {
          dVar6 = -dVar12;
        }
        if (dVar6 < dVar13) {
          bVar3 = true;
        }
      }
      if (bVar3) {
        cVar4 = '\x02';
      }
      else {
        cVar4 = '\x01';
      }
      goto LAB_80199848;
    }
  }
  bVar3 = false;
  if (dVar10 < dVar7) {
    dVar6 = dVar12;
    if (dVar12 < (double)FLOAT_803e4d70) {
      dVar6 = -dVar12;
    }
    if (dVar6 < dVar13) {
      bVar3 = true;
    }
  }
  if (bVar3) {
    cVar4 = -1;
  }
  else {
    cVar4 = -2;
  }
LAB_80199848:
  FUN_801993b0(dVar7,dVar8,dVar9,dVar10,dVar11,dVar12,dVar13,in_f8,param_1,param_2,(int)cVar4,
               (int)fVar1,param_5,param_6,param_7,param_8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80199744
 * EN v1.0 Address: 0x80199744
 * EN v1.0 Size: 260b
 * EN v1.1 Address: 0x80199868
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80199744(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5,
                 undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
  double dVar1;
  float fVar2;
  char cVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f7;
  undefined8 in_f8;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  fVar2 = *(float *)(iVar4 + 0x1c) - *(float *)(param_1 + 0x18);
  dVar10 = (double)(*(float *)(iVar4 + 0x20) - *(float *)(param_1 + 0x1c));
  dVar11 = (double)(*(float *)(iVar4 + 0x24) - *(float *)(param_1 + 0x20));
  dVar9 = (double)(float)(dVar11 * dVar11 + (double)(fVar2 * fVar2 + (float)(dVar10 * dVar10)));
  fVar2 = *(float *)(iVar4 + 0x28) - *(float *)(param_1 + 0x18);
  dVar7 = (double)(*(float *)(iVar4 + 0x2c) - *(float *)(param_1 + 0x1c));
  dVar8 = (double)(*(float *)(iVar4 + 0x30) - *(float *)(param_1 + 0x20));
  dVar1 = dVar8 * dVar8 + (double)(fVar2 * fVar2 + (float)(dVar7 * dVar7));
  dVar6 = (double)(float)dVar1;
  dVar5 = (double)*(float *)(iVar4 + 4);
  if (dVar5 <= dVar6) {
    if (dVar5 <= dVar9) {
      cVar3 = -2;
    }
    else {
      cVar3 = -1;
    }
  }
  else if (dVar5 <= dVar9) {
    cVar3 = '\x01';
  }
  else {
    cVar3 = '\x02';
  }
  FUN_801993b0(dVar6,dVar7,dVar8,dVar9,dVar10,dVar11,in_f7,in_f8,param_1,param_2,(int)cVar3,
               (int)dVar1,param_5,param_6,param_7,param_8);
  return;
}
