// Function: FUN_80084744
// Entry: 80084744
// Size: 1328 bytes

/* WARNING: Removing unreachable block (ram,0x80084c54) */
/* WARNING: Removing unreachable block (ram,0x80084c4c) */
/* WARNING: Removing unreachable block (ram,0x80084c44) */
/* WARNING: Removing unreachable block (ram,0x80084764) */
/* WARNING: Removing unreachable block (ram,0x8008475c) */
/* WARNING: Removing unreachable block (ram,0x80084754) */

void FUN_80084744(undefined4 param_1,undefined4 param_2,float *param_3,short *param_4,char param_5)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  float *pfVar5;
  int iVar6;
  double in_f29;
  double dVar7;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  float local_d8;
  float fStack_d4;
  float local_d0;
  float local_cc;
  undefined4 local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  undefined4 local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  undefined4 local_a8;
  float local_a4;
  float local_a0;
  undefined4 local_98;
  uint uStack_94;
  undefined4 local_90;
  uint uStack_8c;
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
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
  uVar11 = FUN_80286838();
  piVar1 = (int *)((ulonglong)uVar11 >> 0x20);
  pfVar5 = (float *)uVar11;
  dVar7 = (double)pfVar5[2];
  FUN_8008441c(dVar7,piVar1);
  iVar2 = (**(code **)(*DAT_803dd71c + 0x1c))(*piVar1);
  if ((iVar2 == 0) || (piVar1[1] < 0)) {
    if (iVar2 == 0) {
      iVar2 = (**(code **)(*DAT_803dd71c + 0x1c))(piVar1[1]);
    }
    if (iVar2 != 0) {
      *param_3 = *(float *)(iVar2 + 8);
      if (param_5 == '\0') {
        param_3[1] = *(float *)(iVar2 + 0xc) + pfVar5[1];
      }
      param_3[2] = *(float *)(iVar2 + 0x10);
      uStack_54 = (int)*(char *)(iVar2 + 0x2c) << 8 ^ 0x80000000;
      local_58 = 0x43300000;
      dVar7 = (double)FUN_80294964();
      *param_3 = (float)((double)*pfVar5 * dVar7 + (double)*param_3);
      uStack_5c = (int)*(char *)(iVar2 + 0x2c) << 8 ^ 0x80000000;
      local_60 = 0x43300000;
      dVar7 = (double)FUN_802945e0();
      param_3[2] = (float)((double)*pfVar5 * dVar7 + (double)param_3[2]);
      *param_4 = (short)((int)*(char *)(iVar2 + 0x2c) << 8) + -0x8000;
    }
  }
  else {
    iVar3 = (**(code **)(*DAT_803dd71c + 0x1c))();
    iVar6 = 0;
    for (piVar4 = piVar1; (iVar6 < 9 && ((double)(float)piVar4[2] <= dVar7)); piVar4 = piVar4 + 1) {
      iVar6 = iVar6 + 1;
    }
    uStack_94 = iVar6 - 1U ^ 0x80000000;
    local_98 = 0x43300000;
    dVar10 = (double)(((float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803dfc38) +
                      (float)(dVar7 - (double)(float)piVar1[iVar6 + 1]) /
                      (float)((double)(float)piVar1[iVar6 + 2] - (double)(float)piVar1[iVar6 + 1]))
                     * FLOAT_803dfc9c);
    uStack_8c = (uint)*(byte *)(iVar2 + 0x2e);
    local_90 = 0x43300000;
    dVar9 = (double)(FLOAT_803dfc88 *
                    (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803dfc60));
    uStack_84 = (uint)*(byte *)(iVar3 + 0x2e);
    local_88 = 0x43300000;
    dVar8 = (double)(FLOAT_803dfc88 *
                    (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803dfc60));
    local_ac = *(float *)(iVar2 + 8);
    uStack_7c = (int)*(char *)(iVar2 + 0x2c) << 8 ^ 0x80000000;
    local_80 = 0x43300000;
    dVar7 = (double)FUN_802945e0();
    local_a4 = (float)(dVar9 * dVar7);
    local_a8 = *(undefined4 *)(iVar3 + 8);
    uStack_74 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
    local_78 = 0x43300000;
    dVar7 = (double)FUN_802945e0();
    local_a0 = (float)(dVar8 * dVar7);
    local_bc = *(float *)(iVar2 + 0xc);
    uStack_6c = (int)*(char *)(iVar2 + 0x2d) << 8 ^ 0x80000000;
    local_70 = 0x43300000;
    dVar7 = (double)FUN_802945e0();
    local_b4 = (float)(dVar9 * dVar7);
    local_b8 = *(undefined4 *)(iVar3 + 0xc);
    uStack_64 = (int)*(char *)(iVar3 + 0x2d) << 8 ^ 0x80000000;
    local_68 = 0x43300000;
    dVar7 = (double)FUN_802945e0();
    local_b0 = (float)(dVar8 * dVar7);
    local_cc = *(float *)(iVar2 + 0x10);
    uStack_5c = (int)*(char *)(iVar2 + 0x2c) << 8 ^ 0x80000000;
    local_60 = 0x43300000;
    dVar7 = (double)FUN_80294964();
    local_c4 = (float)(dVar9 * dVar7);
    local_c8 = *(undefined4 *)(iVar3 + 0x10);
    uStack_54 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
    local_58 = 0x43300000;
    dVar7 = (double)FUN_80294964();
    local_c0 = (float)(dVar8 * dVar7);
    dVar7 = FUN_80010de0(dVar10,&local_ac,&local_d0);
    *param_3 = (float)dVar7;
    if (param_5 == '\0') {
      dVar7 = FUN_80010de0(dVar10,&local_bc,&fStack_d4);
      param_3[1] = (float)dVar7;
    }
    dVar7 = FUN_80010de0(dVar10,&local_cc,&local_d8);
    param_3[2] = (float)dVar7;
    dVar7 = FUN_80293900((double)(local_d0 * local_d0 + local_d8 * local_d8));
    if ((double)FLOAT_803dfca0 < dVar7) {
      dVar7 = (double)(float)((double)*pfVar5 / dVar7);
      iVar2 = FUN_80021884();
      *param_4 = (short)iVar2 + -0x8000;
      local_d0 = (float)((double)local_d0 * dVar7);
      local_d8 = (float)((double)local_d8 * dVar7);
      *param_3 = *param_3 + local_d8;
      param_3[2] = param_3[2] - local_d0;
      if (param_5 == '\0') {
        param_3[1] = param_3[1] + pfVar5[1];
      }
    }
  }
  FUN_80286884();
  return;
}

