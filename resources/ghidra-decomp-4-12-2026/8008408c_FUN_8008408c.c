// Function: FUN_8008408c
// Entry: 8008408c
// Size: 912 bytes

/* WARNING: Removing unreachable block (ram,0x800843fc) */
/* WARNING: Removing unreachable block (ram,0x800843f4) */
/* WARNING: Removing unreachable block (ram,0x800843ec) */
/* WARNING: Removing unreachable block (ram,0x800840ac) */
/* WARNING: Removing unreachable block (ram,0x800840a4) */
/* WARNING: Removing unreachable block (ram,0x8008409c) */

void FUN_8008408c(undefined4 param_1,undefined4 param_2,int param_3,char param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  float *pfVar4;
  float *pfVar5;
  float *pfVar6;
  double extraout_f1;
  double dVar7;
  double in_f29;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  undefined4 local_138;
  undefined4 local_134;
  float local_130;
  float local_12c;
  undefined4 local_128;
  undefined4 local_124;
  float local_120;
  float local_11c;
  undefined4 local_118;
  undefined4 local_114;
  float local_110;
  float local_10c;
  float local_108 [9];
  float local_e4 [9];
  float local_c0 [10];
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
  iVar1 = (int)((ulonglong)uVar11 >> 0x20);
  iVar3 = (int)uVar11;
  uStack_94 = (uint)*(byte *)(iVar3 + 0x2e);
  local_98 = 0x43300000;
  dVar10 = (double)(FLOAT_803dfc88 *
                   (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803dfc60));
  uStack_8c = (uint)*(byte *)(param_3 + 0x2e);
  local_90 = 0x43300000;
  dVar9 = (double)(FLOAT_803dfc88 *
                  (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803dfc60));
  local_118 = *(undefined4 *)(iVar3 + 8);
  uStack_84 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
  local_88 = 0x43300000;
  dVar8 = extraout_f1;
  dVar7 = (double)FUN_802945e0();
  local_110 = (float)(dVar10 * dVar7);
  local_114 = *(undefined4 *)(param_3 + 8);
  uStack_7c = (int)*(char *)(param_3 + 0x2c) << 8 ^ 0x80000000;
  local_80 = 0x43300000;
  dVar7 = (double)FUN_802945e0();
  local_10c = (float)(dVar9 * dVar7);
  local_128 = *(undefined4 *)(iVar3 + 0xc);
  uStack_74 = (int)*(char *)(iVar3 + 0x2d) << 8 ^ 0x80000000;
  local_78 = 0x43300000;
  dVar7 = (double)FUN_802945e0();
  local_120 = (float)(dVar10 * dVar7);
  local_124 = *(undefined4 *)(param_3 + 0xc);
  uStack_6c = (int)*(char *)(param_3 + 0x2d) << 8 ^ 0x80000000;
  local_70 = 0x43300000;
  dVar7 = (double)FUN_802945e0();
  local_11c = (float)(dVar9 * dVar7);
  local_138 = *(undefined4 *)(iVar3 + 0x10);
  uStack_64 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
  local_68 = 0x43300000;
  dVar7 = (double)FUN_80294964();
  local_130 = (float)(dVar10 * dVar7);
  local_134 = *(undefined4 *)(param_3 + 0x10);
  uStack_5c = (int)*(char *)(param_3 + 0x2c) << 8 ^ 0x80000000;
  local_60 = 0x43300000;
  dVar7 = (double)FUN_80294964();
  local_12c = (float)(dVar9 * dVar7);
  FUN_80010038(&local_118,&local_128,(int)&local_138,local_c0,local_e4,local_108,8,&LAB_80010d74);
  *(float *)(iVar1 + 8) = FLOAT_803dfc30;
  iVar2 = 0;
  pfVar5 = local_c0;
  pfVar6 = local_e4;
  pfVar4 = local_108;
  iVar3 = iVar1;
  do {
    dVar7 = FUN_80293900((double)((pfVar4[1] - *pfVar4) * (pfVar4[1] - *pfVar4) +
                                 (pfVar5[1] - *pfVar5) * (pfVar5[1] - *pfVar5) +
                                 (pfVar6[1] - *pfVar6) * (pfVar6[1] - *pfVar6)));
    *(float *)(iVar3 + 0xc) = (float)((double)*(float *)(iVar3 + 8) + dVar7);
    pfVar5 = pfVar5 + 1;
    pfVar6 = pfVar6 + 1;
    pfVar4 = pfVar4 + 1;
    iVar3 = iVar3 + 4;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 8);
  if (param_4 == '\x01') {
    dVar8 = (double)(float)(dVar8 - (double)*(float *)(iVar1 + 0x28));
  }
  *(float *)(iVar1 + 8) = (float)((double)*(float *)(iVar1 + 8) + dVar8);
  *(float *)(iVar1 + 0xc) = (float)((double)*(float *)(iVar1 + 0xc) + dVar8);
  *(float *)(iVar1 + 0x10) = (float)((double)*(float *)(iVar1 + 0x10) + dVar8);
  *(float *)(iVar1 + 0x14) = (float)((double)*(float *)(iVar1 + 0x14) + dVar8);
  *(float *)(iVar1 + 0x18) = (float)((double)*(float *)(iVar1 + 0x18) + dVar8);
  *(float *)(iVar1 + 0x1c) = (float)((double)*(float *)(iVar1 + 0x1c) + dVar8);
  *(float *)(iVar1 + 0x20) = (float)((double)*(float *)(iVar1 + 0x20) + dVar8);
  *(float *)(iVar1 + 0x24) = (float)((double)*(float *)(iVar1 + 0x24) + dVar8);
  *(float *)(iVar1 + 0x28) = (float)((double)*(float *)(iVar1 + 0x28) + dVar8);
  FUN_80286884();
  return;
}

