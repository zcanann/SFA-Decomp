// Function: FUN_801144c0
// Entry: 801144c0
// Size: 484 bytes

/* WARNING: Removing unreachable block (ram,0x80114684) */
/* WARNING: Removing unreachable block (ram,0x8011467c) */
/* WARNING: Removing unreachable block (ram,0x80114674) */
/* WARNING: Removing unreachable block (ram,0x8011466c) */
/* WARNING: Removing unreachable block (ram,0x80114664) */
/* WARNING: Removing unreachable block (ram,0x8011465c) */
/* WARNING: Removing unreachable block (ram,0x80114654) */
/* WARNING: Removing unreachable block (ram,0x8011464c) */
/* WARNING: Removing unreachable block (ram,0x80114508) */
/* WARNING: Removing unreachable block (ram,0x80114500) */
/* WARNING: Removing unreachable block (ram,0x801144f8) */
/* WARNING: Removing unreachable block (ram,0x801144f0) */
/* WARNING: Removing unreachable block (ram,0x801144e8) */
/* WARNING: Removing unreachable block (ram,0x801144e0) */
/* WARNING: Removing unreachable block (ram,0x801144d8) */
/* WARNING: Removing unreachable block (ram,0x801144d0) */

void FUN_801144c0(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,
                 uint param_5)

{
  float *pfVar1;
  undefined4 *puVar2;
  uint uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double in_f24;
  double in_f25;
  double dVar7;
  double dVar8;
  double in_f26;
  double in_f27;
  double dVar9;
  double in_f28;
  double in_f29;
  double dVar10;
  double in_f30;
  double dVar11;
  double in_f31;
  double dVar12;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar13;
  float local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  uint uStack_b4;
  undefined4 local_b0;
  uint uStack_ac;
  float local_78;
  float fStack_74;
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
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  uVar13 = FUN_80286834();
  pfVar1 = (float *)((ulonglong)uVar13 >> 0x20);
  puVar2 = (undefined4 *)uVar13;
  dVar7 = (double)*pfVar1;
  dVar10 = (double)pfVar1[2];
  dVar6 = (double)pfVar1[1];
  dVar12 = DOUBLE_803e2918;
  for (uVar3 = 1; (int)uVar3 < (int)(param_5 + 1); uVar3 = uVar3 + 1) {
    uStack_b4 = uVar3 ^ 0x80000000;
    local_b8 = 0x43300000;
    local_b0 = 0x43300000;
    dVar9 = (double)((float)((double)CONCAT44(0x43300000,uStack_b4) - dVar12) /
                    (float)((double)CONCAT44(0x43300000,param_5 ^ 0x80000000) - dVar12));
    local_c8 = *pfVar1;
    local_c4 = *param_3;
    local_c0 = *puVar2;
    local_bc = *param_4;
    uStack_ac = param_5 ^ 0x80000000;
    dVar4 = FUN_80010de0(dVar9,&local_c8,(float *)0x0);
    dVar8 = (double)(float)(dVar4 - dVar7);
    local_c8 = pfVar1[1];
    local_c4 = param_3[1];
    local_c0 = puVar2[1];
    local_bc = param_4[1];
    dVar5 = FUN_80010de0(dVar9,&local_c8,(float *)0x0);
    dVar11 = (double)(float)(dVar5 - dVar6);
    local_c8 = pfVar1[2];
    local_c4 = param_3[2];
    local_c0 = puVar2[2];
    local_bc = param_4[2];
    dVar6 = FUN_80010de0(dVar9,&local_c8,(float *)0x0);
    dVar7 = dVar4;
    FUN_80293900((double)((float)(dVar6 - dVar10) * (float)(dVar6 - dVar10) +
                         (float)(dVar8 * dVar8 + (double)(float)(dVar11 * dVar11))));
    dVar10 = dVar6;
    dVar6 = dVar5;
  }
  FUN_80286880();
  return;
}

