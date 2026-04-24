// Function: FUN_802ae5e0
// Entry: 802ae5e0
// Size: 1536 bytes

/* WARNING: Removing unreachable block (ram,0x802aebc0) */
/* WARNING: Removing unreachable block (ram,0x802aebb8) */
/* WARNING: Removing unreachable block (ram,0x802aebb0) */
/* WARNING: Removing unreachable block (ram,0x802aeba8) */
/* WARNING: Removing unreachable block (ram,0x802ae608) */
/* WARNING: Removing unreachable block (ram,0x802ae600) */
/* WARNING: Removing unreachable block (ram,0x802ae5f8) */
/* WARNING: Removing unreachable block (ram,0x802ae5f0) */

void FUN_802ae5e0(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  bool bVar7;
  double dVar8;
  double in_f28;
  double dVar9;
  double in_f29;
  double dVar10;
  double in_f30;
  double in_f31;
  double dVar11;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar12;
  float local_108;
  float local_104;
  float local_100;
  float fStack_fc;
  float local_f8;
  undefined auStack_f4 [8];
  float local_ec;
  float local_e8;
  float local_e4;
  float local_e0;
  ushort local_dc [4];
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float afStack_c4 [17];
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined8 local_70;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
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
  uVar12 = FUN_80286840();
  uVar3 = (uint)((ulonglong)uVar12 >> 0x20);
  iVar6 = (int)uVar12;
  dVar9 = (double)*(float *)(iVar6 + 0x83c);
  uStack_7c = (uint)*(ushort *)(iVar6 + 0x89c);
  local_80 = 0x43300000;
  dVar8 = (double)FUN_802945e0();
  uStack_74 = (uint)*(ushort *)(iVar6 + 0x89c);
  local_78 = 0x43300000;
  iVar4 = (int)(FLOAT_803e8dac * FLOAT_803dc074 +
               (float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e8bd0));
  local_70 = (double)(longlong)iVar4;
  *(short *)(iVar6 + 0x89c) = (short)iVar4;
  fVar1 = (float)(dVar9 + dVar8) - *(float *)(uVar3 + 0x10);
  if (FLOAT_803e8c38 < fVar1) {
    fVar1 = FLOAT_803e8c38;
  }
  *(float *)(uVar3 + 0x28) =
       (fVar1 / FLOAT_803e8c38) * FLOAT_803e8db0 * FLOAT_803dc074 + *(float *)(uVar3 + 0x28);
  *(float *)(uVar3 + 0x28) = -(FLOAT_803e8b94 * FLOAT_803dc074 - *(float *)(uVar3 + 0x28));
  dVar8 = (double)FUN_802932a4((double)FLOAT_803e8c68,(double)FLOAT_803dc074);
  *(float *)(uVar3 + 0x28) = (float)((double)*(float *)(uVar3 + 0x28) * dVar8);
  fVar1 = *(float *)(uVar3 + 0x28);
  fVar2 = FLOAT_803e8db4;
  if ((FLOAT_803e8db4 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8db8 < fVar1)) {
    fVar2 = FLOAT_803e8db8;
  }
  *(float *)(uVar3 + 0x28) = fVar2;
  FUN_802abdf0(&local_104,&local_108,uVar3);
  uStack_64 = (int)*(short *)(iVar6 + 0x478) ^ 0x80000000;
  local_68 = 0x43300000;
  dVar8 = (double)FUN_802945e0();
  uStack_5c = (int)*(short *)(iVar6 + 0x478) ^ 0x80000000;
  local_60 = 0x43300000;
  dVar9 = (double)FUN_80294964();
  fVar1 = FLOAT_803e8b94;
  *(float *)(iVar6 + 0x440) =
       FLOAT_803dc074 *
       FLOAT_803e8b94 *
       ((float)((double)local_104 * dVar9 - (double)(float)((double)local_108 * dVar8)) -
       *(float *)(iVar6 + 0x440)) + *(float *)(iVar6 + 0x440);
  *(float *)(iVar6 + 0x43c) =
       FLOAT_803dc074 *
       fVar1 * ((float)(-(double)local_108 * dVar9 - (double)(float)((double)local_104 * dVar8)) -
               *(float *)(iVar6 + 0x43c)) + *(float *)(iVar6 + 0x43c);
  bVar7 = false;
  if (*(short *)(param_3 + 0x274) == 1) {
    if ((*(uint *)(param_3 + 0x314) & 0x200) != 0) {
      FUN_8000bb00((double)*(float *)(uVar3 + 0xc),(double)*(float *)(iVar6 + 0x83c),
                   (double)*(float *)(uVar3 + 0x14),uVar3,0xe);
    }
    if ((*(float *)(iVar6 + 0x838) < FLOAT_803e8c38) && ((*(uint *)(param_3 + 0x314) & 0x200) != 0))
    {
      uStack_5c = FUN_80022264(0xffffffec,0x14);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_100 = (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e8b58) / FLOAT_803e8b70
      ;
      uStack_64 = FUN_80022264(0xffffffec,0x14);
      uStack_64 = uStack_64 ^ 0x80000000;
      local_68 = 0x43300000;
      local_f8 = (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e8b58) / FLOAT_803e8b70;
      bVar7 = true;
    }
  }
  else {
    if ((*(uint *)(param_3 + 0x314) & 1) != 0) {
      FUN_8000bb00((double)*(float *)(uVar3 + 0xc),(double)*(float *)(iVar6 + 0x83c),
                   (double)*(float *)(uVar3 + 0x14),uVar3,0xf);
    }
    if ((*(float *)(iVar6 + 0x838) < FLOAT_803e8c38) && ((*(uint *)(param_3 + 0x314) & 0x200) != 0))
    {
      uStack_5c = FUN_80022264(0xffffffec,0x14);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_100 = (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e8b58) / FLOAT_803e8b70
      ;
      local_f8 = FLOAT_803e8dbc;
      bVar7 = true;
    }
  }
  if (bVar7) {
    local_d0 = *(float *)(uVar3 + 0xc);
    local_cc = FLOAT_803e8b3c;
    local_c8 = *(float *)(uVar3 + 0x14);
    local_dc[0] = *(ushort *)(iVar6 + 0x478);
    local_dc[1] = 0;
    local_dc[2] = 0;
    local_d4 = FLOAT_803e8b78;
    FUN_80021fac(afStack_c4,local_dc);
    FUN_80022790((double)local_100,(double)FLOAT_803e8b3c,(double)local_f8,afStack_c4,&local_100,
                 &fStack_fc,&local_f8);
    (**(code **)(*DAT_803dd718 + 0x14))
              ((double)local_100,(double)*(float *)(iVar6 + 0x83c),(double)local_f8,
               (double)FLOAT_803e8b3c,0,5);
    if ((FLOAT_803e8dc0 < *(float *)(iVar6 + 0x838)) &&
       (FLOAT_803e8b34 < *(float *)(param_3 + 0x294))) {
      iVar4 = FUN_80021884();
      (**(code **)(*DAT_803dd718 + 0x18))
                ((double)local_100,(double)*(float *)(iVar6 + 0x83c),(double)local_f8,
                 (double)FLOAT_803e8b3c,(int)(short)(*(short *)(iVar6 + 0x478) - (short)iVar4));
    }
  }
  FUN_80038524(uVar3,0x13,&local_d0,&local_cc,&local_c8,0);
  bVar7 = FLOAT_803e8ba8 < *(float *)(iVar6 + 0x83c) - local_cc;
  dVar11 = (double)FLOAT_803e8c3c;
  dVar9 = (double)FLOAT_803e8d24;
  dVar10 = (double)FLOAT_803e8b3c;
  dVar8 = DOUBLE_803e8b58;
  for (iVar4 = 0; iVar4 < (int)(uint)bVar7; iVar4 = iVar4 + 1) {
    uStack_5c = FUN_80022264(0xffffff9c,100);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_e8 = local_d0 +
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - dVar8) / dVar11);
    uStack_64 = FUN_80022264(0xffffff9c,100);
    uStack_64 = uStack_64 ^ 0x80000000;
    local_68 = 0x43300000;
    local_e4 = local_cc +
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_64) - dVar8) / dVar9);
    uVar5 = FUN_80022264(0xffffff9c,100);
    local_70 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
    local_e0 = local_c8 + (float)((double)(float)(local_70 - dVar8) / dVar11);
    local_ec = *(float *)(iVar6 + 0x83c) - local_e4;
    if (dVar10 < (double)local_ec) {
      (**(code **)(*DAT_803dd708 + 8))(uVar3,0x202,auStack_f4,0x200001,0xffffffff,0);
    }
  }
  FUN_8028688c();
  return;
}

