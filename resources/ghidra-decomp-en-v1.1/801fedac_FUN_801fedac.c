// Function: FUN_801fedac
// Entry: 801fedac
// Size: 612 bytes

/* WARNING: Removing unreachable block (ram,0x801feff0) */
/* WARNING: Removing unreachable block (ram,0x801fefe8) */
/* WARNING: Removing unreachable block (ram,0x801fefe0) */
/* WARNING: Removing unreachable block (ram,0x801fefd8) */
/* WARNING: Removing unreachable block (ram,0x801fedd4) */
/* WARNING: Removing unreachable block (ram,0x801fedcc) */
/* WARNING: Removing unreachable block (ram,0x801fedc4) */
/* WARNING: Removing unreachable block (ram,0x801fedbc) */

void FUN_801fedac(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 *puVar4;
  float *pfVar5;
  int iVar6;
  short *psVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double in_f28;
  double in_f29;
  double dVar11;
  double in_f30;
  double in_f31;
  double dVar12;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar13;
  uint local_78 [2];
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
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
  uVar13 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar13 >> 0x20);
  pfVar5 = (float *)uVar13;
  dVar11 = (double)FLOAT_803e6e60;
  dVar9 = dVar11;
  puVar4 = FUN_80037048(0x14,(int *)local_78);
  dVar12 = (double)FLOAT_803e6e80;
  for (iVar6 = 0; fVar1 = FLOAT_803e6e98, iVar6 < (int)local_78[0]; iVar6 = iVar6 + 1) {
    psVar7 = (short *)*puVar4;
    dVar8 = (double)(*(float *)(psVar7 + 8) - *(float *)(iVar3 + 0x10));
    if ((dVar8 <= dVar12) && ((double)FLOAT_803e6e84 <= dVar8)) {
      fVar1 = *(float *)(psVar7 + 6) - *(float *)(iVar3 + 0xc);
      fVar2 = *(float *)(psVar7 + 10) - *(float *)(iVar3 + 0x14);
      dVar8 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
      uStack_6c = (uint)*(byte *)(*(int *)(psVar7 + 0x26) + 0x19);
      local_70 = 0x43300000;
      dVar10 = (double)(FLOAT_803e6e88 *
                       (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e6e70));
      if (dVar8 < dVar10) {
        dVar10 = (double)((float)((double)(float)(dVar10 - dVar8) / dVar10) *
                         FLOAT_803e6e8c * *(float *)(psVar7 + 4));
        uStack_6c = (int)*psVar7 ^ 0x80000000;
        local_70 = 0x43300000;
        dVar8 = (double)FUN_802945e0();
        dVar9 = (double)(float)(dVar10 * dVar8 + dVar9);
        uStack_64 = (int)*psVar7 ^ 0x80000000;
        local_68 = 0x43300000;
        dVar8 = (double)FUN_80294964();
        dVar11 = (double)(float)(dVar10 * dVar8 + dVar11);
      }
    }
    puVar4 = puVar4 + 1;
  }
  if (local_78[0] != 0) {
    uStack_6c = local_78[0] ^ 0x80000000;
    local_68 = 0x43300000;
    local_70 = 0x43300000;
    dVar12 = (double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e6ea8;
    *pfVar5 = -(FLOAT_803e6e98 *
                (float)(dVar9 / (double)(float)((double)CONCAT44(0x43300000,uStack_6c) -
                                               DOUBLE_803e6ea8)) - *pfVar5);
    pfVar5[2] = -(fVar1 * (float)(dVar11 / (double)(float)dVar12) - pfVar5[2]);
    fVar1 = FLOAT_803e6e9c;
    *pfVar5 = *pfVar5 * FLOAT_803e6e9c;
    pfVar5[2] = pfVar5[2] * fVar1;
    uStack_64 = uStack_6c;
    dVar9 = FUN_80293900((double)(*pfVar5 * *pfVar5 + pfVar5[2] * pfVar5[2]));
    if ((double)FLOAT_803e6ea0 < dVar9) {
      fVar1 = (float)((double)FLOAT_803e6ea0 / dVar9);
      *pfVar5 = *pfVar5 * fVar1;
      pfVar5[2] = pfVar5[2] * fVar1;
    }
  }
  FUN_8028688c();
  return;
}

