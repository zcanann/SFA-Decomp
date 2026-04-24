// Function: FUN_802abdf0
// Entry: 802abdf0
// Size: 1112 bytes

/* WARNING: Removing unreachable block (ram,0x802ac228) */
/* WARNING: Removing unreachable block (ram,0x802ac220) */
/* WARNING: Removing unreachable block (ram,0x802ac218) */
/* WARNING: Removing unreachable block (ram,0x802ac210) */
/* WARNING: Removing unreachable block (ram,0x802ac208) */
/* WARNING: Removing unreachable block (ram,0x802ac200) */
/* WARNING: Removing unreachable block (ram,0x802ac1f8) */
/* WARNING: Removing unreachable block (ram,0x802ac1f0) */
/* WARNING: Removing unreachable block (ram,0x802abe38) */
/* WARNING: Removing unreachable block (ram,0x802abe30) */
/* WARNING: Removing unreachable block (ram,0x802abe28) */
/* WARNING: Removing unreachable block (ram,0x802abe20) */
/* WARNING: Removing unreachable block (ram,0x802abe18) */
/* WARNING: Removing unreachable block (ram,0x802abe10) */
/* WARNING: Removing unreachable block (ram,0x802abe08) */
/* WARNING: Removing unreachable block (ram,0x802abe00) */

void FUN_802abdf0(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float *pfVar3;
  undefined4 *puVar4;
  int *piVar5;
  int iVar6;
  short *psVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double in_f24;
  double in_f25;
  double dVar15;
  double dVar16;
  double in_f26;
  double dVar17;
  double in_f27;
  double dVar18;
  double in_f28;
  double in_f29;
  double in_f30;
  double dVar19;
  double in_f31;
  double dVar20;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar21;
  int local_c8 [2];
  undefined4 local_c0;
  uint uStack_bc;
  undefined4 local_b8;
  uint uStack_b4;
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
  uVar21 = FUN_8028682c();
  pfVar3 = (float *)((ulonglong)uVar21 >> 0x20);
  iVar9 = *(int *)(param_3 + 0xb8);
  dVar18 = (double)FLOAT_803e8b3c;
  dVar14 = dVar18;
  puVar4 = FUN_80037048(0x14,local_c8);
  uVar10 = 0;
  for (iVar11 = 0; iVar11 < local_c8[0]; iVar11 = iVar11 + 1) {
    psVar7 = (short *)*puVar4;
    if ((*(byte *)(*(int *)(psVar7 + 0x26) + 0x1a) & 2) != 0) {
      uVar10 = 1;
      fVar1 = *(float *)(psVar7 + 8) - *(float *)(param_3 + 0x10);
      if ((fVar1 <= FLOAT_803e8ce8) && (FLOAT_803e8d88 <= fVar1)) {
        fVar1 = *(float *)(psVar7 + 6) - *(float *)(param_3 + 0xc);
        fVar2 = *(float *)(psVar7 + 10) - *(float *)(param_3 + 0x14);
        dVar12 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
        uStack_bc = (uint)*(byte *)(*(int *)(psVar7 + 0x26) + 0x19);
        local_c0 = 0x43300000;
        dVar19 = (double)(FLOAT_803e8c5c *
                         (float)((double)CONCAT44(0x43300000,uStack_bc) - DOUBLE_803e8bd0));
        if (dVar12 < dVar19) {
          dVar20 = (double)FLOAT_803e8b3c;
          if (dVar20 < dVar19) {
            dVar20 = (double)(float)((double)(float)(dVar19 - dVar12) / dVar19);
          }
          dVar19 = (double)(float)(dVar20 * (double)(FLOAT_803e8b70 * *(float *)(psVar7 + 4)));
          uStack_bc = (int)*psVar7 ^ 0x80000000;
          local_c0 = 0x43300000;
          dVar12 = (double)FUN_802945e0();
          dVar14 = (double)(float)(dVar19 * dVar12 + dVar14);
          uStack_b4 = (int)*psVar7 ^ 0x80000000;
          local_b8 = 0x43300000;
          dVar12 = (double)FUN_80294964();
          dVar18 = (double)(float)(dVar19 * dVar12 + dVar18);
        }
      }
    }
    puVar4 = puVar4 + 1;
  }
  piVar5 = FUN_80037048(0x50,local_c8);
  dVar19 = (double)FLOAT_803e8b70;
  dVar20 = (double)FLOAT_803e8ce8;
  dVar12 = DOUBLE_803e8bd0;
  for (iVar11 = 0; fVar2 = FLOAT_803e8c04, fVar1 = FLOAT_803e8b3c, iVar11 < local_c8[0];
      iVar11 = iVar11 + 1) {
    iVar8 = *piVar5;
    uStack_b4 = (uint)*(byte *)(*(int *)(iVar8 + 0x4c) + 0x32);
    local_b8 = 0x43300000;
    dVar17 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_b4) - dVar12) /
                            dVar19);
    uVar10 = 1;
    dVar13 = (double)(*(float *)(iVar8 + 0x10) - *(float *)(param_3 + 0x10));
    if ((dVar13 <= dVar20) && ((double)FLOAT_803e8d88 <= dVar13)) {
      dVar15 = (double)(*(float *)(iVar8 + 0xc) - *(float *)(param_3 + 0xc));
      dVar13 = (double)(*(float *)(iVar8 + 0x14) - *(float *)(param_3 + 0x14));
      iVar6 = FUN_80021884();
      dVar13 = FUN_80293900((double)(float)(dVar15 * dVar15 + (double)(float)(dVar13 * dVar13)));
      uStack_b4 = (uint)*(byte *)(*(int *)(iVar8 + 0x4c) + 0x29) << 3 ^ 0x80000000;
      local_b8 = 0x43300000;
      dVar15 = (double)(float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e8b58);
      if (dVar13 < dVar15) {
        dVar16 = (double)FLOAT_803e8b3c;
        if (dVar16 < dVar15) {
          dVar16 = (double)(float)((double)(float)(dVar15 - dVar13) / dVar15);
        }
        dVar17 = (double)(float)(dVar16 * dVar17);
        uStack_b4 = (int)(short)((short)iVar6 + -0x7b30) ^ 0x80000000;
        local_b8 = 0x43300000;
        dVar13 = (double)FUN_802945e0();
        dVar14 = (double)(float)(dVar17 * dVar13 + dVar14);
        dVar13 = (double)FUN_80294964();
        dVar18 = (double)(float)(dVar17 * dVar13 + dVar18);
      }
    }
    piVar5 = piVar5 + 1;
  }
  if (uVar10 == 0) {
    *pfVar3 = FLOAT_803e8b3c;
    *(float *)uVar21 = fVar1;
  }
  else {
    uStack_bc = uVar10 ^ 0x80000000;
    local_b8 = 0x43300000;
    local_c0 = 0x43300000;
    dVar12 = (double)CONCAT44(0x43300000,uStack_bc) - DOUBLE_803e8b58;
    *(float *)(iVar9 + 0x648) =
         -(FLOAT_803e8c04 *
           (float)(dVar14 / (double)(float)((double)CONCAT44(0x43300000,uStack_bc) - DOUBLE_803e8b58
                                           )) - *(float *)(iVar9 + 0x648));
    *(float *)(iVar9 + 0x64c) =
         -(fVar2 * (float)(dVar18 / (double)(float)dVar12) - *(float *)(iVar9 + 0x64c));
    fVar1 = FLOAT_803e8c00;
    *(float *)(iVar9 + 0x648) = *(float *)(iVar9 + 0x648) * FLOAT_803e8c00;
    *(float *)(iVar9 + 0x64c) = *(float *)(iVar9 + 0x64c) * fVar1;
    uStack_b4 = uStack_bc;
    dVar14 = FUN_80293900((double)(*(float *)(iVar9 + 0x648) * *(float *)(iVar9 + 0x648) +
                                  *(float *)(iVar9 + 0x64c) * *(float *)(iVar9 + 0x64c)));
    if ((double)FLOAT_803e8bb4 < dVar14) {
      fVar1 = (float)((double)FLOAT_803e8bb4 / dVar14);
      *(float *)(iVar9 + 0x648) = *(float *)(iVar9 + 0x648) * fVar1;
      *(float *)(iVar9 + 0x64c) = *(float *)(iVar9 + 0x64c) * fVar1;
    }
    *pfVar3 = *(float *)(iVar9 + 0x648) * FLOAT_803dc074;
    *(float *)uVar21 = *(float *)(iVar9 + 0x64c) * FLOAT_803dc074;
  }
  FUN_80286878();
  return;
}

