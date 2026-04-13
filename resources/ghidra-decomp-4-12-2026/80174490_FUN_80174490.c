// Function: FUN_80174490
// Entry: 80174490
// Size: 980 bytes

/* WARNING: Removing unreachable block (ram,0x8017483c) */
/* WARNING: Removing unreachable block (ram,0x80174834) */
/* WARNING: Removing unreachable block (ram,0x8017482c) */
/* WARNING: Removing unreachable block (ram,0x80174824) */
/* WARNING: Removing unreachable block (ram,0x8017481c) */
/* WARNING: Removing unreachable block (ram,0x80174814) */
/* WARNING: Removing unreachable block (ram,0x8017480c) */
/* WARNING: Removing unreachable block (ram,0x80174804) */
/* WARNING: Removing unreachable block (ram,0x801747fc) */
/* WARNING: Removing unreachable block (ram,0x80174798) */
/* WARNING: Removing unreachable block (ram,0x801744e0) */
/* WARNING: Removing unreachable block (ram,0x801744d8) */
/* WARNING: Removing unreachable block (ram,0x801744d0) */
/* WARNING: Removing unreachable block (ram,0x801744c8) */
/* WARNING: Removing unreachable block (ram,0x801744c0) */
/* WARNING: Removing unreachable block (ram,0x801744b8) */
/* WARNING: Removing unreachable block (ram,0x801744b0) */
/* WARNING: Removing unreachable block (ram,0x801744a8) */
/* WARNING: Removing unreachable block (ram,0x801744a0) */
/* WARNING: Removing unreachable block (ram,0x80174680) */

void FUN_80174490(int param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *unaff_r31;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  int local_e8;
  int local_e4 [3];
  undefined4 local_d8;
  uint uStack_d4;
  undefined4 local_d0;
  uint uStack_cc;
  undefined4 local_c8;
  uint uStack_c4;
  undefined4 local_c0;
  uint uStack_bc;
  undefined4 local_b8;
  uint uStack_b4;
  undefined4 local_b0;
  uint uStack_ac;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  if (((int)*(uint *)(param_1 + 0xf8) < 0) ||
     (uVar2 = FUN_80020078(*(uint *)(param_1 + 0xf8)), *(byte *)(iVar5 + 0x1f) != uVar2)) {
    local_e4[2] = (uint)*(byte *)(iVar5 + 0x18) * -0x100 ^ 0x80000000;
    local_e4[1] = 0x43300000;
    dVar7 = (double)FUN_80294964();
    uStack_d4 = (uint)*(byte *)(iVar5 + 0x18) * -0x100 ^ 0x80000000;
    local_d8 = 0x43300000;
    dVar8 = (double)FUN_802945e0();
    uStack_cc = (uint)*(byte *)(iVar5 + 0x19) * -0x100 ^ 0x80000000;
    local_d0 = 0x43300000;
    dVar9 = (double)FUN_80294964();
    uStack_c4 = (uint)*(byte *)(iVar5 + 0x19) * -0x100 ^ 0x80000000;
    local_c8 = 0x43300000;
    dVar10 = (double)FUN_802945e0();
    uStack_bc = (uint)*(byte *)(iVar5 + 0x1a);
    local_c0 = 0x43300000;
    dVar16 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x1a)) -
                            DOUBLE_803e41b8);
    uStack_b4 = (uint)*(byte *)(iVar5 + 0x1b) << 1 ^ 0x80000000;
    local_b8 = 0x43300000;
    dVar15 = (double)(float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e41b0);
    uStack_ac = (uint)*(byte *)(iVar5 + 0x1c);
    local_b0 = 0x43300000;
    dVar14 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x1c)) -
                            DOUBLE_803e41b8);
    bVar1 = *(byte *)(iVar5 + 0x22);
    if (bVar1 == 1) {
      local_e4[0] = FUN_8002ba84();
      if (local_e4[0] == 0) {
        return;
      }
      unaff_r31 = local_e4;
      local_e8 = 1;
    }
    else if (bVar1 == 0) {
      local_e4[0] = FUN_8002bac4();
      if (local_e4[0] == 0) {
        return;
      }
      unaff_r31 = local_e4;
      local_e8 = 1;
    }
    else if ((bVar1 < 3) && (unaff_r31 = FUN_80037048(5,&local_e8), unaff_r31 == (int *)0x0)) {
      return;
    }
    dVar18 = -dVar16;
    dVar17 = -dVar14;
    for (iVar4 = 0; iVar4 < local_e8; iVar4 = iVar4 + 1) {
      iVar3 = *unaff_r31;
      dVar11 = (double)(*(float *)(iVar3 + 0xc) - *(float *)(param_1 + 0xc));
      dVar12 = (double)(*(float *)(iVar3 + 0x10) - *(float *)(param_1 + 0x10));
      dVar13 = (double)(*(float *)(iVar3 + 0x14) - *(float *)(param_1 + 0x14));
      dVar6 = (double)(float)(dVar11 * dVar7 + (double)(float)(dVar13 * dVar8));
      if ((((dVar18 < dVar6) && (dVar6 < dVar16)) &&
          (dVar6 = (double)(float)(-dVar12 * dVar10 +
                                  (double)(float)((double)(float)(-dVar11 * dVar8 +
                                                                 (double)(float)(dVar13 * dVar7)) *
                                                 dVar9)), dVar17 < dVar6)) &&
         (((dVar6 < dVar14 &&
           (dVar6 = (double)(float)(dVar12 * dVar9 + (double)(float)(dVar6 * dVar10)),
           (double)FLOAT_803e41ac <= dVar6)) && (dVar6 < dVar15)))) {
        bVar1 = *(byte *)(iVar5 + 0x22);
        if (bVar1 != 1) {
          if (bVar1 == 0) {
            uStack_ac = (uint)*(byte *)(iVar5 + 0x1d);
            local_b0 = 0x43300000;
            FUN_80296078((double)(float)((double)CONCAT44(0x43300000,uStack_ac) - DOUBLE_803e41b8),
                         iVar3,1);
          }
          else if (bVar1 < 3) {
            (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,*(undefined *)(iVar5 + 0x1d));
          }
        }
      }
      unaff_r31 = unaff_r31 + 1;
    }
  }
  return;
}

