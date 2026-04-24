// Function: FUN_80173fe4
// Entry: 80173fe4
// Size: 980 bytes

/* WARNING: Removing unreachable block (ram,0x80174388) */
/* WARNING: Removing unreachable block (ram,0x80174378) */
/* WARNING: Removing unreachable block (ram,0x80174368) */
/* WARNING: Removing unreachable block (ram,0x80174358) */
/* WARNING: Removing unreachable block (ram,0x801742ec) */
/* WARNING: Removing unreachable block (ram,0x801741d4) */
/* WARNING: Removing unreachable block (ram,0x80174350) */
/* WARNING: Removing unreachable block (ram,0x80174360) */
/* WARNING: Removing unreachable block (ram,0x80174370) */
/* WARNING: Removing unreachable block (ram,0x80174380) */
/* WARNING: Removing unreachable block (ram,0x80174390) */

void FUN_80173fe4(int param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *unaff_r31;
  undefined4 uVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  undefined8 in_f23;
  double dVar15;
  undefined8 in_f24;
  double dVar16;
  undefined8 in_f25;
  double dVar17;
  undefined8 in_f26;
  double dVar18;
  undefined8 in_f27;
  double dVar19;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  int local_e8;
  int local_e4;
  undefined4 local_e0;
  uint uStack220;
  undefined4 local_d8;
  uint uStack212;
  undefined4 local_d0;
  uint uStack204;
  undefined4 local_c8;
  uint uStack196;
  undefined4 local_c0;
  uint uStack188;
  undefined4 local_b8;
  uint uStack180;
  undefined4 local_b0;
  uint uStack172;
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  __psq_st0(auStack136,(int)((ulonglong)in_f23 >> 0x20),0);
  __psq_st1(auStack136,(int)in_f23,0);
  iVar5 = *(int *)(param_1 + 0x4c);
  if ((*(int *)(param_1 + 0xf8) < 0) || (uVar2 = FUN_8001ffb4(), *(byte *)(iVar5 + 0x1f) != uVar2))
  {
    uStack220 = (uint)*(byte *)(iVar5 + 0x18) * -0x100 ^ 0x80000000;
    local_e0 = 0x43300000;
    dVar8 = (double)FUN_80294204((double)((FLOAT_803e350c *
                                          (float)((double)CONCAT44(0x43300000,uStack220) -
                                                 DOUBLE_803e3518)) / FLOAT_803e3510));
    uStack212 = (uint)*(byte *)(iVar5 + 0x18) * -0x100 ^ 0x80000000;
    local_d8 = 0x43300000;
    dVar9 = (double)FUN_80293e80((double)((FLOAT_803e350c *
                                          (float)((double)CONCAT44(0x43300000,uStack212) -
                                                 DOUBLE_803e3518)) / FLOAT_803e3510));
    uStack204 = (uint)*(byte *)(iVar5 + 0x19) * -0x100 ^ 0x80000000;
    local_d0 = 0x43300000;
    dVar10 = (double)FUN_80294204((double)((FLOAT_803e350c *
                                           (float)((double)CONCAT44(0x43300000,uStack204) -
                                                  DOUBLE_803e3518)) / FLOAT_803e3510));
    uStack196 = (uint)*(byte *)(iVar5 + 0x19) * -0x100 ^ 0x80000000;
    local_c8 = 0x43300000;
    dVar11 = (double)FUN_80293e80((double)((FLOAT_803e350c *
                                           (float)((double)CONCAT44(0x43300000,uStack196) -
                                                  DOUBLE_803e3518)) / FLOAT_803e3510));
    uStack188 = (uint)*(byte *)(iVar5 + 0x1a);
    local_c0 = 0x43300000;
    dVar17 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x1a)) -
                            DOUBLE_803e3520);
    uStack180 = (uint)*(byte *)(iVar5 + 0x1b) << 1 ^ 0x80000000;
    local_b8 = 0x43300000;
    dVar16 = (double)(float)((double)CONCAT44(0x43300000,uStack180) - DOUBLE_803e3518);
    uStack172 = (uint)*(byte *)(iVar5 + 0x1c);
    local_b0 = 0x43300000;
    dVar15 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x1c)) -
                            DOUBLE_803e3520);
    bVar1 = *(byte *)(iVar5 + 0x22);
    if (bVar1 == 1) {
      local_e4 = FUN_8002b9ac();
      if (local_e4 == 0) goto LAB_80174350;
      unaff_r31 = &local_e4;
      local_e8 = 1;
    }
    else if (bVar1 == 0) {
      local_e4 = FUN_8002b9ec();
      if (local_e4 == 0) goto LAB_80174350;
      unaff_r31 = &local_e4;
      local_e8 = 1;
    }
    else if ((bVar1 < 3) && (unaff_r31 = (int *)FUN_80036f50(5,&local_e8), unaff_r31 == (int *)0x0))
    goto LAB_80174350;
    dVar19 = -dVar17;
    dVar18 = -dVar15;
    for (iVar4 = 0; iVar4 < local_e8; iVar4 = iVar4 + 1) {
      iVar3 = *unaff_r31;
      dVar12 = (double)(*(float *)(iVar3 + 0xc) - *(float *)(param_1 + 0xc));
      dVar13 = (double)(*(float *)(iVar3 + 0x10) - *(float *)(param_1 + 0x10));
      dVar14 = (double)(*(float *)(iVar3 + 0x14) - *(float *)(param_1 + 0x14));
      dVar7 = (double)(float)(dVar12 * dVar8 + (double)(float)(dVar14 * dVar9));
      if ((((dVar19 < dVar7) && (dVar7 < dVar17)) &&
          (dVar7 = (double)(float)(-dVar13 * dVar11 +
                                  (double)(float)((double)(float)(-dVar12 * dVar9 +
                                                                 (double)(float)(dVar14 * dVar8)) *
                                                 dVar10)), dVar18 < dVar7)) &&
         (((dVar7 < dVar15 &&
           (dVar7 = (double)(float)(dVar13 * dVar10 + (double)(float)(dVar7 * dVar11)),
           (double)FLOAT_803e3514 <= dVar7)) && (dVar7 < dVar16)))) {
        bVar1 = *(byte *)(iVar5 + 0x22);
        if (bVar1 != 1) {
          if (bVar1 == 0) {
            uStack172 = (uint)*(byte *)(iVar5 + 0x1d);
            local_b0 = 0x43300000;
            FUN_80295918((double)(float)((double)CONCAT44(0x43300000,uStack172) - DOUBLE_803e3520),
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
LAB_80174350:
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  __psq_l0(auStack56,uVar6);
  __psq_l1(auStack56,uVar6);
  __psq_l0(auStack72,uVar6);
  __psq_l1(auStack72,uVar6);
  __psq_l0(auStack88,uVar6);
  __psq_l1(auStack88,uVar6);
  __psq_l0(auStack104,uVar6);
  __psq_l1(auStack104,uVar6);
  __psq_l0(auStack120,uVar6);
  __psq_l1(auStack120,uVar6);
  __psq_l0(auStack136,uVar6);
  __psq_l1(auStack136,uVar6);
  return;
}

