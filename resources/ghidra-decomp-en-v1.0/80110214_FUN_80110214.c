// Function: FUN_80110214
// Entry: 80110214
// Size: 876 bytes

/* WARNING: Removing unreachable block (ram,0x80110558) */
/* WARNING: Removing unreachable block (ram,0x80110550) */
/* WARNING: Removing unreachable block (ram,0x80110560) */

void FUN_80110214(short *param_1)

{
  float fVar1;
  undefined2 *puVar2;
  short *psVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  short local_c8;
  short local_c6;
  float local_c4;
  float local_c0;
  float local_bc;
  undefined2 local_b8;
  undefined2 local_b6;
  undefined2 local_b4;
  float local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined auStack160 [64];
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  psVar3 = *(short **)(param_1 + 0x52);
  FUN_8029697c(psVar3,&local_c6,&local_c8);
  puVar2 = (undefined2 *)FUN_802972a8(psVar3);
  if (puVar2 == (undefined2 *)0x0) {
    local_bc = *(float *)(psVar3 + 0xc);
    local_c0 = *(float *)(psVar3 + 0xe) + FLOAT_803db9d0;
    local_c4 = *(float *)(psVar3 + 0x10);
  }
  else if (puVar2[0x23] == 0x419) {
    local_ac = *(undefined4 *)(puVar2 + 0xc);
    local_a8 = *(undefined4 *)(puVar2 + 0xe);
    local_a4 = *(undefined4 *)(puVar2 + 0x10);
    local_b8 = *puVar2;
    local_b6 = puVar2[1];
    local_b4 = puVar2[2];
    local_b0 = FLOAT_803e1b20;
    FUN_80021ee8(auStack160,&local_b8);
    FUN_800226cc((double)FLOAT_803e1b24,(double)FLOAT_803e1b28,(double)FLOAT_803e1b2c,auStack160,
                 &local_bc,&local_c0,&local_c4);
  }
  else {
    local_bc = *(float *)(psVar3 + 0xc);
    local_c0 = *(float *)(psVar3 + 0xe) + FLOAT_803db9d0;
    local_c4 = *(float *)(psVar3 + 0x10);
  }
  local_c6 = ((-0x8000 - *psVar3) + local_c6) - *param_1;
  if (0x8000 < local_c6) {
    local_c6 = local_c6 + 1;
  }
  if (local_c6 < -0x8000) {
    local_c6 = local_c6 + -1;
  }
  *param_1 = *param_1 + local_c6;
  local_c8 = local_c8 - param_1[1];
  if (0x8000 < local_c8) {
    local_c8 = local_c8 + 1;
  }
  if (local_c8 < -0x8000) {
    local_c8 = local_c8 + -1;
  }
  param_1[1] = param_1[1] + local_c8;
  param_1[2] = psVar3[2] * (short)DAT_803db9d4;
  uStack92 = (int)*param_1 - 0x4000U ^ 0x80000000;
  local_60 = 0x43300000;
  dVar5 = (double)FUN_80293e80((double)((FLOAT_803e1b30 *
                                        (float)((double)CONCAT44(0x43300000,uStack92) -
                                               DOUBLE_803e1b38)) / FLOAT_803e1b34));
  uStack84 = (int)*param_1 - 0x4000U ^ 0x80000000;
  local_58 = 0x43300000;
  dVar6 = (double)FUN_80294204((double)((FLOAT_803e1b30 *
                                        (float)((double)CONCAT44(0x43300000,uStack84) -
                                               DOUBLE_803e1b38)) / FLOAT_803e1b34));
  uStack76 = (int)param_1[1] ^ 0x80000000;
  local_50 = 0x43300000;
  dVar7 = (double)FUN_80294204((double)((FLOAT_803e1b30 *
                                        (float)((double)CONCAT44(0x43300000,uStack76) -
                                               DOUBLE_803e1b38)) / FLOAT_803e1b34));
  uStack68 = (int)param_1[1] ^ 0x80000000;
  local_48 = 0x43300000;
  dVar8 = (double)FUN_80293e80((double)((FLOAT_803e1b30 *
                                        (float)((double)CONCAT44(0x43300000,uStack68) -
                                               DOUBLE_803e1b38)) / FLOAT_803e1b34));
  fVar1 = *(float *)(DAT_803dd5b8 + 0xc);
  dVar7 = (double)(float)((double)fVar1 * dVar7);
  *(float *)(param_1 + 0xc) = local_bc + (float)(dVar7 * dVar6);
  *(float *)(param_1 + 0xe) = local_c0 + (float)((double)fVar1 * dVar8);
  *(float *)(param_1 + 0x10) = local_c4 + (float)(dVar7 * dVar5);
  FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
               *(undefined4 *)(param_1 + 0x18));
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  return;
}

