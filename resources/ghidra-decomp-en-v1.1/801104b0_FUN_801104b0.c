// Function: FUN_801104b0
// Entry: 801104b0
// Size: 876 bytes

/* WARNING: Removing unreachable block (ram,0x801107fc) */
/* WARNING: Removing unreachable block (ram,0x801107f4) */
/* WARNING: Removing unreachable block (ram,0x801107ec) */
/* WARNING: Removing unreachable block (ram,0x801104d0) */
/* WARNING: Removing unreachable block (ram,0x801104c8) */
/* WARNING: Removing unreachable block (ram,0x801104c0) */

void FUN_801104b0(short *param_1)

{
  float fVar1;
  ushort *puVar2;
  short *psVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  short local_c8;
  short local_c6;
  float local_c4;
  float local_c0;
  float local_bc;
  ushort local_b8;
  ushort local_b6;
  ushort local_b4;
  float local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  float afStack_a0 [16];
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  
  psVar3 = *(short **)(param_1 + 0x52);
  FUN_802970dc((int)psVar3,&local_c6,&local_c8);
  puVar2 = (ushort *)FUN_80297a08((int)psVar3);
  if (puVar2 == (ushort *)0x0) {
    local_bc = *(float *)(psVar3 + 0xc);
    local_c0 = *(float *)(psVar3 + 0xe) + FLOAT_803dc630;
    local_c4 = *(float *)(psVar3 + 0x10);
  }
  else if (puVar2[0x23] == 0x419) {
    local_ac = *(undefined4 *)(puVar2 + 0xc);
    local_a8 = *(undefined4 *)(puVar2 + 0xe);
    local_a4 = *(undefined4 *)(puVar2 + 0x10);
    local_b8 = *puVar2;
    local_b6 = puVar2[1];
    local_b4 = puVar2[2];
    local_b0 = FLOAT_803e27a0;
    FUN_80021fac(afStack_a0,&local_b8);
    FUN_80022790((double)FLOAT_803e27a4,(double)FLOAT_803e27a8,(double)FLOAT_803e27ac,afStack_a0,
                 &local_bc,&local_c0,&local_c4);
  }
  else {
    local_bc = *(float *)(psVar3 + 0xc);
    local_c0 = *(float *)(psVar3 + 0xe) + FLOAT_803dc630;
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
  param_1[2] = psVar3[2] * (short)DAT_803dc634;
  uStack_5c = (int)*param_1 - 0x4000U ^ 0x80000000;
  local_60 = 0x43300000;
  dVar4 = (double)FUN_802945e0();
  uStack_54 = (int)*param_1 - 0x4000U ^ 0x80000000;
  local_58 = 0x43300000;
  dVar5 = (double)FUN_80294964();
  uStack_4c = (int)param_1[1] ^ 0x80000000;
  local_50 = 0x43300000;
  dVar6 = (double)FUN_80294964();
  uStack_44 = (int)param_1[1] ^ 0x80000000;
  local_48 = 0x43300000;
  dVar7 = (double)FUN_802945e0();
  fVar1 = *(float *)(DAT_803de230 + 0xc);
  dVar6 = (double)(float)((double)fVar1 * dVar6);
  *(float *)(param_1 + 0xc) = local_bc + (float)(dVar6 * dVar5);
  *(float *)(param_1 + 0xe) = local_c0 + (float)((double)fVar1 * dVar7);
  *(float *)(param_1 + 0x10) = local_c4 + (float)(dVar6 * dVar4);
  FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
               (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  return;
}

