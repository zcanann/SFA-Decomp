// Function: FUN_8010d608
// Entry: 8010d608
// Size: 1188 bytes

void FUN_8010d608(ushort *param_1)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  short *psVar5;
  double dVar6;
  float local_d8;
  undefined local_d4 [4];
  float local_d0;
  undefined local_cc [4];
  float local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  float local_bc;
  undefined4 local_b8;
  float local_b4;
  undefined auStack_b0 [112];
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  psVar5 = *(short **)(param_1 + 0x52);
  if (*(short *)(DAT_803de1f0 + 0xb) != 0) {
    *(ushort *)(DAT_803de1f0 + 0xb) = *(short *)(DAT_803de1f0 + 0xb) - (ushort)DAT_803dc070;
    if (*(short *)(DAT_803de1f0 + 0xb) < 0) {
      *(undefined2 *)(DAT_803de1f0 + 0xb) = 0;
    }
    uStack_3c = (int)*(short *)((int)DAT_803de1f0 + 0x2e) - (int)*(short *)(DAT_803de1f0 + 0xb) ^
                0x80000000;
    local_40 = 0x43300000;
    uStack_34 = (int)*(short *)((int)DAT_803de1f0 + 0x2e) ^ 0x80000000;
    local_38 = 0x43300000;
    fVar1 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e2610) /
            (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e2610);
    uStack_24 = (uint)*(ushort *)((int)DAT_803de1f0 + 0x32);
    uStack_2c = *(ushort *)(DAT_803de1f0 + 0xd) - uStack_24 ^ 0x80000000;
    local_30 = 0x43300000;
    local_28 = 0x43300000;
    *(short *)(DAT_803de1f0 + 0xc) =
         (short)(int)(fVar1 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e2610) +
                     (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e2618));
    *DAT_803de1f0 = fVar1 * (DAT_803de1f0[6] - DAT_803de1f0[5]) + DAT_803de1f0[5];
    DAT_803de1f0[3] = fVar1 * (DAT_803de1f0[8] - DAT_803de1f0[7]) + DAT_803de1f0[7];
    DAT_803de1f0[4] = fVar1 * (DAT_803de1f0[10] - DAT_803de1f0[9]) + DAT_803de1f0[9];
  }
  local_d0 = *(float *)(psVar5 + 0xe) + DAT_803de1f0[4];
  fVar2 = *(float *)(psVar5 + 0xe) + DAT_803de1f0[3];
  fVar1 = *(float *)(param_1 + 0xe);
  if (fVar2 <= fVar1) {
    if (fVar1 <= local_d0) {
      local_d0 = FLOAT_803e2620;
    }
    else {
      local_d0 = local_d0 - fVar1;
    }
  }
  else {
    local_d0 = fVar2 - fVar1;
  }
  local_d0 = local_d0 * DAT_803de1f0[2] * FLOAT_803dc074;
  *(float *)(param_1 + 0xe) = *(float *)(param_1 + 0xe) + local_d0;
  local_d8 = (*DAT_803de1f0 - DAT_803de1f0[1]) * FLOAT_803e2624 * FLOAT_803dc074;
  DAT_803de1f0[1] = DAT_803de1f0[1] + local_d8;
  _local_20 = CONCAT44(0x43300000,(int)*psVar5 ^ 0x80000000);
  dVar6 = (double)FUN_802945e0();
  local_bc = (float)((double)FLOAT_803e2628 * dVar6 + (double)*(float *)(psVar5 + 0xc));
  local_b8 = *(undefined4 *)(psVar5 + 0xe);
  uStack_24 = (int)*psVar5 ^ 0x80000000;
  local_28 = 0x43300000;
  dVar6 = (double)FUN_80294964();
  local_b4 = (float)((double)FLOAT_803e2628 * dVar6 + (double)*(float *)(psVar5 + 0x10));
  uStack_2c = (int)*psVar5 ^ 0x80000000;
  local_30 = 0x43300000;
  dVar6 = (double)FUN_802945e0();
  *(float *)(param_1 + 0xc) = (float)((double)DAT_803de1f0[1] * dVar6 + (double)local_bc);
  uStack_34 = (int)*psVar5 ^ 0x80000000;
  local_38 = 0x43300000;
  dVar6 = (double)FUN_80294964();
  *(float *)(param_1 + 0x10) = (float)((double)DAT_803de1f0[1] * dVar6 + (double)local_b4);
  FUN_801037c0((double)FLOAT_803e2634,&local_bc,(float *)(param_1 + 0xc),&local_c8,(int)auStack_b0,3
               ,'\x01','\x01');
  *(float *)(param_1 + 0xc) = local_c8;
  *(undefined4 *)(param_1 + 0xe) = local_c4;
  *(undefined4 *)(param_1 + 0x10) = local_c0;
  uStack_3c = (uint)*(ushort *)(DAT_803de1f0 + 0xc);
  local_40 = 0x43300000;
  (**(code **)(*DAT_803dd6d0 + 0x38))
            ((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e2618),param_1,
             local_cc,&local_d0,local_d4,&local_d8,0);
  uVar3 = FUN_80021884();
  iVar4 = (0x8000 - (uVar3 & 0xffff)) - (uint)*param_1;
  if (0x8000 < iVar4) {
    iVar4 = iVar4 + -0xffff;
  }
  if (iVar4 < -0x8000) {
    iVar4 = iVar4 + 0xffff;
  }
  *param_1 = *param_1 + (short)iVar4;
  uStack_14 = (uint)*(ushort *)(DAT_803de1f0 + 0xc);
  local_18 = 0x43300000;
  local_d0 = *(float *)(param_1 + 0xe) -
             (*(float *)(psVar5 + 0xe) +
             (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e2618));
  uVar3 = FUN_80021884();
  iVar4 = (uVar3 & 0xffff) - (uint)param_1[1];
  if (0x8000 < iVar4) {
    iVar4 = iVar4 + -0xffff;
  }
  if (iVar4 < -0x8000) {
    iVar4 = iVar4 + 0xffff;
  }
  iVar4 = iVar4 * (uint)DAT_803dc070;
  param_1[1] = param_1[1] +
               ((short)((ulonglong)((longlong)iVar4 * 0x2aaaaaab) >> 0x20) -
               ((short)((short)(iVar4 / 0x60000) + (short)(iVar4 >> 0x1f)) >> 0xf));
  FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
               (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  return;
}

