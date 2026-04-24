// Function: FUN_801049b0
// Entry: 801049b0
// Size: 1552 bytes

/* WARNING: Removing unreachable block (ram,0x80104f94) */
/* WARNING: Removing unreachable block (ram,0x80104f8c) */
/* WARNING: Removing unreachable block (ram,0x80104f9c) */

void FUN_801049b0(int param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  float local_c8;
  float local_c4;
  undefined auStack192 [4];
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  short local_ac;
  undefined2 local_aa;
  undefined2 local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  undefined auStack148 [68];
  undefined4 local_50;
  uint uStack76;
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
  (**(code **)(*DAT_803dca50 + 0x38))
            ((double)DAT_803dd530[0x23],param_1,&local_b0,&local_b4,&local_b8,&local_bc,0);
  local_bc = local_b8 * local_b8 + local_b0 * local_b0 + local_b4 * local_b4;
  if (FLOAT_803e16ac < local_bc) {
    dVar5 = (double)FUN_802931a0();
    local_bc = (float)dVar5;
  }
  if (local_bc < FLOAT_803e1694) {
    local_bc = FLOAT_803e1694;
  }
  fVar1 = *(float *)(param_2 + 0x1c) + DAT_803dd530[0x23];
  dVar9 = (double)(DAT_803dd530[3] + fVar1);
  dVar5 = (double)(DAT_803dd530[2] + fVar1);
  if (*(short *)(param_2 + 0x44) == 1) {
    iVar3 = *(int *)(param_2 + 0xb8);
    local_ac = FUN_800217c0((double)local_b0,(double)local_b8);
    local_ac = -0x8000 - local_ac;
    local_aa = 0;
    local_a8 = 0;
    local_a4 = FLOAT_803e16a4;
    local_a0 = FLOAT_803e16ac;
    local_9c = FLOAT_803e16ac;
    local_98 = FLOAT_803e16ac;
    FUN_80021ba0(auStack148,&local_ac);
    FUN_800226cc((double)*(float *)(iVar3 + 0x1a4),(double)*(float *)(iVar3 + 0x1a8),
                 (double)*(float *)(iVar3 + 0x1ac),auStack148,auStack192,&local_c4,&local_c8);
    uVar2 = FUN_800217c0((double)local_c4,(double)local_c8);
    DAT_803dd530[0x2b] =
         (float)((int)DAT_803dd530[0x2b] +
                ((int)((uint)DAT_803db410 * ((0x4000 - (uVar2 & 0xffff)) - (int)DAT_803dd530[0x2b]))
                >> 5));
  }
  else {
    DAT_803dd530[0x2b] =
         (float)((int)DAT_803dd530[0x2b] -
                ((int)((int)DAT_803dd530[0x2b] * (uint)DAT_803db410) >> 5));
  }
  fVar1 = DAT_803dd530[0x2b];
  if ((int)fVar1 < 0) {
    uStack76 = (uint)fVar1 ^ 0x80000000;
    local_50 = 0x43300000;
    dVar6 = (double)FUN_80293e80((double)((FLOAT_803e168c *
                                          (float)((double)CONCAT44(0x43300000,uStack76) -
                                                 DOUBLE_803e1698)) / FLOAT_803e1690));
    dVar6 = (double)(float)((double)DAT_803dd530[7] * dVar6);
  }
  else if ((int)fVar1 < 1) {
    dVar6 = (double)FLOAT_803e16ac;
  }
  else {
    uStack76 = (uint)fVar1 ^ 0x80000000;
    local_50 = 0x43300000;
    dVar6 = (double)FUN_80293e80((double)((FLOAT_803e168c *
                                          (float)((double)CONCAT44(0x43300000,uStack76) -
                                                 DOUBLE_803e1698)) / FLOAT_803e1690));
    dVar6 = (double)(float)((double)DAT_803dd530[6] * dVar6);
  }
  dVar8 = (double)(float)(dVar5 + dVar6);
  dVar9 = (double)(float)(dVar9 + dVar6);
  dVar5 = (double)(*DAT_803dd530 - FLOAT_803e16d8);
  if ((double)(*DAT_803dd530 - FLOAT_803e16d8) < (double)FLOAT_803e16dc) {
    dVar5 = (double)FLOAT_803e16dc;
  }
  if (*(short *)(param_2 + 0x44) == 1) {
    dVar6 = (double)FUN_802966f4(param_2);
    if ((double)FLOAT_803e16dc < dVar6) {
      local_b4 = (DAT_803dd530[0x26] - DAT_803dd530[2]) * FLOAT_803e16e4;
      if (FLOAT_803e16e8 < local_b4) {
        local_b4 = FLOAT_803e16e8;
      }
      if (local_b4 < FLOAT_803e16ec) {
        local_b4 = FLOAT_803e16ec;
      }
      DAT_803dd530[2] = DAT_803dd530[2] + local_b4;
      if (DAT_803dd530[2] < DAT_803dd530[0x26]) {
        DAT_803dd530[2] = DAT_803dd530[0x26];
      }
      local_b4 = (DAT_803dd530[0x27] - DAT_803dd530[3]) * FLOAT_803e16e4;
      if (FLOAT_803e16e8 < local_b4) {
        local_b4 = FLOAT_803e16e8;
      }
      if (local_b4 < FLOAT_803e16ec) {
        local_b4 = FLOAT_803e16ec;
      }
      DAT_803dd530[3] = DAT_803dd530[3] + local_b4;
      if (DAT_803dd530[3] < DAT_803dd530[0x27]) {
        DAT_803dd530[3] = DAT_803dd530[0x27];
      }
      dVar7 = (double)local_bc;
      dVar6 = (double)FLOAT_803e16dc;
      if (dVar7 <= dVar6) {
        dVar8 = (double)(FLOAT_803e16e0 * (float)(dVar6 - dVar7) +
                        FLOAT_803e16f0 + *(float *)(param_2 + 0x1c));
        dVar9 = dVar8;
      }
      else if (dVar7 <= dVar5) {
        if (FLOAT_803e16ac < (float)(dVar5 - dVar6)) {
          local_bc = (float)(dVar7 - dVar6) / (float)(dVar5 - dVar6);
        }
        if (FLOAT_803e16ac <= local_bc) {
          if (FLOAT_803e16a4 < local_bc) {
            local_bc = FLOAT_803e16a4;
          }
        }
        else {
          local_bc = FLOAT_803e16ac;
        }
        fVar1 = FLOAT_803e16f0 + *(float *)(param_2 + 0x1c);
        dVar8 = (double)(local_bc * ((DAT_803dd530[0x23] + DAT_803dd530[2]) - FLOAT_803e16f0) +
                        fVar1);
        dVar9 = (double)(local_bc * ((DAT_803dd530[0x23] + DAT_803dd530[3]) - FLOAT_803e16f0) +
                        fVar1);
      }
    }
    else {
      local_b4 = (FLOAT_803e16e0 * DAT_803dd530[1] - DAT_803dd530[2]) * FLOAT_803e16e4;
      if (FLOAT_803e16b4 < local_b4) {
        local_b4 = FLOAT_803e16b4;
      }
      DAT_803dd530[2] = DAT_803dd530[2] + local_b4;
      if (DAT_803dd530[1] < DAT_803dd530[2]) {
        DAT_803dd530[2] = DAT_803dd530[1];
      }
      local_b4 = (FLOAT_803e16e0 * DAT_803dd530[1] - DAT_803dd530[3]) * FLOAT_803e16e4;
      if (FLOAT_803e16b4 < local_b4) {
        local_b4 = FLOAT_803e16b4;
      }
      DAT_803dd530[3] = DAT_803dd530[3] + local_b4;
      if (DAT_803dd530[1] < DAT_803dd530[3]) {
        DAT_803dd530[3] = DAT_803dd530[1];
      }
    }
  }
  dVar5 = (double)*(float *)(param_1 + 0x1c);
  if (dVar8 <= dVar5) {
    if (dVar5 <= dVar9) {
      local_b4 = FLOAT_803e16ac;
    }
    else {
      local_b4 = (float)(dVar9 - dVar5);
    }
  }
  else {
    local_b4 = (float)(dVar8 - dVar5);
  }
  dVar5 = (double)FUN_80021370((double)local_b4,(double)DAT_803dd530[5],(double)FLOAT_803db414);
  local_b4 = (float)dVar5;
  if ((FLOAT_803e16e8 < (float)dVar5) && ((float)dVar5 < FLOAT_803e16f4)) {
    local_b4 = FLOAT_803e16ac;
  }
  *(float *)(param_1 + 0x1c) = *(float *)(param_1 + 0x1c) + local_b4;
  if ((float)((double)FLOAT_803e16b8 + dVar9) < *(float *)(param_1 + 0x1c)) {
    *(float *)(param_1 + 0x1c) = (float)((double)FLOAT_803e16b8 + dVar9);
  }
  if (DAT_803dd530[3] <= DAT_803dd530[0x27]) {
    *(byte *)(DAT_803dd530 + 0x32) = *(byte *)(DAT_803dd530 + 0x32) & 0xbf;
  }
  else {
    if (((*(byte *)(DAT_803dd530 + 0x32) >> 6 & 1) != 0) &&
       (DAT_803dd530[0x2f] < *(float *)(param_1 + 0x1c))) {
      *(float *)(param_1 + 0x1c) = DAT_803dd530[0x2f];
    }
    if (FLOAT_803e16ac < *(float *)(param_2 + 0x28)) {
      *(byte *)(DAT_803dd530 + 0x32) = *(byte *)(DAT_803dd530 + 0x32) & 0xbf;
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  return;
}

