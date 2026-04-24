// Function: FUN_8010509c
// Entry: 8010509c
// Size: 1140 bytes

/* WARNING: Removing unreachable block (ram,0x801054e8) */
/* WARNING: Removing unreachable block (ram,0x801054f0) */

void FUN_8010509c(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar6;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  (**(code **)(*DAT_803dca50 + 0x38))
            ((double)DAT_803dd530[0x23],param_1,&local_2c,&local_30,&local_34,&local_38,1);
  local_38 = local_34 * local_34 + local_2c * local_2c + local_30 * local_30;
  if (FLOAT_803e16ac < local_38) {
    dVar4 = (double)FUN_802931a0();
    local_38 = (float)dVar4;
  }
  if (local_38 < FLOAT_803e1694) {
    local_38 = FLOAT_803e1694;
  }
  if (FLOAT_803e1700 * DAT_803dd530[1] < local_38) {
    FUN_80103708(param_1,param_2,param_1 + 0x18,param_1 + 2);
    FUN_8000e034((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                 (double)*(float *)(param_1 + 0x20),param_1 + 0xc,param_1 + 0x10,param_1 + 0x14,
                 *(undefined4 *)(param_1 + 0x30));
    *(undefined4 *)(param_1 + 0xb8) = *(undefined4 *)(param_1 + 0x18);
    *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(param_1 + 0x1c);
    *(undefined4 *)(param_1 + 0xc0) = *(undefined4 *)(param_1 + 0x20);
    (**(code **)(*DAT_803dca50 + 0x38))
              ((double)DAT_803dd530[0x23],param_1,&local_2c,&local_30,&local_34,&local_38,1);
    local_38 = local_34 * local_34 + local_2c * local_2c + local_30 * local_30;
    if (FLOAT_803e16ac < local_38) {
      dVar4 = (double)FUN_802931a0();
      local_38 = (float)dVar4;
    }
    if (local_38 < FLOAT_803e1694) {
      local_38 = FLOAT_803e1694;
    }
  }
  fVar1 = DAT_803dd530[1];
  if (local_38 <= fVar1) {
    fVar1 = *DAT_803dd530;
    if (fVar1 <= local_38) {
      *(byte *)(DAT_803dd530 + 0x32) = *(byte *)(DAT_803dd530 + 0x32) & 0x7f;
      fVar1 = local_38;
    }
    else {
      *(byte *)(DAT_803dd530 + 0x32) = *(byte *)(DAT_803dd530 + 0x32) & 0x7f;
    }
  }
  else {
    *(byte *)((int)DAT_803dd530 + 0xc6) = *(byte *)((int)DAT_803dd530 + 0xc6) & 0x7f;
    *(byte *)(DAT_803dd530 + 0x32) = *(byte *)(DAT_803dd530 + 0x32) & 0x7f | 0x80;
  }
  dVar6 = (double)*(float *)(param_1 + 0xc);
  dVar4 = (double)*(float *)(param_1 + 0x14);
  if (((-1 < *(char *)((int)DAT_803dd530 + 0xc6)) && (fVar1 != local_38)) &&
     (FLOAT_803e16ac != DAT_803dd530[4])) {
    if (local_38 < FLOAT_803e16a4) {
      local_38 = FLOAT_803e16a4;
    }
    dVar5 = (double)FUN_80021370((double)(local_38 - fVar1),(double)DAT_803dd530[4],
                                 (double)FLOAT_803db414);
    fVar1 = (float)((double)(float)((double)local_38 + dVar5) / (double)local_38);
    if (FLOAT_803e16ac < fVar1) {
      dVar6 = (double)(*(float *)(param_2 + 0xc) + local_2c / fVar1);
      dVar4 = (double)(*(float *)(param_2 + 0x14) + local_34 / fVar1);
    }
  }
  local_2c = (float)(dVar6 - (double)*(float *)(param_1 + 0xc));
  local_34 = (float)(dVar4 - (double)*(float *)(param_1 + 0x14));
  dVar4 = (double)FUN_802931a0((double)(local_2c * local_2c + local_34 * local_34));
  local_38 = (float)dVar4;
  fVar1 = (float)dVar4;
  if (FLOAT_803e16ac < fVar1) {
    local_2c = local_2c / fVar1;
    local_34 = local_34 / fVar1;
  }
  dVar4 = (double)FUN_802477f0(param_2 + 0x24);
  fVar1 = (float)(dVar4 * (double)(FLOAT_803e1704 * FLOAT_803db414));
  if (fVar1 < FLOAT_803e16a4) {
    fVar1 = FLOAT_803e16a4;
  }
  fVar2 = FLOAT_803e16ac;
  if ((FLOAT_803e16ac <= local_38) && (fVar2 = local_38, fVar1 < local_38)) {
    fVar2 = fVar1;
  }
  local_38 = FLOAT_803e16ac;
  if ((FLOAT_803e16ac <= fVar2) && (local_38 = fVar2, FLOAT_803e1708 < fVar2)) {
    local_38 = FLOAT_803e1708;
  }
  *(float *)(param_1 + 0xc) = local_2c * local_38 + *(float *)(param_1 + 0xc);
  *(float *)(param_1 + 0x14) = local_34 * local_38 + *(float *)(param_1 + 0x14);
  if (DAT_803dd530[0x27] < DAT_803dd530[3]) {
    local_2c = *(float *)(param_1 + 0xc) - *(float *)(param_2 + 0xc);
    local_34 = *(float *)(param_1 + 0x14) - *(float *)(param_2 + 0x14);
    dVar4 = (double)FUN_802931a0((double)(local_2c * local_2c + local_34 * local_34));
    fVar1 = (float)dVar4;
    if (fVar1 < FLOAT_803e170c * *DAT_803dd530) {
      if (FLOAT_803e16ac < fVar1) {
        local_2c = local_2c / fVar1;
        local_34 = local_34 / fVar1;
      }
      fVar1 = FLOAT_803e170c * *DAT_803dd530;
      *(float *)(param_1 + 0xc) = fVar1 * local_2c + *(float *)(param_2 + 0xc);
      *(float *)(param_1 + 0x14) = fVar1 * local_34 + *(float *)(param_2 + 0x14);
    }
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  return;
}

