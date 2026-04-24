// Function: FUN_80105338
// Entry: 80105338
// Size: 1140 bytes

/* WARNING: Removing unreachable block (ram,0x8010578c) */
/* WARNING: Removing unreachable block (ram,0x80105784) */
/* WARNING: Removing unreachable block (ram,0x80105350) */
/* WARNING: Removing unreachable block (ram,0x80105348) */

void FUN_80105338(int param_1,short *param_2)

{
  float fVar1;
  float fVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  
  (**(code **)(*DAT_803dd6d0 + 0x38))
            ((double)DAT_803de1a8[0x23],param_1,&local_2c,&local_30,&local_34,&local_38,1);
  local_38 = local_34 * local_34 + local_2c * local_2c + local_30 * local_30;
  if ((double)FLOAT_803e232c < (double)local_38) {
    dVar3 = FUN_80293900((double)local_38);
    local_38 = (float)dVar3;
  }
  if (local_38 < FLOAT_803e2314) {
    local_38 = FLOAT_803e2314;
  }
  if (FLOAT_803e2380 * DAT_803de1a8[1] < local_38) {
    FUN_801039a4(param_1,param_2,(float *)(param_1 + 0x18),(short *)(param_1 + 2));
    FUN_8000e054((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                 (double)*(float *)(param_1 + 0x20),(float *)(param_1 + 0xc),
                 (float *)(param_1 + 0x10),(float *)(param_1 + 0x14),*(int *)(param_1 + 0x30));
    *(undefined4 *)(param_1 + 0xb8) = *(undefined4 *)(param_1 + 0x18);
    *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(param_1 + 0x1c);
    *(undefined4 *)(param_1 + 0xc0) = *(undefined4 *)(param_1 + 0x20);
    (**(code **)(*DAT_803dd6d0 + 0x38))
              ((double)DAT_803de1a8[0x23],param_1,&local_2c,&local_30,&local_34,&local_38,1);
    local_38 = local_34 * local_34 + local_2c * local_2c + local_30 * local_30;
    if ((double)FLOAT_803e232c < (double)local_38) {
      dVar3 = FUN_80293900((double)local_38);
      local_38 = (float)dVar3;
    }
    if (local_38 < FLOAT_803e2314) {
      local_38 = FLOAT_803e2314;
    }
  }
  fVar1 = DAT_803de1a8[1];
  if (local_38 <= fVar1) {
    fVar1 = *DAT_803de1a8;
    if (fVar1 <= local_38) {
      *(byte *)(DAT_803de1a8 + 0x32) = *(byte *)(DAT_803de1a8 + 0x32) & 0x7f;
      fVar1 = local_38;
    }
    else {
      *(byte *)(DAT_803de1a8 + 0x32) = *(byte *)(DAT_803de1a8 + 0x32) & 0x7f;
    }
  }
  else {
    *(byte *)((int)DAT_803de1a8 + 0xc6) = *(byte *)((int)DAT_803de1a8 + 0xc6) & 0x7f;
    *(byte *)(DAT_803de1a8 + 0x32) = *(byte *)(DAT_803de1a8 + 0x32) & 0x7f | 0x80;
  }
  dVar5 = (double)*(float *)(param_1 + 0xc);
  dVar3 = (double)*(float *)(param_1 + 0x14);
  if (((-1 < *(char *)((int)DAT_803de1a8 + 0xc6)) && (fVar1 != local_38)) &&
     (FLOAT_803e232c != DAT_803de1a8[4])) {
    if (local_38 < FLOAT_803e2324) {
      local_38 = FLOAT_803e2324;
    }
    dVar4 = FUN_80021434((double)(local_38 - fVar1),(double)DAT_803de1a8[4],(double)FLOAT_803dc074);
    fVar1 = (float)((double)(float)((double)local_38 + dVar4) / (double)local_38);
    if (FLOAT_803e232c < fVar1) {
      dVar5 = (double)(*(float *)(param_2 + 6) + local_2c / fVar1);
      dVar3 = (double)(*(float *)(param_2 + 10) + local_34 / fVar1);
    }
  }
  local_2c = (float)(dVar5 - (double)*(float *)(param_1 + 0xc));
  local_34 = (float)(dVar3 - (double)*(float *)(param_1 + 0x14));
  dVar3 = FUN_80293900((double)(local_2c * local_2c + local_34 * local_34));
  local_38 = (float)dVar3;
  fVar1 = (float)dVar3;
  if (FLOAT_803e232c < fVar1) {
    local_2c = local_2c / fVar1;
    local_34 = local_34 / fVar1;
  }
  dVar3 = FUN_80247f54((float *)(param_2 + 0x12));
  fVar1 = (float)(dVar3 * (double)(FLOAT_803e2384 * FLOAT_803dc074));
  if (fVar1 < FLOAT_803e2324) {
    fVar1 = FLOAT_803e2324;
  }
  fVar2 = FLOAT_803e232c;
  if ((FLOAT_803e232c <= local_38) && (fVar2 = local_38, fVar1 < local_38)) {
    fVar2 = fVar1;
  }
  local_38 = FLOAT_803e232c;
  if ((FLOAT_803e232c <= fVar2) && (local_38 = fVar2, FLOAT_803e2388 < fVar2)) {
    local_38 = FLOAT_803e2388;
  }
  *(float *)(param_1 + 0xc) = local_2c * local_38 + *(float *)(param_1 + 0xc);
  *(float *)(param_1 + 0x14) = local_34 * local_38 + *(float *)(param_1 + 0x14);
  if (DAT_803de1a8[0x27] < DAT_803de1a8[3]) {
    local_2c = *(float *)(param_1 + 0xc) - *(float *)(param_2 + 6);
    local_34 = *(float *)(param_1 + 0x14) - *(float *)(param_2 + 10);
    dVar3 = FUN_80293900((double)(local_2c * local_2c + local_34 * local_34));
    fVar1 = (float)dVar3;
    if (fVar1 < FLOAT_803e238c * *DAT_803de1a8) {
      if (FLOAT_803e232c < fVar1) {
        local_2c = local_2c / fVar1;
        local_34 = local_34 / fVar1;
      }
      fVar1 = FLOAT_803e238c * *DAT_803de1a8;
      *(float *)(param_1 + 0xc) = fVar1 * local_2c + *(float *)(param_2 + 6);
      *(float *)(param_1 + 0x14) = fVar1 * local_34 + *(float *)(param_2 + 10);
    }
  }
  return;
}

