// Function: FUN_80104c4c
// Entry: 80104c4c
// Size: 1552 bytes

/* WARNING: Removing unreachable block (ram,0x80105238) */
/* WARNING: Removing unreachable block (ram,0x80105230) */
/* WARNING: Removing unreachable block (ram,0x80105228) */
/* WARNING: Removing unreachable block (ram,0x80104c6c) */
/* WARNING: Removing unreachable block (ram,0x80104c64) */
/* WARNING: Removing unreachable block (ram,0x80104c5c) */

void FUN_80104c4c(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  float local_c8;
  float local_c4;
  float fStack_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  short local_ac [4];
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float afStack_94 [17];
  undefined4 local_50;
  float fStack_4c;
  
  (**(code **)(*DAT_803dd6d0 + 0x38))
            ((double)DAT_803de1a8[0x23],param_1,&local_b0,&local_b4,&local_b8,&local_bc,0);
  local_bc = local_b8 * local_b8 + local_b0 * local_b0 + local_b4 * local_b4;
  if ((double)FLOAT_803e232c < (double)local_bc) {
    dVar5 = FUN_80293900((double)local_bc);
    local_bc = (float)dVar5;
  }
  if (local_bc < FLOAT_803e2314) {
    local_bc = FLOAT_803e2314;
  }
  fVar1 = *(float *)(param_2 + 0x1c) + DAT_803de1a8[0x23];
  dVar9 = (double)(DAT_803de1a8[3] + fVar1);
  dVar5 = (double)(DAT_803de1a8[2] + fVar1);
  if (*(short *)(param_2 + 0x44) == 1) {
    iVar4 = *(int *)(param_2 + 0xb8);
    iVar2 = FUN_80021884();
    local_ac[0] = -0x8000 - (short)iVar2;
    local_ac[1] = 0;
    local_ac[2] = 0;
    local_a4 = FLOAT_803e2324;
    local_a0 = FLOAT_803e232c;
    local_9c = FLOAT_803e232c;
    local_98 = FLOAT_803e232c;
    FUN_80021c64(afStack_94,(int)local_ac);
    FUN_80022790((double)*(float *)(iVar4 + 0x1a4),(double)*(float *)(iVar4 + 0x1a8),
                 (double)*(float *)(iVar4 + 0x1ac),afStack_94,&fStack_c0,&local_c4,&local_c8);
    uVar3 = FUN_80021884();
    DAT_803de1a8[0x2b] =
         (float)((int)DAT_803de1a8[0x2b] +
                ((int)((uint)DAT_803dc070 * ((0x4000 - (uVar3 & 0xffff)) - (int)DAT_803de1a8[0x2b]))
                >> 5));
  }
  else {
    DAT_803de1a8[0x2b] =
         (float)((int)DAT_803de1a8[0x2b] -
                ((int)((int)DAT_803de1a8[0x2b] * (uint)DAT_803dc070) >> 5));
  }
  fVar1 = DAT_803de1a8[0x2b];
  if ((int)fVar1 < 0) {
    fStack_4c = -fVar1;
    local_50 = 0x43300000;
    dVar6 = (double)FUN_802945e0();
    dVar6 = (double)(float)((double)DAT_803de1a8[7] * dVar6);
  }
  else if ((int)fVar1 < 1) {
    dVar6 = (double)FLOAT_803e232c;
  }
  else {
    fStack_4c = -fVar1;
    local_50 = 0x43300000;
    dVar6 = (double)FUN_802945e0();
    dVar6 = (double)(float)((double)DAT_803de1a8[6] * dVar6);
  }
  dVar8 = (double)(float)(dVar5 + dVar6);
  dVar9 = (double)(float)(dVar9 + dVar6);
  dVar5 = (double)(*DAT_803de1a8 - FLOAT_803e2358);
  if ((double)(*DAT_803de1a8 - FLOAT_803e2358) < (double)FLOAT_803e235c) {
    dVar5 = (double)FLOAT_803e235c;
  }
  if (*(short *)(param_2 + 0x44) == 1) {
    dVar6 = FUN_80296e54(param_2);
    if ((double)FLOAT_803e235c < dVar6) {
      local_b4 = (DAT_803de1a8[0x26] - DAT_803de1a8[2]) * FLOAT_803e2364;
      if (FLOAT_803e2368 < local_b4) {
        local_b4 = FLOAT_803e2368;
      }
      if (local_b4 < FLOAT_803e236c) {
        local_b4 = FLOAT_803e236c;
      }
      DAT_803de1a8[2] = DAT_803de1a8[2] + local_b4;
      if (DAT_803de1a8[2] < DAT_803de1a8[0x26]) {
        DAT_803de1a8[2] = DAT_803de1a8[0x26];
      }
      local_b4 = (DAT_803de1a8[0x27] - DAT_803de1a8[3]) * FLOAT_803e2364;
      if (FLOAT_803e2368 < local_b4) {
        local_b4 = FLOAT_803e2368;
      }
      if (local_b4 < FLOAT_803e236c) {
        local_b4 = FLOAT_803e236c;
      }
      DAT_803de1a8[3] = DAT_803de1a8[3] + local_b4;
      if (DAT_803de1a8[3] < DAT_803de1a8[0x27]) {
        DAT_803de1a8[3] = DAT_803de1a8[0x27];
      }
      dVar7 = (double)local_bc;
      dVar6 = (double)FLOAT_803e235c;
      if (dVar7 <= dVar6) {
        dVar8 = (double)(FLOAT_803e2360 * (float)(dVar6 - dVar7) +
                        FLOAT_803e2370 + *(float *)(param_2 + 0x1c));
        dVar9 = dVar8;
      }
      else if (dVar7 <= dVar5) {
        if (FLOAT_803e232c < (float)(dVar5 - dVar6)) {
          local_bc = (float)(dVar7 - dVar6) / (float)(dVar5 - dVar6);
        }
        if (FLOAT_803e232c <= local_bc) {
          if (FLOAT_803e2324 < local_bc) {
            local_bc = FLOAT_803e2324;
          }
        }
        else {
          local_bc = FLOAT_803e232c;
        }
        fVar1 = FLOAT_803e2370 + *(float *)(param_2 + 0x1c);
        dVar8 = (double)(local_bc * ((DAT_803de1a8[0x23] + DAT_803de1a8[2]) - FLOAT_803e2370) +
                        fVar1);
        dVar9 = (double)(local_bc * ((DAT_803de1a8[0x23] + DAT_803de1a8[3]) - FLOAT_803e2370) +
                        fVar1);
      }
    }
    else {
      local_b4 = (FLOAT_803e2360 * DAT_803de1a8[1] - DAT_803de1a8[2]) * FLOAT_803e2364;
      if (FLOAT_803e2334 < local_b4) {
        local_b4 = FLOAT_803e2334;
      }
      DAT_803de1a8[2] = DAT_803de1a8[2] + local_b4;
      if (DAT_803de1a8[1] < DAT_803de1a8[2]) {
        DAT_803de1a8[2] = DAT_803de1a8[1];
      }
      local_b4 = (FLOAT_803e2360 * DAT_803de1a8[1] - DAT_803de1a8[3]) * FLOAT_803e2364;
      if (FLOAT_803e2334 < local_b4) {
        local_b4 = FLOAT_803e2334;
      }
      DAT_803de1a8[3] = DAT_803de1a8[3] + local_b4;
      if (DAT_803de1a8[1] < DAT_803de1a8[3]) {
        DAT_803de1a8[3] = DAT_803de1a8[1];
      }
    }
  }
  dVar5 = (double)*(float *)(param_1 + 0x1c);
  if (dVar8 <= dVar5) {
    if (dVar5 <= dVar9) {
      local_b4 = FLOAT_803e232c;
    }
    else {
      local_b4 = (float)(dVar9 - dVar5);
    }
  }
  else {
    local_b4 = (float)(dVar8 - dVar5);
  }
  dVar5 = FUN_80021434((double)local_b4,(double)DAT_803de1a8[5],(double)FLOAT_803dc074);
  local_b4 = (float)dVar5;
  if ((FLOAT_803e2368 < (float)dVar5) && ((float)dVar5 < FLOAT_803e2374)) {
    local_b4 = FLOAT_803e232c;
  }
  *(float *)(param_1 + 0x1c) = *(float *)(param_1 + 0x1c) + local_b4;
  if ((float)((double)FLOAT_803e2338 + dVar9) < *(float *)(param_1 + 0x1c)) {
    *(float *)(param_1 + 0x1c) = (float)((double)FLOAT_803e2338 + dVar9);
  }
  if (DAT_803de1a8[3] <= DAT_803de1a8[0x27]) {
    *(byte *)(DAT_803de1a8 + 0x32) = *(byte *)(DAT_803de1a8 + 0x32) & 0xbf;
  }
  else {
    if (((*(byte *)(DAT_803de1a8 + 0x32) >> 6 & 1) != 0) &&
       (DAT_803de1a8[0x2f] < *(float *)(param_1 + 0x1c))) {
      *(float *)(param_1 + 0x1c) = DAT_803de1a8[0x2f];
    }
    if (FLOAT_803e232c < *(float *)(param_2 + 0x28)) {
      *(byte *)(DAT_803de1a8 + 0x32) = *(byte *)(DAT_803de1a8 + 0x32) & 0xbf;
    }
  }
  return;
}

