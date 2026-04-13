// Function: FUN_801668f0
// Entry: 801668f0
// Size: 1020 bytes

/* WARNING: Removing unreachable block (ram,0x80166cc8) */
/* WARNING: Removing unreachable block (ram,0x80166cc0) */
/* WARNING: Removing unreachable block (ram,0x80166cb8) */
/* WARNING: Removing unreachable block (ram,0x80166910) */
/* WARNING: Removing unreachable block (ram,0x80166908) */
/* WARNING: Removing unreachable block (ram,0x80166900) */

void FUN_801668f0(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  uint auStack_cc [6];
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_74;
  undefined local_60;
  
  dVar4 = FUN_80293900((double)(*(float *)(param_1 + 0x2c) * *(float *)(param_1 + 0x2c) +
                               *(float *)(param_1 + 0x24) * *(float *)(param_1 + 0x24) +
                               *(float *)(param_1 + 0x28) * *(float *)(param_1 + 0x28)));
  dVar6 = (double)FLOAT_803e3c74;
  iVar3 = 0;
  local_74 = FLOAT_803e3c74;
  local_60 = 3;
  local_d8 = *(float *)(param_1 + 0xc);
  local_d4 = *(float *)(param_1 + 0x10);
  local_d0 = *(float *)(param_1 + 0x14);
  local_e4 = local_d8 + *(float *)(param_1 + 0x24);
  local_e0 = local_d4 + *(float *)(param_1 + 0x28);
  local_dc = local_d0 + *(float *)(param_1 + 0x2c);
  local_e8 = FLOAT_803e3cb8;
  FUN_80069798(auStack_cc,&local_d8,&local_e4,&local_e8,1);
  FUN_8006933c(param_1,auStack_cc,0,'\x01');
  dVar7 = (double)FLOAT_803e3c8c;
  while ((dVar6 < dVar4 && (iVar3 = iVar3 + 1, iVar3 < 10))) {
    local_d8 = *(float *)(param_1 + 0xc);
    local_d4 = *(float *)(param_1 + 0x10);
    local_d0 = *(float *)(param_1 + 0x14);
    fVar1 = (float)(dVar7 - (double)(float)(dVar6 / dVar4));
    local_e4 = *(float *)(param_1 + 0x24) * fVar1 + local_d8;
    local_e0 = *(float *)(param_1 + 0x28) * fVar1 + local_d4;
    local_dc = *(float *)(param_1 + 0x2c) * fVar1 + local_d0;
    iVar2 = FUN_80067ad4();
    if (iVar2 == 0) {
      *(float *)(param_1 + 0xc) = local_e4;
      *(float *)(param_1 + 0x10) = local_e0;
      *(float *)(param_1 + 0x14) = local_dc;
      dVar6 = dVar4;
    }
    else {
      dVar5 = FUN_80293900((double)((local_dc - local_d0) * (local_dc - local_d0) +
                                   (local_e4 - local_d8) * (local_e4 - local_d8) +
                                   (local_e0 - local_d4) * (local_e0 - local_d4)));
      dVar6 = (double)(float)(dVar6 + dVar5);
      FUN_80166cec(param_1,param_2,&local_b4,&local_e4);
    }
  }
  local_d8 = *(float *)(param_1 + 0xc);
  local_d4 = *(float *)(param_1 + 0x10);
  local_d0 = *(float *)(param_1 + 0x14);
  local_e4 = -(FLOAT_803e3cc0 * *(float *)(param_2 + 0x7c) - local_d8);
  local_e0 = -(FLOAT_803e3cc0 * *(float *)(param_2 + 0x80) - local_d4);
  local_dc = -(FLOAT_803e3cc0 * *(float *)(param_2 + 0x84) - local_d0);
  local_74 = FLOAT_803e3c74;
  local_60 = 3;
  iVar3 = FUN_80067ad4();
  if (iVar3 == 0) {
    local_d8 = local_e4;
    local_d4 = local_e0;
    local_d0 = local_dc;
    local_e4 = -*(float *)(param_1 + 0x24);
    local_e0 = -*(float *)(param_1 + 0x28);
    local_dc = -*(float *)(param_1 + 0x2c);
    FUN_800228f0(&local_e4);
    local_e4 = FLOAT_803e3cc4 * local_e4 + local_d8;
    local_e0 = FLOAT_803e3cc4 * local_e0 + local_d4;
    local_dc = FLOAT_803e3cc4 * local_dc + local_d0;
    local_74 = FLOAT_803e3c74;
    local_60 = 3;
    iVar3 = FUN_80067ad4();
    fVar1 = FLOAT_803e3cc8;
    if (iVar3 == 0) {
      *(float *)(param_1 + 0x24) = FLOAT_803e3cc8 * *(float *)(param_2 + 0x7c);
      *(float *)(param_1 + 0x28) = fVar1 * *(float *)(param_2 + 0x80);
      *(float *)(param_1 + 0x2c) = fVar1 * *(float *)(param_2 + 0x84);
      *(byte *)(param_2 + 0x92) = *(byte *)(param_2 + 0x92) & 0xfb | 4;
    }
    else {
      FUN_80166cec(param_1,param_2,&local_b4,&local_e4);
    }
  }
  else if ((((local_b4 == *(float *)(param_2 + 0x7c)) && (local_b0 == *(float *)(param_2 + 0x80)))
           && (local_ac == *(float *)(param_2 + 0x84))) && (local_a8 == *(float *)(param_2 + 0x88)))
  {
    *(float *)(param_1 + 0xc) = local_e4;
    *(float *)(param_1 + 0x10) = local_e0;
    *(float *)(param_1 + 0x14) = local_dc;
  }
  else {
    FUN_80166cec(param_1,param_2,&local_b4,&local_e4);
  }
  *(byte *)(param_2 + 0x92) = *(byte *)(param_2 + 0x92) & 0xf7 | 8;
  return;
}

