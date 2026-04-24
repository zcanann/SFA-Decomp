// Function: FUN_80166444
// Entry: 80166444
// Size: 1020 bytes

/* WARNING: Removing unreachable block (ram,0x80166814) */
/* WARNING: Removing unreachable block (ram,0x8016680c) */
/* WARNING: Removing unreachable block (ram,0x8016681c) */

void FUN_80166444(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f29;
  double dVar7;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar8;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  undefined auStack204 [24];
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_74;
  undefined local_60;
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
  dVar5 = (double)FUN_802931a0((double)(*(float *)(param_1 + 0x2c) * *(float *)(param_1 + 0x2c) +
                                       *(float *)(param_1 + 0x24) * *(float *)(param_1 + 0x24) +
                                       *(float *)(param_1 + 0x28) * *(float *)(param_1 + 0x28)));
  dVar7 = (double)FLOAT_803e2fdc;
  iVar3 = 0;
  local_74 = FLOAT_803e2fdc;
  local_60 = 3;
  local_d8 = *(float *)(param_1 + 0xc);
  local_d4 = *(float *)(param_1 + 0x10);
  local_d0 = *(float *)(param_1 + 0x14);
  local_e4 = local_d8 + *(float *)(param_1 + 0x24);
  local_e0 = local_d4 + *(float *)(param_1 + 0x28);
  local_dc = local_d0 + *(float *)(param_1 + 0x2c);
  local_e8 = FLOAT_803e3020;
  FUN_8006961c(auStack204,&local_d8,&local_e4,&local_e8,1);
  FUN_800691c0(param_1,auStack204,0,1);
  dVar8 = (double)FLOAT_803e2ff4;
  while ((dVar7 < dVar5 && (iVar3 = iVar3 + 1, iVar3 < 10))) {
    local_d8 = *(float *)(param_1 + 0xc);
    local_d4 = *(float *)(param_1 + 0x10);
    local_d0 = *(float *)(param_1 + 0x14);
    fVar1 = (float)(dVar8 - (double)(float)(dVar7 / dVar5));
    local_e4 = *(float *)(param_1 + 0x24) * fVar1 + local_d8;
    local_e0 = *(float *)(param_1 + 0x28) * fVar1 + local_d4;
    local_dc = *(float *)(param_1 + 0x2c) * fVar1 + local_d0;
    iVar2 = FUN_80067958(param_1,&local_d8,&local_e4,1,&local_b4,0x20);
    if (iVar2 == 0) {
      *(float *)(param_1 + 0xc) = local_e4;
      *(float *)(param_1 + 0x10) = local_e0;
      *(float *)(param_1 + 0x14) = local_dc;
      dVar7 = dVar5;
    }
    else {
      dVar6 = (double)FUN_802931a0((double)((local_dc - local_d0) * (local_dc - local_d0) +
                                           (local_e4 - local_d8) * (local_e4 - local_d8) +
                                           (local_e0 - local_d4) * (local_e0 - local_d4)));
      dVar7 = (double)(float)(dVar7 + dVar6);
      FUN_80166840(param_1,param_2,&local_b4,&local_e4);
    }
  }
  local_d8 = *(float *)(param_1 + 0xc);
  local_d4 = *(float *)(param_1 + 0x10);
  local_d0 = *(float *)(param_1 + 0x14);
  local_e4 = -(FLOAT_803e3028 * *(float *)(param_2 + 0x7c) - local_d8);
  local_e0 = -(FLOAT_803e3028 * *(float *)(param_2 + 0x80) - local_d4);
  local_dc = -(FLOAT_803e3028 * *(float *)(param_2 + 0x84) - local_d0);
  local_74 = FLOAT_803e2fdc;
  local_60 = 3;
  iVar3 = FUN_80067958(param_1,&local_d8,&local_e4,1,&local_b4,0x20);
  if (iVar3 == 0) {
    local_d8 = local_e4;
    local_d4 = local_e0;
    local_d0 = local_dc;
    local_e4 = -*(float *)(param_1 + 0x24);
    local_e0 = -*(float *)(param_1 + 0x28);
    local_dc = -*(float *)(param_1 + 0x2c);
    FUN_8002282c(&local_e4);
    local_e4 = FLOAT_803e302c * local_e4 + local_d8;
    local_e0 = FLOAT_803e302c * local_e0 + local_d4;
    local_dc = FLOAT_803e302c * local_dc + local_d0;
    local_74 = FLOAT_803e2fdc;
    local_60 = 3;
    iVar3 = FUN_80067958(param_1,&local_d8,&local_e4,1,&local_b4,0x20);
    fVar1 = FLOAT_803e3030;
    if (iVar3 == 0) {
      *(float *)(param_1 + 0x24) = FLOAT_803e3030 * *(float *)(param_2 + 0x7c);
      *(float *)(param_1 + 0x28) = fVar1 * *(float *)(param_2 + 0x80);
      *(float *)(param_1 + 0x2c) = fVar1 * *(float *)(param_2 + 0x84);
      *(byte *)(param_2 + 0x92) = *(byte *)(param_2 + 0x92) & 0xfb | 4;
    }
    else {
      FUN_80166840(param_1,param_2,&local_b4,&local_e4);
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
    FUN_80166840(param_1,param_2,&local_b4,&local_e4);
  }
  *(byte *)(param_2 + 0x92) = *(byte *)(param_2 + 0x92) & 0xf7 | 8;
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  return;
}

