// Function: FUN_8020d9e4
// Entry: 8020d9e4
// Size: 480 bytes

/* WARNING: Removing unreachable block (ram,0x8020dba0) */

void FUN_8020d9e4(int param_1)

{
  float fVar1;
  uint uVar2;
  byte bVar3;
  undefined4 uVar4;
  undefined8 in_f31;
  double dVar5;
  undefined auStack56 [8];
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  dVar5 = (double)FLOAT_803e6640;
  for (bVar3 = 0; bVar3 < 10; bVar3 = bVar3 + 1) {
    fVar1 = *(float *)(param_1 + 8);
    uVar2 = (uint)bVar3;
    local_2c = (float)(dVar5 * (double)(fVar1 * (float)(&DAT_8032a210)[uVar2 * 5]));
    local_28 = (float)(dVar5 * (double)(fVar1 * (float)(&DAT_8032a214)[uVar2 * 5]));
    local_24 = (float)(dVar5 * (double)(fVar1 * (float)(&DAT_8032a218)[uVar2 * 5]));
    FUN_800971a0((double)(fVar1 * (float)(&DAT_8032a21c)[uVar2 * 5]),param_1,3,
                 (&DAT_8032a220)[uVar2 * 0x14],(&DAT_8032a221)[uVar2 * 0x14],auStack56);
  }
  local_30 = FLOAT_803e6644;
  fVar1 = *(float *)(param_1 + 8);
  local_2c = FLOAT_803e6640 * FLOAT_803e6648 * fVar1;
  local_28 = FLOAT_803e6640 * FLOAT_803e664c * fVar1;
  local_24 = FLOAT_803e6640 * FLOAT_803e6650 * fVar1;
  FUN_8009837c((double)(FLOAT_803e6654 * fVar1),(double)FLOAT_803e6658,param_1,1,0,6,auStack56);
  local_2c = FLOAT_803e665c;
  fVar1 = *(float *)(param_1 + 8);
  local_28 = FLOAT_803e6640 * FLOAT_803e6660 * fVar1;
  local_24 = FLOAT_803e6640 * FLOAT_803e6664 * fVar1;
  FUN_8009837c((double)(FLOAT_803e6654 * fVar1),(double)FLOAT_803e6668,param_1,1,0,6,auStack56);
  fVar1 = *(float *)(param_1 + 8);
  local_2c = FLOAT_803e6640 * FLOAT_803e666c * fVar1;
  local_28 = FLOAT_803e6640 * FLOAT_803e664c * fVar1;
  local_24 = FLOAT_803e6640 * FLOAT_803e6650 * fVar1;
  FUN_8009837c((double)(FLOAT_803e6654 * fVar1),(double)FLOAT_803e6658,param_1,1,0,6,auStack56);
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return;
}

