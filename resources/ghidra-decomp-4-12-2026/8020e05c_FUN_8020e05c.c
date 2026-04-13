// Function: FUN_8020e05c
// Entry: 8020e05c
// Size: 480 bytes

/* WARNING: Removing unreachable block (ram,0x8020e218) */
/* WARNING: Removing unreachable block (ram,0x8020e06c) */

void FUN_8020e05c(int param_1)

{
  float fVar1;
  uint uVar2;
  byte bVar3;
  double dVar4;
  undefined auStack_38 [8];
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  dVar4 = (double)FLOAT_803e72d8;
  for (bVar3 = 0; bVar3 < 10; bVar3 = bVar3 + 1) {
    fVar1 = *(float *)(param_1 + 8);
    uVar2 = (uint)bVar3;
    local_2c = (float)(dVar4 * (double)(fVar1 * (float)(&DAT_8032ae68)[uVar2 * 5]));
    local_28 = (float)(dVar4 * (double)(fVar1 * (float)(&DAT_8032ae6c)[uVar2 * 5]));
    local_24 = (float)(dVar4 * (double)(fVar1 * (float)(&DAT_8032ae70)[uVar2 * 5]));
    FUN_8009742c((double)(fVar1 * (float)(&DAT_8032ae74)[uVar2 * 5]),param_1,3,
                 (uint)(byte)(&DAT_8032ae78)[uVar2 * 0x14],(uint)(byte)(&DAT_8032ae79)[uVar2 * 0x14]
                 ,(int)auStack_38);
  }
  local_30 = FLOAT_803e72dc;
  fVar1 = *(float *)(param_1 + 8);
  local_2c = FLOAT_803e72d8 * FLOAT_803e72e0 * fVar1;
  local_28 = FLOAT_803e72d8 * FLOAT_803e72e4 * fVar1;
  local_24 = FLOAT_803e72d8 * FLOAT_803e72e8 * fVar1;
  FUN_80098608((double)(FLOAT_803e72ec * fVar1),(double)FLOAT_803e72f0);
  local_2c = FLOAT_803e72f4;
  fVar1 = *(float *)(param_1 + 8);
  local_28 = FLOAT_803e72d8 * FLOAT_803e72f8 * fVar1;
  local_24 = FLOAT_803e72d8 * FLOAT_803e72fc * fVar1;
  FUN_80098608((double)(FLOAT_803e72ec * fVar1),(double)FLOAT_803e7300);
  fVar1 = *(float *)(param_1 + 8);
  local_2c = FLOAT_803e72d8 * FLOAT_803e7304 * fVar1;
  local_28 = FLOAT_803e72d8 * FLOAT_803e72e4 * fVar1;
  local_24 = FLOAT_803e72d8 * FLOAT_803e72e8 * fVar1;
  FUN_80098608((double)(FLOAT_803e72ec * fVar1),(double)FLOAT_803e72f0);
  return;
}

