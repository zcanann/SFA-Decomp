// Function: FUN_80216798
// Entry: 80216798
// Size: 784 bytes

void FUN_80216798(int param_1)

{
  float fVar1;
  short sVar3;
  int iVar2;
  byte *pbVar4;
  int iVar5;
  undefined4 local_28 [2];
  undefined4 local_20;
  uint uStack28;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  pbVar4 = *(byte **)(param_1 + 0xb8);
  pbVar4[1] = *pbVar4;
  *pbVar4 = *pbVar4 & 0xfc;
  sVar3 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x1a));
  if (sVar3 < *(short *)(iVar5 + 0x1c)) {
    *pbVar4 = *pbVar4 & 0xfb;
    iVar2 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x1e));
    if (iVar2 == 0) {
      return;
    }
  }
  else {
    *pbVar4 = *pbVar4 | 4;
  }
  *(short *)(param_1 + 4) = *(short *)(param_1 + 4) + 0x38e;
  if ((0xe < sVar3) && ((*pbVar4 & 9) == 0)) {
    FUN_800200e8((int)*(short *)(iVar5 + 0x1e),1);
    *pbVar4 = *pbVar4 | 9;
    FUN_802164d0((double)FLOAT_803e68b8,param_1,0x78);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x47e,0,2,0xffffffff,0);
    iVar5 = 10;
    do {
      local_28[0] = 2;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x48c,0,2,0xffffffff,local_28);
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
    uStack28 = FUN_800221a0(1,0x3c);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(pbVar4 + 4) = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e68a8);
  }
  if ((*pbVar4 & 4) != 0) {
    local_28[0] = 0;
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x48c,0,2,0xffffffff,local_28);
    local_28[0] = 1;
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x48c,0,2,0xffffffff,local_28);
    if ((pbVar4[1] & 4) == 0) {
      FUN_8000bb18(param_1,0x82);
    }
  }
  if ((*pbVar4 & 8) != 0) {
    local_28[0] = 0;
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x48c,0,2,0xffffffff,local_28);
    local_28[0] = 2;
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x48c,0,2,0xffffffff,local_28);
  }
  if (((*pbVar4 & 8) == 0) && ((pbVar4[1] & 8) != 0)) {
    FUN_8000bb18(param_1,0x84);
  }
  fVar1 = FLOAT_803e6898;
  if ((FLOAT_803e6898 < *(float *)(pbVar4 + 4)) &&
     (*(float *)(pbVar4 + 4) = *(float *)(pbVar4 + 4) - FLOAT_803db414,
     *(float *)(pbVar4 + 4) <= fVar1)) {
    FUN_8000bb18(param_1,0x83);
    *(float *)(pbVar4 + 4) = FLOAT_803e6898;
  }
  return;
}

