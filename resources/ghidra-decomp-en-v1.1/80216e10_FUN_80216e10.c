// Function: FUN_80216e10
// Entry: 80216e10
// Size: 784 bytes

void FUN_80216e10(ushort *param_1)

{
  float fVar1;
  uint uVar2;
  uint uVar3;
  byte *pbVar4;
  int iVar5;
  undefined4 local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar5 = *(int *)(param_1 + 0x26);
  pbVar4 = *(byte **)(param_1 + 0x5c);
  pbVar4[1] = *pbVar4;
  *pbVar4 = *pbVar4 & 0xfc;
  uVar2 = FUN_80020078((int)*(short *)(iVar5 + 0x1a));
  if ((short)uVar2 < *(short *)(iVar5 + 0x1c)) {
    *pbVar4 = *pbVar4 & 0xfb;
    uVar3 = FUN_80020078((int)*(short *)(iVar5 + 0x1e));
    if (uVar3 == 0) {
      return;
    }
  }
  else {
    *pbVar4 = *pbVar4 | 4;
  }
  param_1[2] = param_1[2] + 0x38e;
  if ((0xe < (short)uVar2) && ((*pbVar4 & 9) == 0)) {
    FUN_800201ac((int)*(short *)(iVar5 + 0x1e),1);
    *pbVar4 = *pbVar4 | 9;
    FUN_80216b48((double)FLOAT_803e7550,param_1,0x78);
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x47e,0,2,0xffffffff,0);
    iVar5 = 10;
    do {
      local_28[0] = 2;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x48c,0,2,0xffffffff,local_28);
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
    uStack_1c = FUN_80022264(1,0x3c);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(pbVar4 + 4) = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7540);
  }
  if ((*pbVar4 & 4) != 0) {
    local_28[0] = 0;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x48c,0,2,0xffffffff,local_28);
    local_28[0] = 1;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x48c,0,2,0xffffffff,local_28);
    if ((pbVar4[1] & 4) == 0) {
      FUN_8000bb38((uint)param_1,0x82);
    }
  }
  if ((*pbVar4 & 8) != 0) {
    local_28[0] = 0;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x48c,0,2,0xffffffff,local_28);
    local_28[0] = 2;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x48c,0,2,0xffffffff,local_28);
  }
  if (((*pbVar4 & 8) == 0) && ((pbVar4[1] & 8) != 0)) {
    FUN_8000bb38((uint)param_1,0x84);
  }
  fVar1 = FLOAT_803e7530;
  if ((FLOAT_803e7530 < *(float *)(pbVar4 + 4)) &&
     (*(float *)(pbVar4 + 4) = *(float *)(pbVar4 + 4) - FLOAT_803dc074,
     *(float *)(pbVar4 + 4) <= fVar1)) {
    FUN_8000bb38((uint)param_1,0x83);
    *(float *)(pbVar4 + 4) = FLOAT_803e7530;
  }
  return;
}

