// Function: FUN_8018a284
// Entry: 8018a284
// Size: 696 bytes

void FUN_8018a284(int param_1)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined auStack40 [4];
  undefined2 local_24;
  undefined2 local_22;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_8002b9ec();
  if ((*(byte *)(iVar3 + 0x1d) >> 6 & 1) == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  if ((*(char *)(iVar3 + 0x1d) < '\0') && (iVar2 = FUN_80295ce4(), iVar2 != 0)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  bVar1 = *(byte *)(iVar4 + 0x1c);
  if (bVar1 == 2) {
    FUN_801899b4(param_1,iVar3);
  }
  else {
    if (bVar1 < 2) {
      if (bVar1 == 0) {
        if (((*(byte *)(param_1 + 0xaf) & 4) != 0) && (iVar2 = FUN_8001ffb4(0xd2a), iVar2 == 0)) {
          (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
          FUN_800200e8(0xd2a,1);
        }
        iVar2 = FUN_8001ffb4(0x957);
        if (iVar2 == 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
        }
        iVar2 = 0;
        if ((*(short *)(iVar4 + 0x22) == -1) || (iVar4 = FUN_8001ffb4(), iVar4 != 0)) {
          iVar2 = 1;
        }
        *(byte *)(iVar3 + 0x1d) = (byte)(iVar2 << 7) | *(byte *)(iVar3 + 0x1d) & 0x7f;
        if (-1 < *(char *)(iVar3 + 0x1d)) {
          return;
        }
        local_1c = FLOAT_803e3c00;
        local_18 = FLOAT_803e3c04;
        local_14 = FLOAT_803e3bdc;
        local_20 = FLOAT_803e3bbc;
        local_22 = 0;
        local_24 = 100;
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x7c3,auStack40,2,0xffffffff,0);
        local_1c = FLOAT_803e3c00;
        local_18 = FLOAT_803e3c04;
        local_14 = FLOAT_803e3bdc;
        local_20 = FLOAT_803e3bbc;
        local_22 = 5;
        local_24 = 10;
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x7c3,auStack40,2,0xffffffff,0);
        return;
      }
    }
    else if (bVar1 < 6) {
      if (bVar1 < 4) {
        FUN_80189610(param_1,iVar3);
        return;
      }
      FUN_80189858(param_1,iVar3);
      return;
    }
    iVar2 = 0;
    if ((*(short *)(iVar4 + 0x22) == -1) || (iVar4 = FUN_8001ffb4(), iVar4 != 0)) {
      iVar2 = 1;
    }
    *(byte *)(iVar3 + 0x1d) = (byte)(iVar2 << 7) | *(byte *)(iVar3 + 0x1d) & 0x7f;
  }
  return;
}

