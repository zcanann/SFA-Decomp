// Function: FUN_8013aa44
// Entry: 8013aa44
// Size: 312 bytes

int FUN_8013aa44(int param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  
  if (param_3 == 0) {
    return 0;
  }
  if ((*(int *)(param_1 + 0x6ec) == param_3) && (*(int *)(param_1 + 0x6e8) == param_2)) {
    uVar1 = FUN_8004b294(param_1 + 0x6b8);
    *(undefined4 *)(param_1 + 0x6e8) = uVar1;
    iVar3 = *(int *)(param_1 + 0x6e8);
    if (iVar3 == 0) {
      return 0;
    }
    if (iVar3 != 0) {
      if ((((int)*(short *)(iVar3 + 0x30) != 0xffffffff) &&
          (uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x30)), uVar2 == 0)) ||
         (((int)*(short *)(iVar3 + 0x32) != 0xffffffff &&
          (uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x32)), uVar2 != 0)))) {
        iVar3 = 0;
      }
    }
    else {
      iVar3 = 0;
    }
    *(int *)(param_1 + 0x6e8) = iVar3;
    if (*(int *)(param_1 + 0x6e8) != 0) {
      return *(int *)(param_1 + 0x6e8);
    }
  }
  FUN_8004b498((int *)(param_1 + 0x6b8),param_2,*(int *)(param_1 + 0x28),param_3,
               (byte)*(undefined4 *)(param_1 + 0x4a0));
  iVar3 = FUN_8004b394();
  if (iVar3 == 1) {
    FUN_8004b2c4((int *)(param_1 + 0x6b8));
    uVar1 = FUN_8004b294(param_1 + 0x6b8);
    *(undefined4 *)(param_1 + 0x6e8) = uVar1;
    *(int *)(param_1 + 0x6ec) = param_3;
    iVar3 = *(int *)(param_1 + 0x6e8);
  }
  else {
    iVar3 = 0;
  }
  return iVar3;
}

