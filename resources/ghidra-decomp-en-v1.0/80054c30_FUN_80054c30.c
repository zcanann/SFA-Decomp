// Function: FUN_80054c30
// Entry: 80054c30
// Size: 104 bytes

void FUN_80054c30(int param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  
  if ((int)(uint)*(ushort *)(param_1 + 0x10) <= param_2) {
    param_2 = *(ushort *)(param_1 + 0x10) - 1;
  }
  uVar1 = param_2 >> 8;
  if ((int)uVar1 < 1) {
    return;
  }
  uVar2 = uVar1 >> 3;
  if (uVar2 != 0) {
    do {
      uVar2 = uVar2 - 1;
    } while (uVar2 != 0);
    uVar1 = uVar1 & 7;
    if (uVar1 == 0) {
      return;
    }
  }
  do {
    uVar1 = uVar1 - 1;
  } while (uVar1 != 0);
  return;
}

