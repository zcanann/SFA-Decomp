// Function: FUN_801fbdc4
// Entry: 801fbdc4
// Size: 116 bytes

void FUN_801fbdc4(int param_1)

{
  uint uVar1;
  
  uVar1 = (uint)*(short *)(*(int *)(param_1 + 0xb8) + 0xc);
  if ((uVar1 == 0xffffffff) || (uVar1 = FUN_80020078(uVar1), uVar1 != 0)) {
    if ((*(byte *)(param_1 + 0xaf) & 8) != 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) ^ 8;
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  return;
}

