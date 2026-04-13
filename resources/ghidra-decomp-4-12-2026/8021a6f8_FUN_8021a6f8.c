// Function: FUN_8021a6f8
// Entry: 8021a6f8
// Size: 112 bytes

void FUN_8021a6f8(int param_1)

{
  uint uVar1;
  
  uVar1 = FUN_80020078((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e));
  if (uVar1 == 0) {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    FUN_80036018(param_1);
  }
  else {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    FUN_80035ff8(param_1);
  }
  return;
}

