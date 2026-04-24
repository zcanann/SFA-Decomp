// Function: FUN_8027a9bc
// Entry: 8027a9bc
// Size: 92 bytes

void FUN_8027a9bc(int param_1)

{
  uint uVar1;
  
  uVar1 = *(uint *)(param_1 + 0xf4);
  if (uVar1 == 0xffffffff) {
    return;
  }
  if (*(byte *)(param_1 + 0x121) == 0xff) {
    return;
  }
  if (*(byte *)(param_1 + 0x122) == 0xff) {
    (&DAT_803cb7b0)[uVar1 & 0xff] = (char)uVar1;
    return;
  }
  (&DAT_803cb730)[(uint)*(byte *)(param_1 + 0x121) + (uint)*(byte *)(param_1 + 0x122) * 0x10] =
       (char)uVar1;
  return;
}

