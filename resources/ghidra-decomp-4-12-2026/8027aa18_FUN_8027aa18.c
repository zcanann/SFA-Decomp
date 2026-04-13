// Function: FUN_8027aa18
// Entry: 8027aa18
// Size: 124 bytes

void FUN_8027aa18(int param_1)

{
  uint uVar1;
  
  if (*(uint *)(param_1 + 0xf4) == 0xffffffff) {
    return;
  }
  if (*(byte *)(param_1 + 0x121) == 0xff) {
    return;
  }
  uVar1 = *(uint *)(param_1 + 0xf4) & 0xff;
  if (*(byte *)(param_1 + 0x122) != 0xff) {
    if (uVar1 != (byte)(&DAT_803cb730)
                       [(uint)*(byte *)(param_1 + 0x121) + (uint)*(byte *)(param_1 + 0x122) * 0x10])
    {
      return;
    }
    (&DAT_803cb730)[(uint)*(byte *)(param_1 + 0x121) + (uint)*(byte *)(param_1 + 0x122) * 0x10] =
         0xff;
    return;
  }
  if ((byte)(&DAT_803cb7b0)[uVar1] != uVar1) {
    return;
  }
  (&DAT_803cb7b0)[uVar1] = 0xff;
  return;
}

