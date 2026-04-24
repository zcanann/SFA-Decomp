// Function: FUN_8027a1dc
// Entry: 8027a1dc
// Size: 124 bytes

undefined4 FUN_8027a1dc(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0xf4) != 0xffffffff) && (*(byte *)(param_1 + 0x121) != 0xff)) {
    uVar1 = *(uint *)(param_1 + 0xf4) & 0xff;
    if (*(byte *)(param_1 + 0x122) == 0xff) {
      if ((byte)(&DAT_803cab50)[uVar1] == uVar1) {
        return 1;
      }
    }
    else if (uVar1 == (byte)(&DAT_803caad0)
                            [(uint)*(byte *)(param_1 + 0x121) +
                             (uint)*(byte *)(param_1 + 0x122) * 0x10]) {
      return 1;
    }
  }
  return 0;
}

