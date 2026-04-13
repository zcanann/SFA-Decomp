// Function: FUN_8027a940
// Entry: 8027a940
// Size: 124 bytes

undefined4 FUN_8027a940(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0xf4) != 0xffffffff) && (*(byte *)(param_1 + 0x121) != 0xff)) {
    uVar1 = *(uint *)(param_1 + 0xf4) & 0xff;
    if (*(byte *)(param_1 + 0x122) == 0xff) {
      if ((byte)(&DAT_803cb7b0)[uVar1] == uVar1) {
        return 1;
      }
    }
    else if (uVar1 == (byte)(&DAT_803cb730)
                            [(uint)*(byte *)(param_1 + 0x121) +
                             (uint)*(byte *)(param_1 + 0x122) * 0x10]) {
      return 1;
    }
  }
  return 0;
}

