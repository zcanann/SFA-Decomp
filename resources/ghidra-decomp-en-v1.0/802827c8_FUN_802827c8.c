// Function: FUN_802827c8
// Entry: 802827c8
// Size: 72 bytes

uint FUN_802827c8(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x800) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x3c4);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xfffff7ff;
    uVar1 = FUN_80282070(param_1,param_1 + 0x3a4,*(undefined *)(param_1 + 0x121),
                         *(undefined *)(param_1 + 0x122));
  }
  return uVar1;
}

