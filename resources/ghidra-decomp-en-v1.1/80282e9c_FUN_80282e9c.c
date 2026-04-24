// Function: FUN_80282e9c
// Entry: 80282e9c
// Size: 72 bytes

uint FUN_80282e9c(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x200) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x37c);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xfffffdff;
    uVar1 = FUN_802827d4(param_1,(byte *)(param_1 + 0x35c),(uint)*(byte *)(param_1 + 0x121),
                         (uint)*(byte *)(param_1 + 0x122));
  }
  return uVar1;
}

