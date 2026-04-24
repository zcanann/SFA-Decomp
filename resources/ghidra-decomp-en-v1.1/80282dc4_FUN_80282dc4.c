// Function: FUN_80282dc4
// Entry: 80282dc4
// Size: 72 bytes

uint FUN_80282dc4(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x20) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x2ec);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xffffffdf;
    uVar1 = FUN_802827d4(param_1,(byte *)(param_1 + 0x2cc),(uint)*(byte *)(param_1 + 0x121),
                         (uint)*(byte *)(param_1 + 0x122));
  }
  return uVar1;
}

