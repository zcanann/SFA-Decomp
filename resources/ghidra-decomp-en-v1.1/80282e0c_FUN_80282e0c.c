// Function: FUN_80282e0c
// Entry: 80282e0c
// Size: 72 bytes

uint FUN_80282e0c(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x40) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x310);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xffffffbf;
    uVar1 = FUN_802827d4(param_1,(byte *)(param_1 + 0x2f0),(uint)*(byte *)(param_1 + 0x121),
                         (uint)*(byte *)(param_1 + 0x122));
  }
  return uVar1;
}

