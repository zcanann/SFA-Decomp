// Function: FUN_80282f2c
// Entry: 80282f2c
// Size: 72 bytes

uint FUN_80282f2c(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x800) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x3c4);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xfffff7ff;
    uVar1 = FUN_802827d4(param_1,(byte *)(param_1 + 0x3a4),(uint)*(byte *)(param_1 + 0x121),
                         (uint)*(byte *)(param_1 + 0x122));
  }
  return uVar1;
}

