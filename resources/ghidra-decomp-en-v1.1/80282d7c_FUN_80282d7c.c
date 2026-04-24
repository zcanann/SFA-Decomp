// Function: FUN_80282d7c
// Entry: 80282d7c
// Size: 72 bytes

uint FUN_80282d7c(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x10) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x2c8);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xffffffef;
    uVar1 = FUN_802827d4(param_1,(byte *)(param_1 + 0x2a8),(uint)*(byte *)(param_1 + 0x121),
                         (uint)*(byte *)(param_1 + 0x122));
  }
  return uVar1;
}

