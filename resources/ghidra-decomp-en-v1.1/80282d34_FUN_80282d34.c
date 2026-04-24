// Function: FUN_80282d34
// Entry: 80282d34
// Size: 72 bytes

uint FUN_80282d34(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 8) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x2a4);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xfffffff7;
    uVar1 = FUN_802827d4(param_1,(byte *)(param_1 + 0x284),(uint)*(byte *)(param_1 + 0x121),
                         (uint)*(byte *)(param_1 + 0x122));
  }
  return uVar1;
}

