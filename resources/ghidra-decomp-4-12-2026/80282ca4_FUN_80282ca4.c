// Function: FUN_80282ca4
// Entry: 80282ca4
// Size: 72 bytes

uint FUN_80282ca4(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 2) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x25c);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xfffffffd;
    uVar1 = FUN_802827d4(param_1,(byte *)(param_1 + 0x23c),(uint)*(byte *)(param_1 + 0x121),
                         (uint)*(byte *)(param_1 + 0x122));
  }
  return uVar1;
}

