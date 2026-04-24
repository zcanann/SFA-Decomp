// Function: FUN_80282c5c
// Entry: 80282c5c
// Size: 72 bytes

uint FUN_80282c5c(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 1) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x238);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xfffffffe;
    uVar1 = FUN_802827d4(param_1,(byte *)(param_1 + 0x218),(uint)*(byte *)(param_1 + 0x121),
                         (uint)*(byte *)(param_1 + 0x122));
  }
  return uVar1;
}

