// Function: FUN_80282f74
// Entry: 80282f74
// Size: 72 bytes

uint FUN_80282f74(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x1000) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 1000);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xffffefff;
    uVar1 = FUN_802827d4(param_1,(byte *)(param_1 + 0x3c8),(uint)*(byte *)(param_1 + 0x121),
                         (uint)*(byte *)(param_1 + 0x122));
  }
  return uVar1;
}

