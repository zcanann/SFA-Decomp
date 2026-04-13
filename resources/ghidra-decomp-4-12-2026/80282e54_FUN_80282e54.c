// Function: FUN_80282e54
// Entry: 80282e54
// Size: 72 bytes

uint FUN_80282e54(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x100) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x358);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xfffffeff;
    uVar1 = FUN_802827d4(param_1,(byte *)(param_1 + 0x338),(uint)*(byte *)(param_1 + 0x121),
                         (uint)*(byte *)(param_1 + 0x122));
  }
  return uVar1;
}

