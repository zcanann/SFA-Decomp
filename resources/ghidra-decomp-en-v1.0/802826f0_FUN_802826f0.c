// Function: FUN_802826f0
// Entry: 802826f0
// Size: 72 bytes

uint FUN_802826f0(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x100) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x358);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xfffffeff;
    uVar1 = FUN_80282070(param_1,param_1 + 0x338,*(undefined *)(param_1 + 0x121),
                         *(undefined *)(param_1 + 0x122));
  }
  return uVar1;
}

