// Function: FUN_802826a8
// Entry: 802826a8
// Size: 72 bytes

uint FUN_802826a8(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x40) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x310);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xffffffbf;
    uVar1 = FUN_80282070(param_1,param_1 + 0x2f0,*(undefined *)(param_1 + 0x121),
                         *(undefined *)(param_1 + 0x122));
  }
  return uVar1;
}

