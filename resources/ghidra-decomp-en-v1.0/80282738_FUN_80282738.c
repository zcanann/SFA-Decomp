// Function: FUN_80282738
// Entry: 80282738
// Size: 72 bytes

uint FUN_80282738(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x200) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x37c);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xfffffdff;
    uVar1 = FUN_80282070(param_1,param_1 + 0x35c,*(undefined *)(param_1 + 0x121),
                         *(undefined *)(param_1 + 0x122));
  }
  return uVar1;
}

