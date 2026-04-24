// Function: FUN_80282618
// Entry: 80282618
// Size: 72 bytes

uint FUN_80282618(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x10) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x2c8);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xffffffef;
    uVar1 = FUN_80282070(param_1,param_1 + 0x2a8,*(undefined *)(param_1 + 0x121),
                         *(undefined *)(param_1 + 0x122));
  }
  return uVar1;
}

