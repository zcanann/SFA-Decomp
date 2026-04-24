// Function: FUN_80282780
// Entry: 80282780
// Size: 72 bytes

uint FUN_80282780(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x400) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x3a0);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xfffffbff;
    uVar1 = FUN_80282070(param_1,param_1 + 0x380,*(undefined *)(param_1 + 0x121),
                         *(undefined *)(param_1 + 0x122));
  }
  return uVar1;
}

