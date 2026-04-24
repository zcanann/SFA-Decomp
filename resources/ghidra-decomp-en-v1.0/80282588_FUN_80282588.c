// Function: FUN_80282588
// Entry: 80282588
// Size: 72 bytes

uint FUN_80282588(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 4) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x280);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xfffffffb;
    uVar1 = FUN_80282070(param_1,param_1 + 0x260,*(undefined *)(param_1 + 0x121),
                         *(undefined *)(param_1 + 0x122));
  }
  return uVar1;
}

