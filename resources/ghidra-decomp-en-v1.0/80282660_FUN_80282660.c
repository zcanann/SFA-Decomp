// Function: FUN_80282660
// Entry: 80282660
// Size: 72 bytes

uint FUN_80282660(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x20) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x2ec);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xffffffdf;
    uVar1 = FUN_80282070(param_1,param_1 + 0x2cc,*(undefined *)(param_1 + 0x121),
                         *(undefined *)(param_1 + 0x122));
  }
  return uVar1;
}

