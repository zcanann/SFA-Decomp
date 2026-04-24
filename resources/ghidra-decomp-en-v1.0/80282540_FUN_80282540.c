// Function: FUN_80282540
// Entry: 80282540
// Size: 72 bytes

uint FUN_80282540(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 2) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x25c);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xfffffffd;
    uVar1 = FUN_80282070(param_1,param_1 + 0x23c,*(undefined *)(param_1 + 0x121),
                         *(undefined *)(param_1 + 0x122));
  }
  return uVar1;
}

