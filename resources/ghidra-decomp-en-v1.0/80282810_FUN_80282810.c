// Function: FUN_80282810
// Entry: 80282810
// Size: 72 bytes

uint FUN_80282810(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 0x1000) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 1000);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xffffefff;
    uVar1 = FUN_80282070(param_1,param_1 + 0x3c8,*(undefined *)(param_1 + 0x121),
                         *(undefined *)(param_1 + 0x122));
  }
  return uVar1;
}

