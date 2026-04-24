// Function: FUN_802825d0
// Entry: 802825d0
// Size: 72 bytes

uint FUN_802825d0(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 8) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x2a4);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xfffffff7;
    uVar1 = FUN_80282070(param_1,param_1 + 0x284,*(undefined *)(param_1 + 0x121),
                         *(undefined *)(param_1 + 0x122));
  }
  return uVar1;
}

