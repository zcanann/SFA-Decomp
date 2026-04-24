// Function: FUN_802824f8
// Entry: 802824f8
// Size: 72 bytes

uint FUN_802824f8(int param_1)

{
  uint uVar1;
  
  if ((*(uint *)(param_1 + 0x214) & 1) == 0) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x238);
  }
  else {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) & 0xfffffffe;
    uVar1 = FUN_80282070(param_1,param_1 + 0x218,*(undefined *)(param_1 + 0x121),
                         *(undefined *)(param_1 + 0x122));
  }
  return uVar1;
}

