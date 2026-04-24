// Function: FUN_8026f584
// Entry: 8026f584
// Size: 52 bytes

undefined4 FUN_8026f584(int param_1)

{
  uint uVar1;
  
  uVar1 = (uint)*(byte *)(param_1 + 0x122);
  if (uVar1 == 0xff) {
    uVar1 = 8;
  }
  return *(undefined4 *)(&DAT_803bcd90 + (uint)*(byte *)(param_1 + 0x123) * 4 + uVar1 * 0x40);
}

