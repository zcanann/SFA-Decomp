// Function: FUN_8026fce8
// Entry: 8026fce8
// Size: 52 bytes

undefined4 FUN_8026fce8(int param_1)

{
  uint uVar1;
  
  uVar1 = (uint)*(byte *)(param_1 + 0x122);
  if (uVar1 == 0xff) {
    uVar1 = 8;
  }
  return *(undefined4 *)(&DAT_803bd9f0 + (uint)*(byte *)(param_1 + 0x123) * 4 + uVar1 * 0x40);
}

