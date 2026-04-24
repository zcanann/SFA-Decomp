// Function: FUN_80283f80
// Entry: 80283f80
// Size: 32 bytes

uint FUN_80283f80(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(1 - (uint)*(byte *)(DAT_803de344 + param_1 * 0xf4 + 0xec));
  return uVar1 >> 5;
}

