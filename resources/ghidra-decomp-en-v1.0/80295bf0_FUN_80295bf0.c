// Function: FUN_80295bf0
// Entry: 80295bf0
// Size: 28 bytes

uint FUN_80295bf0(int param_1)

{
  uint uVar1;
  
  uVar1 = (uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x8c8);
  return (0x44 - uVar1 | uVar1 - 0x44) >> 0x1f;
}

