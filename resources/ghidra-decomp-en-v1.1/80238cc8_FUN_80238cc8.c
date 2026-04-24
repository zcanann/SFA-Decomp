// Function: FUN_80238cc8
// Entry: 80238cc8
// Size: 24 bytes

uint FUN_80238cc8(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(2 - (uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0xc));
  return uVar1 >> 5;
}

