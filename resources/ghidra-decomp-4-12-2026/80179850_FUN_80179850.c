// Function: FUN_80179850
// Entry: 80179850
// Size: 20 bytes

uint FUN_80179850(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros((uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x274));
  return uVar1 >> 5;
}

