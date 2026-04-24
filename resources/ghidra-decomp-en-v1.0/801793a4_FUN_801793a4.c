// Function: FUN_801793a4
// Entry: 801793a4
// Size: 20 bytes

uint FUN_801793a4(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros((uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x274));
  return uVar1 >> 5;
}

