// Function: FUN_800138c4
// Entry: 800138c4
// Size: 28 bytes

uint FUN_800138c4(short *param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros((param_1[1] + -1) - (int)*param_1);
  return uVar1 >> 5;
}

