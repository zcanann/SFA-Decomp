// Function: FUN_8001377c
// Entry: 8001377c
// Size: 16 bytes

uint FUN_8001377c(short *param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros((int)*param_1);
  return uVar1 >> 5;
}

