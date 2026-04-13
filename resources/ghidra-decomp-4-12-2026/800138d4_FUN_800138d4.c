// Function: FUN_800138d4
// Entry: 800138d4
// Size: 16 bytes

uint FUN_800138d4(short *param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros((int)*param_1);
  return uVar1 >> 5;
}

