// Function: FUN_80022ed0
// Entry: 80022ed0
// Size: 24 bytes

uint FUN_80022ed0(uint param_1)

{
  if ((param_1 & 1) == 0) {
    return param_1;
  }
  return param_1 + (2 - (param_1 & 1));
}

