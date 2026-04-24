// Function: FUN_80022e24
// Entry: 80022e24
// Size: 24 bytes

uint FUN_80022e24(uint param_1)

{
  if ((param_1 & 3) == 0) {
    return param_1;
  }
  return param_1 + (4 - (param_1 & 3));
}

