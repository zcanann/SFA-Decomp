// Function: FUN_80022e3c
// Entry: 80022e3c
// Size: 24 bytes

uint FUN_80022e3c(uint param_1)

{
  if ((param_1 & 7) == 0) {
    return param_1;
  }
  return param_1 + (8 - (param_1 & 7));
}

