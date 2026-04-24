// Function: FUN_80022e0c
// Entry: 80022e0c
// Size: 24 bytes

uint FUN_80022e0c(uint param_1)

{
  if ((param_1 & 1) == 0) {
    return param_1;
  }
  return param_1 + (2 - (param_1 & 1));
}

