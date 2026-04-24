// Function: FUN_80022e6c
// Entry: 80022e6c
// Size: 24 bytes

uint FUN_80022e6c(uint param_1)

{
  if ((param_1 & 0x1f) == 0) {
    return param_1;
  }
  return param_1 + (0x20 - (param_1 & 0x1f));
}

