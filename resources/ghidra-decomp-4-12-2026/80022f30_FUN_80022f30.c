// Function: FUN_80022f30
// Entry: 80022f30
// Size: 24 bytes

uint FUN_80022f30(uint param_1)

{
  if ((param_1 & 0x1f) == 0) {
    return param_1;
  }
  return param_1 + (0x20 - (param_1 & 0x1f));
}

