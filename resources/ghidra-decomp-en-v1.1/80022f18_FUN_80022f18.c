// Function: FUN_80022f18
// Entry: 80022f18
// Size: 24 bytes

uint FUN_80022f18(uint param_1)

{
  if ((param_1 & 0xf) == 0) {
    return param_1;
  }
  return param_1 + (0x10 - (param_1 & 0xf));
}

