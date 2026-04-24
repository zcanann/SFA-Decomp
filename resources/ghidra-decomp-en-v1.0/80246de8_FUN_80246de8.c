// Function: FUN_80246de8
// Entry: 80246de8
// Size: 28 bytes

uint FUN_80246de8(uint param_1)

{
  return *(uint *)(DAT_803dde98 + 4) & 1 << (param_1 & 0xff);
}

