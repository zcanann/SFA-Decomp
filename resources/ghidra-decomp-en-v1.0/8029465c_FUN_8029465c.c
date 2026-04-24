// Function: FUN_8029465c
// Entry: 8029465c
// Size: 40 bytes

uint FUN_8029465c(uint param_1)

{
  if (param_1 == 0xffffffff) {
    return 0xffffffff;
  }
  return (uint)(byte)(&DAT_803326e8)[param_1 & 0xff];
}

