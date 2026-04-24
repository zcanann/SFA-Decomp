// Function: FUN_80287738
// Entry: 80287738
// Size: 100 bytes

void FUN_80287738(int param_1)

{
  if (((param_1 != -1) && (-1 < param_1)) && (param_1 < 3)) {
    FUN_8028aefc(&DAT_803d6920 + param_1 * 0x890);
    (&DAT_803d6924)[param_1 * 0x224] = 0;
    FUN_8028aef4(&DAT_803d6920 + param_1 * 0x890);
  }
  return;
}

