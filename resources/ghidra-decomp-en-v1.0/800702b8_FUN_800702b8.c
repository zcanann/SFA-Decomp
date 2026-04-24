// Function: FUN_800702b8
// Entry: 800702b8
// Size: 88 bytes

void FUN_800702b8(uint param_1)

{
  if (((uint)DAT_803dd011 != (param_1 & 0xff)) || (DAT_803dd019 == '\0')) {
    FUN_8025c780(param_1);
    DAT_803dd011 = (byte)param_1;
    DAT_803dd019 = '\x01';
  }
  return;
}

