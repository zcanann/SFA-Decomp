// Function: FUN_80070434
// Entry: 80070434
// Size: 88 bytes

void FUN_80070434(uint param_1)

{
  if (((uint)DAT_803ddc91 != (param_1 & 0xff)) || (DAT_803ddc99 == '\0')) {
    FUN_8025cee4(param_1);
    DAT_803ddc91 = (byte)param_1;
    DAT_803ddc99 = '\x01';
  }
  return;
}

