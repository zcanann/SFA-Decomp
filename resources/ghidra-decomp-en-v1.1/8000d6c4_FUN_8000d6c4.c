// Function: FUN_8000d6c4
// Entry: 8000d6c4
// Size: 132 bytes

void FUN_8000d6c4(uint param_1)

{
  if (((param_1 & 0xff) == 0) && (DAT_803dd4c8 = 0, DAT_803dd4e8 != 0)) {
    FUN_802501f4(0);
    FUN_80250220(0);
    DAT_803dd4e8 = 0;
    DAT_803dd448 = 0;
    FUN_8024ff34(0);
    DAT_803dd4dc = 0;
    DAT_803dd4e0 = 0;
  }
  DAT_803dd5dc = param_1;
  DAT_803dbeb2 = 1;
  return;
}

