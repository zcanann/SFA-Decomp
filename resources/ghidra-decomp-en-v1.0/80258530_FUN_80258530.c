// Function: FUN_80258530
// Entry: 80258530
// Size: 28 bytes

void FUN_80258530(int param_1)

{
  *(ushort *)(DAT_803de0b0 + 2) =
       *(ushort *)(DAT_803de0b0 + 2) & 0xffef | (ushort)(param_1 << 4) & 0xff0;
  return;
}

