// Function: FUN_802585d4
// Entry: 802585d4
// Size: 28 bytes

void FUN_802585d4(int param_1)

{
  *(ushort *)(DAT_803de0b0 + 2) =
       *(ushort *)(DAT_803de0b0 + 2) & 0xfff7 | (ushort)(param_1 << 3) & 0x7f8;
  return;
}

