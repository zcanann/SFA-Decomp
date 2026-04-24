// Function: FUN_80258604
// Entry: 80258604
// Size: 28 bytes

void FUN_80258604(int param_1)

{
  *(ushort *)(DAT_803de0b0 + 2) =
       *(ushort *)(DAT_803de0b0 + 2) & 0xfffb | (ushort)(param_1 << 2) & 0x3fc;
  return;
}

