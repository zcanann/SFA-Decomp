// Function: FUN_802585f0
// Entry: 802585f0
// Size: 20 bytes

void FUN_802585f0(int param_1,ushort param_2)

{
  *(ushort *)(DAT_803de0b0 + 4) = param_2 & 0xff | (ushort)(param_1 << 8);
  return;
}

