// Function: FUN_80258508
// Entry: 80258508
// Size: 20 bytes

void FUN_80258508(int param_1,ushort param_2)

{
  *(ushort *)(DAT_803de0b0 + 6) = (ushort)(param_1 << 8) | param_2 & 0xff;
  return;
}

