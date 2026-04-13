// Function: FUN_80258c6c
// Entry: 80258c6c
// Size: 20 bytes

void FUN_80258c6c(int param_1,ushort param_2)

{
  *(ushort *)(DAT_803ded30 + 6) = (ushort)(param_1 << 8) | param_2 & 0xff;
  return;
}

