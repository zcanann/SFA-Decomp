// Function: FUN_80258c94
// Entry: 80258c94
// Size: 28 bytes

void FUN_80258c94(int param_1)

{
  *(ushort *)(DAT_803ded30 + 2) =
       *(ushort *)(DAT_803ded30 + 2) & 0xffef | (ushort)(param_1 << 4) & 0xff0;
  return;
}

