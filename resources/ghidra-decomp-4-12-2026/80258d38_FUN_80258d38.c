// Function: FUN_80258d38
// Entry: 80258d38
// Size: 28 bytes

void FUN_80258d38(int param_1)

{
  *(ushort *)(DAT_803ded30 + 2) =
       *(ushort *)(DAT_803ded30 + 2) & 0xfff7 | (ushort)(param_1 << 3) & 0x7f8;
  return;
}

