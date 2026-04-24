// Function: FUN_80258d68
// Entry: 80258d68
// Size: 28 bytes

void FUN_80258d68(int param_1)

{
  *(ushort *)(DAT_803ded30 + 2) =
       *(ushort *)(DAT_803ded30 + 2) & 0xfffb | (ushort)(param_1 << 2) & 0x3fc;
  return;
}

