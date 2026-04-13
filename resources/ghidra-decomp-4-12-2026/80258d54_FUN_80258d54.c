// Function: FUN_80258d54
// Entry: 80258d54
// Size: 20 bytes

void FUN_80258d54(int param_1,ushort param_2)

{
  *(ushort *)(DAT_803ded30 + 4) = param_2 & 0xff | (ushort)(param_1 << 8);
  return;
}

