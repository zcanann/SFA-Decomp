// Function: FUN_80258d84
// Entry: 80258d84
// Size: 40 bytes

void FUN_80258d84(ushort param_1,int param_2,int param_3)

{
  *DAT_803ded30 =
       (param_1 & 0xf1 | (ushort)(param_2 << 1)) & 0xffef | (ushort)(param_3 << 4) & 0xff0;
  return;
}

