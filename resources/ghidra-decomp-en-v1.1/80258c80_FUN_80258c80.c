// Function: FUN_80258c80
// Entry: 80258c80
// Size: 20 bytes

void FUN_80258c80(ushort param_1)

{
  *(ushort *)(DAT_803ded30 + 8) = param_1 & 0xfffb | 4;
  return;
}

