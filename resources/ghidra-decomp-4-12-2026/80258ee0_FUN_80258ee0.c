// Function: FUN_80258ee0
// Entry: 80258ee0
// Size: 128 bytes

void FUN_80258ee0(void)

{
  FUN_80243ec0(0x12,&LAB_80258dd4);
  FUN_80243ec0(0x13,&LAB_80258e5c);
  FUN_802464dc((undefined4 *)&DAT_803ded64);
  FUN_802442c4(0x2000);
  FUN_802442c4(0x1000);
  *(ushort *)(DAT_803ded30 + 10) = *(ushort *)(DAT_803ded30 + 10) & 0xfff0 | 0xf;
  return;
}

