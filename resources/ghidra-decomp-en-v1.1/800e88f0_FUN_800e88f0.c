// Function: FUN_800e88f0
// Entry: 800e88f0
// Size: 100 bytes

void FUN_800e88f0(void)

{
  FUN_80244e58(0,0);
  DAT_803dc4f0 = (undefined)((int)(*(byte *)(DAT_803de110 + 0x21) & 0x60) >> 5);
  *(byte *)(DAT_803de110 + 0x21) = *(byte *)(DAT_803de110 + 0x21) & 0x1f;
  (**(code **)(*DAT_803dd72c + 0x20))();
  return;
}

