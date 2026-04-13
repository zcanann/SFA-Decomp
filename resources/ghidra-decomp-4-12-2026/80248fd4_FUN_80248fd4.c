// Function: FUN_80248fd4
// Entry: 80248fd4
// Size: 56 bytes

void FUN_80248fd4(void)

{
  DAT_803deb68 = 0x80000000;
  DAT_803deb6c = DAT_80000038;
  if (DAT_80000038 == 0) {
    return;
  }
  DAT_803deb74 = *(int *)(DAT_80000038 + 8);
  DAT_803deb70 = DAT_80000038 + *(int *)(DAT_80000038 + 8) * 0xc;
  return;
}

