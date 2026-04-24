// Function: FUN_80248870
// Entry: 80248870
// Size: 56 bytes

void FUN_80248870(void)

{
  if (DAT_80000038 == 0) {
    DAT_803ddee8 = 0x80000000;
    DAT_803ddeec = DAT_80000038;
    return;
  }
  DAT_803ddee8 = 0x80000000;
  DAT_803ddeec = DAT_80000038;
  DAT_803ddef0 = DAT_80000038 + *(int *)(DAT_80000038 + 8) * 0xc;
  DAT_803ddef4 = *(int *)(DAT_80000038 + 8);
  return;
}

