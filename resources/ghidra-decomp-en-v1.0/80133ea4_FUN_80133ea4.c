// Function: FUN_80133ea4
// Entry: 80133ea4
// Size: 156 bytes

void FUN_80133ea4(void)

{
  byte bVar1;
  
  if (DAT_803dd93c != 0) {
    FUN_80054308();
  }
  FUN_80054308(DAT_803dd940);
  for (bVar1 = 0; bVar1 < 2; bVar1 = bVar1 + 1) {
    if (*(int *)(&DAT_803dbbc8 + (uint)bVar1 * 4) != 0) {
      FUN_8002cbc4();
      *(undefined4 *)(&DAT_803dbbc8 + (uint)bVar1 * 4) = 0;
    }
  }
  DAT_803dd93c = 0;
  DAT_803dd940 = 0;
  return;
}

