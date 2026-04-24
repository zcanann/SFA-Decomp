// Function: FUN_80284af4
// Entry: 80284af4
// Size: 56 bytes

void FUN_80284af4(void)

{
  bool bVar1;
  short sVar2;
  
  sVar2 = DAT_803de3bc + 1;
  bVar1 = DAT_803de3bc == 0;
  DAT_803de3bc = sVar2;
  if (bVar1) {
    DAT_803de3c0 = FUN_8024377c();
  }
  return;
}

