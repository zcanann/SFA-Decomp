// Function: FUN_80285258
// Entry: 80285258
// Size: 56 bytes

void FUN_80285258(void)

{
  bool bVar1;
  short sVar2;
  ulonglong uVar3;
  
  sVar2 = DAT_803df03c + 1;
  bVar1 = DAT_803df03c == 0;
  DAT_803df03c = sVar2;
  if (bVar1) {
    uVar3 = FUN_80243e74();
    DAT_803df040 = (undefined4)(uVar3 >> 0x20);
  }
  return;
}

