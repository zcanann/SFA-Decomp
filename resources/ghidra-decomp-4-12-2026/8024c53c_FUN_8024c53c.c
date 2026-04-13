// Function: FUN_8024c53c
// Entry: 8024c53c
// Size: 360 bytes

void FUN_8024c53c(void)

{
  int iVar1;
  undefined auStack_40 [52];
  
  FUN_80241de8();
  DAT_803debd8 = auStack_40;
  DAT_803debd4 = &DAT_803aec60;
  FUN_8024ba40();
  FUN_8024b5a4((undefined4 *)&DAT_803aec98,DAT_803debd8,&LAB_8024c464);
  do {
    iVar1 = FUN_8024bad0();
  } while (iVar1 != 0);
  DAT_80000038 = *(undefined4 *)(DAT_803debd4 + 0x10);
  DAT_8000003c = *(undefined4 *)(DAT_803debd4 + 0xc);
  FUN_80003494(0x80000000,(uint)DAT_803debd8,0x20);
  FUN_8007d858();
  FUN_8007d858();
  FUN_8007d858();
  FUN_8007d858();
  FUN_8007d858();
  FUN_8007d858();
  FUN_8007d858();
  FUN_80241df8(*(undefined4 *)(DAT_803debd4 + 0x10));
  return;
}

