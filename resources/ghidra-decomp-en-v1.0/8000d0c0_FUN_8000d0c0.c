// Function: FUN_8000d0c0
// Entry: 8000d0c0
// Size: 120 bytes

void FUN_8000d0c0(void)

{
  int iVar1;
  
  FUN_8024fa90(0);
  FUN_8024fabc(0);
  iVar1 = FUN_8024afd8(&DAT_80336c70,&LAB_8000d0b4);
  if (iVar1 == 0) {
    FUN_8007d6dc(s_WARNING_DVDCancelStreamAsync_ret_802c5dc4);
  }
  DAT_803dc7c8 = 0;
  DAT_803dc85c = 0;
  DAT_803dc860 = 0;
  DAT_803dc868 = 0;
  DAT_803dc86c = 0;
  DAT_803dc870 = 0;
  DAT_803dc874 = 0;
  return;
}

