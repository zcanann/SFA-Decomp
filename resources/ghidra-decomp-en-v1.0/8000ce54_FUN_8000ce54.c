// Function: FUN_8000ce54
// Entry: 8000ce54
// Size: 256 bytes

void FUN_8000ce54(void)

{
  int iVar1;
  
  if (DAT_803dc849 != '\0') {
    FUN_8024fa90(0);
    FUN_8024fabc(0);
    iVar1 = FUN_8024afd8(&DAT_80336c70,&LAB_8000d0b4);
    if (iVar1 == 0) {
      FUN_8007d6dc(s_WARNING_DVDCancelStreamAsync_ret_802c5dc4);
    }
    DAT_803dc874 = 0;
    DAT_803dc870 = 0;
    DAT_803dc868 = 0;
    DAT_803dc86c = 0;
    DAT_803dc7c8 = 0;
    DAT_803dc85c = 0;
    DAT_803dc860 = 0;
  }
  if (DAT_803dc868 == 0) {
    DAT_803dc848 = 0;
  }
  else {
    FUN_8024fa90(0);
    FUN_8024fabc(0);
    iVar1 = FUN_8024afd8(&DAT_80336c40,FUN_8000cfe4);
    if (iVar1 == 0) {
      FUN_8007d6dc(s_WARNING_DVDCancelStreamAsync_ret_802c5dc4);
      DAT_803dc848 = 0;
    }
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

