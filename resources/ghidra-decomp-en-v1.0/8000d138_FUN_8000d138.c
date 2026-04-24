// Function: FUN_8000d138
// Entry: 8000d138
// Size: 200 bytes

void FUN_8000d138(void)

{
  int iVar1;
  
  if (DAT_803dc870 == 0) {
    if (DAT_803dc874 == 0) {
      if (DAT_803dc868 == 0) {
        DAT_803dc85c = 0;
        DAT_803dc860 = 0;
        DAT_803dc86c = 0;
        DAT_803dc7c8 = 0;
      }
    }
    else {
      iVar1 = FUN_80020620();
      if (iVar1 == 1) {
        iVar1 = FUN_80020620();
        if (iVar1 == 1) {
          FUN_8024fa90(DAT_803db250);
          FUN_8024fabc(DAT_803db251);
          FUN_8024f7d0(1);
          DAT_803dc848 = 1;
          FLOAT_803dc858 = FLOAT_803de5d0;
          DAT_803dc868 = DAT_803dc874;
          DAT_803dc874 = 0;
          DAT_803dc870 = 0;
          DAT_803dc86c = 0;
        }
        else {
          DAT_803dc848 = 0;
        }
      }
    }
  }
  else {
    DAT_803dc86c = 1;
  }
  return;
}

