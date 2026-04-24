// Function: FUN_80119a1c
// Entry: 80119a1c
// Size: 204 bytes

void FUN_80119a1c(void)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  
  do {
    if (DAT_803a5dff != '\0') {
      while (DAT_803a5e30 < 0) {
        iVar1 = FUN_80119488();
        uVar3 = *(int *)(iVar1 + 4) + DAT_803a5e18;
        if ((uVar3 - (uVar3 / DAT_803a5db0) * DAT_803a5db0 == DAT_803a5db0 - 1) &&
           ((DAT_803a5dfe & 1) == 0)) {
          FUN_80119798();
        }
        FUN_801194bc(iVar1);
        FUN_8024377c();
        DAT_803a5e30 = DAT_803a5e30 + 1;
        FUN_802437a4();
      }
    }
    if (DAT_803a5dff == '\0') {
      uVar2 = FUN_801194ec();
    }
    else {
      uVar2 = FUN_80119488();
    }
    FUN_80119798(uVar2);
    FUN_801194bc(uVar2);
  } while( true );
}

