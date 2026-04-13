// Function: FUN_80119cc4
// Entry: 80119cc4
// Size: 204 bytes

void FUN_80119cc4(void)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  
  do {
    if (DAT_803a6a5f != '\0') {
      while (DAT_803a6a90 < 0) {
        iVar1 = FUN_80119730();
        uVar3 = *(int *)(iVar1 + 4) + DAT_803a6a78;
        if ((uVar3 - (uVar3 / DAT_803a6a10) * DAT_803a6a10 == DAT_803a6a10 - 1) &&
           ((DAT_803a6a5e & 1) == 0)) {
          FUN_80119a40();
        }
        FUN_80119764(iVar1);
        FUN_80243e74();
        DAT_803a6a90 = DAT_803a6a90 + 1;
        FUN_80243e9c();
      }
    }
    if (DAT_803a6a5f == '\0') {
      uVar2 = FUN_80119794();
    }
    else {
      uVar2 = FUN_80119730();
    }
    FUN_80119a40();
    FUN_80119764(uVar2);
  } while( true );
}

