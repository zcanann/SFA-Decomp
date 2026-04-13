// Function: FUN_80119b88
// Entry: 80119b88
// Size: 316 bytes

void FUN_80119b88(void)

{
  int iVar1;
  
  iVar1 = 0;
  do {
    if (DAT_803a6a5f != '\0') {
      while (DAT_803a6a90 < 0) {
        FUN_80243e74();
        DAT_803a6a90 = DAT_803a6a90 + 1;
        FUN_80243e9c();
        if (((iVar1 + DAT_803a6a78) - ((uint)(iVar1 + DAT_803a6a78) / DAT_803a6a10) * DAT_803a6a10
             == DAT_803a6a10 - 1) && ((DAT_803a6a5e & 1) == 0)) break;
        iVar1 = iVar1 + 1;
      }
    }
    FUN_80119a40();
    if (((iVar1 + DAT_803a6a78) - ((uint)(iVar1 + DAT_803a6a78) / DAT_803a6a10) * DAT_803a6a10 ==
         DAT_803a6a10 - 1) && ((DAT_803a6a5e & 1) == 0)) {
      FUN_80247054(-0x7fc57058);
    }
    iVar1 = iVar1 + 1;
  } while( true );
}

