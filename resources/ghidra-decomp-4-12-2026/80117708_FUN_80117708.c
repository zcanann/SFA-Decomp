// Function: FUN_80117708
// Entry: 80117708
// Size: 172 bytes

void FUN_80117708(void)

{
  int iVar1;
  
  iVar1 = 0;
  do {
    FUN_80117628();
    if (((iVar1 + DAT_803a6a78) - ((uint)(iVar1 + DAT_803a6a78) / DAT_803a6a10) * DAT_803a6a10 ==
         DAT_803a6a10 - 1) && ((DAT_803a6a5e & 1) == 0)) {
      FUN_80247054(-0x7fc59f00);
    }
    iVar1 = iVar1 + 1;
  } while( true );
}

