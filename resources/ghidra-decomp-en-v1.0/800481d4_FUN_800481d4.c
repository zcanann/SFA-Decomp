// Function: FUN_800481d4
// Entry: 800481d4
// Size: 340 bytes

void FUN_800481d4(void)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined **ppuVar4;
  int *piVar5;
  
  uVar2 = FUN_80014e70(2);
  if ((uVar2 & 0x100) != 0) {
    iVar1 = 7;
    do {
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
    FUN_80022d58(1);
  }
  uVar2 = FUN_80014e70(2);
  if ((uVar2 & 0x200) != 0) {
    FUN_80041e3c(0);
  }
  if (DAT_803dcc78 != 0) {
    if (DAT_803dcc78 == 1) {
      FUN_80041e3c(0);
    }
    DAT_803dcc78 = DAT_803dcc78 + -1;
  }
  iVar1 = 0;
  piVar5 = &DAT_8035ef48;
  ppuVar4 = &PTR_s_AUDIO_tab_802cb2f4;
  do {
    if (*piVar5 != -1) {
      FUN_80137520(0,0xff,0,0xff);
      FUN_80137948(s_HALT__s_802cc518,*ppuVar4);
      FUN_80137520(0xff,0xff,0xff,0xff);
      DAT_803dcc70 = 1;
      iVar3 = FUN_800443cc(*piVar5,iVar1);
      if (iVar3 != 0) {
        *piVar5 = -1;
        FUN_80022d58(1);
      }
      DAT_803dcc70 = 0;
    }
    piVar5 = piVar5 + 1;
    ppuVar4 = ppuVar4 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x58);
  FUN_800430e0();
  return;
}

