// Function: FUN_8016f028
// Entry: 8016f028
// Size: 324 bytes

void FUN_8016f028(void)

{
  undefined4 uVar1;
  short *psVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  
  psVar2 = &DAT_803208a0;
  iVar5 = 5;
  do {
    if (*psVar2 == 0) {
      *psVar2 = 0xc3;
    }
    if (psVar2[1] == 0) {
      psVar2[1] = 0xc3;
    }
    if (psVar2[2] == 0) {
      psVar2[2] = 0xc3;
    }
    if (psVar2[3] == 0) {
      psVar2[3] = 0xc3;
    }
    if (psVar2[4] == 0) {
      psVar2[4] = 0xc3;
    }
    if (psVar2[5] == 0) {
      psVar2[5] = 0xc3;
    }
    if (psVar2[6] == 0) {
      psVar2[6] = 0xc3;
    }
    psVar2 = psVar2 + 7;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  DAT_803ddaa4 = &DAT_803dbd50;
  if (DAT_803ddaa8 == 0) {
    iVar5 = 0;
    iVar4 = 0;
    puVar3 = &DAT_803ddaa8;
    do {
      uVar1 = FUN_800544a4((int)*(short *)(DAT_803ddaa4 + iVar4),0);
      *puVar3 = uVar1;
      iVar4 = iVar4 + 2;
      puVar3 = puVar3 + 1;
      iVar5 = iVar5 + 1;
    } while (iVar5 < 2);
  }
  if (DAT_803ddaa0 == 0) {
    DAT_803ddaa0 = FUN_80013ec8(0x5a,1);
  }
  return;
}

