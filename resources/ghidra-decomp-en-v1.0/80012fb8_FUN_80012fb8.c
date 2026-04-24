// Function: FUN_80012fb8
// Entry: 80012fb8
// Size: 776 bytes

void FUN_80012fb8(void)

{
  char cVar1;
  char cVar2;
  int iVar3;
  short *psVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  int *piVar9;
  int unaff_r27;
  int iVar10;
  double dVar11;
  
  psVar4 = (short *)FUN_802860d0();
  uVar8 = (psVar4[2] * 10 + 5) - DAT_803dcdcc;
  dVar11 = (double)FUN_80291e40((double)((float)((double)CONCAT44(0x43300000,
                                                                  (*psVar4 * 10 + 5) - DAT_803dcdc8
                                                                  ^ 0x80000000) - DOUBLE_803de6a8) /
                                        FLOAT_803de6b4));
  iVar6 = (int)dVar11;
  dVar11 = (double)FUN_80291e40((double)((float)((double)CONCAT44(0x43300000,uVar8 ^ 0x80000000) -
                                                DOUBLE_803de6a8) / FLOAT_803de6b4));
  iVar7 = (int)dVar11;
  DAT_803387e8 = DAT_803dcdc8 + iVar6 * 0x280;
  DAT_803387ec = DAT_803dcdcc + iVar7 * 0x280;
  iVar3 = DAT_803387e8 / 10 + (DAT_803387e8 >> 0x1f);
  DAT_803387f0 = iVar3 - (iVar3 >> 0x1f);
  iVar3 = DAT_803387ec / 10 + (DAT_803387ec >> 0x1f);
  DAT_803387f4 = iVar3 - (iVar3 >> 0x1f);
  iVar10 = -1;
  iVar3 = FUN_8005af2c(iVar6,iVar7,0);
  if (iVar3 != 0) {
    unaff_r27 = FUN_80059334(iVar6,iVar7);
    iVar10 = (int)*(short *)(unaff_r27 + 6);
  }
  if (iVar10 != -1) {
    iVar6 = -1;
    iVar7 = 0;
    while (iVar7 < 6) {
      iVar3 = iVar7;
      if (iVar10 == (&DAT_803387d0)[iVar7]) {
        iVar3 = 6;
        iVar6 = iVar7;
      }
      iVar7 = iVar3 + 1;
    }
    if (iVar6 == -1) {
      iVar7 = -1;
      iVar6 = -1;
      if ((DAT_803dc8d0 == '\0') && (-1 < DAT_803387b8)) {
        iVar7 = 0;
        iVar6 = DAT_803387b8;
      }
      if ((cRam803dc8d1 == '\0') && (iVar6 < DAT_803387bc)) {
        iVar7 = 1;
        iVar6 = DAT_803387bc;
      }
      if ((cRam803dc8d2 == '\0') && (iVar6 < DAT_803387c0)) {
        iVar7 = 2;
        iVar6 = DAT_803387c0;
      }
      if ((cRam803dc8d3 == '\0') && (iVar6 < DAT_803387c4)) {
        iVar7 = 3;
        iVar6 = DAT_803387c4;
      }
      if ((cRam803dc8d4 == '\0') && (iVar6 < DAT_803387c8)) {
        iVar7 = 4;
        iVar6 = DAT_803387c8;
      }
      if ((cRam803dc8d5 == '\0') && (iVar6 < DAT_803387cc)) {
        iVar7 = 5;
      }
      cVar1 = *(char *)(unaff_r27 + 8);
      cVar2 = *(char *)(unaff_r27 + 9);
      piVar9 = &DAT_803387fc + iVar7;
      if (*piVar9 != 0) {
        uVar5 = FUN_80023834(0);
        FUN_80023800(*piVar9);
        FUN_80023834(uVar5);
      }
      iVar6 = FUN_800132c0(iVar10,iVar7,(int)cVar2,(int)cVar1);
      *piVar9 = iVar6;
      (&DAT_803387d0)[iVar7] = iVar10;
      (&DAT_803387b8)[iVar7] = 0;
      (&DAT_803387a0)[iVar7 * 2] = (short)DAT_803387f0;
      (&DAT_803387a2)[iVar7 * 2] = (short)DAT_803387f4;
    }
    else {
      (&DAT_803387b8)[iVar6] = 0;
    }
  }
  DAT_803387f8 = 0;
  FUN_8028611c(&DAT_803387e8);
  return;
}

