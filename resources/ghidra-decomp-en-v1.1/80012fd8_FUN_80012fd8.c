// Function: FUN_80012fd8
// Entry: 80012fd8
// Size: 776 bytes

void FUN_80012fd8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  char cVar1;
  char cVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint *puVar8;
  int unaff_r27;
  int iVar9;
  double dVar10;
  
  FUN_80286834();
  dVar10 = (double)FUN_802925a0();
  iVar6 = (int)dVar10;
  dVar10 = (double)FUN_802925a0();
  iVar7 = (int)dVar10;
  DAT_80339448 = DAT_803dda48 + iVar6 * 0x280;
  DAT_8033944c = DAT_803dda4c + iVar7 * 0x280;
  iVar3 = DAT_80339448 / 10 + (DAT_80339448 >> 0x1f);
  DAT_80339450 = iVar3 - (iVar3 >> 0x1f);
  iVar3 = DAT_8033944c / 10 + (DAT_8033944c >> 0x1f);
  DAT_80339454 = iVar3 - (iVar3 >> 0x1f);
  iVar9 = -1;
  iVar3 = FUN_8005b0a8(iVar6,iVar7,0);
  if (iVar3 != 0) {
    unaff_r27 = FUN_800594b0(iVar6,iVar7);
    iVar9 = (int)*(short *)(unaff_r27 + 6);
  }
  if (iVar9 != -1) {
    iVar6 = -1;
    iVar7 = 0;
    while (iVar7 < 6) {
      iVar3 = iVar7;
      if (iVar9 == (&DAT_80339430)[iVar7]) {
        iVar3 = 6;
        iVar6 = iVar7;
      }
      iVar7 = iVar3 + 1;
    }
    if (iVar6 == -1) {
      iVar7 = -1;
      iVar6 = -1;
      if ((DAT_803dd550 == '\0') && (-1 < DAT_80339418)) {
        iVar7 = 0;
        iVar6 = DAT_80339418;
      }
      if ((cRam803dd551 == '\0') && (iVar6 < DAT_8033941c)) {
        iVar7 = 1;
        iVar6 = DAT_8033941c;
      }
      if ((cRam803dd552 == '\0') && (iVar6 < DAT_80339420)) {
        iVar7 = 2;
        iVar6 = DAT_80339420;
      }
      if ((cRam803dd553 == '\0') && (iVar6 < DAT_80339424)) {
        iVar7 = 3;
        iVar6 = DAT_80339424;
      }
      if ((cRam803dd554 == '\0') && (iVar6 < DAT_80339428)) {
        iVar7 = 4;
        iVar6 = DAT_80339428;
      }
      if ((cRam803dd555 == '\0') && (iVar6 < DAT_8033942c)) {
        iVar7 = 5;
      }
      cVar1 = *(char *)(unaff_r27 + 8);
      cVar2 = *(char *)(unaff_r27 + 9);
      puVar8 = &DAT_8033945c + iVar7;
      if (*puVar8 != 0) {
        uVar4 = FUN_800238f8(0);
        dVar10 = (double)FUN_800238c4(*puVar8);
        FUN_800238f8(uVar4);
      }
      uVar5 = FUN_800132e0(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar9,
                           iVar7,(int)cVar2,(int)cVar1,in_r7,in_r8,in_r9,in_r10);
      *puVar8 = uVar5;
      (&DAT_80339430)[iVar7] = iVar9;
      (&DAT_80339418)[iVar7] = 0;
      (&DAT_80339400)[iVar7 * 2] = (short)DAT_80339450;
      (&DAT_80339402)[iVar7 * 2] = (short)DAT_80339454;
    }
    else {
      (&DAT_80339418)[iVar6] = 0;
    }
  }
  DAT_80339458 = 0;
  FUN_80286880();
  return;
}

