// Function: FUN_80121c4c
// Entry: 80121c4c
// Size: 2472 bytes

void FUN_80121c4c(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_802860c0();
  iVar5 = DAT_803a9384;
  iVar3 = DAT_803a936c;
  uVar2 = (undefined4)((ulonglong)uVar12 >> 0x20);
  uVar4 = (undefined4)uVar12;
  iVar10 = DAT_803a9384 + -0xd;
  iVar11 = DAT_803a936c;
  if (7 < DAT_803a936c) {
    iVar11 = 7;
  }
  if (iVar11 != 0) {
    iVar11 = iVar11 + 1;
  }
  iVar7 = 8 - iVar11;
  iVar8 = DAT_803a936c + -7;
  if (iVar10 < DAT_803a936c + -7) {
    iVar8 = iVar10;
  }
  if (iVar8 < 1) {
    iVar8 = 0;
  }
  iVar6 = iVar10 - iVar8;
  iVar1 = (DAT_803a936c + -7) - iVar10;
  if (5 < iVar1) {
    iVar1 = 5;
  }
  if (iVar1 < 1) {
    iVar1 = 0;
  }
  if (DAT_803a936c == DAT_803a9384) {
    iVar1 = 7;
  }
  iVar9 = 0x10 - iVar1;
  if ((param_3 & 0xff) == 0) {
    FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,DAT_803dbad8 ^ 0x80000000) -
                                DOUBLE_803e1e78),
                 (double)(float)((double)CONCAT44(0x43300000,DAT_803dbadc ^ 0x80000000) -
                                DOUBLE_803e1e78),DAT_803a8a4c,uVar2,0x100);
  }
  else {
    FUN_8011eda4((double)(float)((double)CONCAT44(0x43300000,DAT_803dbad0 ^ 0x80000000) -
                                DOUBLE_803e1e78),
                 (double)(float)((double)CONCAT44(0x43300000,DAT_803dbad4 ^ 0x80000000) -
                                DOUBLE_803e1e78),DAT_803a8a4c,uVar4,uVar2,0x100,0);
  }
  if (iVar11 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,DAT_803dbad8 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbadc ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a50,uVar2,0x100,iVar11,0x12,0);
    }
    else {
      FUN_8011eb3c((double)(float)((double)CONCAT44(0x43300000,DAT_803dbad0 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbad4 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a50,uVar4,uVar2,0x100,iVar11,0x12,0);
    }
  }
  if (iVar7 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_80075fc8((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar11 + DAT_803dbad8 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbadc ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a54,uVar2,0x100,iVar7,0x12,iVar11,0);
    }
    else {
      FUN_8011e8d8((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar11 + DAT_803dbad0 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbad4 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a54,uVar4,uVar2,iVar7,0x12,iVar11,0);
    }
  }
  if (iVar8 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,DAT_803dbad8 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbadc ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a58,uVar2,0x100,iVar8,0x12,0);
    }
    else {
      FUN_8011eb3c((double)(float)((double)CONCAT44(0x43300000,DAT_803dbad0 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbad4 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a58,uVar4,uVar2,0x100,iVar8,0x12,0);
    }
  }
  if (iVar6 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar8 + DAT_803dbad8 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbadc ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a5c,uVar2,0x100,iVar6,0x12,0);
    }
    else {
      FUN_8011eb3c((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar8 + DAT_803dbad0 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbad4 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a5c,uVar4,uVar2,0x100,iVar6,0x12,0);
    }
  }
  if (iVar1 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar10 + DAT_803dbad8 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbadc ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a60,uVar2,0x100,iVar1,0x12,0);
    }
    else {
      FUN_8011eb3c((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar10 + DAT_803dbad0 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbad4 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a60,uVar4,uVar2,0x100,iVar1,0x12,0);
    }
  }
  if (iVar9 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_80075fc8((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar10 + iVar1 + DAT_803dbad8 + 0x24 ^
                                                    0x80000000) - DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbadc ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a64,uVar2,0x100,iVar9,0x12,iVar1,0);
    }
    else {
      FUN_8011e8d8((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar10 + iVar1 + DAT_803dbad0 + 0x24 ^
                                                    0x80000000) - DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbad4 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a64,uVar4,uVar2,iVar9,0x12,iVar1,0);
    }
  }
  iVar3 = iVar3 - (uint)DAT_803dd7b3;
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  if (iVar3 != 0) {
    iVar3 = iVar3 + 1;
  }
  if (iVar3 == iVar5) {
    iVar3 = iVar3 + 1;
  }
  iVar5 = iVar3;
  if (8 < iVar3) {
    iVar5 = 8;
  }
  iVar11 = iVar11 - iVar5;
  iVar7 = iVar3 + -8;
  if (iVar10 < iVar3 + -8) {
    iVar7 = iVar10;
  }
  if (iVar7 < 1) {
    iVar7 = 0;
  }
  iVar8 = iVar8 - iVar7;
  iVar3 = (iVar3 + -8) - iVar10;
  if (8 < iVar3) {
    iVar3 = 8;
  }
  if (iVar3 < 1) {
    iVar3 = 0;
  }
  iVar1 = iVar1 - iVar3;
  if (iVar11 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_80075fc8((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar5 + DAT_803dbad8 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbadc ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a74,uVar2,0x100,iVar11,0x12,iVar5,0);
    }
    else {
      FUN_8011e8d8((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar5 + DAT_803dbad0 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbad4 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a74,uVar4,uVar2,iVar11,0x12,iVar5,0);
    }
  }
  if (iVar8 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar7 + DAT_803dbad8 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbadc ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a78,uVar2,0x100,iVar8,0x12,0);
    }
    else {
      FUN_8011eb3c((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar7 + DAT_803dbad0 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbad4 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a78,uVar4,uVar2,0x100,iVar8,0x12,0);
    }
  }
  if (iVar1 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar10 + iVar3 + DAT_803dbad8 + 0x24 ^
                                                    0x80000000) - DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbadc ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a7c,uVar2,0x100,iVar1,0x12,0);
    }
    else {
      FUN_8011eb3c((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar10 + iVar3 + DAT_803dbad0 + 0x24 ^
                                                    0x80000000) - DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dbad4 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a8a7c,uVar4,uVar2,0x100,iVar1,0x12,0);
    }
  }
  FUN_8028610c();
  return;
}

