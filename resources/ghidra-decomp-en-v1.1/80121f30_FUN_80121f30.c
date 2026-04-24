// Function: FUN_80121f30
// Entry: 80121f30
// Size: 2472 bytes

void FUN_80121f30(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_80286824();
  iVar6 = DAT_803a9fe4;
  iVar3 = DAT_803a9fcc;
  uVar2 = (uint)((ulonglong)uVar13 >> 0x20);
  iVar4 = (int)uVar13;
  iVar11 = DAT_803a9fe4 + -0xd;
  iVar12 = DAT_803a9fcc;
  if (7 < DAT_803a9fcc) {
    iVar12 = 7;
  }
  if (iVar12 != 0) {
    iVar12 = iVar12 + 1;
  }
  iVar8 = 8 - iVar12;
  iVar9 = DAT_803a9fcc + -7;
  if (iVar11 < DAT_803a9fcc + -7) {
    iVar9 = iVar11;
  }
  if (iVar9 < 1) {
    iVar9 = 0;
  }
  iVar7 = iVar11 - iVar9;
  iVar1 = (DAT_803a9fcc + -7) - iVar11;
  if (5 < iVar1) {
    iVar1 = 5;
  }
  if (iVar1 < 1) {
    iVar1 = 0;
  }
  if (DAT_803a9fcc == DAT_803a9fe4) {
    iVar1 = 7;
  }
  iVar10 = 0x10 - iVar1;
  uVar5 = (undefined)((ulonglong)uVar13 >> 0x20);
  if ((param_3 & 0xff) == 0) {
    FUN_80077318((double)(float)((double)CONCAT44(0x43300000,DAT_803dc740 ^ 0x80000000) -
                                DOUBLE_803e2af8),
                 (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                DOUBLE_803e2af8),DAT_803a96ac,uVar2,0x100);
  }
  else {
    FUN_8011f088((double)(float)((double)CONCAT44(0x43300000,DAT_803dc738 ^ 0x80000000) -
                                DOUBLE_803e2af8),
                 (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                DOUBLE_803e2af8),DAT_803a96ac,iVar4,uVar5,0x100,0);
  }
  if (iVar12 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,DAT_803dc740 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96b0,uVar2,0x100,iVar12,0x12,0);
    }
    else {
      FUN_8011ee20((double)(float)((double)CONCAT44(0x43300000,DAT_803dc738 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96b0,iVar4,uVar5,0x100,iVar12,0x12,0);
    }
  }
  if (iVar8 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_80076144((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar12 + DAT_803dc740 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96b4,uVar2,0x100,iVar8,0x12,iVar12,0);
    }
    else {
      FUN_8011ebbc((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar12 + DAT_803dc738 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96b4,iVar4,uVar5,iVar8,0x12,iVar12,0);
    }
  }
  if (iVar9 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,DAT_803dc740 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96b8,uVar2,0x100,iVar9,0x12,0);
    }
    else {
      FUN_8011ee20((double)(float)((double)CONCAT44(0x43300000,DAT_803dc738 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96b8,iVar4,uVar5,0x100,iVar9,0x12,0);
    }
  }
  if (iVar7 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar9 + DAT_803dc740 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96bc,uVar2,0x100,iVar7,0x12,0);
    }
    else {
      FUN_8011ee20((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar9 + DAT_803dc738 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96bc,iVar4,uVar5,0x100,iVar7,0x12,0);
    }
  }
  if (iVar1 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar11 + DAT_803dc740 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96c0,uVar2,0x100,iVar1,0x12,0);
    }
    else {
      FUN_8011ee20((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar11 + DAT_803dc738 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96c0,iVar4,uVar5,0x100,iVar1,0x12,0);
    }
  }
  if (iVar10 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_80076144((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar11 + iVar1 + DAT_803dc740 + 0x24 ^
                                                    0x80000000) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96c4,uVar2,0x100,iVar10,0x12,iVar1,0);
    }
    else {
      FUN_8011ebbc((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar11 + iVar1 + DAT_803dc738 + 0x24 ^
                                                    0x80000000) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96c4,iVar4,uVar5,iVar10,0x12,iVar1,0);
    }
  }
  iVar3 = iVar3 - (uint)DAT_803de433;
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  if (iVar3 != 0) {
    iVar3 = iVar3 + 1;
  }
  if (iVar3 == iVar6) {
    iVar3 = iVar3 + 1;
  }
  iVar6 = iVar3;
  if (8 < iVar3) {
    iVar6 = 8;
  }
  iVar12 = iVar12 - iVar6;
  iVar8 = iVar3 + -8;
  if (iVar11 < iVar3 + -8) {
    iVar8 = iVar11;
  }
  if (iVar8 < 1) {
    iVar8 = 0;
  }
  iVar9 = iVar9 - iVar8;
  iVar3 = (iVar3 + -8) - iVar11;
  if (8 < iVar3) {
    iVar3 = 8;
  }
  if (iVar3 < 1) {
    iVar3 = 0;
  }
  iVar1 = iVar1 - iVar3;
  if (iVar12 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_80076144((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar6 + DAT_803dc740 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96d4,uVar2,0x100,iVar12,0x12,iVar6,0);
    }
    else {
      FUN_8011ebbc((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar6 + DAT_803dc738 + 0x1c ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96d4,iVar4,uVar5,iVar12,0x12,iVar6,0);
    }
  }
  if (iVar9 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar8 + DAT_803dc740 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96d8,uVar2,0x100,iVar9,0x12,0);
    }
    else {
      FUN_8011ee20((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar8 + DAT_803dc738 + 0x24 ^ 0x80000000) -
                                  DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96d8,iVar4,uVar5,0x100,iVar9,0x12,0);
    }
  }
  if (iVar1 != 0) {
    if ((param_3 & 0xff) == 0) {
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar11 + iVar3 + DAT_803dc740 + 0x24 ^
                                                    0x80000000) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc744 ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96dc,uVar2,0x100,iVar1,0x12,0);
    }
    else {
      FUN_8011ee20((double)(float)((double)CONCAT44(0x43300000,
                                                    iVar11 + iVar3 + DAT_803dc738 + 0x24 ^
                                                    0x80000000) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000) -
                                  DOUBLE_803e2af8),DAT_803a96dc,iVar4,uVar5,0x100,iVar1,0x12,0);
    }
  }
  FUN_80286870();
  return;
}

