// Function: FUN_8011b868
// Entry: 8011b868
// Size: 1540 bytes

undefined4 FUN_8011b868(void)

{
  bool bVar1;
  int iVar2;
  char cVar5;
  uint uVar3;
  undefined *puVar4;
  
  cVar5 = FUN_80014cc0(0);
  FUN_80014b68(0);
  if ((int)cVar5 == 0) {
    if (DAT_803dd6da == '\0') {
      FLOAT_803dd6d4 = FLOAT_803e1db4;
    }
    else if (DAT_803dd6e4 < 0x14) {
      FLOAT_803dd6d4 = FLOAT_803e1db8;
    }
    else {
      FLOAT_803dd6d4 = FLOAT_803e1dbc;
    }
  }
  else {
    DAT_803dd6da = '\0';
    FLOAT_803dd6d4 =
         FLOAT_803e1db0 *
         (float)((double)CONCAT44(0x43300000,(int)cVar5 ^ 0x80000000) - DOUBLE_803e1da8);
    if (FLOAT_803dd6d4 * FLOAT_803dd6d0 < FLOAT_803e1db4) {
      FLOAT_803dd6d4 = FLOAT_803e1db4;
    }
  }
  if (FLOAT_803e1db4 <= FLOAT_803dd6d0) {
    if (FLOAT_803e1db4 < FLOAT_803dd6d0) {
      FLOAT_803dd6e0 = FLOAT_803dd6e0 + FLOAT_803dd6d0;
      bVar1 = (float)((double)CONCAT44(0x43300000,DAT_803dd6e8 + DAT_803a8730 / 2) - DOUBLE_803e1da0
                     ) <= FLOAT_803dd6e0;
      if (bVar1) {
        FLOAT_803dd6e0 =
             FLOAT_803dd6e0 - (float)((double)CONCAT44(0x43300000,DAT_803dd6e8) - DOUBLE_803e1da0);
      }
      if ((DAT_803dd6e4 < 0x27) &&
         ((float)((double)CONCAT44(0x43300000,
                                   *(int *)(&DAT_803a8694 + DAT_803dd6e4 * 4) +
                                   *(int *)(&DAT_803a8734 + DAT_803dd6e4 * 4) / 2 ^ 0x80000000) -
                 DOUBLE_803e1da8) <= FLOAT_803dd6e0)) {
        bVar1 = true;
      }
      if (bVar1) {
        if (FLOAT_803e1db4 == FLOAT_803dd6d4) {
          FLOAT_803dd6d0 = FLOAT_803e1db4;
        }
        iVar2 = DAT_803dd6e4 + 1;
        if (0x27 < DAT_803dd6e4 + 1) {
          iVar2 = DAT_803dd6e4 + -0x27;
        }
        DAT_803dd6e4 = iVar2;
        if ((DAT_803dd6e4 == 0x27) && (DAT_803dd6da != '\0')) {
          DAT_803dd6da = '\0';
          FLOAT_803dd6d4 = FLOAT_803e1db4;
          FLOAT_803dd6d0 = FLOAT_803e1db4;
        }
      }
    }
  }
  else {
    FLOAT_803dd6e0 = FLOAT_803dd6e0 + FLOAT_803dd6d0;
    bVar1 = FLOAT_803dd6e0 <=
            (float)((double)CONCAT44(0x43300000,-DAT_803a87cc / 2 ^ 0x80000000) - DOUBLE_803e1da8);
    if (bVar1) {
      FLOAT_803dd6e0 =
           FLOAT_803dd6e0 + (float)((double)CONCAT44(0x43300000,DAT_803dd6e8) - DOUBLE_803e1da0);
    }
    if ((0 < DAT_803dd6e4) &&
       (FLOAT_803dd6e0 <=
        (float)((double)CONCAT44(0x43300000,
                                 (&DAT_803a8690)[DAT_803dd6e4] -
                                 *(int *)(&DAT_803a872c + DAT_803dd6e4 * 4) / 2 ^ 0x80000000) -
               DOUBLE_803e1da8))) {
      bVar1 = true;
    }
    if (bVar1) {
      if (FLOAT_803e1db4 == FLOAT_803dd6d4) {
        FLOAT_803dd6d0 = FLOAT_803e1db4;
      }
      iVar2 = DAT_803dd6e4 + -1;
      if (DAT_803dd6e4 + -1 < 0) {
        iVar2 = DAT_803dd6e4 + 0x27;
      }
      DAT_803dd6e4 = iVar2;
      if ((DAT_803dd6e4 == 0x27) && (DAT_803dd6da != '\0')) {
        FLOAT_803dd6d4 = FLOAT_803e1db4;
        FLOAT_803dd6d0 = FLOAT_803e1db4;
        DAT_803dd6da = '\0';
      }
    }
  }
  DAT_803dd6dc = DAT_803dd6e8;
  if ((float)((double)CONCAT44(0x43300000,DAT_803dd6e8 >> 2) - DOUBLE_803e1da0) <= FLOAT_803dd6e0) {
    DAT_803dd6dc = 0;
  }
  if ((FLOAT_803e1db4 != FLOAT_803dd6d0) || (FLOAT_803e1db4 != FLOAT_803dd6d4)) {
    if ((FLOAT_803dd6d0 < FLOAT_803e1db4) || (FLOAT_803dd6d4 < FLOAT_803e1db4)) {
      if (FLOAT_803dd6d0 <= FLOAT_803e1dc0) {
        FLOAT_803dd6d0 = FLOAT_803e1dc4 * (FLOAT_803dd6d4 - FLOAT_803dd6d0) + FLOAT_803dd6d0;
      }
      else {
        FLOAT_803dd6d0 = FLOAT_803e1dc0;
      }
    }
    else if (FLOAT_803e1dc8 <= FLOAT_803dd6d0) {
      FLOAT_803dd6d0 = FLOAT_803e1dc4 * (FLOAT_803dd6d4 - FLOAT_803dd6d0) + FLOAT_803dd6d0;
    }
    else {
      FLOAT_803dd6d0 = FLOAT_803e1dc8;
    }
  }
  if ((cVar5 == '\0') && (FLOAT_803e1db4 == FLOAT_803dd6d0)) {
    uVar3 = FUN_80014e70(0);
    FUN_80014b3c(0,uVar3);
    if ((uVar3 & 0x100) == 0) {
      if ((uVar3 & 0x200) != 0) {
        DAT_803dd6da = '\0';
        FUN_8000bb18(0,0x419);
        if (DAT_803dd6f4 == 0) {
          FUN_80014948(5);
          FUN_80014928(5);
        }
        else {
          DAT_803dd6f4 = DAT_803dd6f4 - 1;
          (&DAT_803dd6f0)[DAT_803dd6f4] = 0;
          DAT_803dd6ec = 2;
        }
      }
    }
    else if ((DAT_803dd6e4 < 0x26) && (DAT_803dd6f4 < 3)) {
      puVar4 = (undefined *)FUN_80019444((&DAT_8031a880)[DAT_803dd6e4]);
      uVar3 = (uint)DAT_803dd6f4;
      DAT_803dd6f4 = DAT_803dd6f4 + 1;
      (&DAT_803dd6f0)[uVar3] = *puVar4;
      (&DAT_803dd6f0)[DAT_803dd6f4] = 0;
      DAT_803dd6ec = 2;
      FUN_8000bb18(0,0x41a);
      if (DAT_803dd6f4 == 3) {
        DAT_803dd6da = '\x01';
      }
    }
    else if ((DAT_803dd6e4 == 0x26) && (DAT_803dd6f4 != 0)) {
      FUN_8000bb18(0,0x419);
      DAT_803dd6f4 = DAT_803dd6f4 - 1;
      (&DAT_803dd6f0)[DAT_803dd6f4] = 0;
      DAT_803dd6ec = 2;
      DAT_803dd6da = '\0';
    }
    else if (DAT_803dd6e4 == 0x27) {
      if (DAT_803dd6f4 == 0) {
        DAT_803dd6f0 = 0x46;
        uRam803dd6f1 = 0x4f;
        uRam803dd6f2 = 0x58;
        uRam803dd6f3 = 0;
      }
      FUN_8000bb18(0,0x418);
      FUN_800e8abc(&DAT_803dd6f0,DAT_803dd6a4);
      FUN_80014948(5);
      DAT_803dd6ec = 2;
    }
  }
  return 0;
}

