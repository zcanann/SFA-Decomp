// Function: FUN_801e1b78
// Entry: 801e1b78
// Size: 1316 bytes

/* WARNING: Removing unreachable block (ram,0x801e207c) */
/* WARNING: Removing unreachable block (ram,0x801e1b88) */

void FUN_801e1b78(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  int *piVar13;
  int iVar14;
  int iVar15;
  double dVar16;
  
  fVar12 = DAT_802c2ba4;
  fVar11 = DAT_802c2ba0;
  fVar10 = DAT_802c2b9c;
  fVar9 = DAT_802c2b98;
  fVar8 = DAT_802c2b94;
  fVar7 = DAT_802c2b90;
  fVar6 = DAT_802c2b8c;
  fVar5 = DAT_802c2b88;
  fVar4 = DAT_802c2b84;
  fVar3 = DAT_802c2b80;
  fVar2 = DAT_802c2b7c;
  fVar1 = DAT_802c2b78;
  FUN_8005cf74(0);
  FUN_8008947c(1);
  FUN_80089468(0x29,0x4b,0xa9);
  FUN_8008999c(7,1,0);
  dVar16 = FUN_8008f014();
  if ((double)FLOAT_803e6364 < dVar16) {
    FLOAT_803de8a4 = FLOAT_803e643c;
    FLOAT_803de8a8 = FLOAT_803e643c;
  }
  FLOAT_803de8a8 = -(FLOAT_803e644c * FLOAT_803dc074 - FLOAT_803de8a8);
  if (FLOAT_803de8a8 < FLOAT_803e6364) {
    FLOAT_803de8a8 = FLOAT_803e6364;
  }
  DAT_803de8b8 = (byte)(int)(FLOAT_803de8a8 *
                             (float)((double)CONCAT44(0x43300000,
                                                      (uint)DAT_803dccec - (uint)DAT_803dcce8 ^
                                                      0x80000000) - DOUBLE_803e6458) +
                            (float)((double)CONCAT44(0x43300000,DAT_803dcce8 ^ 0x80000000) -
                                   DOUBLE_803e6458));
  bRam803de8b9 = (byte)(int)(FLOAT_803de8a8 *
                             (float)((double)CONCAT44(0x43300000,
                                                      (uint)bRam803dcced - (uint)bRam803dcce9 ^
                                                      0x80000000) - DOUBLE_803e6458) +
                            (float)((double)CONCAT44(0x43300000,bRam803dcce9 ^ 0x80000000) -
                                   DOUBLE_803e6458));
  bRam803de8ba = (byte)(int)(FLOAT_803de8a8 *
                             (float)((double)CONCAT44(0x43300000,
                                                      (uint)bRam803dccee - (uint)bRam803dccea ^
                                                      0x80000000) - DOUBLE_803e6458) +
                            (float)((double)CONCAT44(0x43300000,bRam803dccea ^ 0x80000000) -
                                   DOUBLE_803e6458));
  FUN_8008986c(7,DAT_803de8b8,bRam803de8b9,bRam803de8ba,0x40,0x40);
  DAT_803de8b4 = (undefined)
                 (int)(FLOAT_803de8a8 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)DAT_803dcce4 - (uint)DAT_803dcce0 ^ 0x80000000
                                               ) - DOUBLE_803e6458) +
                      (float)((double)CONCAT44(0x43300000,DAT_803dcce0 ^ 0x80000000) -
                             DOUBLE_803e6458));
  uRam803de8b5 = (undefined)
                 (int)(FLOAT_803de8a8 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)bRam803dcce5 - (uint)bRam803dcce1 ^ 0x80000000
                                               ) - DOUBLE_803e6458) +
                      (float)((double)CONCAT44(0x43300000,bRam803dcce1 ^ 0x80000000) -
                             DOUBLE_803e6458));
  uRam803de8b6 = (undefined)
                 (int)(FLOAT_803de8a8 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)bRam803dcce6 - (uint)bRam803dcce2 ^ 0x80000000
                                               ) - DOUBLE_803e6458) +
                      (float)((double)CONCAT44(0x43300000,bRam803dcce2 ^ 0x80000000) -
                             DOUBLE_803e6458));
  FUN_8008979c(7,DAT_803de8b4,uRam803de8b5,uRam803de8b6);
  DAT_803de8b0 = (undefined)
                 (int)(FLOAT_803de8a8 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)DAT_803dccf4 - (uint)DAT_803dccf0 ^ 0x80000000
                                               ) - DOUBLE_803e6458) +
                      (float)((double)CONCAT44(0x43300000,DAT_803dccf0 ^ 0x80000000) -
                             DOUBLE_803e6458));
  uRam803de8b1 = (undefined)
                 (int)(FLOAT_803de8a8 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)bRam803dccf5 - (uint)bRam803dccf1 ^ 0x80000000
                                               ) - DOUBLE_803e6458) +
                      (float)((double)CONCAT44(0x43300000,bRam803dccf1 ^ 0x80000000) -
                             DOUBLE_803e6458));
  uRam803de8b2 = (undefined)
                 (int)(FLOAT_803de8a8 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)bRam803dccf6 - (uint)bRam803dccf2 ^ 0x80000000
                                               ) - DOUBLE_803e6458) +
                      (float)((double)CONCAT44(0x43300000,bRam803dccf2 ^ 0x80000000) -
                             DOUBLE_803e6458));
  FUN_80089804(7,DAT_803de8b0,uRam803de8b1,uRam803de8b2);
  DAT_803de8ad = (undefined)(int)(FLOAT_803de8a8 * FLOAT_803e6478 + FLOAT_803e6488);
  FUN_800894c0(1);
  FUN_80089484((double)(FLOAT_803de8a8 * (fVar10 - fVar7) + fVar7),
               (double)(FLOAT_803de8a8 * (fVar11 - fVar8) + fVar8),
               (double)(FLOAT_803de8a8 * (fVar12 - fVar9) + fVar9),(double)FLOAT_803e63bc);
  if (*(char *)(param_2 + 0xab) == '\0') {
    FUN_80089734((double)fVar1,(double)fVar2,(double)fVar3,7);
  }
  else {
    FUN_80089734((double)fVar4,(double)fVar5,(double)fVar6,7);
  }
  piVar13 = (int *)FUN_8002b660(param_1);
  dVar16 = (double)FLOAT_803e648c;
  for (iVar15 = 0; iVar15 < (int)(uint)*(byte *)(*piVar13 + 0xf8); iVar15 = iVar15 + 1) {
    iVar14 = FUN_800284e8(*piVar13,iVar15);
    if (*(char *)(iVar14 + 0x29) == '\x01') {
      *(char *)(iVar14 + 0xc) = (char)(int)(dVar16 * (double)FLOAT_803de8a8);
    }
  }
  return;
}

