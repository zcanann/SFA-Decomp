// Function: FUN_800dc27c
// Entry: 800dc27c
// Size: 936 bytes

int FUN_800dc27c(float *param_1)

{
  short sVar1;
  short sVar2;
  uint uVar3;
  int iVar4;
  byte bVar5;
  
  sVar2 = (short)DAT_803de0e0;
  if (DAT_803de0e0 == 0xb4) {
    sVar1 = 0;
  }
  else {
    sVar1 = sVar2 + 1;
  }
  do {
    iVar4 = (int)sVar2;
    if (iVar4 == sVar1) {
      if ((&DAT_803a2390)[iVar4] != '\0') {
        if ((param_1[1] <
             (float)((double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0768)[iVar4 * 0x14] ^ 0x80000000) -
                    DOUBLE_803e1260)) &&
           ((float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_803a076a)[iVar4 * 0x14] ^ 0x80000000) -
                   DOUBLE_803e1260) < param_1[1])) {
          bVar5 = 0;
          uVar3 = 0;
          while ((bVar5 < 4 &&
                 (*(float *)(&DAT_803a0748 + iVar4 * 0x14 + (uint)bVar5 * 2 + 8) +
                  *param_1 *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_803a0748)
                                                       [iVar4 * 0x14 + (uVar3 & 0xff)] ^ 0x80000000)
                         - DOUBLE_803e1260) +
                  param_1[2] *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_803a0748)
                                                       [iVar4 * 0x14 + (uVar3 & 0xff) + 1] ^
                                           0x80000000) - DOUBLE_803e1260) <= FLOAT_803e1270))) {
            bVar5 = bVar5 + 1;
            uVar3 = uVar3 + 2;
          }
          if (bVar5 == 4) {
            DAT_803de0e0 = (int)sVar2;
            return (int)sVar2;
          }
        }
      }
      return 0;
    }
    iVar4 = (int)sVar2;
    if ((&DAT_803a2390)[iVar4] != '\0') {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_803a0768)[iVar4 * 0x14] ^ 0x80000000) -
                  DOUBLE_803e1260)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)(&DAT_803a076a)[iVar4 * 0x14] ^ 0x80000000
                                  ) - DOUBLE_803e1260) < param_1[1])) {
        bVar5 = 0;
        uVar3 = 0;
        while ((bVar5 < 4 &&
               (*(float *)(&DAT_803a0748 + iVar4 * 0x14 + (uint)bVar5 * 2 + 8) +
                *param_1 *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_803a0748)[iVar4 * 0x14 + (uVar3 & 0xff)]
                                         ^ 0x80000000) - DOUBLE_803e1260) +
                param_1[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_803a0748)
                                                     [iVar4 * 0x14 + (uVar3 & 0xff) + 1] ^
                                         0x80000000) - DOUBLE_803e1260) <= FLOAT_803e1270))) {
          bVar5 = bVar5 + 1;
          uVar3 = uVar3 + 2;
        }
        if (bVar5 == 4) {
          DAT_803de0e0 = (int)sVar2;
          return (int)sVar2;
        }
      }
    }
    iVar4 = (int)sVar1;
    if ((&DAT_803a2390)[iVar4] != '\0') {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_803a0768)[iVar4 * 0x14] ^ 0x80000000) -
                  DOUBLE_803e1260)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)(&DAT_803a076a)[iVar4 * 0x14] ^ 0x80000000
                                  ) - DOUBLE_803e1260) < param_1[1])) {
        bVar5 = 0;
        uVar3 = 0;
        while ((bVar5 < 4 &&
               (*(float *)(&DAT_803a0748 + iVar4 * 0x14 + (uint)bVar5 * 2 + 8) +
                *param_1 *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_803a0748)[iVar4 * 0x14 + (uVar3 & 0xff)]
                                         ^ 0x80000000) - DOUBLE_803e1260) +
                param_1[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_803a0748)
                                                     [iVar4 * 0x14 + (uVar3 & 0xff) + 1] ^
                                         0x80000000) - DOUBLE_803e1260) <= FLOAT_803e1270))) {
          bVar5 = bVar5 + 1;
          uVar3 = uVar3 + 2;
        }
        if (bVar5 == 4) {
          DAT_803de0e0 = (int)sVar1;
          return (int)sVar1;
        }
      }
    }
    sVar2 = sVar2 + -1;
    if (sVar2 == -1) {
      sVar2 = 0xb4;
    }
    sVar1 = sVar1 + 1;
    if (sVar1 == 0xb5) {
      sVar1 = 0;
    }
  } while( true );
}

