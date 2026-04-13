// Function: FUN_800db670
// Entry: 800db670
// Size: 1268 bytes

void FUN_800db670(undefined4 param_1,undefined4 param_2,int param_3)

{
  ushort uVar1;
  uint uVar2;
  float *pfVar3;
  float *pfVar4;
  byte bVar6;
  uint uVar5;
  undefined2 *in_r10;
  byte bVar8;
  uint uVar7;
  byte bVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_8028683c();
  pfVar3 = (float *)((ulonglong)uVar10 >> 0x20);
  pfVar4 = (float *)uVar10;
  for (bVar6 = 0; bVar6 < 4; bVar6 = bVar6 + 1) {
    uVar5 = (uint)*(byte *)((int)&DAT_803a0748 + bVar6 + 0x24 + param_3 * 0x28);
    if (uVar5 != 0) {
      in_r10 = &DAT_8039d748 + uVar5 * 0x18;
      if ((pfVar3[1] <
           (float)((double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_8039d768)[uVar5 * 0x18] ^ 0x80000000) -
                  DOUBLE_803e1260)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)(&DAT_8039d76a)[uVar5 * 0x18] ^ 0x80000000
                                  ) - DOUBLE_803e1260) < pfVar3[1])) {
        bVar8 = 0;
        uVar2 = 0;
        while ((bVar8 < 4 &&
               (*(float *)(in_r10 + (uint)bVar8 * 2 + 8) +
                *pfVar3 * (float)((double)CONCAT44(0x43300000,
                                                   (int)(short)in_r10[uVar2 & 0xff] ^ 0x80000000) -
                                 DOUBLE_803e1260) +
                pfVar3[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)in_r10[(uVar2 & 0xff) + 1] ^ 0x80000000) -
                       DOUBLE_803e1260) <= FLOAT_803e1270))) {
          bVar8 = bVar8 + 1;
          uVar2 = uVar2 + 2;
        }
        if (((bVar8 == 4) &&
            (pfVar4[1] <
             (float)((double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_8039d768)[uVar5 * 0x18] ^ 0x80000000) -
                    DOUBLE_803e1260))) &&
           ((float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039d76a)[uVar5 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e1260) < pfVar4[1])) {
          bVar8 = 0;
          uVar5 = 0;
          while ((bVar8 < 4 &&
                 (*(float *)(in_r10 + (uint)bVar8 * 2 + 8) +
                  *pfVar4 * (float)((double)CONCAT44(0x43300000,
                                                     (int)(short)in_r10[uVar5 & 0xff] ^ 0x80000000)
                                   - DOUBLE_803e1260) +
                  pfVar4[2] *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)in_r10[(uVar5 & 0xff) + 1] ^ 0x80000000) -
                         DOUBLE_803e1260) <= FLOAT_803e1270))) {
            bVar8 = bVar8 + 1;
            uVar5 = uVar5 + 2;
          }
          if (bVar8 == 4) goto LAB_800dbb4c;
        }
      }
    }
  }
  for (bVar6 = 0; bVar6 < 4; bVar6 = bVar6 + 1) {
    uVar5 = (uint)*(byte *)((int)&DAT_803a0748 + bVar6 + 0x24 + param_3 * 0x28);
    if (uVar5 != 0) {
      uVar2 = countLeadingZeros(0xff - param_3);
      uVar1 = (&DAT_8039d76c)[uVar5 * 0x18];
      if ((uVar2 >> 5 & (uint)uVar1) == 0) {
        uVar5 = uVar1 & 0xff;
      }
      else {
        uVar5 = (int)(uVar1 & 0xff00) >> 8;
      }
      for (bVar8 = 0; bVar8 < 4; bVar8 = bVar8 + 1) {
        uVar2 = (uint)(byte)(&DAT_803a076c)[uVar5 * 0x28 + (uint)bVar8];
        if (uVar2 != 0) {
          if ((&DAT_8039d76c)[uVar2 * 0x18] != in_r10[0x12]) {
            if ((pfVar3[1] <
                 (float)((double)CONCAT44(0x43300000,
                                          (int)(short)(&DAT_8039d768)[uVar2 * 0x18] ^ 0x80000000) -
                        DOUBLE_803e1260)) &&
               ((float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_8039d76a)[uVar2 * 0x18] ^ 0x80000000) -
                       DOUBLE_803e1260) < pfVar3[1])) {
              bVar9 = 0;
              uVar7 = 0;
              while ((bVar9 < 4 &&
                     (*(float *)(&DAT_8039d748 + uVar2 * 0x18 + (uint)bVar9 * 2 + 8) +
                      *pfVar3 * (float)((double)CONCAT44(0x43300000,
                                                         (int)(short)(&DAT_8039d748)
                                                                     [uVar2 * 0x18 + (uVar7 & 0xff)]
                                                         ^ 0x80000000) - DOUBLE_803e1260) +
                      pfVar3[2] *
                      (float)((double)CONCAT44(0x43300000,
                                               (int)(short)(&DAT_8039d748)
                                                           [uVar2 * 0x18 + (uVar7 & 0xff) + 1] ^
                                               0x80000000) - DOUBLE_803e1260) <= FLOAT_803e1270))) {
                bVar9 = bVar9 + 1;
                uVar7 = uVar7 + 2;
              }
              if (((bVar9 == 4) &&
                  (pfVar4[1] <
                   (float)((double)CONCAT44(0x43300000,
                                            (int)(short)(&DAT_8039d768)[uVar2 * 0x18] ^ 0x80000000)
                          - DOUBLE_803e1260))) &&
                 ((float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039d76a)[uVar2 * 0x18] ^ 0x80000000) -
                         DOUBLE_803e1260) < pfVar4[1])) {
                bVar9 = 0;
                uVar7 = 0;
                while ((bVar9 < 4 &&
                       (*(float *)(&DAT_8039d748 + uVar2 * 0x18 + (uint)bVar9 * 2 + 8) +
                        *pfVar4 * (float)((double)CONCAT44(0x43300000,
                                                           (int)(short)(&DAT_8039d748)
                                                                       [uVar2 * 0x18 +
                                                                        (uVar7 & 0xff)] ^ 0x80000000
                                                          ) - DOUBLE_803e1260) +
                        pfVar4[2] *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_8039d748)
                                                             [uVar2 * 0x18 + (uVar7 & 0xff) + 1] ^
                                                 0x80000000) - DOUBLE_803e1260) <= FLOAT_803e1270)))
                {
                  bVar9 = bVar9 + 1;
                  uVar7 = uVar7 + 2;
                }
                if (bVar9 == 4) {
                  FUN_8007d858();
                  goto LAB_800dbb4c;
                }
              }
            }
          }
        }
      }
    }
  }
LAB_800dbb4c:
  FUN_80286888();
  return;
}

