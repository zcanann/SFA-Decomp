// Function: FUN_800db3e4
// Entry: 800db3e4
// Size: 1268 bytes

void FUN_800db3e4(undefined4 param_1,undefined4 param_2,uint param_3)

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
  
  uVar10 = FUN_802860d8();
  pfVar3 = (float *)((ulonglong)uVar10 >> 0x20);
  pfVar4 = (float *)uVar10;
  for (bVar6 = 0; bVar6 < 4; bVar6 = bVar6 + 1) {
    uVar5 = (uint)*(byte *)((int)&DAT_8039fae8 + bVar6 + 0x24 + param_3 * 0x28);
    if (uVar5 != 0) {
      in_r10 = &DAT_8039cae8 + uVar5 * 0x18;
      if ((pfVar3[1] <
           (float)((double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_8039cb08)[uVar5 * 0x18] ^ 0x80000000) -
                  DOUBLE_803e05e0)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)(&DAT_8039cb0a)[uVar5 * 0x18] ^ 0x80000000
                                  ) - DOUBLE_803e05e0) < pfVar3[1])) {
        bVar8 = 0;
        uVar2 = 0;
        while ((bVar8 < 4 &&
               (*(float *)(in_r10 + (uint)bVar8 * 2 + 8) +
                *pfVar3 * (float)((double)CONCAT44(0x43300000,
                                                   (int)(short)in_r10[uVar2 & 0xff] ^ 0x80000000) -
                                 DOUBLE_803e05e0) +
                pfVar3[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)in_r10[(uVar2 & 0xff) + 1] ^ 0x80000000) -
                       DOUBLE_803e05e0) <= FLOAT_803e05f0))) {
          bVar8 = bVar8 + 1;
          uVar2 = uVar2 + 2;
        }
        if (((bVar8 == 4) &&
            (pfVar4[1] <
             (float)((double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_8039cb08)[uVar5 * 0x18] ^ 0x80000000) -
                    DOUBLE_803e05e0))) &&
           ((float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039cb0a)[uVar5 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e05e0) < pfVar4[1])) {
          bVar8 = 0;
          uVar5 = 0;
          while ((bVar8 < 4 &&
                 (*(float *)(in_r10 + (uint)bVar8 * 2 + 8) +
                  *pfVar4 * (float)((double)CONCAT44(0x43300000,
                                                     (int)(short)in_r10[uVar5 & 0xff] ^ 0x80000000)
                                   - DOUBLE_803e05e0) +
                  pfVar4[2] *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)in_r10[(uVar5 & 0xff) + 1] ^ 0x80000000) -
                         DOUBLE_803e05e0) <= FLOAT_803e05f0))) {
            bVar8 = bVar8 + 1;
            uVar5 = uVar5 + 2;
          }
          if (bVar8 == 4) goto LAB_800db8c0;
        }
      }
    }
  }
  for (bVar6 = 0; bVar6 < 4; bVar6 = bVar6 + 1) {
    uVar5 = (uint)*(byte *)((int)&DAT_8039fae8 + bVar6 + 0x24 + param_3 * 0x28);
    if (uVar5 != 0) {
      uVar2 = countLeadingZeros(0xff - param_3);
      uVar1 = (&DAT_8039cb0c)[uVar5 * 0x18];
      if ((uVar2 >> 5 & (uint)uVar1) == 0) {
        uVar5 = uVar1 & 0xff;
      }
      else {
        uVar5 = (int)(uVar1 & 0xff00) >> 8;
      }
      for (bVar8 = 0; bVar8 < 4; bVar8 = bVar8 + 1) {
        uVar2 = (uint)(byte)(&DAT_8039fb0c)[uVar5 * 0x28 + (uint)bVar8];
        if (uVar2 != 0) {
          if ((&DAT_8039cb0c)[uVar2 * 0x18] != in_r10[0x12]) {
            if ((pfVar3[1] <
                 (float)((double)CONCAT44(0x43300000,
                                          (int)(short)(&DAT_8039cb08)[uVar2 * 0x18] ^ 0x80000000) -
                        DOUBLE_803e05e0)) &&
               ((float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_8039cb0a)[uVar2 * 0x18] ^ 0x80000000) -
                       DOUBLE_803e05e0) < pfVar3[1])) {
              bVar9 = 0;
              uVar7 = 0;
              while ((bVar9 < 4 &&
                     (*(float *)(&DAT_8039cae8 + uVar2 * 0x18 + (uint)bVar9 * 2 + 8) +
                      *pfVar3 * (float)((double)CONCAT44(0x43300000,
                                                         (int)(short)(&DAT_8039cae8)
                                                                     [uVar2 * 0x18 + (uVar7 & 0xff)]
                                                         ^ 0x80000000) - DOUBLE_803e05e0) +
                      pfVar3[2] *
                      (float)((double)CONCAT44(0x43300000,
                                               (int)(short)(&DAT_8039cae8)
                                                           [uVar2 * 0x18 + (uVar7 & 0xff) + 1] ^
                                               0x80000000) - DOUBLE_803e05e0) <= FLOAT_803e05f0))) {
                bVar9 = bVar9 + 1;
                uVar7 = uVar7 + 2;
              }
              if (((bVar9 == 4) &&
                  (pfVar4[1] <
                   (float)((double)CONCAT44(0x43300000,
                                            (int)(short)(&DAT_8039cb08)[uVar2 * 0x18] ^ 0x80000000)
                          - DOUBLE_803e05e0))) &&
                 ((float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039cb0a)[uVar2 * 0x18] ^ 0x80000000) -
                         DOUBLE_803e05e0) < pfVar4[1])) {
                bVar9 = 0;
                uVar7 = 0;
                while ((bVar9 < 4 &&
                       (*(float *)(&DAT_8039cae8 + uVar2 * 0x18 + (uint)bVar9 * 2 + 8) +
                        *pfVar4 * (float)((double)CONCAT44(0x43300000,
                                                           (int)(short)(&DAT_8039cae8)
                                                                       [uVar2 * 0x18 +
                                                                        (uVar7 & 0xff)] ^ 0x80000000
                                                          ) - DOUBLE_803e05e0) +
                        pfVar4[2] *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_8039cae8)
                                                             [uVar2 * 0x18 + (uVar7 & 0xff) + 1] ^
                                                 0x80000000) - DOUBLE_803e05e0) <= FLOAT_803e05f0)))
                {
                  bVar9 = bVar9 + 1;
                  uVar7 = uVar7 + 2;
                }
                if (bVar9 == 4) {
                  FUN_8007d6dc(s_Found_new_walk_group_patch_from_w_80311518,uVar5);
                  param_3 = uVar5;
                  goto LAB_800db8c0;
                }
              }
            }
          }
        }
      }
    }
  }
  param_3 = 0;
LAB_800db8c0:
  FUN_80286124(param_3);
  return;
}

