// Function: FUN_800dbf88
// Entry: 800dbf88
// Size: 464 bytes

void FUN_800dbf88(float *param_1,undefined *param_2)

{
  uint uVar1;
  uint uVar2;
  byte bVar3;
  uint uVar4;
  uint uVar5;
  byte unaff_r31;
  
  uVar2 = FUN_800dc27c(param_1);
  if ((param_2 != (undefined *)0x0) && ((uVar2 & 0xff) != 0)) {
    *param_2 = (char)uVar2;
    param_2[1] = 0;
    uVar1 = 1;
    for (bVar3 = 0; bVar3 < 4; bVar3 = bVar3 + 1) {
      uVar5 = (uint)bVar3;
      uVar4 = (uint)(byte)(&DAT_803a076c)[(uVar2 & 0xff) * 0x28 + uVar5];
      if (uVar4 == 0) {
        *(undefined2 *)(param_2 + uVar5 * 2 + 2) = 0;
      }
      else {
        *(undefined2 *)(param_2 + uVar5 * 2 + 2) = (&DAT_8039d76c)[uVar4 * 0x18];
        if (param_1[1] <
            (float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039d768)[uVar4 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e1260)) {
          if ((float)((double)CONCAT44(0x43300000,
                                       (int)(short)(&DAT_8039d76a)[uVar4 * 0x18] ^ 0x80000000) -
                     DOUBLE_803e1260) < param_1[1]) {
            uVar5 = 0;
            for (unaff_r31 = 0; unaff_r31 < 4; unaff_r31 = unaff_r31 + 1) {
              if (FLOAT_803e1270 <
                  *(float *)(&DAT_8039d748 + uVar4 * 0x18 + (uint)unaff_r31 * 2 + 8) +
                  *param_1 *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039d748)
                                                       [uVar4 * 0x18 + (uVar5 & 0xff)] ^ 0x80000000)
                         - DOUBLE_803e1260) +
                  param_1[2] *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039d748)
                                                       [uVar4 * 0x18 + (uVar5 & 0xff) + 1] ^
                                           0x80000000) - DOUBLE_803e1260)) break;
              uVar5 = uVar5 + 2;
            }
          }
        }
        if (unaff_r31 == 4) {
          param_2[1] = param_2[1] | (byte)uVar1;
        }
      }
      uVar1 = (uVar1 & 0x7f) << 1;
    }
  }
  return;
}

