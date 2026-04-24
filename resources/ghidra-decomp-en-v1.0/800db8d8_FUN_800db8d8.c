// Function: FUN_800db8d8
// Entry: 800db8d8
// Size: 372 bytes

uint FUN_800db8d8(float *param_1,uint param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  byte bVar3;
  
  bVar3 = 0;
  do {
    if (3 < bVar3) {
      FUN_8007d6dc(s_Error_in_isPointWithinPatchGroup_80311548);
      return 0;
    }
    uVar1 = (uint)(byte)(&DAT_8039fb0c)[param_2 * 0x28 + (uint)bVar3];
    if (uVar1 != 0) {
      if ((ushort)(&DAT_8039cb0c)[uVar1 * 0x18] == param_3) {
        if ((param_1[1] <
             (float)((double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_8039cb08)[uVar1 * 0x18] ^ 0x80000000) -
                    DOUBLE_803e05e0)) &&
           ((float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039cb0a)[uVar1 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e05e0) < param_1[1])) {
          param_2 = 0;
          uVar2 = 0;
          while (((param_2 & 0xff) < 4 &&
                 (*(float *)(&DAT_8039cae8 + uVar1 * 0x18 + (param_2 & 0xff) * 2 + 8) +
                  *param_1 *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039cae8)
                                                       [uVar1 * 0x18 + (uVar2 & 0xff)] ^ 0x80000000)
                         - DOUBLE_803e05e0) +
                  param_1[2] *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039cae8)
                                                       [uVar1 * 0x18 + (uVar2 & 0xff) + 1] ^
                                           0x80000000) - DOUBLE_803e05e0) <= FLOAT_803e05f0))) {
            param_2 = param_2 + 1;
            uVar2 = uVar2 + 2;
          }
        }
        uVar1 = countLeadingZeros(4 - (param_2 & 0xff));
        return uVar1 >> 5;
      }
    }
    bVar3 = bVar3 + 1;
  } while( true );
}

