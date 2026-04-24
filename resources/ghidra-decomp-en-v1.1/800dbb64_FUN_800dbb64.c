// Function: FUN_800dbb64
// Entry: 800dbb64
// Size: 372 bytes

uint FUN_800dbb64(float *param_1,uint param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  byte bVar3;
  
  bVar3 = 0;
  do {
    if (3 < bVar3) {
      FUN_8007d858();
      return 0;
    }
    uVar1 = (uint)(byte)(&DAT_803a076c)[param_2 * 0x28 + (uint)bVar3];
    if (uVar1 != 0) {
      if ((ushort)(&DAT_8039d76c)[uVar1 * 0x18] == param_3) {
        if ((param_1[1] <
             (float)((double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_8039d768)[uVar1 * 0x18] ^ 0x80000000) -
                    DOUBLE_803e1260)) &&
           ((float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039d76a)[uVar1 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e1260) < param_1[1])) {
          param_2 = 0;
          uVar2 = 0;
          while (((param_2 & 0xff) < 4 &&
                 (*(float *)(&DAT_8039d748 + uVar1 * 0x18 + (param_2 & 0xff) * 2 + 8) +
                  *param_1 *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039d748)
                                                       [uVar1 * 0x18 + (uVar2 & 0xff)] ^ 0x80000000)
                         - DOUBLE_803e1260) +
                  param_1[2] *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039d748)
                                                       [uVar1 * 0x18 + (uVar2 & 0xff) + 1] ^
                                           0x80000000) - DOUBLE_803e1260) <= FLOAT_803e1270))) {
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

