// Function: FUN_800dbcd8
// Entry: 800dbcd8
// Size: 344 bytes

undefined2
FUN_800dbcd8(float *param_1,int param_2,undefined4 param_3,undefined4 param_4,byte param_5)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  
  bVar1 = 0;
  do {
    if (3 < bVar1) {
      return 0;
    }
    if (((&DAT_803a2390)[param_2] != '\0') &&
       (uVar2 = (uint)(byte)(&DAT_803a076c)[param_2 * 0x28 + (uint)bVar1], uVar2 != 0)) {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_8039d768)[uVar2 * 0x18] ^ 0x80000000) -
                  DOUBLE_803e1260)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)(&DAT_8039d76a)[uVar2 * 0x18] ^ 0x80000000
                                  ) - DOUBLE_803e1260) < param_1[1])) {
        param_5 = 0;
        uVar3 = 0;
        while ((param_5 < 4 &&
               (*(float *)(&DAT_8039d748 + uVar2 * 0x18 + (uint)param_5 * 2 + 8) +
                *param_1 *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_8039d748)[uVar2 * 0x18 + (uVar3 & 0xff)]
                                         ^ 0x80000000) - DOUBLE_803e1260) +
                param_1[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_8039d748)
                                                     [uVar2 * 0x18 + (uVar3 & 0xff) + 1] ^
                                         0x80000000) - DOUBLE_803e1260) <= FLOAT_803e1270))) {
          param_5 = param_5 + 1;
          uVar3 = uVar3 + 2;
        }
      }
      if (param_5 == 4) {
        return (&DAT_8039d76c)[uVar2 * 0x18];
      }
    }
    bVar1 = bVar1 + 1;
  } while( true );
}

