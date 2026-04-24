// Function: FUN_800dba4c
// Entry: 800dba4c
// Size: 344 bytes

undefined2
FUN_800dba4c(float *param_1,int param_2,undefined4 param_3,undefined4 param_4,byte param_5)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  
  bVar1 = 0;
  do {
    if (3 < bVar1) {
      return 0;
    }
    if (((&DAT_803a1730)[param_2] != '\0') &&
       (uVar2 = (uint)(byte)(&DAT_8039fb0c)[param_2 * 0x28 + (uint)bVar1], uVar2 != 0)) {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_8039cb08)[uVar2 * 0x18] ^ 0x80000000) -
                  DOUBLE_803e05e0)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)(&DAT_8039cb0a)[uVar2 * 0x18] ^ 0x80000000
                                  ) - DOUBLE_803e05e0) < param_1[1])) {
        param_5 = 0;
        uVar3 = 0;
        while ((param_5 < 4 &&
               (*(float *)(&DAT_8039cae8 + uVar2 * 0x18 + (uint)param_5 * 2 + 8) +
                *param_1 *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_8039cae8)[uVar2 * 0x18 + (uVar3 & 0xff)]
                                         ^ 0x80000000) - DOUBLE_803e05e0) +
                param_1[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_8039cae8)
                                                     [uVar2 * 0x18 + (uVar3 & 0xff) + 1] ^
                                         0x80000000) - DOUBLE_803e05e0) <= FLOAT_803e05f0))) {
          param_5 = param_5 + 1;
          uVar3 = uVar3 + 2;
        }
      }
      if (param_5 == 4) {
        return (&DAT_8039cb0c)[uVar2 * 0x18];
      }
    }
    bVar1 = bVar1 + 1;
  } while( true );
}

