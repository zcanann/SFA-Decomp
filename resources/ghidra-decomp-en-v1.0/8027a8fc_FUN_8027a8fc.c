// Function: FUN_8027a8fc
// Entry: 8027a8fc
// Size: 340 bytes

/* WARNING: Removing unreachable block (ram,0x8027a928) */

undefined4 FUN_8027a8fc(char *param_1,uint param_2)

{
  uint uVar1;
  
  if (*param_1 == '\x01') {
    if ((param_1[0x26] == '\0') && (param_1[1] == '\x01')) {
      *(uint *)(param_1 + 0xc) =
           (0xc1 - (uint)(byte)(&DAT_8032f79c)[*(int *)(param_1 + 8) >> 0x15]) * 0x10000;
    }
    uVar1 = FUN_80285fb4((double)(FLOAT_803e7848 *
                                  (float)((double)CONCAT44(0x43300000,
                                                           *(uint *)(param_1 + 0xc) ^ 0x80000000) -
                                         DOUBLE_803e7840) *
                                 (float)((double)CONCAT44(0x43300000,param_2) - DOUBLE_803e7850)));
    *(uint *)(param_1 + 4) = uVar1 >> 0xc;
    param_1[1] = '\x04';
    if (*(uint *)(param_1 + 4) == 0) {
      *(undefined4 *)(param_1 + 4) = 1;
      *(undefined4 *)(param_1 + 8) = 0;
      *(undefined4 *)(param_1 + 0xc) = 0;
      *(undefined4 *)(param_1 + 0x10) = 0;
      return 1;
    }
    *(uint *)(param_1 + 0x10) = -(*(uint *)(param_1 + 0xc) / *(uint *)(param_1 + 4));
  }
  else if (*param_1 == '\0') {
    param_1[1] = '\x04';
    *(uint *)(param_1 + 4) = param_2;
    if (param_2 == 0) {
      *(undefined4 *)(param_1 + 4) = 1;
      *(undefined4 *)(param_1 + 0x10) = 0;
      return 1;
    }
    *(uint *)(param_1 + 0x10) = -(*(uint *)(param_1 + 8) / param_2);
  }
  return 0;
}

