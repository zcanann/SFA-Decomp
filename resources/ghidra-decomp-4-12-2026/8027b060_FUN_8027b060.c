// Function: FUN_8027b060
// Entry: 8027b060
// Size: 340 bytes

/* WARNING: Removing unreachable block (ram,0x8027b08c) */

undefined4 FUN_8027b060(char *param_1,uint param_2)

{
  uint uVar1;
  
  if (*param_1 == '\x01') {
    if ((param_1[0x26] == '\0') && (param_1[1] == '\x01')) {
      *(uint *)(param_1 + 0xc) =
           (0xc1 - (uint)(byte)(&DAT_803303fc)[*(int *)(param_1 + 8) >> 0x15]) * 0x10000;
    }
    uVar1 = FUN_80286718((double)(FLOAT_803e84e0 *
                                  (float)((double)CONCAT44(0x43300000,
                                                           *(uint *)(param_1 + 0xc) ^ 0x80000000) -
                                         DOUBLE_803e84d8) *
                                 (float)((double)CONCAT44(0x43300000,param_2) - DOUBLE_803e84e8)));
    *(uint *)(param_1 + 4) = uVar1 >> 0xc;
    param_1[1] = '\x04';
    if (*(uint *)(param_1 + 4) == 0) {
      param_1[4] = '\0';
      param_1[5] = '\0';
      param_1[6] = '\0';
      param_1[7] = '\x01';
      param_1[8] = '\0';
      param_1[9] = '\0';
      param_1[10] = '\0';
      param_1[0xb] = '\0';
      param_1[0xc] = '\0';
      param_1[0xd] = '\0';
      param_1[0xe] = '\0';
      param_1[0xf] = '\0';
      param_1[0x10] = '\0';
      param_1[0x11] = '\0';
      param_1[0x12] = '\0';
      param_1[0x13] = '\0';
      return 1;
    }
    *(uint *)(param_1 + 0x10) = -(*(uint *)(param_1 + 0xc) / *(uint *)(param_1 + 4));
  }
  else if (*param_1 == '\0') {
    param_1[1] = '\x04';
    *(uint *)(param_1 + 4) = param_2;
    if (param_2 == 0) {
      param_1[4] = '\0';
      param_1[5] = '\0';
      param_1[6] = '\0';
      param_1[7] = '\x01';
      param_1[0x10] = '\0';
      param_1[0x11] = '\0';
      param_1[0x12] = '\0';
      param_1[0x13] = '\0';
      return 1;
    }
    *(uint *)(param_1 + 0x10) = -(*(uint *)(param_1 + 8) / param_2);
  }
  return 0;
}

