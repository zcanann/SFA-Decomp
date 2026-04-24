// Function: FUN_80256288
// Entry: 80256288
// Size: 220 bytes

void FUN_80256288(int *param_1)

{
  undefined4 uVar1;
  
  uVar1 = FUN_8024377c();
  FUN_802582a0();
  *param_1 = *(int *)(DAT_803de0a8 + 0xc) + -0x80000000;
  param_1[1] = *(int *)(DAT_803de0a8 + 0x10) + -0x80000000;
  param_1[6] = (*(uint *)(DAT_803de0a8 + 0x14) & 0xfbffffff) + 0x80000000;
  if (DAT_803de0c4 == '\0') {
    param_1[7] = param_1[6] - param_1[5];
    if (param_1[7] < 0) {
      param_1[7] = param_1[7] + param_1[2];
    }
  }
  else {
    param_1[5] = CONCAT22(*(undefined2 *)(DAT_803de0ac + 0x3a),*(undefined2 *)(DAT_803de0ac + 0x38))
                 + -0x80000000;
    param_1[7] = CONCAT22(*(undefined2 *)(DAT_803de0ac + 0x32),*(undefined2 *)(DAT_803de0ac + 0x30))
    ;
  }
  FUN_802437a4(uVar1);
  return;
}

