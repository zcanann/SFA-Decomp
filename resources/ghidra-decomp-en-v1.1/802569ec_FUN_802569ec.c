// Function: FUN_802569ec
// Entry: 802569ec
// Size: 220 bytes

void FUN_802569ec(int *param_1,undefined4 param_2,uint param_3)

{
  ulonglong uVar1;
  
  uVar1 = FUN_80243e74();
  FUN_80258a04((int)(uVar1 >> 0x20),(int)uVar1,param_3);
  *param_1 = *(int *)(DAT_803ded28 + 0xc) + -0x80000000;
  param_1[1] = *(int *)(DAT_803ded28 + 0x10) + -0x80000000;
  param_1[6] = (*(uint *)(DAT_803ded28 + 0x14) & 0xfbffffff) + 0x80000000;
  if (DAT_803ded44 == '\0') {
    param_1[7] = param_1[6] - param_1[5];
    if (param_1[7] < 0) {
      param_1[7] = param_1[7] + param_1[2];
    }
  }
  else {
    param_1[5] = CONCAT22(*(undefined2 *)(DAT_803ded2c + 0x3a),*(undefined2 *)(DAT_803ded2c + 0x38))
                 + -0x80000000;
    param_1[7] = CONCAT22(*(undefined2 *)(DAT_803ded2c + 0x32),*(undefined2 *)(DAT_803ded2c + 0x30))
    ;
  }
  FUN_80243e9c();
  return;
}

