// Function: FUN_800221a0
// Entry: 800221a0
// Size: 192 bytes

uint FUN_800221a0(uint param_1,uint param_2)

{
  undefined4 uVar1;
  
  if (param_1 != param_2) {
    uVar1 = FUN_80292dc0();
    param_1 = (uint)(((float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803de800) / FLOAT_803de7f8
                     ) * ((FLOAT_803de7c4 +
                          (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) -
                                 DOUBLE_803de7e0)) -
                         (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803de7e0
                                )) +
                    (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803de7e0));
  }
  return param_1;
}

