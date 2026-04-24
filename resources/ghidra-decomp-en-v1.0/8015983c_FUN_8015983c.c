// Function: FUN_8015983c
// Entry: 8015983c
// Size: 124 bytes

void FUN_8015983c(double param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6)

{
  double dVar1;
  undefined auStack72 [48];
  undefined4 local_18;
  uint uStack20;
  
  uStack20 = param_6 ^ 0x80000000;
  local_18 = 0x43300000;
  dVar1 = (double)FUN_802943f4((double)(float)((double)FLOAT_803e2c20 * param_1 -
                                              (double)(FLOAT_803e2c24 *
                                                      (float)((double)CONCAT44(0x43300000,uStack20)
                                                             - DOUBLE_803e2c28))));
  FUN_802470c8((double)(float)((double)FLOAT_803e2c1c * dVar1),auStack72,0x79);
  FUN_80247574(auStack72,param_4,param_4);
  return;
}

