// Function: FUN_800d7a8c
// Entry: 800d7a8c
// Size: 96 bytes

void FUN_800d7a8c(double param_1,uint param_2,undefined param_3)

{
  FLOAT_803dd420 = (float)((double)FLOAT_803e0558 * param_1);
  FLOAT_803dd424 =
       -(float)((double)FLOAT_803e055c * param_1) /
       (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803e0550);
  FLOAT_803dd428 = FLOAT_803e0560;
  DAT_803dd42c = param_3;
  DAT_803dd42e = 1;
  return;
}

