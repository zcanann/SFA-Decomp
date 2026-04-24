// Function: FUN_800d7bcc
// Entry: 800d7bcc
// Size: 120 bytes

void FUN_800d7bcc(uint param_1,undefined param_2)

{
  if ((FLOAT_803dd424 <= FLOAT_803e0560) || (FLOAT_803e0558 == FLOAT_803dd420)) {
    FLOAT_803dd420 = FLOAT_803e0560;
  }
  FLOAT_803dd424 =
       FLOAT_803e055c / (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803e0550)
  ;
  FLOAT_803dd428 = FLOAT_803e0560;
  DAT_803dd42c = param_2;
  DAT_803dd42e = 0;
  return;
}

