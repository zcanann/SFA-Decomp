// Function: FUN_800146bc
// Entry: 800146bc
// Size: 176 bytes

void FUN_800146bc(byte param_1,int param_2)

{
  FLOAT_803dc900 = FLOAT_803de6b8;
  if ((param_1 & 1) != 0) {
    FLOAT_803dc900 =
         (float)((double)CONCAT44(0x43300000,param_2 * 0x3c ^ 0x80000000) - DOUBLE_803de6d8);
  }
  if ((param_1 & 3) == 0) {
    DAT_803dc8f8 = DAT_803dc8f8 & 0xf9 | 1;
  }
  else {
    DAT_803dc8f8 = DAT_803dc8f8 & 0xfd | 5;
  }
  DAT_803dc8f9 = param_1;
  FLOAT_803dc8fc =
       (float)((double)CONCAT44(0x43300000,param_2 * 0x3c ^ 0x80000000) - DOUBLE_803de6d8);
  return;
}

