// Function: FUN_800146e8
// Entry: 800146e8
// Size: 176 bytes

void FUN_800146e8(byte param_1,int param_2)

{
  DAT_803dd579 = param_1;
  FLOAT_803dd580 = FLOAT_803df338;
  if ((param_1 & 1) != 0) {
    FLOAT_803dd580 =
         (float)((double)CONCAT44(0x43300000,param_2 * 0x3c ^ 0x80000000) - DOUBLE_803df358);
  }
  FLOAT_803dd57c =
       (float)((double)CONCAT44(0x43300000,param_2 * 0x3c ^ 0x80000000) - DOUBLE_803df358);
  if ((param_1 & 3) == 0) {
    DAT_803dd578 = DAT_803dd578 & 0xf9 | 1;
  }
  else {
    DAT_803dd578 = DAT_803dd578 & 0xfd | 5;
  }
  return;
}

