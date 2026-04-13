// Function: FUN_8005ced0
// Entry: 8005ced0
// Size: 92 bytes

undefined4 FUN_8005ced0(char param_1)

{
  if (param_1 == '\0') {
    DAT_803dda68 = DAT_803dda68 & 0xfffffff7;
    FUN_8000fc4c((double)FLOAT_803dc2d0);
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 8;
    FUN_8000fc4c((double)FLOAT_803df89c);
  }
  return 0;
}

