// Function: FUN_8005cd54
// Entry: 8005cd54
// Size: 92 bytes

undefined4 FUN_8005cd54(char param_1)

{
  if (param_1 == '\0') {
    DAT_803dcde8 = DAT_803dcde8 & 0xfffffff7;
    FUN_8000fc2c((double)FLOAT_803db670);
  }
  else {
    DAT_803dcde8 = DAT_803dcde8 | 8;
    FUN_8000fc2c((double)FLOAT_803dec1c);
  }
  return 0;
}

