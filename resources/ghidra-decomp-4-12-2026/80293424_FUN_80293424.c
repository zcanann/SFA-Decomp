// Function: FUN_80293424
// Entry: 80293424
// Size: 120 bytes

void FUN_80293424(void)

{
  float *pfVar1;
  double extraout_f1;
  
  pfVar1 = (float *)FUN_802867b4();
  FUN_80292444((double)(FLOAT_803e8890 * ABS((float)extraout_f1)),pfVar1);
  *(ushort *)pfVar1 = *(short *)pfVar1 + 1U & 0xfffe;
  FUN_80292428(pfVar1);
  FUN_80286800();
  return;
}

