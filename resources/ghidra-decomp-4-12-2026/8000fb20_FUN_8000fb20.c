// Function: FUN_8000fb20
// Entry: 8000fb20
// Size: 232 bytes

void FUN_8000fb20(void)

{
  double dVar1;
  
  if (DAT_803dd510 == 1) {
    FUN_80247dfc((double)FLOAT_803dd520,(double)FLOAT_803dd51c,(double)FLOAT_803dd518,
                 (double)FLOAT_803dd514,(double)FLOAT_803dbec0,(double)FLOAT_803dbec4,
                 (float *)&DAT_803393b0);
  }
  else {
    FUN_80247d2c((double)FLOAT_803dd524,(double)FLOAT_803dbec8,(double)FLOAT_803dbec0,
                 (double)FLOAT_803dbec4,(float *)&DAT_803393b0);
    FUN_80247aa4((double)FLOAT_803dd524,(double)FLOAT_803dbec8,(double)FLOAT_803df2a8,
                 (double)FLOAT_803df2a8,(double)FLOAT_803df2ac,(double)FLOAT_803df2ac,
                 (float *)&DAT_803974b0);
    dVar1 = (double)FLOAT_803df2ac;
    FUN_80247aa4((double)FLOAT_803dd524,(double)FLOAT_803dbec8,dVar1,dVar1,dVar1,dVar1,
                 (float *)&DAT_80397450);
    dVar1 = (double)FLOAT_803df2ac;
    FUN_80247aa4((double)FLOAT_803dd524,(double)FLOAT_803dbec8,dVar1,(double)FLOAT_803df2b0,dVar1,
                 dVar1,(float *)&DAT_80397480);
  }
  FUN_8025d6ac(&DAT_803393b0,DAT_803dd510);
  return;
}

