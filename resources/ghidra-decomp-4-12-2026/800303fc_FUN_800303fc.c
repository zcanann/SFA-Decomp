// Function: FUN_800303fc
// Entry: 800303fc
// Size: 48 bytes

undefined4 FUN_800303fc(double param_1,int param_2)

{
  double dVar1;
  
  dVar1 = (double)FLOAT_803df588;
  if ((param_1 <= dVar1) && (dVar1 = param_1, param_1 < (double)FLOAT_803df570)) {
    dVar1 = (double)FLOAT_803df570;
  }
  *(float *)(param_2 + 0x98) = (float)dVar1;
  return 0;
}

