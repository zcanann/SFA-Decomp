// Function: FUN_8002f304
// Entry: 8002f304
// Size: 48 bytes

undefined4 FUN_8002f304(double param_1,int param_2)

{
  double dVar1;
  
  dVar1 = (double)FLOAT_803df588;
  if ((param_1 <= dVar1) && (dVar1 = param_1, param_1 < (double)FLOAT_803df570)) {
    dVar1 = (double)FLOAT_803df570;
  }
  *(float *)(param_2 + 0x9c) = (float)dVar1;
  return 0;
}

