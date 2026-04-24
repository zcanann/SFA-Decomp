// Function: FUN_8002f20c
// Entry: 8002f20c
// Size: 48 bytes

undefined4 FUN_8002f20c(double param_1,int param_2)

{
  double dVar1;
  
  dVar1 = (double)FLOAT_803de908;
  if ((param_1 <= dVar1) && (dVar1 = param_1, param_1 < (double)FLOAT_803de8f0)) {
    dVar1 = (double)FLOAT_803de8f0;
  }
  *(float *)(param_2 + 0x9c) = (float)dVar1;
  return 0;
}

