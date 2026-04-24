// Function: FUN_8001d910
// Entry: 8001d910
// Size: 44 bytes

void FUN_8001d910(double param_1,int param_2)

{
  double dVar1;
  
  dVar1 = (double)FLOAT_803df40c;
  if ((dVar1 <= param_1) && (dVar1 = param_1, (double)*(float *)(param_2 + 0x164) < param_1)) {
    dVar1 = (double)*(float *)(param_2 + 0x164);
  }
  *(float *)(param_2 + 0x160) = (float)dVar1;
  return;
}

