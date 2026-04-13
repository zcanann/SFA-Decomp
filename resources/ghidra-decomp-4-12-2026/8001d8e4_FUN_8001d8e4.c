// Function: FUN_8001d8e4
// Entry: 8001d8e4
// Size: 44 bytes

void FUN_8001d8e4(double param_1,int param_2)

{
  double dVar1;
  
  dVar1 = (double)*(float *)(param_2 + 0x160);
  if ((dVar1 <= param_1) && (dVar1 = param_1, (double)FLOAT_803df3e4 < param_1)) {
    dVar1 = (double)FLOAT_803df3e4;
  }
  *(float *)(param_2 + 0x164) = (float)dVar1;
  return;
}

