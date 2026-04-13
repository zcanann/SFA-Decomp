// Function: FUN_8001dcfc
// Entry: 8001dcfc
// Size: 88 bytes

void FUN_8001dcfc(double param_1,double param_2,int param_3)

{
  *(float *)(param_3 + 0x140) = (float)param_1;
  *(float *)(param_3 + 0x144) = (float)param_2;
  FUN_80259fac((double)*(float *)(param_3 + 0x140),(double)FLOAT_803df3d8,param_3 + 0x68,2);
  FUN_80259e10(param_3 + 0x68,(undefined4 *)(param_3 + 0x124),(undefined4 *)(param_3 + 0x128),
               (undefined4 *)(param_3 + 300));
  return;
}

