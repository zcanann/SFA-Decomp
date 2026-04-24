// Function: FUN_8001db24
// Entry: 8001db24
// Size: 88 bytes

void FUN_8001db24(double param_1,int param_2,int param_3)

{
  *(float *)(param_2 + 0xb4) = (float)param_1;
  *(int *)(param_2 + 0xb8) = param_3;
  if (param_3 == 0) {
    FUN_80259df0((double)FLOAT_803df3e0,(double)FLOAT_803df3dc,(double)FLOAT_803df3dc,param_2 + 0x68
                );
  }
  else {
    FUN_80259e2c((double)*(float *)(param_2 + 0xb4),param_2 + 0x68,*(undefined4 *)(param_2 + 0xb8));
  }
  return;
}

