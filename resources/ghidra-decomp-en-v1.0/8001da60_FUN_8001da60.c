// Function: FUN_8001da60
// Entry: 8001da60
// Size: 88 bytes

void FUN_8001da60(double param_1,int param_2,int param_3)

{
  *(float *)(param_2 + 0xb4) = (float)param_1;
  *(int *)(param_2 + 0xb8) = param_3;
  if (param_3 == 0) {
    FUN_8025968c((double)FLOAT_803de760,(double)FLOAT_803de75c,(double)FLOAT_803de75c,param_2 + 0x68
                );
  }
  else {
    FUN_802596c8((double)*(float *)(param_2 + 0xb4),param_2 + 0x68,*(undefined4 *)(param_2 + 0xb8));
  }
  return;
}

