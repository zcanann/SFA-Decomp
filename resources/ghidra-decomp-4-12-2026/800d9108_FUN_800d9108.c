// Function: FUN_800d9108
// Entry: 800d9108
// Size: 88 bytes

void FUN_800d9108(double param_1,double param_2,short *param_3,int param_4)

{
  float fVar1;
  double dVar2;
  
  dVar2 = (double)(float)(param_2 * param_1 + (double)*(float *)(param_4 + 0x2a8));
  if ((double)FLOAT_803e1208 < dVar2) {
    dVar2 = (double)FLOAT_803e1208;
  }
  fVar1 = (float)(dVar2 - (double)*(float *)(param_4 + 0x2a8));
  if (FLOAT_803e11f0 < fVar1) {
    *param_3 = *param_3 + (short)(int)(*(float *)(param_4 + 0x300) * fVar1);
    *(float *)(param_4 + 0x2a8) = (float)dVar2;
  }
  return;
}

