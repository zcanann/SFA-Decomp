// Function: FUN_800e1f3c
// Entry: 800e1f3c
// Size: 184 bytes

undefined4 FUN_800e1f3c(double param_1,undefined8 param_2,double param_3,int param_4,int param_5)

{
  float fVar1;
  float fVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  dVar3 = (double)*(float *)(param_4 + 8);
  dVar5 = (double)*(float *)(param_4 + 0x10);
  dVar4 = (double)*(float *)(param_5 + 8);
  dVar6 = (double)*(float *)(param_5 + 0x10);
  fVar2 = (float)(dVar4 * dVar5 - (double)(float)(dVar3 * dVar6));
  fVar1 = fVar2 + (float)(param_1 * (double)(float)(dVar6 - dVar5) +
                         (double)(float)(param_3 * (double)(float)(dVar3 - dVar4)));
  if (((fVar1 <= FLOAT_803e0638) && (FLOAT_803e0638 <= fVar2)) ||
     ((FLOAT_803e0638 <= fVar1 && (fVar2 < FLOAT_803e0638)))) {
    fVar2 = (float)(-param_3 * dVar3 + (double)(float)(param_1 * dVar5));
    fVar1 = (float)(-param_3 * dVar4 + (double)(float)(param_1 * dVar6));
    if (((fVar2 <= FLOAT_803e0638) && (FLOAT_803e0638 <= fVar1)) ||
       ((FLOAT_803e0638 <= fVar2 && (fVar1 < FLOAT_803e0638)))) {
      return 1;
    }
  }
  return 0;
}

