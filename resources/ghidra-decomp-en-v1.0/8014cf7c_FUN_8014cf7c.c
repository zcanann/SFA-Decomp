// Function: FUN_8014cf7c
// Entry: 8014cf7c
// Size: 272 bytes

void FUN_8014cf7c(double param_1,double param_2,short *param_3,undefined4 param_4,uint param_5,
                 short param_6)

{
  float fVar1;
  short sVar2;
  
  sVar2 = FUN_800217c0((double)(float)((double)*(float *)(param_3 + 6) - param_1),
                       (double)(float)((double)*(float *)(param_3 + 10) - param_2));
  sVar2 = sVar2 - *param_3;
  if (0x8000 < sVar2) {
    sVar2 = sVar2 + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  fVar1 = FLOAT_803db414 / (float)((double)CONCAT44(0x43300000,param_5 & 0xffff) - DOUBLE_803e25e0);
  if (FLOAT_803e256c < fVar1) {
    fVar1 = FLOAT_803e256c;
  }
  *param_3 = *param_3 +
             (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)(short)(sVar2 + param_6) ^ 0x80000000) -
                                 DOUBLE_803e2580) * fVar1);
  return;
}

