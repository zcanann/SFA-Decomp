// Function: FUN_800d83f8
// Entry: 800d83f8
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x800d8518) */
/* WARNING: Removing unreachable block (ram,0x800d8510) */
/* WARNING: Removing unreachable block (ram,0x800d8508) */
/* WARNING: Removing unreachable block (ram,0x800d8418) */
/* WARNING: Removing unreachable block (ram,0x800d8410) */
/* WARNING: Removing unreachable block (ram,0x800d8408) */

void FUN_800d83f8(double param_1,double param_2,double param_3,int param_4,uint *param_5)

{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  *param_5 = *param_5 & 0xffefffff;
  dVar4 = (double)(float)((double)*(float *)(param_4 + 0xc) - param_1);
  dVar3 = (double)(float)((double)*(float *)(param_4 + 0x14) - param_2);
  dVar2 = FUN_80293900((double)(float)(dVar4 * dVar4 + (double)(float)(dVar3 * dVar3)));
  param_5[0xaf] = (uint)(float)dVar2;
  fVar1 = FLOAT_803e11f8;
  if ((float)param_5[0xaf] < FLOAT_803e1200) {
    fVar1 = FLOAT_803e1204 * (float)param_5[0xaf];
    param_5[0xa5] = (uint)((float)param_5[0xa5] * FLOAT_803e11f4);
  }
  if ((double)fVar1 < dVar2) {
    dVar2 = (double)(float)(dVar2 / (double)fVar1);
    dVar4 = (double)(float)(dVar4 / dVar2);
    dVar3 = (double)(float)(dVar3 / dVar2);
  }
  param_5[0xa4] = (uint)(float)dVar4;
  param_5[0xa3] = (uint)(float)-dVar3;
  param_5[0xa4] = (uint)(float)((double)(float)param_5[0xa4] * param_3);
  param_5[0xa3] = (uint)(float)((double)(float)param_5[0xa3] * param_3);
  if (FLOAT_803e11f8 < (float)param_5[0xa4]) {
    param_5[0xa4] = (uint)FLOAT_803e11f8;
  }
  if ((float)param_5[0xa4] < FLOAT_803e11fc) {
    param_5[0xa4] = (uint)FLOAT_803e11fc;
  }
  if (FLOAT_803e11f8 < (float)param_5[0xa3]) {
    param_5[0xa3] = (uint)FLOAT_803e11f8;
  }
  if ((float)param_5[0xa3] < FLOAT_803e11fc) {
    param_5[0xa3] = (uint)FLOAT_803e11fc;
  }
  return;
}

