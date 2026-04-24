// Function: FUN_800d82ac
// Entry: 800d82ac
// Size: 332 bytes

/* WARNING: Removing unreachable block (ram,0x800d83dc) */
/* WARNING: Removing unreachable block (ram,0x800d83d4) */
/* WARNING: Removing unreachable block (ram,0x800d83cc) */
/* WARNING: Removing unreachable block (ram,0x800d83c4) */
/* WARNING: Removing unreachable block (ram,0x800d83bc) */
/* WARNING: Removing unreachable block (ram,0x800d82dc) */
/* WARNING: Removing unreachable block (ram,0x800d82d4) */
/* WARNING: Removing unreachable block (ram,0x800d82cc) */
/* WARNING: Removing unreachable block (ram,0x800d82c4) */
/* WARNING: Removing unreachable block (ram,0x800d82bc) */

void FUN_800d82ac(double param_1,double param_2,double param_3,double param_4,double param_5,
                 int param_6,int param_7)

{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  dVar4 = (double)(float)((double)*(float *)(param_6 + 0xc) - param_1);
  dVar3 = (double)(float)((double)*(float *)(param_6 + 0x14) - param_2);
  dVar2 = FUN_80293900((double)(float)(dVar4 * dVar4 + (double)(float)(dVar3 * dVar3)));
  *(float *)(param_7 + 700) = (float)dVar2;
  if ((double)FLOAT_803e11f0 != dVar2) {
    dVar4 = (double)(float)(dVar4 / dVar2);
    dVar3 = (double)(float)(dVar3 / dVar2);
  }
  if (*(float *)(param_7 + 700) <= (float)(param_3 + param_4)) {
    *(float *)(param_7 + 0x294) = *(float *)(param_7 + 0x294) * FLOAT_803e11f4;
    fVar1 = FLOAT_803e11f0;
    *(float *)(param_7 + 0x290) = FLOAT_803e11f0;
    *(float *)(param_7 + 0x28c) = fVar1;
  }
  else {
    *(float *)(param_7 + 0x290) = (float)(dVar4 * param_5);
    *(float *)(param_7 + 0x28c) = (float)(-dVar3 * param_5);
  }
  if (FLOAT_803e11f8 < *(float *)(param_7 + 0x290)) {
    *(float *)(param_7 + 0x290) = FLOAT_803e11f8;
  }
  if (*(float *)(param_7 + 0x290) < FLOAT_803e11fc) {
    *(float *)(param_7 + 0x290) = FLOAT_803e11fc;
  }
  if (FLOAT_803e11f8 < *(float *)(param_7 + 0x28c)) {
    *(float *)(param_7 + 0x28c) = FLOAT_803e11f8;
  }
  if (*(float *)(param_7 + 0x28c) < FLOAT_803e11fc) {
    *(float *)(param_7 + 0x28c) = FLOAT_803e11fc;
  }
  return;
}

