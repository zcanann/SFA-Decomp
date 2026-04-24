// Function: FUN_802477f0
// Entry: 802477f0
// Size: 60 bytes

/* WARNING: Removing unreachable block (ram,0x802477f0) */

double FUN_802477f0(int param_1)

{
  float fVar1;
  float fVar3;
  double dVar2;
  float fVar4;
  double dVar5;
  
  fVar1 = (float)__psq_l0(param_1,0);
  fVar3 = (float)__psq_l1(param_1,0);
  fVar4 = (float)((ulonglong)(double)*(float *)(param_1 + 8) >> 0x20);
  dVar5 = (double)CONCAT44(fVar4 * fVar4 + fVar1 * fVar1 + fVar3 * fVar3,fVar3 * fVar3);
  dVar2 = 1.0 / SQRT(dVar5);
  dVar2 = (double)(-(float)((double)(float)(dVar2 * dVar2) * dVar5 - (double)FLOAT_803e764c) *
                  (float)(dVar2 * (double)FLOAT_803e7648));
  if (dVar2 <= 0.0) {
    dVar2 = dVar5;
  }
  return (double)(float)(dVar5 * dVar2);
}

