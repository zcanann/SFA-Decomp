// Function: FUN_8014cfcc
// Entry: 8014cfcc
// Size: 456 bytes

/* WARNING: Removing unreachable block (ram,0x8014d178) */
/* WARNING: Removing unreachable block (ram,0x8014d170) */
/* WARNING: Removing unreachable block (ram,0x8014d168) */
/* WARNING: Removing unreachable block (ram,0x8014d160) */
/* WARNING: Removing unreachable block (ram,0x8014d158) */
/* WARNING: Removing unreachable block (ram,0x8014d150) */
/* WARNING: Removing unreachable block (ram,0x8014d148) */
/* WARNING: Removing unreachable block (ram,0x8014d00c) */
/* WARNING: Removing unreachable block (ram,0x8014d004) */
/* WARNING: Removing unreachable block (ram,0x8014cffc) */
/* WARNING: Removing unreachable block (ram,0x8014cff4) */
/* WARNING: Removing unreachable block (ram,0x8014cfec) */
/* WARNING: Removing unreachable block (ram,0x8014cfe4) */
/* WARNING: Removing unreachable block (ram,0x8014cfdc) */

double FUN_8014cfcc(double param_1,double param_2,double param_3,double param_4,double param_5,
                   double param_6,double param_7,int param_8)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  dVar2 = (double)(float)(param_1 - (double)*(float *)(param_8 + 0x18));
  dVar4 = (double)(float)(param_2 - (double)*(float *)(param_8 + 0x1c));
  dVar3 = (double)(float)(param_3 - (double)*(float *)(param_8 + 0x20));
  dVar1 = FUN_80293900((double)(float)(dVar2 * dVar2 + (double)(float)(dVar3 * dVar3)));
  if (dVar1 <= param_4) {
    if ((double)FLOAT_803e31fc < dVar1) {
      *(float *)(param_8 + 0x24) =
           FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar2 / param_4)) +
           *(float *)(param_8 + 0x24);
      *(float *)(param_8 + 0x2c) =
           FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar3 / param_4)) +
           *(float *)(param_8 + 0x2c);
    }
  }
  else {
    *(float *)(param_8 + 0x24) =
         FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar2 / dVar1)) +
         *(float *)(param_8 + 0x24);
    *(float *)(param_8 + 0x2c) =
         FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar3 / dVar1)) +
         *(float *)(param_8 + 0x2c);
  }
  dVar1 = -param_6;
  if (dVar1 <= (double)*(float *)(param_8 + 0x24)) {
    if (param_6 < (double)*(float *)(param_8 + 0x24)) {
      *(float *)(param_8 + 0x24) = (float)param_6;
    }
  }
  else {
    *(float *)(param_8 + 0x24) = (float)dVar1;
  }
  if (dVar1 <= (double)*(float *)(param_8 + 0x2c)) {
    if (param_6 < (double)*(float *)(param_8 + 0x2c)) {
      *(float *)(param_8 + 0x2c) = (float)param_6;
    }
  }
  else {
    *(float *)(param_8 + 0x2c) = (float)dVar1;
  }
  if ((double)FLOAT_803e31fc != param_7) {
    dVar1 = (double)FUN_802932a4(param_7,(double)FLOAT_803dc074);
    *(float *)(param_8 + 0x24) = (float)((double)*(float *)(param_8 + 0x24) * dVar1);
    dVar1 = (double)FUN_802932a4(param_7,(double)FLOAT_803dc074);
    *(float *)(param_8 + 0x2c) = (float)((double)*(float *)(param_8 + 0x2c) * dVar1);
  }
  return dVar4;
}

