// Function: FUN_8014cd98
// Entry: 8014cd98
// Size: 564 bytes

/* WARNING: Removing unreachable block (ram,0x8014cfb0) */
/* WARNING: Removing unreachable block (ram,0x8014cfa8) */
/* WARNING: Removing unreachable block (ram,0x8014cfa0) */
/* WARNING: Removing unreachable block (ram,0x8014cf98) */
/* WARNING: Removing unreachable block (ram,0x8014cf90) */
/* WARNING: Removing unreachable block (ram,0x8014cf88) */
/* WARNING: Removing unreachable block (ram,0x8014cf80) */
/* WARNING: Removing unreachable block (ram,0x8014cdd8) */
/* WARNING: Removing unreachable block (ram,0x8014cdd0) */
/* WARNING: Removing unreachable block (ram,0x8014cdc8) */
/* WARNING: Removing unreachable block (ram,0x8014cdc0) */
/* WARNING: Removing unreachable block (ram,0x8014cdb8) */
/* WARNING: Removing unreachable block (ram,0x8014cdb0) */
/* WARNING: Removing unreachable block (ram,0x8014cda8) */

double FUN_8014cd98(double param_1,double param_2,double param_3,double param_4,double param_5,
                   double param_6,double param_7,int param_8)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  dVar2 = (double)(float)(param_1 - (double)*(float *)(param_8 + 0x18));
  dVar4 = (double)(float)(param_2 - (double)*(float *)(param_8 + 0x1c));
  dVar3 = (double)(float)(param_3 - (double)*(float *)(param_8 + 0x20));
  dVar1 = FUN_80293900((double)(float)(dVar3 * dVar3 +
                                      (double)(float)(dVar2 * dVar2 + (double)(float)(dVar4 * dVar4)
                                                     )));
  if (dVar1 <= param_4) {
    if ((double)FLOAT_803e31fc < dVar1) {
      *(float *)(param_8 + 0x24) =
           FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar2 / param_4)) +
           *(float *)(param_8 + 0x24);
      *(float *)(param_8 + 0x28) =
           FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar4 / param_4)) +
           *(float *)(param_8 + 0x28);
      *(float *)(param_8 + 0x2c) =
           FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar3 / param_4)) +
           *(float *)(param_8 + 0x2c);
    }
  }
  else {
    *(float *)(param_8 + 0x24) =
         FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar2 / dVar1)) +
         *(float *)(param_8 + 0x24);
    *(float *)(param_8 + 0x28) =
         FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar4 / dVar1)) +
         *(float *)(param_8 + 0x28);
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
  if (dVar1 <= (double)*(float *)(param_8 + 0x28)) {
    if (param_6 < (double)*(float *)(param_8 + 0x28)) {
      *(float *)(param_8 + 0x28) = (float)param_6;
    }
  }
  else {
    *(float *)(param_8 + 0x28) = (float)dVar1;
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
    *(float *)(param_8 + 0x28) = (float)((double)*(float *)(param_8 + 0x28) * dVar1);
    dVar1 = (double)FUN_802932a4(param_7,(double)FLOAT_803dc074);
    *(float *)(param_8 + 0x2c) = (float)((double)*(float *)(param_8 + 0x2c) * dVar1);
  }
  return dVar4;
}

