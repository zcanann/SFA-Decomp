// Function: FUN_80113bf8
// Entry: 80113bf8
// Size: 628 bytes

/* WARNING: Removing unreachable block (ram,0x80113e4c) */
/* WARNING: Removing unreachable block (ram,0x80113e44) */
/* WARNING: Removing unreachable block (ram,0x80113e3c) */
/* WARNING: Removing unreachable block (ram,0x80113e34) */
/* WARNING: Removing unreachable block (ram,0x80113e2c) */
/* WARNING: Removing unreachable block (ram,0x80113c28) */
/* WARNING: Removing unreachable block (ram,0x80113c20) */
/* WARNING: Removing unreachable block (ram,0x80113c18) */
/* WARNING: Removing unreachable block (ram,0x80113c10) */
/* WARNING: Removing unreachable block (ram,0x80113c08) */

double FUN_80113bf8(double param_1,double param_2,double param_3,int param_4,int param_5)

{
  float fVar1;
  float fVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  fVar1 = (float)((double)*(float *)(param_5 + 0x18) - param_1);
  fVar2 = (float)((double)*(float *)(param_5 + 0x20) - param_2);
  dVar3 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
  if (dVar3 < param_3) {
    dVar4 = (double)FUN_802945e0();
    dVar5 = (double)FUN_80294964();
    fVar1 = -(float)(dVar4 * (double)(float)(param_1 - dVar4) +
                    (double)(float)(dVar5 * (double)(float)(param_2 - dVar5)));
    dVar6 = (double)(fVar1 + (float)(dVar4 * (double)*(float *)(param_5 + 0x18) +
                                    (double)(float)(dVar5 * (double)*(float *)(param_5 + 0x20))));
    fVar1 = fVar1 + (float)(dVar4 * (double)*(float *)(param_5 + 0x8c) +
                           (double)(float)(dVar5 * (double)*(float *)(param_5 + 0x94)));
    if ((dVar6 <= (double)FLOAT_803e28ac) || (FLOAT_803e28c8 < fVar1)) {
      if (FLOAT_803e28c8 < fVar1) {
        dVar3 = (double)(float)((double)FLOAT_803e28c0 * param_3);
      }
    }
    else {
      *(float *)(param_5 + 0x18) = -(float)(dVar4 * dVar6 - (double)*(float *)(param_5 + 0x18));
      *(float *)(param_5 + 0x20) = -(float)(dVar5 * dVar6 - (double)*(float *)(param_5 + 0x20));
      FUN_8000e054((double)*(float *)(param_5 + 0x18),(double)*(float *)(param_5 + 0x1c),
                   (double)*(float *)(param_5 + 0x20),(float *)(param_5 + 0xc),
                   (float *)(param_5 + 0x10),(float *)(param_5 + 0x14),*(int *)(param_5 + 0x30));
    }
  }
  if (dVar3 < param_3) {
    param_1 = (double)*(float *)(param_5 + 0x18);
    param_2 = (double)*(float *)(param_5 + 0x20);
  }
  dVar3 = (double)FUN_802945e0();
  dVar4 = (double)FUN_80294964();
  return -(double)(-(float)((double)*(float *)(param_4 + 0xc) * dVar3 +
                           (double)(float)((double)*(float *)(param_4 + 0x14) * dVar4)) +
                  (float)(dVar3 * param_1 + (double)(float)(dVar4 * param_2)));
}

