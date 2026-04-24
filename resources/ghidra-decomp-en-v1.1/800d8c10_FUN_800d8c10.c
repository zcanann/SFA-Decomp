// Function: FUN_800d8c10
// Entry: 800d8c10
// Size: 556 bytes

/* WARNING: Removing unreachable block (ram,0x800d8e1c) */
/* WARNING: Removing unreachable block (ram,0x800d8e14) */
/* WARNING: Removing unreachable block (ram,0x800d8e0c) */
/* WARNING: Removing unreachable block (ram,0x800d8e04) */
/* WARNING: Removing unreachable block (ram,0x800d8c38) */
/* WARNING: Removing unreachable block (ram,0x800d8c30) */
/* WARNING: Removing unreachable block (ram,0x800d8c28) */
/* WARNING: Removing unreachable block (ram,0x800d8c20) */

void FUN_800d8c10(double param_1,double param_2,int param_3,int param_4)

{
  float fVar1;
  double dVar2;
  double dVar3;
  
  *(byte *)(param_4 + 0x34c) = *(byte *)(param_4 + 0x34c) | 1;
  if (DAT_803de0b4 == '\0') {
    dVar2 = (double)FUN_802945e0();
    dVar2 = (double)(float)(param_2 * (double)(float)((double)*(float *)(param_4 + 0x298) * -dVar2))
    ;
    dVar3 = (double)FUN_80294964();
    dVar3 = (double)(float)(param_2 * (double)(float)((double)*(float *)(param_4 + 0x298) * -dVar3))
    ;
    if ((double)*(float *)(param_4 + 0x298) < (double)FLOAT_803e122c) {
      dVar3 = (double)FLOAT_803e11f0;
      dVar2 = dVar3;
    }
    *(float *)(param_3 + 0x24) =
         (float)((double)*(float *)(param_3 + 0x24) +
                (double)((float)(param_1 *
                                (double)(float)(dVar2 - (double)*(float *)(param_3 + 0x24))) /
                        *(float *)(param_4 + 0x2b8)));
    *(float *)(param_3 + 0x2c) =
         (float)((double)*(float *)(param_3 + 0x2c) +
                (double)((float)(param_1 *
                                (double)(float)(dVar3 - (double)*(float *)(param_3 + 0x2c))) /
                        *(float *)(param_4 + 0x2b8)));
  }
  else {
    *(byte *)(param_4 + 0x34c) = *(byte *)(param_4 + 0x34c) & 0xfe;
  }
  dVar2 = FUN_80293900((double)(*(float *)(param_3 + 0x24) * *(float *)(param_3 + 0x24) +
                               *(float *)(param_3 + 0x2c) * *(float *)(param_3 + 0x2c)));
  *(float *)(param_4 + 0x294) = (float)dVar2;
  fVar1 = FLOAT_803e11f0;
  if (*(float *)(param_4 + 0x294) < FLOAT_803e1230) {
    *(float *)(param_4 + 0x294) = FLOAT_803e11f0;
    *(float *)(param_3 + 0x24) = fVar1;
    *(float *)(param_3 + 0x2c) = fVar1;
  }
  dVar2 = (double)FUN_802945e0();
  dVar3 = (double)FUN_80294964();
  *(float *)(param_4 + 0x284) =
       (float)((double)*(float *)(param_3 + 0x24) * dVar3 -
              (double)(float)((double)*(float *)(param_3 + 0x2c) * dVar2));
  *(float *)(param_4 + 0x280) =
       (float)(-(double)*(float *)(param_3 + 0x2c) * dVar3 -
              (double)(float)((double)*(float *)(param_3 + 0x24) * dVar2));
  return;
}

