// Function: FUN_801ee880
// Entry: 801ee880
// Size: 364 bytes

/* WARNING: Removing unreachable block (ram,0x801ee9d0) */
/* WARNING: Removing unreachable block (ram,0x801ee890) */

void FUN_801ee880(undefined4 param_1,int param_2)

{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  
  (**(code **)(*DAT_803dd6e4 + 0x20))((int)*(short *)(param_2 + 0x6a));
  dVar3 = (double)FUN_80294964();
  dVar4 = (double)FUN_802945e0();
  fVar1 = FLOAT_803e6908;
  if (*(int *)(param_2 + 0x10) != 0) {
    fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x2e) ^ 0x80000000) -
                   DOUBLE_803e6938) / FLOAT_803e6924;
  }
  *(float *)(param_2 + 0x60) =
       FLOAT_803dc074 * (fVar1 - *(float *)(param_2 + 0x60)) * FLOAT_803e6928 +
       *(float *)(param_2 + 0x60);
  fVar1 = FLOAT_803e692c;
  dVar5 = (double)FLOAT_803e692c;
  dVar2 = -(double)*(float *)(param_2 + 0x60);
  *(float *)(param_2 + 0x78) = *(float *)(param_2 + 0x60);
  *(float *)(param_2 + 0x7c) = fVar1;
  (**(code **)(*DAT_803dd6e4 + 0x28))
            ((double)(((float)(dVar4 * dVar2 + (double)(float)(dVar5 * -dVar3)) * FLOAT_803dc074) /
                     FLOAT_803e6930),
             (double)(((float)(dVar3 * dVar2 + (double)(float)(dVar5 * dVar4)) * FLOAT_803dc074) /
                     FLOAT_803e6930));
  return;
}

