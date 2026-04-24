// Function: FUN_8015224c
// Entry: 8015224c
// Size: 588 bytes

/* WARNING: Removing unreachable block (ram,0x80152470) */
/* WARNING: Removing unreachable block (ram,0x80152468) */
/* WARNING: Removing unreachable block (ram,0x80152460) */
/* WARNING: Removing unreachable block (ram,0x8015226c) */
/* WARNING: Removing unreachable block (ram,0x80152264) */
/* WARNING: Removing unreachable block (ram,0x8015225c) */

void FUN_8015224c(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  
  iVar3 = FUN_8002bac4();
  iVar4 = *(int *)(param_1 + 0x4c);
  fVar1 = *(float *)(iVar3 + 0x10) - *(float *)(param_1 + 0x10);
  if (fVar1 < FLOAT_803e3470) {
    fVar1 = -fVar1;
  }
  if (fVar1 <= FLOAT_803e3474) {
    dVar5 = (double)FUN_802945e0();
    dVar8 = -(double)(float)((double)FLOAT_803e3474 * dVar5 - (double)*(float *)(iVar4 + 8));
    dVar5 = (double)FUN_80294964();
    dVar7 = -(double)(float)((double)FLOAT_803e3474 * dVar5 - (double)*(float *)(iVar4 + 0x10));
    fVar1 = (float)((double)*(float *)(iVar3 + 0x18) - dVar8);
    fVar2 = (float)((double)*(float *)(iVar3 + 0x20) - dVar7);
    dVar5 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
    if (dVar5 < (double)*(float *)(param_2 + 0x2ac)) {
      dVar5 = (double)FUN_802945e0();
      dVar6 = (double)FUN_80294964();
      fVar1 = -(float)(dVar5 * (double)(float)(dVar8 - dVar5) +
                      (double)(float)(dVar6 * (double)(float)(dVar7 - dVar6)));
      dVar7 = (double)(fVar1 + (float)(dVar5 * (double)*(float *)(iVar3 + 0x8c) +
                                      (double)(float)(dVar6 * (double)*(float *)(iVar3 + 0x94))));
      if ((FLOAT_803e3470 <
           fVar1 + (float)(dVar5 * (double)*(float *)(iVar3 + 0x18) +
                          (double)(float)(dVar6 * (double)*(float *)(iVar3 + 0x20)))) &&
         ((double)FLOAT_803e3480 <= dVar7)) {
        *(float *)(iVar3 + 0x18) = -(float)(dVar5 * dVar7 - (double)*(float *)(iVar3 + 0x18));
        *(float *)(iVar3 + 0x20) = -(float)(dVar6 * dVar7 - (double)*(float *)(iVar3 + 0x20));
        FUN_8000e054((double)*(float *)(iVar3 + 0x18),(double)*(float *)(iVar3 + 0x1c),
                     (double)*(float *)(iVar3 + 0x20),(float *)(iVar3 + 0xc),(float *)(iVar3 + 0x10)
                     ,(float *)(iVar3 + 0x14),*(int *)(iVar3 + 0x30));
      }
    }
  }
  return;
}

