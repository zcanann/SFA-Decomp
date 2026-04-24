// Function: FUN_8016f70c
// Entry: 8016f70c
// Size: 748 bytes

/* WARNING: Removing unreachable block (ram,0x8016f9d0) */
/* WARNING: Removing unreachable block (ram,0x8016f9c8) */
/* WARNING: Removing unreachable block (ram,0x8016f9c0) */
/* WARNING: Removing unreachable block (ram,0x8016f72c) */
/* WARNING: Removing unreachable block (ram,0x8016f724) */
/* WARNING: Removing unreachable block (ram,0x8016f71c) */

void FUN_8016f70c(int param_1,int param_2,int param_3)

{
  float fVar1;
  float *pfVar2;
  double dVar3;
  double dVar4;
  
  pfVar2 = (float *)(*(int *)(param_3 + 0x74) + (uint)*(byte *)(param_3 + 0xe4) * 0x18);
  if (pfVar2 != (float *)0x0) {
    dVar4 = (double)(*pfVar2 - *(float *)(param_2 + 0x24));
    dVar3 = (double)(pfVar2[2] - *(float *)(param_2 + 0x2c));
    FUN_80021884();
    FUN_80293900((double)(*(float *)(param_1 + 0x24) * *(float *)(param_1 + 0x24) +
                         *(float *)(param_1 + 0x2c) * *(float *)(param_1 + 0x2c)));
    FUN_80021884();
    FUN_80021884();
    FUN_80293900((double)(float)(dVar4 * dVar4 + (double)(float)(dVar3 * dVar3)));
    FUN_80021884();
    dVar3 = (double)FUN_802945e0();
    *(float *)(param_1 + 0x24) = (float)dVar3;
    dVar3 = (double)FUN_80294964();
    *(float *)(param_1 + 0x2c) = (float)dVar3;
    dVar3 = (double)FUN_802945e0();
    dVar4 = (double)FUN_80294964();
    if ((double)FLOAT_803e3fc8 != dVar4) {
      dVar3 = (double)(float)(dVar3 / dVar4);
    }
    *(float *)(param_1 + 0x28) = (float)dVar3;
    dVar3 = FUN_80293900((double)(*(float *)(param_1 + 0x2c) * *(float *)(param_1 + 0x2c) +
                                 *(float *)(param_1 + 0x24) * *(float *)(param_1 + 0x24) +
                                 *(float *)(param_1 + 0x28) * *(float *)(param_1 + 0x28)));
    fVar1 = (float)((double)FLOAT_803e3fd8 / dVar3);
    *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * fVar1;
    *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * fVar1;
    *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * fVar1;
  }
  return;
}

