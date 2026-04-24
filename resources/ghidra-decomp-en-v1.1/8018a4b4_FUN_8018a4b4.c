// Function: FUN_8018a4b4
// Entry: 8018a4b4
// Size: 676 bytes

void FUN_8018a4b4(int param_1,float *param_2,float *param_3)

{
  byte bVar1;
  float *pfVar2;
  double dVar3;
  
  pfVar2 = *(float **)(param_1 + 0xb8);
  bVar1 = *(byte *)(*(int *)(param_1 + 0x4c) + 0x1c);
  if (bVar1 == 2) {
    dVar3 = (double)FUN_802945e0();
    *param_2 = -(float)((double)FLOAT_803e4888 * dVar3 - (double)*pfVar2);
    dVar3 = (double)FUN_80294964();
    *param_3 = -(float)((double)FLOAT_803e4888 * dVar3 - (double)pfVar2[1]);
  }
  else {
    if (bVar1 < 2) {
      if (bVar1 == 0) {
        dVar3 = (double)FUN_802945e0();
        *param_2 = (float)((double)FLOAT_803e4894 * dVar3 + (double)*(float *)(param_1 + 0xc));
        dVar3 = (double)FUN_80294964();
        *param_3 = (float)((double)FLOAT_803e4894 * dVar3 + (double)*(float *)(param_1 + 0x14));
        return;
      }
    }
    else if (bVar1 < 4) {
      dVar3 = (double)FUN_802945e0();
      *param_2 = (float)((double)FLOAT_803e4888 * dVar3 + (double)*pfVar2);
      dVar3 = (double)FUN_80294964();
      *param_3 = (float)((double)FLOAT_803e4888 * dVar3 + (double)pfVar2[1]);
      return;
    }
    dVar3 = (double)FUN_802945e0();
    *param_2 = (float)((double)FLOAT_803e4888 * dVar3 + (double)*(float *)(param_1 + 0xc));
    dVar3 = (double)FUN_80294964();
    *param_3 = (float)((double)FLOAT_803e4888 * dVar3 + (double)*(float *)(param_1 + 0x14));
  }
  return;
}

