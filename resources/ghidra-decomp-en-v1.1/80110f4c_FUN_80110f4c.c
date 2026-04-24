// Function: FUN_80110f4c
// Entry: 80110f4c
// Size: 268 bytes

void FUN_80110f4c(undefined2 *param_1)

{
  int iVar1;
  double dVar2;
  
  iVar1 = *(int *)(param_1 + 0x52);
  *DAT_803de240 = -(FLOAT_803e27f8 * FLOAT_803dc074 - *DAT_803de240);
  if (*DAT_803de240 < FLOAT_803e27fc) {
    *DAT_803de240 = FLOAT_803e27fc;
  }
  dVar2 = (double)FUN_802945e0();
  *(float *)(param_1 + 6) =
       -(float)((double)FLOAT_803e2800 * dVar2 - (double)*(float *)(iVar1 + 0x18));
  *(float *)(param_1 + 8) = DAT_803de240[1];
  dVar2 = (double)FUN_80294964();
  *(float *)(param_1 + 10) =
       -(float)((double)FLOAT_803e2800 * dVar2 - (double)*(float *)(iVar1 + 0x20));
  *param_1 = 0;
  param_1[1] = 0xc000;
  param_1[2] = 0;
  return;
}

