// Function: FUN_8014caf0
// Entry: 8014caf0
// Size: 680 bytes

/* WARNING: Removing unreachable block (ram,0x8014cd70) */
/* WARNING: Removing unreachable block (ram,0x8014cd68) */
/* WARNING: Removing unreachable block (ram,0x8014cd60) */
/* WARNING: Removing unreachable block (ram,0x8014cd58) */
/* WARNING: Removing unreachable block (ram,0x8014cd50) */
/* WARNING: Removing unreachable block (ram,0x8014cb20) */
/* WARNING: Removing unreachable block (ram,0x8014cb18) */
/* WARNING: Removing unreachable block (ram,0x8014cb10) */
/* WARNING: Removing unreachable block (ram,0x8014cb08) */
/* WARNING: Removing unreachable block (ram,0x8014cb00) */

void FUN_8014caf0(double param_1,double param_2,double param_3,int param_4,int param_5,
                 float *param_6,char param_7)

{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  float afStack_c8 [3];
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float afStack_a4 [13];
  undefined4 local_70;
  uint uStack_6c;
  
  dVar2 = FUN_80247f54((float *)(param_5 + 0x2b8));
  if (dVar2 <= (double)FLOAT_803e31fc) {
    local_b0 = FLOAT_803e31fc;
    local_ac = FLOAT_803e31fc;
    local_a8 = FLOAT_803e31fc;
  }
  else {
    local_a8 = (float)((double)FLOAT_803e3200 / dVar2);
    local_b0 = *(float *)(param_5 + 0x2b8) * local_a8;
    local_ac = *(float *)(param_5 + 700) * local_a8;
    local_a8 = *(float *)(param_5 + 0x2c0) * local_a8;
    FUN_80247ef8(&local_b0,&local_b0);
  }
  dVar3 = FUN_80247f54(param_6);
  if (dVar3 <= (double)FLOAT_803e31fc) {
    local_bc = FLOAT_803e31fc;
    local_b8 = FLOAT_803e31fc;
    local_b4 = FLOAT_803e31fc;
  }
  else {
    local_b4 = (float)((double)FLOAT_803e3200 / dVar3);
    local_bc = *param_6 * local_b4;
    local_b8 = param_6[1] * local_b4;
    local_b4 = param_6[2] * local_b4;
  }
  FUN_80247fb0(&local_b0,&local_bc,afStack_c8);
  dVar4 = FUN_80247f54(afStack_c8);
  if ((double)FLOAT_803e31fc < dVar4) {
    FUN_80247f90(&local_b0,&local_bc);
    dVar4 = (double)FUN_80292754();
    uStack_6c = ((uint)(byte)((param_3 < dVar4) << 2) << 0x1c) >> 0x1e ^ 0x80000000;
    local_70 = 0x43300000;
    if (ABS((double)(float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e3218)) !=
        (double)FLOAT_803e31fc) {
      fVar1 = FLOAT_803e3258;
      if ((double)FLOAT_803e31fc < dVar4) {
        fVar1 = FLOAT_803e3200;
      }
      FUN_80247944((double)(float)(param_3 * (double)fVar1),afStack_a4,afStack_c8);
      FUN_80247cd8(afStack_a4,&local_b0,&local_bc);
    }
  }
  dVar4 = (double)(float)(dVar3 * (double)FLOAT_803e3280);
  dVar3 = (double)(float)(dVar2 + param_2);
  if ((dVar4 <= dVar3) && (dVar3 = dVar4, dVar4 < (double)(float)(dVar2 - param_2))) {
    dVar3 = (double)(float)(dVar2 - param_2);
  }
  if (param_1 < dVar3) {
    dVar3 = param_1;
  }
  *(float *)(param_4 + 0x24) = (float)((double)local_bc * dVar3);
  *(float *)(param_4 + 0x28) = (float)((double)local_b8 * dVar3);
  *(float *)(param_4 + 0x2c) = (float)((double)local_b4 * dVar3);
  if ((param_7 != '\0') && (*(float *)(param_4 + 0x28) < FLOAT_803e31fc)) {
    fVar1 = FLOAT_803e3264 + *(float *)(*(int *)(param_5 + 0x29c) + 0x10);
    if (*(float *)(param_4 + 0x10) < fVar1) {
      *(float *)(param_4 + 0x28) =
           *(float *)(param_4 + 0x28) *
           (FLOAT_803e3200 - (fVar1 - *(float *)(param_4 + 0x10)) / FLOAT_803e3264);
    }
  }
  return;
}

