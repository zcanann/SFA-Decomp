// Function: FUN_80222564
// Entry: 80222564
// Size: 588 bytes

/* WARNING: Removing unreachable block (ram,0x8022278c) */
/* WARNING: Removing unreachable block (ram,0x80222784) */
/* WARNING: Removing unreachable block (ram,0x8022277c) */
/* WARNING: Removing unreachable block (ram,0x80222774) */
/* WARNING: Removing unreachable block (ram,0x8022276c) */
/* WARNING: Removing unreachable block (ram,0x80222594) */
/* WARNING: Removing unreachable block (ram,0x8022258c) */
/* WARNING: Removing unreachable block (ram,0x80222584) */
/* WARNING: Removing unreachable block (ram,0x8022257c) */
/* WARNING: Removing unreachable block (ram,0x80222574) */

void FUN_80222564(double param_1,double param_2,double param_3,int param_4,float *param_5,
                 float *param_6)

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
  
  dVar2 = FUN_80247f54(param_5);
  if (dVar2 <= (double)FLOAT_803e78d0) {
    local_b0 = FLOAT_803e78d0;
    local_ac = FLOAT_803e78d0;
    local_a8 = FLOAT_803e78d0;
  }
  else {
    local_a8 = (float)((double)FLOAT_803e7904 / dVar2);
    local_b0 = *param_5 * local_a8;
    local_ac = param_5[1] * local_a8;
    local_a8 = param_5[2] * local_a8;
    FUN_80247ef8(&local_b0,&local_b0);
  }
  dVar3 = FUN_80247f54(param_6);
  if (dVar3 <= (double)FLOAT_803e78d0) {
    local_bc = FLOAT_803e78d0;
    local_b8 = FLOAT_803e78d0;
    local_b4 = FLOAT_803e78d0;
  }
  else {
    local_b4 = (float)((double)FLOAT_803e7904 / dVar3);
    local_bc = *param_6 * local_b4;
    local_b8 = param_6[1] * local_b4;
    local_b4 = param_6[2] * local_b4;
  }
  FUN_80247fb0(&local_b0,&local_bc,afStack_c8);
  dVar4 = FUN_80247f54(afStack_c8);
  if ((double)FLOAT_803e78d0 < dVar4) {
    FUN_80247f90(&local_b0,&local_bc);
    dVar4 = (double)FUN_80292754();
    uStack_6c = ((uint)(byte)((param_3 < dVar4) << 2) << 0x1c) >> 0x1e ^ 0x80000000;
    local_70 = 0x43300000;
    if (ABS((double)(float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e78e8)) !=
        (double)FLOAT_803e78d0) {
      fVar1 = FLOAT_803e7908;
      if ((double)FLOAT_803e78d0 < dVar4) {
        fVar1 = FLOAT_803e7904;
      }
      FUN_80247944((double)(float)(param_3 * (double)fVar1),afStack_a4,afStack_c8);
      FUN_80247cd8(afStack_a4,&local_b0,&local_bc);
    }
  }
  dVar4 = (double)(float)(dVar3 * (double)FLOAT_803e790c);
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
  return;
}

