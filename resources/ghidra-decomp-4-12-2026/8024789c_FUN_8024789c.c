// Function: FUN_8024789c
// Entry: 8024789c
// Size: 168 bytes

/* WARNING: Removing unreachable block (ram,0x802478e8) */
/* WARNING: Removing unreachable block (ram,0x802478e4) */
/* WARNING: Removing unreachable block (ram,0x802478e0) */
/* WARNING: Removing unreachable block (ram,0x802478dc) */
/* WARNING: Removing unreachable block (ram,0x802478d4) */
/* WARNING: Removing unreachable block (ram,0x802478cc) */
/* WARNING: Removing unreachable block (ram,0x802478c8) */
/* WARNING: Removing unreachable block (ram,0x8024793c) */
/* WARNING: Removing unreachable block (ram,0x80247938) */
/* WARNING: Removing unreachable block (ram,0x80247934) */
/* WARNING: Removing unreachable block (ram,0x8024792c) */
/* WARNING: Removing unreachable block (ram,0x80247928) */
/* WARNING: Removing unreachable block (ram,0x8024791c) */
/* WARNING: Removing unreachable block (ram,0x80247914) */
/* WARNING: Removing unreachable block (ram,0x80247910) */
/* WARNING: Removing unreachable block (ram,0x8024790c) */
/* WARNING: Removing unreachable block (ram,0x80247908) */
/* WARNING: Removing unreachable block (ram,0x802478fc) */
/* WARNING: Removing unreachable block (ram,0x802478f8) */

void FUN_8024789c(double param_1,double param_2,float *param_3,uint param_4)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  
  fVar2 = FLOAT_803e82b4;
  fVar1 = FLOAT_803e82b0;
  uVar3 = param_4 | 0x20;
  if (uVar3 == 0x78) {
    *param_3 = FLOAT_803e82b0;
    param_3[1] = fVar2;
    param_3[2] = fVar2;
    param_3[3] = fVar2;
    param_3[4] = fVar2;
    param_3[7] = fVar2;
    param_3[8] = fVar2;
    param_3[0xb] = fVar2;
    param_3[9] = (float)param_1;
    param_3[10] = (float)param_2;
    param_3[5] = (float)param_2;
    param_3[6] = (float)-param_1;
  }
  else if (uVar3 == 0x79) {
    param_3[6] = FLOAT_803e82b4;
    param_3[7] = fVar2;
    *param_3 = (float)param_2;
    param_3[1] = fVar2;
    param_3[10] = (float)param_2;
    param_3[0xb] = fVar2;
    param_3[4] = fVar2;
    param_3[5] = fVar1;
    param_3[2] = (float)param_1;
    param_3[3] = (float)param_1;
    param_3[8] = (float)-param_1;
    param_3[9] = fVar2;
  }
  else if (uVar3 == 0x7a) {
    param_3[2] = FLOAT_803e82b4;
    param_3[3] = fVar2;
    param_3[6] = fVar2;
    param_3[7] = fVar2;
    param_3[8] = fVar2;
    param_3[9] = fVar2;
    param_3[4] = (float)param_1;
    param_3[5] = (float)param_2;
    *param_3 = (float)param_2;
    param_3[1] = (float)param_2;
    param_3[10] = fVar1;
    param_3[0xb] = fVar2;
  }
  return;
}

