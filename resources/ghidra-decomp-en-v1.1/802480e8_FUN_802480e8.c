// Function: FUN_802480e8
// Entry: 802480e8
// Size: 76 bytes

/* WARNING: Removing unreachable block (ram,0x802480f8) */
/* WARNING: Removing unreachable block (ram,0x802480f4) */
/* WARNING: Removing unreachable block (ram,0x802480ec) */
/* WARNING: Removing unreachable block (ram,0x802480e8) */

double FUN_802480e8(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  
  fVar2 = (*param_1 - *param_2) * (*param_1 - *param_2) +
          (param_1[1] - param_2[1]) * (param_1[1] - param_2[1]) +
          (param_1[2] - param_2[2]) * (param_1[2] - param_2[2]);
  fVar1 = 1.0 / SQRT(fVar2);
  fVar1 = -(fVar1 * fVar1 * fVar2 - FLOAT_803e82e4) * fVar1 * FLOAT_803e82e0;
  if (fVar1 < 0.0) {
    fVar1 = fVar2;
  }
  return (double)(fVar2 * fVar1);
}

