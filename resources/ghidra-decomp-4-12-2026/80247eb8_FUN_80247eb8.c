// Function: FUN_80247eb8
// Entry: 80247eb8
// Size: 36 bytes

/* WARNING: Removing unreachable block (ram,0x80247ed4) */
/* WARNING: Removing unreachable block (ram,0x80247ecc) */
/* WARNING: Removing unreachable block (ram,0x80247ec8) */
/* WARNING: Removing unreachable block (ram,0x80247ec4) */
/* WARNING: Removing unreachable block (ram,0x80247ebc) */
/* WARNING: Removing unreachable block (ram,0x80247eb8) */

void FUN_80247eb8(float *param_1,float *param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  
  fVar1 = param_1[1];
  fVar2 = param_2[1];
  *param_3 = *param_1 - *param_2;
  param_3[1] = fVar1 - fVar2;
  param_3[2] = param_1[2] - param_2[2];
  return;
}

