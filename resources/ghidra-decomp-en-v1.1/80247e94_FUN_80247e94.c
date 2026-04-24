// Function: FUN_80247e94
// Entry: 80247e94
// Size: 36 bytes

/* WARNING: Removing unreachable block (ram,0x80247eb0) */
/* WARNING: Removing unreachable block (ram,0x80247ea8) */
/* WARNING: Removing unreachable block (ram,0x80247ea4) */
/* WARNING: Removing unreachable block (ram,0x80247ea0) */
/* WARNING: Removing unreachable block (ram,0x80247e98) */
/* WARNING: Removing unreachable block (ram,0x80247e94) */

void FUN_80247e94(float *param_1,float *param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  
  fVar1 = param_1[1];
  fVar2 = param_2[1];
  *param_3 = *param_1 + *param_2;
  param_3[1] = fVar1 + fVar2;
  param_3[2] = param_1[2] + param_2[2];
  return;
}

