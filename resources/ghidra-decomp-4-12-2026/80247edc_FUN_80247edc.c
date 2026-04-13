// Function: FUN_80247edc
// Entry: 80247edc
// Size: 28 bytes

/* WARNING: Removing unreachable block (ram,0x80247ef0) */
/* WARNING: Removing unreachable block (ram,0x80247ee8) */
/* WARNING: Removing unreachable block (ram,0x80247ee0) */
/* WARNING: Removing unreachable block (ram,0x80247edc) */

void FUN_80247edc(double param_1,float *param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  
  fVar2 = param_2[1];
  fVar1 = param_2[2];
  *param_3 = (float)((double)*param_2 * param_1);
  param_3[1] = (float)((double)fVar2 * param_1);
  param_3[2] = (float)((double)fVar1 * param_1);
  return;
}

