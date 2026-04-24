// Function: FUN_80113590
// Entry: 80113590
// Size: 164 bytes

/* WARNING: Removing unreachable block (ram,0x80113614) */
/* WARNING: Removing unreachable block (ram,0x801135a0) */

void FUN_80113590(double param_1,int param_2,uint *param_3,char param_4)

{
  float fVar1;
  
  *param_3 = *param_3 | 0x8000;
  *(undefined2 *)(param_3 + 0xcc) = 0;
  if (*(int *)(param_2 + 0x54) != 0) {
    FUN_80035eec(param_2,0,0,-1);
  }
  if (param_4 != -1) {
    *(char *)((int)param_3 + 0x25f) = param_4;
  }
  param_3[0xa9] = (uint)(float)param_1;
  fVar1 = FLOAT_803e28ac;
  param_3[0xa4] = (uint)FLOAT_803e28ac;
  param_3[0xa3] = (uint)fVar1;
  param_3[199] = 0;
  param_3[0xc6] = 0;
  return;
}

