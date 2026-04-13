// Function: FUN_800e6d14
// Entry: 800e6d14
// Size: 168 bytes

/* WARNING: Removing unreachable block (ram,0x800e6da4) */
/* WARNING: Removing unreachable block (ram,0x800e6d9c) */
/* WARNING: Removing unreachable block (ram,0x800e6d2c) */
/* WARNING: Removing unreachable block (ram,0x800e6d24) */

double FUN_800e6d14(undefined8 param_1,double param_2,double param_3,double param_4,int param_5)

{
  float *pfVar1;
  float *pfVar2;
  int iVar3;
  double in_f30;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  int local_28 [4];
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  pfVar1 = (float *)FUN_800e6dbc(param_1,param_3,param_5,local_28,1);
  iVar3 = 0;
  pfVar2 = pfVar1;
  if (0 < local_28[0]) {
    do {
      if ((*pfVar2 < (float)(param_2 + param_4)) && (FLOAT_803e12e8 < pfVar2[2])) {
        return (double)pfVar1[iVar3 * 6];
      }
      pfVar2 = pfVar2 + 6;
      iVar3 = iVar3 + 1;
      local_28[0] = local_28[0] + -1;
    } while (local_28[0] != 0);
  }
  return param_2;
}

