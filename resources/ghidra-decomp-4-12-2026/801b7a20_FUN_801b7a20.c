// Function: FUN_801b7a20
// Entry: 801b7a20
// Size: 324 bytes

/* WARNING: Removing unreachable block (ram,0x801b7b40) */
/* WARNING: Removing unreachable block (ram,0x801b7a30) */

void FUN_801b7a20(undefined2 *param_1,int param_2)

{
  float *pfVar1;
  double dVar2;
  double dVar3;
  
  dVar3 = (double)((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000)
                          - DOUBLE_803e5708) / FLOAT_803e56fc);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  pfVar1 = *(float **)(param_1 + 0x5c);
  dVar2 = (double)FUN_802945e0();
  *pfVar1 = (float)(dVar3 * dVar2);
  dVar2 = (double)FUN_80294964();
  pfVar1[1] = (float)(dVar3 * dVar2);
  pfVar1[3] = FLOAT_803e56f8;
  pfVar1[4] = 0.0;
  FUN_800372f8((int)param_1,0x16);
  param_1[0x58] = param_1[0x58] | 0x2000;
  if (*(int *)(param_2 + 0x14) == 0x49b23) {
    FUN_800201ac(0xc5c,1);
  }
  return;
}

