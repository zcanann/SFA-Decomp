// Function: FUN_801c1970
// Entry: 801c1970
// Size: 164 bytes

void FUN_801c1970(double param_1,double param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_3 + 0xb8);
  param_1 = param_1 - (double)(float)((double)CONCAT44(0x43300000,
                                                       (int)(char)(int)param_1 ^ 0x80000000) -
                                     DOUBLE_803e4df0);
  uVar2 = (uint)(char)(int)param_1;
  dVar5 = (double)((float)param_1 -
                  (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e4df0));
  iVar3 = uVar2 * 0x34;
  iVar1 = **(int **)(iVar4 + 0x2c) + iVar3;
  *(float *)(iVar1 + 0x1c) = (float)(param_2 * dVar5 + (double)*(float *)(iVar1 + 0x1c));
  iVar3 = **(int **)(iVar4 + 0x2c) + iVar3;
  *(float *)(iVar3 + 0x1c) =
       (float)(param_2 * (double)(float)((double)FLOAT_803e4e18 - dVar5) +
              (double)*(float *)(iVar3 + 0x1c));
  return;
}

