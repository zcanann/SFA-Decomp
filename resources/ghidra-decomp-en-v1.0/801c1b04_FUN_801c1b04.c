// Function: FUN_801c1b04
// Entry: 801c1b04
// Size: 196 bytes

void FUN_801c1b04(double param_1,int param_2,float *param_3,float *param_4,float *param_5)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  
  iVar9 = *(int *)(param_2 + 0xb8);
  fVar1 = (float)(param_1 -
                 (double)(float)((double)CONCAT44(0x43300000,(int)(char)(int)param_1 ^ 0x80000000) -
                                DOUBLE_803e4df0));
  iVar8 = (char)(int)param_1 * 0x34;
  iVar7 = **(int **)(iVar9 + 0x2c) + iVar8;
  fVar2 = *(float *)(iVar7 + 0x38);
  fVar3 = *(float *)(iVar7 + 4);
  fVar4 = *(float *)(iVar7 + 0x3c);
  fVar5 = *(float *)(iVar7 + 8);
  fVar6 = *(float *)(**(int **)(iVar9 + 0x2c) + iVar8);
  *param_3 = (*(float *)(iVar7 + 0x34) - fVar6) * fVar1 + *(float *)(param_2 + 0xc) + fVar6;
  *param_4 = (fVar2 - fVar3) * fVar1 +
             *(float *)(param_2 + 0x10) + *(float *)(**(int **)(iVar9 + 0x2c) + iVar8 + 4);
  *param_5 = (fVar4 - fVar5) * fVar1 +
             *(float *)(param_2 + 0x14) + *(float *)(**(int **)(iVar9 + 0x2c) + iVar8 + 8);
  return;
}

