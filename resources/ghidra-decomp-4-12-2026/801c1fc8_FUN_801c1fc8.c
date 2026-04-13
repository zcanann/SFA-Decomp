// Function: FUN_801c1fc8
// Entry: 801c1fc8
// Size: 240 bytes

/* WARNING: Removing unreachable block (ram,0x801c2098) */
/* WARNING: Removing unreachable block (ram,0x801c1fd8) */

void FUN_801c1fc8(double param_1,int param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  double dVar7;
  
  iVar3 = *(int *)(param_2 + 0xb8);
  cVar6 = (char)(int)*param_3;
  *param_3 = *param_3 -
             (float)((double)CONCAT44(0x43300000,(int)cVar6 ^ 0x80000000) - DOUBLE_803e5a88);
  iVar4 = **(int **)(iVar3 + 0x2c);
  iVar3 = cVar6 * 0x34;
  iVar5 = iVar4 + iVar3;
  fVar1 = *(float *)(iVar4 + iVar3) - *(float *)(iVar5 + 0x34);
  fVar2 = *(float *)(iVar5 + 8) - *(float *)(iVar5 + 0x3c);
  dVar7 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
  *param_3 = *param_3 + (float)(param_1 / dVar7);
  *param_3 = *param_3 +
             (float)((double)CONCAT44(0x43300000,(int)cVar6 ^ 0x80000000) - DOUBLE_803e5a88);
  return;
}

