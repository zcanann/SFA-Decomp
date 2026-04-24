// Function: FUN_801c1a14
// Entry: 801c1a14
// Size: 240 bytes

/* WARNING: Removing unreachable block (ram,0x801c1ae4) */

void FUN_801c1a14(double param_1,int param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  undefined4 uVar7;
  double dVar8;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar3 = *(int *)(param_2 + 0xb8);
  cVar6 = (char)(int)*param_3;
  *param_3 = *param_3 -
             (float)((double)CONCAT44(0x43300000,(int)cVar6 ^ 0x80000000) - DOUBLE_803e4df0);
  iVar4 = **(int **)(iVar3 + 0x2c);
  iVar3 = cVar6 * 0x34;
  iVar5 = iVar4 + iVar3;
  fVar1 = *(float *)(iVar4 + iVar3) - *(float *)(iVar5 + 0x34);
  fVar2 = *(float *)(iVar5 + 8) - *(float *)(iVar5 + 0x3c);
  dVar8 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
  *param_3 = *param_3 + (float)(param_1 / dVar8);
  *param_3 = *param_3 +
             (float)((double)CONCAT44(0x43300000,(int)cVar6 ^ 0x80000000) - DOUBLE_803e4df0);
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return;
}

