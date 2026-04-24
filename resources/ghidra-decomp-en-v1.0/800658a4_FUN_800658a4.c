// Function: FUN_800658a4
// Entry: 800658a4
// Size: 260 bytes

/* WARNING: Removing unreachable block (ram,0x8006598c) */

undefined4
FUN_800658a4(undefined8 param_1,double param_2,undefined4 param_3,float *param_4,undefined4 param_5)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  float **ppfVar6;
  int iVar7;
  int iVar8;
  undefined4 uVar9;
  undefined8 in_f31;
  float **local_28 [5];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = FUN_80065e50(param_3,local_28,0,param_5);
  if (iVar4 == 0) {
    *param_4 = FLOAT_803decb4;
    uVar5 = 1;
  }
  else {
    fVar1 = (float)(param_2 - (double)**local_28[0]);
    if (fVar1 < FLOAT_803decb4) {
      fVar1 = -fVar1;
    }
    iVar8 = 0;
    iVar7 = 1;
    iVar3 = iVar4 + -1;
    ppfVar6 = local_28[0];
    if (1 < iVar4) {
      do {
        ppfVar6 = ppfVar6 + 1;
        fVar2 = (float)(param_2 - (double)**ppfVar6);
        if (fVar2 < FLOAT_803decb4) {
          fVar2 = -fVar2;
        }
        if (fVar2 < fVar1) {
          iVar8 = iVar7;
          fVar1 = fVar2;
        }
        iVar7 = iVar7 + 1;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    *param_4 = (float)(param_2 - (double)*local_28[0][iVar8]);
    uVar5 = 0;
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  return uVar5;
}

