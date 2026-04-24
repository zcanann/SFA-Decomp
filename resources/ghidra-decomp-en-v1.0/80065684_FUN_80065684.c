// Function: FUN_80065684
// Entry: 80065684
// Size: 228 bytes

/* WARNING: Removing unreachable block (ram,0x8006574c) */

undefined4
FUN_80065684(undefined8 param_1,double param_2,undefined4 param_3,float *param_4,undefined4 param_5)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined8 in_f31;
  float **local_28 [5];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = FUN_80065e50(param_3,local_28,0,param_5);
  if (iVar4 == 0) {
    *param_4 = FLOAT_803decb4;
    uVar5 = 0;
  }
  else {
    fVar1 = (float)(param_2 - (double)**local_28[0]);
    iVar3 = iVar4 + -1;
    if (1 < iVar4) {
      do {
        local_28[0] = local_28[0] + 1;
        fVar2 = (float)(param_2 - (double)**local_28[0]);
        if ((FLOAT_803decb4 <= fVar2) && ((fVar1 < FLOAT_803decb4 || (fVar2 < fVar1)))) {
          fVar1 = fVar2;
        }
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    if (fVar1 < FLOAT_803decb4) {
      *param_4 = FLOAT_803decb4;
      uVar5 = 0;
    }
    else {
      *param_4 = fVar1;
      uVar5 = 1;
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return uVar5;
}

