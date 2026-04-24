// Function: FUN_80144e40
// Entry: 80144e40
// Size: 272 bytes

/* WARNING: Removing unreachable block (ram,0x80144f20) */
/* WARNING: Removing unreachable block (ram,0x80144f28) */

int FUN_80144e40(int param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  int local_38 [2];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar3 = 0;
  piVar1 = (int *)FUN_80036f50(0x4b,local_38);
  dVar5 = (double)FUN_8002166c(*(int *)(param_2 + 4) + 0x18,param_1 + 0x18);
  if ((((double)FLOAT_803e2538 <= dVar5) || (FLOAT_803e23dc < *(float *)(param_2 + 0x71c))) &&
     (iVar2 = FUN_8005a10c((double)FLOAT_803e2500,param_1 + 0xc), iVar2 == 0)) {
    dVar7 = (double)FLOAT_803e2418;
    for (iVar2 = 0; iVar2 < local_38[0]; iVar2 = iVar2 + 1) {
      dVar6 = (double)FUN_8002166c(*(int *)(param_2 + 4) + 0x18,*piVar1 + 0x18);
      if ((dVar6 < dVar5) && (dVar6 < dVar7)) {
        iVar3 = *piVar1;
        dVar7 = dVar6;
      }
      piVar1 = piVar1 + 1;
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  return iVar3;
}

