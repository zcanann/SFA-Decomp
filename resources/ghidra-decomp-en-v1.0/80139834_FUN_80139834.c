// Function: FUN_80139834
// Entry: 80139834
// Size: 252 bytes

/* WARNING: Removing unreachable block (ram,0x80139900) */
/* WARNING: Removing unreachable block (ram,0x801398f8) */
/* WARNING: Removing unreachable block (ram,0x80139908) */

undefined4 FUN_80139834(double param_1,int param_2,int param_3)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f29;
  double dVar6;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar2 = 0;
  fVar1 = FLOAT_803e244c * (float)(param_1 * (double)FLOAT_803db414);
  dVar7 = (double)(fVar1 * fVar1);
  dVar5 = (double)FUN_8002166c(param_3 + 0x68,param_2 + 0x18);
  fVar1 = FLOAT_803e23f8;
  if (*(int *)(param_3 + 0x80) != 0) {
    fVar1 = FLOAT_803e2448;
  }
  dVar6 = (double)fVar1;
  iVar3 = 0;
  dVar8 = (double)FLOAT_803e2424;
  do {
    if ((dVar8 < dVar5) && (dVar7 < dVar5)) goto LAB_801398f8;
    uVar2 = 1;
    FUN_800da928(dVar6,param_3);
    dVar5 = (double)FUN_8002166c(param_3 + 0x68,param_2 + 0x18);
    iVar3 = iVar3 + 1;
  } while (iVar3 < 5);
  uVar2 = 1;
LAB_801398f8:
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  return uVar2;
}

