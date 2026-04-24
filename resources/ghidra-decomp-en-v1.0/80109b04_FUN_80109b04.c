// Function: FUN_80109b04
// Entry: 80109b04
// Size: 272 bytes

/* WARNING: Removing unreachable block (ram,0x80109bec) */
/* WARNING: Removing unreachable block (ram,0x80109bdc) */
/* WARNING: Removing unreachable block (ram,0x80109be4) */
/* WARNING: Removing unreachable block (ram,0x80109bf4) */

void FUN_80109b04(undefined8 param_1,double param_2,double param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  double extraout_f1;
  double dVar9;
  undefined8 in_f28;
  double dVar10;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar11;
  undefined8 uVar12;
  int local_68 [12];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar12 = FUN_802860d8();
  dVar11 = (double)FLOAT_803e1878;
  iVar6 = 0;
  dVar10 = extraout_f1;
  piVar4 = (int *)FUN_80036f50(7,local_68);
  for (iVar7 = 0; iVar7 < local_68[0]; iVar7 = iVar7 + 1) {
    iVar5 = *piVar4;
    if ((((int)*(short *)(iVar5 + 0x44) == (int)uVar12) &&
        ((uint)*(byte *)(*(int *)(iVar5 + 0x4c) + 0x18) == (uint)((ulonglong)uVar12 >> 0x20))) &&
       (fVar1 = (float)(dVar10 - (double)*(float *)(iVar5 + 0x18)),
       fVar2 = (float)(param_2 - (double)*(float *)(iVar5 + 0x1c)),
       fVar3 = (float)(param_3 - (double)*(float *)(iVar5 + 0x20)),
       dVar9 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2)),
       dVar9 < dVar11)) {
      iVar6 = iVar5;
      dVar11 = dVar9;
    }
    piVar4 = piVar4 + 1;
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  FUN_80286124(iVar6);
  return;
}

