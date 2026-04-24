// Function: FUN_800e2214
// Entry: 800e2214
// Size: 372 bytes

/* WARNING: Removing unreachable block (ram,0x800e2358) */
/* WARNING: Removing unreachable block (ram,0x800e2348) */
/* WARNING: Removing unreachable block (ram,0x800e2340) */
/* WARNING: Removing unreachable block (ram,0x800e2350) */
/* WARNING: Removing unreachable block (ram,0x800e2360) */

int FUN_800e2214(double param_1,double param_2,double param_3,int param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  int local_78;
  undefined auStack116 [4];
  double local_70;
  undefined auStack72 [16];
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
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  piVar4 = (int *)FUN_8002e0fc(auStack116,&local_78);
  dVar10 = (double)FLOAT_803e0630;
  dVar11 = (double)FLOAT_803e0638;
  for (iVar7 = 0; iVar7 < local_78; iVar7 = iVar7 + 1) {
    iVar5 = *piVar4;
    if ((((*(short *)(iVar5 + 0x44) == 0x2c) && (*(char *)(iVar5 + 0xac) != param_4)) &&
        (iVar6 = *(int *)(iVar5 + 0x4c), iVar6 != 0)) &&
       ((*(char *)(iVar6 + 0x19) == '\x16' &&
        ((fVar1 = (float)((double)*(float *)(iVar5 + 0x18) - param_1),
         fVar2 = (float)((double)*(float *)(iVar5 + 0x1c) - param_2),
         fVar3 = (float)((double)*(float *)(iVar5 + 0x20) - param_3),
         dVar9 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2)),
         (double)FLOAT_803e0630 == dVar10 || (dVar9 < dVar11)))))) {
      local_70 = (double)CONCAT44(0x43300000,*(undefined4 *)(iVar6 + 0x14));
      dVar10 = (double)(float)(local_70 - DOUBLE_803e0628);
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
  __psq_l0(auStack72,uVar8);
  __psq_l1(auStack72,uVar8);
  return (int)dVar10;
}

