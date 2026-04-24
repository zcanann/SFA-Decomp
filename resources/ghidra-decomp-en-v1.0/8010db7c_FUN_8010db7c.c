// Function: FUN_8010db7c
// Entry: 8010db7c
// Size: 424 bytes

/* WARNING: Removing unreachable block (ram,0x8010dcfc) */
/* WARNING: Removing unreachable block (ram,0x8010dcec) */
/* WARNING: Removing unreachable block (ram,0x8010dcf4) */
/* WARNING: Removing unreachable block (ram,0x8010dd04) */

void FUN_8010db7c(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)

{
  float fVar1;
  float *pfVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar7;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  double dVar10;
  undefined8 uVar11;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar11 = FUN_802860d8();
  pfVar2 = DAT_803dd584;
  iVar3 = (int)((ulonglong)uVar11 >> 0x20);
  dVar9 = (double)(*(float *)(iVar3 + 0x18) - *DAT_803dd584);
  dVar7 = (double)(*(float *)(iVar3 + 0x20) - DAT_803dd584[2]);
  dVar6 = (double)FUN_802931a0((double)(float)(dVar9 * dVar9 + (double)(float)(dVar7 * dVar7)));
  uVar4 = FUN_800217c0(dVar9,dVar7);
  dVar10 = (double)((float)(dVar9 * (double)DAT_803dd584[0x11]) + *pfVar2);
  dVar8 = (double)((float)(dVar7 * (double)DAT_803dd584[0x11]) + pfVar2[2]);
  dVar7 = (double)FUN_80293e80((double)((FLOAT_803e19d0 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (uVar4 & 0xffff) +
                                                                 (int)DAT_803dd584[6] ^ 0x80000000)
                                               - DOUBLE_803e19e0)) / FLOAT_803e19d4));
  dVar9 = (double)FUN_80294204((double)((FLOAT_803e19d0 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (uVar4 & 0xffff) +
                                                                 (int)DAT_803dd584[6] ^ 0x80000000)
                                               - DOUBLE_803e19e0)) / FLOAT_803e19d4));
  if (dVar6 < (double)DAT_803dd584[0x10]) {
    dVar6 = (double)DAT_803dd584[0x10];
  }
  fVar1 = DAT_803dd584[4];
  *(float *)uVar11 = (float)(dVar7 * (double)(float)(dVar6 + (double)fVar1) + dVar10);
  *param_3 = -(FLOAT_803e19d8 * ((FLOAT_803e19dc + *(float *)(iVar3 + 0x1c)) - pfVar2[1]) -
              (*(float *)(iVar3 + 0x1c) + DAT_803dd584[0xc]));
  *param_4 = (float)(dVar9 * (double)(float)(dVar6 + (double)fVar1) + dVar8);
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  __psq_l0(auStack40,uVar5);
  __psq_l1(auStack40,uVar5);
  __psq_l0(auStack56,uVar5);
  __psq_l1(auStack56,uVar5);
  FUN_80286124();
  return;
}

