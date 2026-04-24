// Function: FUN_8010dd58
// Entry: 8010dd58
// Size: 664 bytes

/* WARNING: Removing unreachable block (ram,0x8010dfc4) */
/* WARNING: Removing unreachable block (ram,0x8010dfb4) */
/* WARNING: Removing unreachable block (ram,0x8010dfbc) */
/* WARNING: Removing unreachable block (ram,0x8010dfcc) */

void FUN_8010dd58(short *param_1)

{
  float *pfVar1;
  short sVar2;
  int iVar3;
  undefined4 uVar4;
  undefined8 uVar5;
  undefined8 in_f28;
  double dVar6;
  undefined8 in_f29;
  double dVar7;
  undefined8 in_f30;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  pfVar1 = DAT_803dd584;
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  iVar3 = *(int *)(param_1 + 0x52);
  if (iVar3 != 0) {
    if (DAT_803dd584[7] == 8.407791e-45) {
      DAT_803dd584[6] =
           (float)(int)((float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)((int)DAT_803dd584 + 0x22) ^
                                                 0x80000000) - DOUBLE_803e19e0) * FLOAT_803db414 +
                       (float)((double)CONCAT44(0x43300000,(uint)DAT_803dd584[6] ^ 0x80000000) -
                              DOUBLE_803e19e0));
      if ((*(short *)((int)DAT_803dd584 + 0x22) < 1) || ((int)DAT_803dd584[6] < 0xd6d9)) {
        if ((*(short *)((int)DAT_803dd584 + 0x22) < 0) && ((int)DAT_803dd584[6] < -55000)) {
          DAT_803dd584[6] = -NAN;
        }
      }
      else {
        DAT_803dd584[6] = 7.707142e-41;
      }
      FUN_8010db7c(iVar3,DAT_803dd584 + 9,DAT_803dd584 + 10,DAT_803dd584 + 0xb);
    }
    *(float *)(param_1 + 0xc) = DAT_803dd584[9];
    *(float *)(param_1 + 0xe) = DAT_803dd584[10];
    *(float *)(param_1 + 0x10) = DAT_803dd584[0xb];
    dVar7 = (double)((*(float *)(iVar3 + 0x18) - *pfVar1) * DAT_803dd584[0x12]);
    dVar8 = (double)(((*(float *)(iVar3 + 0x1c) + DAT_803dd584[0xe]) - pfVar1[1]) *
                    DAT_803dd584[0xf]);
    dVar6 = (double)((*(float *)(iVar3 + 0x20) - pfVar1[2]) * DAT_803dd584[0x12]);
    if (DAT_803dd584[7] == 4.203895e-45) {
      uVar5 = FUN_802931a0((double)(float)(dVar7 * dVar7 + (double)(float)(dVar6 * dVar6)));
      sVar2 = FUN_800217c0((double)(float)((double)FLOAT_803db9c4 * dVar8),uVar5);
      param_1[1] = sVar2;
    }
    dVar9 = (double)(*(float *)(param_1 + 0xc) - (float)(dVar7 + (double)*pfVar1));
    dVar7 = (double)(*(float *)(param_1 + 0xe) - (float)(dVar8 + (double)pfVar1[1]));
    dVar6 = (double)(*(float *)(param_1 + 0x10) - (float)(dVar6 + (double)pfVar1[2]));
    sVar2 = FUN_800217c0(dVar9,dVar6);
    *param_1 = -0x8000 - sVar2;
    if (DAT_803dd584[7] != 4.203895e-45) {
      uVar5 = FUN_802931a0((double)(float)(dVar9 * dVar9 + (double)(float)(dVar6 * dVar6)));
      sVar2 = FUN_800217c0(dVar7,uVar5);
      param_1[1] = sVar2;
    }
    FUN_8005507c((double)*pfVar1,(double)pfVar1[1],(double)pfVar1[2],1,0);
    FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
                 *(undefined4 *)(param_1 + 0x18));
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  __psq_l0(auStack56,uVar4);
  __psq_l1(auStack56,uVar4);
  return;
}

