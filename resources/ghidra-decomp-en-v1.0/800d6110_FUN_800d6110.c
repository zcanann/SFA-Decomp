// Function: FUN_800d6110
// Entry: 800d6110
// Size: 888 bytes

/* WARNING: Removing unreachable block (ram,0x800d6460) */
/* WARNING: Removing unreachable block (ram,0x800d6450) */
/* WARNING: Removing unreachable block (ram,0x800d6440) */
/* WARNING: Removing unreachable block (ram,0x800d6438) */
/* WARNING: Removing unreachable block (ram,0x800d6448) */
/* WARNING: Removing unreachable block (ram,0x800d6458) */
/* WARNING: Removing unreachable block (ram,0x800d6468) */

void FUN_800d6110(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  short *psVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  short sVar5;
  short sVar6;
  int iVar7;
  char cVar8;
  short unaff_r25;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  double extraout_f1;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  undefined8 in_f25;
  double dVar17;
  undefined8 in_f26;
  undefined8 in_f27;
  double dVar18;
  undefined8 in_f28;
  double dVar19;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined8 uVar20;
  undefined auStack232 [4];
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_c8;
  float local_c4;
  float local_b8;
  float local_b4;
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
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
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  uVar20 = FUN_802860c4();
  psVar1 = (short *)((ulonglong)uVar20 >> 0x20);
  iVar7 = (int)uVar20;
  iVar9 = 0;
  dVar18 = (double)FLOAT_803e04e8;
  dVar19 = (double)FLOAT_803e0504;
  dVar17 = extraout_f1;
  do {
    if (*(int *)(iVar7 + 0x10) < 0) {
      uVar2 = 1;
      goto LAB_800d6438;
    }
    iVar3 = FUN_800d5530(*(int *)(iVar7 + 0x10),auStack232);
    if (iVar3 == 0) {
      uVar2 = 1;
      goto LAB_800d6438;
    }
    if (*(int *)(iVar3 + 0x20) < 0) {
      *(undefined4 *)(iVar7 + 0x10) = 0xffffffff;
      uVar2 = 1;
      goto LAB_800d6438;
    }
    iVar10 = 0;
    if ((-1 < *(int *)(iVar3 + 0x24)) && (*(char *)(iVar7 + 0x30) != '\0')) {
      iVar10 = 1;
    }
    iVar4 = FUN_800d55bc((double)FLOAT_803e04e8,(double)FLOAT_803e04e8,iVar3,iVar10,&local_b8,
                         &local_c8,&local_d8,param_3 + 2U & 0xff);
    if (iVar4 == 0) {
      uVar2 = 1;
      goto LAB_800d6438;
    }
    dVar12 = (double)FUN_802931a0((double)((local_d8 - local_d4) * (local_d8 - local_d4) +
                                          (local_b8 - local_b4) * (local_b8 - local_b4) +
                                          (local_c8 - local_c4) * (local_c8 - local_c4)));
    dVar12 = (double)(*(float *)(iVar7 + 8) + (float)(dVar17 / dVar12));
    cVar8 = '\0';
    if (dVar12 < dVar18) {
      cVar8 = -1;
      dVar12 = dVar18;
    }
    if (dVar19 < dVar12) {
      cVar8 = '\x01';
      dVar12 = dVar19;
    }
    dVar13 = (double)FUN_80010dc0(dVar12,&local_b8,&local_dc);
    dVar14 = (double)FUN_80010dc0(dVar12,&local_c8,&local_e0);
    dVar15 = (double)FUN_80010dc0(dVar12,&local_d8,&local_e4);
    sVar5 = FUN_800217c0((double)local_dc,(double)local_e4);
    if ((param_4 & 0xff) == 0) {
      dVar16 = (double)FUN_802931a0((double)((float)(dVar13 - (double)*(float *)(psVar1 + 6)) *
                                             (float)(dVar13 - (double)*(float *)(psVar1 + 6)) +
                                            (float)(dVar15 - (double)*(float *)(psVar1 + 10)) *
                                            (float)(dVar15 - (double)*(float *)(psVar1 + 10))));
    }
    else {
      uVar20 = FUN_802931a0((double)(local_dc * local_dc + local_e4 * local_e4));
      sVar6 = FUN_800217c0(uVar20,(double)local_e0);
      unaff_r25 = sVar6 + -0x4000;
      dVar16 = (double)FUN_802931a0((double)((float)(dVar13 - (double)*(float *)(psVar1 + 6)) *
                                             (float)(dVar13 - (double)*(float *)(psVar1 + 6)) +
                                            (float)(dVar15 - (double)*(float *)(psVar1 + 10)) *
                                            (float)(dVar15 - (double)*(float *)(psVar1 + 10))));
    }
    if (dVar17 < dVar18) {
      dVar16 = -dVar16;
    }
    if ((cVar8 != -1) || (dVar17 <= dVar16)) {
      if ((cVar8 != '\x01') || (dVar17 <= dVar16)) {
        *(float *)(iVar7 + 8) = (float)dVar12;
      }
      else {
        *(undefined4 *)(iVar7 + 0x10) = *(undefined4 *)(iVar3 + iVar10 * 4 + 0x20);
        *(float *)(iVar7 + 8) = FLOAT_803e04e8;
        if ((iVar10 != 0) && (*(int *)(iVar7 + 0x10) < 0)) {
          *(undefined4 *)(iVar7 + 0x10) = *(undefined4 *)(iVar3 + 0x20);
        }
      }
    }
    else {
      *(undefined4 *)(iVar7 + 0x10) = *(undefined4 *)(iVar3 + iVar10 * 4 + 0x18);
      *(float *)(iVar7 + 8) = FLOAT_803e0508;
      if ((iVar10 != 0) && (*(int *)(iVar7 + 0x10) < 0)) {
        *(undefined4 *)(iVar7 + 0x10) = *(undefined4 *)(iVar3 + 0x18);
      }
    }
    dVar17 = (double)(float)(dVar17 - dVar16);
    *(float *)(psVar1 + 6) = (float)dVar13;
    if ((param_4 & 0xff) != 0) {
      *(float *)(psVar1 + 8) = (float)dVar14;
    }
    *(float *)(psVar1 + 10) = (float)dVar15;
    iVar9 = iVar9 + 1;
  } while (iVar9 < 3);
  *psVar1 = sVar5 + -0x8000;
  if ((param_4 & 0xff) != 0) {
    psVar1[1] = unaff_r25;
  }
  uVar2 = 0;
LAB_800d6438:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  __psq_l0(auStack40,uVar11);
  __psq_l1(auStack40,uVar11);
  __psq_l0(auStack56,uVar11);
  __psq_l1(auStack56,uVar11);
  __psq_l0(auStack72,uVar11);
  __psq_l1(auStack72,uVar11);
  __psq_l0(auStack88,uVar11);
  __psq_l1(auStack88,uVar11);
  __psq_l0(auStack104,uVar11);
  __psq_l1(auStack104,uVar11);
  FUN_80286110(uVar2);
  return;
}

