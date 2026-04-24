// Function: FUN_8018c830
// Entry: 8018c830
// Size: 1116 bytes

/* WARNING: Removing unreachable block (ram,0x8018cc64) */
/* WARNING: Removing unreachable block (ram,0x8018cc54) */
/* WARNING: Removing unreachable block (ram,0x8018cc5c) */
/* WARNING: Removing unreachable block (ram,0x8018cc6c) */

void FUN_8018c830(void)

{
  bool bVar1;
  short *psVar2;
  undefined2 *puVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  float *pfVar7;
  undefined4 uVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar13;
  undefined8 in_f31;
  double dVar14;
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
  psVar2 = (short *)FUN_802860dc();
  puVar3 = (undefined2 *)FUN_8000faac();
  pfVar7 = *(float **)(psVar2 + 0x5c);
  iVar4 = FUN_8002b9ec();
  bVar1 = false;
  iVar5 = FUN_80296c5c();
  if (iVar5 == 0) {
    pfVar7[5] = FLOAT_803e3d2c;
    iVar4 = (**(code **)(*DAT_803dca4c + 0x14))();
    bVar1 = iVar4 != 0;
    if (bVar1) {
      FUN_8002fa48((double)FLOAT_803e3d20,(double)FLOAT_803db414,psVar2,0);
    }
    if (FLOAT_803e3d24 < *(float *)(psVar2 + 0x4c)) {
      puVar6 = (undefined4 *)FUN_800394ac(psVar2,5,0);
      *puVar6 = 0x200;
      puVar6 = (undefined4 *)FUN_800394ac(psVar2,4,0);
      *puVar6 = 0x200;
    }
    *pfVar7 = *pfVar7 - FLOAT_803db414;
    if ((*pfVar7 <= FLOAT_803e3d1c) && (*pfVar7 = FLOAT_803e3d1c, -1 < *(char *)(pfVar7 + 8))) {
      FUN_8011dd88();
      *(byte *)(pfVar7 + 8) = *(byte *)(pfVar7 + 8) & 0x7f | 0x80;
    }
  }
  else {
    pfVar7[5] = FLOAT_803e3d18;
    if (psVar2[0x50] != 0x92) {
      FUN_8000d01c();
      FUN_8000d200(0x51e1,FUN_8000d138);
      FUN_80030334((double)FLOAT_803e3d1c,psVar2,0x92,0);
    }
    FUN_8002fa48((double)FLOAT_803e3d20,(double)FLOAT_803db414,psVar2,0);
    if (FLOAT_803e3d24 < *(float *)(psVar2 + 0x4c)) {
      puVar6 = (undefined4 *)FUN_800394ac(psVar2,5,0);
      *puVar6 = 0;
      puVar6 = (undefined4 *)FUN_800394ac(psVar2,4,0);
      *puVar6 = 0;
    }
    if (*(float *)(psVar2 + 0x4c) < FLOAT_803e3d28) {
      bVar1 = true;
    }
    else {
      if ((*(byte *)(pfVar7 + 8) >> 5 & 1) == 0) {
        FUN_800d7a70(0);
        (**(code **)(*DAT_803dca4c + 0xc))(10,1);
        *(byte *)(pfVar7 + 8) = *(byte *)(pfVar7 + 8) & 0xdf | 0x20;
      }
      iVar5 = (**(code **)(*DAT_803dca4c + 0x14))();
      if (iVar5 != 0) {
        if (iVar4 != 0) {
          FUN_80296c6c(iVar4,0);
        }
        FUN_800206e8(0);
        FUN_8005cf68(0);
        FUN_8002cbc4(psVar2);
      }
    }
  }
  if (bVar1) {
    dVar9 = (double)FUN_80293e80((double)FLOAT_803e3d30);
    dVar10 = (double)FUN_80294204((double)FLOAT_803e3d30);
    dVar11 = (double)FUN_80294204((double)FLOAT_803e3d34);
    dVar12 = (double)FUN_80293e80((double)FLOAT_803e3d34);
    dVar13 = (double)(float)((double)pfVar7[4] * dVar12);
    dVar11 = (double)(float)((double)pfVar7[4] * dVar11);
    dVar14 = (double)(float)(dVar11 * dVar10);
    dVar12 = (double)(float)(dVar11 * dVar9);
    *puVar3 = 0x2000;
    puVar3[1] = 0x1000;
    dVar9 = (double)FUN_80293e80((double)((FLOAT_803e3d3c *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*psVar2 ^ 0x80000000) -
                                                 DOUBLE_803e3d50)) / FLOAT_803e3d40));
    dVar11 = (double)(float)((double)FLOAT_803e3d38 * -dVar9);
    dVar9 = (double)FUN_80294204((double)((FLOAT_803e3d3c *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*psVar2 ^ 0x80000000) -
                                                 DOUBLE_803e3d50)) / FLOAT_803e3d40));
    dVar10 = (double)FLOAT_803e3d38;
    *(float *)(puVar3 + 6) =
         (float)(dVar14 + (double)(float)((double)*(float *)(psVar2 + 0xc) + dVar11));
    *(float *)(puVar3 + 8) =
         (float)((double)(float)(dVar10 + (double)*(float *)(psVar2 + 0xe)) + dVar13);
    *(float *)(puVar3 + 10) =
         (float)(dVar12 + (double)(*(float *)(psVar2 + 0x10) + (float)(dVar10 * -dVar9)));
    FUN_8000fc3c((double)FLOAT_803e3d44);
    *(byte *)(pfVar7 + 8) = *(byte *)(pfVar7 + 8) & 0xbf | 0x40;
    dVar9 = (double)FUN_80021370((double)(pfVar7[5] - pfVar7[4]),(double)FLOAT_803e3d48,
                                 (double)FLOAT_803db414);
    pfVar7[4] = (float)((double)pfVar7[4] + dVar9);
    FUN_800550a4(0);
  }
  else {
    *puVar3 = SUB42(pfVar7[6],0);
    puVar3[1] = SUB42(pfVar7[7],0);
    *(float *)(puVar3 + 6) = pfVar7[1];
    *(float *)(puVar3 + 8) = pfVar7[2];
    *(float *)(puVar3 + 10) = pfVar7[3];
    *(byte *)(pfVar7 + 8) = *(byte *)(pfVar7 + 8) & 0xbf;
  }
  if ((*(byte *)(pfVar7 + 8) >> 6 & 1) == 0) {
    psVar2[3] = psVar2[3] | 0x4000;
  }
  else {
    psVar2[3] = psVar2[3] & 0xbfff;
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  FUN_80286128();
  return;
}

