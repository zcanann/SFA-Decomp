// Function: FUN_802aa014
// Entry: 802aa014
// Size: 668 bytes

/* WARNING: Removing unreachable block (ram,0x802aa288) */
/* WARNING: Removing unreachable block (ram,0x802aa290) */

void FUN_802aa014(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  short *psVar4;
  char cVar9;
  int iVar5;
  short *psVar6;
  uint uVar7;
  undefined4 uVar8;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f30;
  double dVar13;
  undefined8 in_f31;
  double dVar14;
  float local_68;
  float local_64;
  float local_60;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar3 = FUN_802860dc();
  iVar10 = *(int *)(iVar3 + 0xb8);
  psVar4 = (short *)FUN_8000faac();
  cVar9 = FUN_8002e04c();
  if (cVar9 != '\0') {
    iVar5 = FUN_8002bdf4(0x24,0x14b);
    *(undefined *)(iVar5 + 4) = 2;
    *(undefined *)(iVar5 + 5) = 1;
    *(undefined *)(iVar5 + 6) = 0xff;
    *(undefined *)(iVar5 + 7) = 0xff;
    *(undefined4 *)(iVar5 + 8) = *(undefined4 *)(psVar4 + 6);
    *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(psVar4 + 8);
    *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(psVar4 + 10);
    FUN_8000bb18(iVar3,0x20b);
    psVar6 = (short *)FUN_8002df90(iVar5,5,0xffffffff,0xffffffff,0);
    if (psVar6 != (short *)0x0) {
      psVar6[3] = psVar6[3] | 0x2000;
      uVar7 = FUN_8006fed4();
      *psVar6 = *psVar4;
      dVar12 = (double)FUN_8000fc34();
      dVar13 = (double)((FLOAT_803e7f94 * (float)(dVar12 * (double)FLOAT_803e80d4)) / FLOAT_803e7f98
                       );
      dVar12 = (double)FUN_80293e80(dVar13);
      dVar13 = (double)FUN_80294204(dVar13);
      dVar14 = (double)(FLOAT_803e7f5c * (float)(dVar12 / dVar13));
      dVar12 = (double)FUN_8000fc24();
      uStack84 = (int)(uVar7 & 0xffff) >> 1 ^ 0x80000000;
      local_58 = 0x43300000;
      local_50 = 0x43300000;
      dVar13 = (double)(float)(dVar14 * -(double)(float)((double)((*(float *)(iVar10 + 0x788) -
                                                                  (float)((double)CONCAT44(
                                                  0x43300000,uStack84) - DOUBLE_803e7ec0)) /
                                                  (float)((double)CONCAT44(0x43300000,uStack84) -
                                                         DOUBLE_803e7ec0)) * dVar12));
      uStack68 = (int)uVar7 >> 0x11 ^ 0x80000000;
      local_48 = 0x43300000;
      local_40 = 0x43300000;
      dVar14 = (double)(float)(dVar14 * (double)((*(float *)(iVar10 + 0x78c) -
                                                 (float)((double)CONCAT44(0x43300000,uStack68) -
                                                        DOUBLE_803e7ec0)) /
                                                (float)((double)CONCAT44(0x43300000,uStack68) -
                                                       DOUBLE_803e7ec0)));
      uStack76 = uStack84;
      uStack60 = uStack68;
      dVar12 = (double)FUN_802931a0((double)(FLOAT_803e80ac +
                                            (float)(dVar13 * dVar13 +
                                                   (double)(float)(dVar14 * dVar14))));
      local_68 = (float)(dVar13 / dVar12);
      local_64 = (float)(dVar14 / dVar12);
      local_60 = (float)((double)FLOAT_803e7f5c / dVar12);
      uVar8 = FUN_8000e814();
      FUN_80022650(uVar8,&local_68,&local_68);
      fVar1 = FLOAT_803e80d8;
      *(float *)(psVar6 + 0x12) = local_68 * FLOAT_803e80d8;
      *(float *)(psVar6 + 0x14) = local_64 * fVar1;
      *(float *)(psVar6 + 0x16) = local_60 * fVar1;
      fVar2 = FLOAT_803e7ed4;
      fVar1 = FLOAT_803e7ed4 * *(float *)(psVar6 + 0x12) + *(float *)(psVar4 + 6);
      *(float *)(psVar6 + 0xc) = fVar1;
      *(float *)(psVar6 + 6) = fVar1;
      fVar1 = fVar2 * *(float *)(psVar6 + 0x14) + *(float *)(psVar4 + 8);
      *(float *)(psVar6 + 0xe) = fVar1;
      *(float *)(psVar6 + 8) = fVar1;
      fVar1 = fVar2 * *(float *)(psVar6 + 0x16) + *(float *)(psVar4 + 10);
      *(float *)(psVar6 + 0x10) = fVar1;
      *(float *)(psVar6 + 10) = fVar1;
      psVar6[1] = psVar4[1] / 2;
      *psVar6 = -*psVar4;
      *(undefined4 *)(psVar6 + 0x7a) = 100;
    }
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  FUN_80286128();
  return;
}

