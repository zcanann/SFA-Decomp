// Function: FUN_802aa4b0
// Entry: 802aa4b0
// Size: 1056 bytes

/* WARNING: Removing unreachable block (ram,0x802aa8a8) */
/* WARNING: Removing unreachable block (ram,0x802aa8b0) */

void FUN_802aa4b0(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  short *psVar4;
  char cVar10;
  int iVar5;
  undefined uVar11;
  short *psVar6;
  float *pfVar7;
  uint uVar8;
  undefined4 uVar9;
  int iVar12;
  int iVar13;
  int iVar14;
  undefined4 uVar15;
  undefined8 in_f30;
  double dVar16;
  double dVar17;
  undefined8 in_f31;
  double dVar18;
  undefined8 uVar19;
  float local_c8;
  float local_c4;
  float local_c0;
  short local_bc;
  undefined2 local_ba;
  undefined2 local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  undefined auStack164 [68];
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar19 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar19 >> 0x20);
  iVar12 = (int)uVar19;
  iVar14 = 0;
  iVar13 = *(int *)(iVar3 + 0xb8);
  psVar4 = (short *)FUN_8000faac();
  cVar10 = FUN_8002e04c();
  if (cVar10 != '\0') {
    FUN_8000bb18(iVar3,0x20a);
    iVar5 = FUN_8002bdf4(0x24,0x14b);
    *(undefined *)(iVar5 + 4) = 2;
    *(undefined *)(iVar5 + 5) = 1;
    *(undefined *)(iVar5 + 6) = 0xff;
    *(undefined *)(iVar5 + 7) = 0xff;
    if (*(int *)(iVar12 + 0x2d0) == 0) {
      *(undefined4 *)(iVar5 + 8) = *(undefined4 *)(psVar4 + 6);
      *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(psVar4 + 8);
      *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(psVar4 + 10);
    }
    else {
      FUN_8003842c(DAT_803de44c,0,iVar5 + 8,iVar5 + 0xc,iVar5 + 0x10,0);
    }
    uVar11 = (**(code **)(**(int **)(DAT_803de44c + 0x68) + 0x44))();
    *(undefined *)(iVar5 + 0x19) = uVar11;
    if (*(int *)(iVar12 + 0x2d0) == 0) {
      *(undefined2 *)(iVar5 + 0x1a) = 1;
    }
    psVar6 = (short *)FUN_8002df90(iVar5,5,0xffffffff,0xffffffff,0);
    if (psVar6 != (short *)0x0) {
      psVar6[3] = psVar6[3] | 0x2000;
      iVar12 = *(int *)(iVar12 + 0x2d0);
      if (iVar12 == 0) {
        uVar8 = FUN_8006fed4();
        *psVar6 = *psVar4;
        dVar16 = (double)FUN_8000fc34();
        dVar17 = (double)((FLOAT_803e7f94 * (float)(dVar16 * (double)FLOAT_803e80d4)) /
                         FLOAT_803e7f98);
        dVar16 = (double)FUN_80293e80(dVar17);
        dVar17 = (double)FUN_80294204(dVar17);
        dVar18 = (double)(FLOAT_803e7f5c * (float)(dVar16 / dVar17));
        dVar16 = (double)FUN_8000fc24();
        uStack92 = (int)(uVar8 & 0xffff) >> 1 ^ 0x80000000;
        local_60 = 0x43300000;
        local_58 = 0x43300000;
        dVar17 = (double)(float)(dVar18 * -(double)(float)((double)((*(float *)(iVar13 + 0x788) -
                                                                    (float)((double)CONCAT44(
                                                  0x43300000,uStack92) - DOUBLE_803e7ec0)) /
                                                  (float)((double)CONCAT44(0x43300000,uStack92) -
                                                         DOUBLE_803e7ec0)) * dVar16));
        uStack76 = (int)uVar8 >> 0x11 ^ 0x80000000;
        local_50 = 0x43300000;
        local_48 = 0x43300000;
        dVar18 = (double)(float)(dVar18 * (double)((*(float *)(iVar13 + 0x78c) -
                                                   (float)((double)CONCAT44(0x43300000,uStack76) -
                                                          DOUBLE_803e7ec0)) /
                                                  (float)((double)CONCAT44(0x43300000,uStack76) -
                                                         DOUBLE_803e7ec0)));
        uStack84 = uStack92;
        uStack68 = uStack76;
        dVar16 = (double)FUN_802931a0((double)(FLOAT_803e80ac +
                                              (float)(dVar17 * dVar17 +
                                                     (double)(float)(dVar18 * dVar18))));
        local_c8 = (float)(dVar17 / dVar16);
        local_c4 = (float)(dVar18 / dVar16);
        local_c0 = (float)((double)FLOAT_803e7f5c / dVar16);
        uVar9 = FUN_8000e814();
        FUN_80022650(uVar9,&local_c8,&local_c8);
        fVar1 = FLOAT_803e80dc;
        *(float *)(psVar6 + 0x12) = FLOAT_803e80dc * local_c8;
        *(float *)(psVar6 + 0x14) = fVar1 * local_c4;
        *(float *)(psVar6 + 0x16) = fVar1 * local_c0;
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
      }
      else {
        pfVar7 = (float *)(*(int *)(iVar12 + 0x74) + (uint)*(byte *)(iVar12 + 0xe4) * 0x18);
        fVar1 = *pfVar7 - *(float *)(DAT_803de44c + 0xc);
        dVar16 = (double)(pfVar7[1] - *(float *)(DAT_803de44c + 0x10));
        fVar2 = pfVar7[2] - *(float *)(DAT_803de44c + 0x14);
        local_b0 = FLOAT_803e7ea4;
        local_ac = FLOAT_803e7ea4;
        local_a8 = FLOAT_803e7ea4;
        local_b4 = FLOAT_803e7ee0;
        local_bc = *(short *)(iVar13 + 0x478);
        uVar19 = FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
        local_ba = FUN_800217c0(dVar16,uVar19);
        local_b8 = 0;
        if (*(short **)(iVar3 + 0x30) != (short *)0x0) {
          local_bc = local_bc + **(short **)(iVar3 + 0x30);
        }
        FUN_80021ee8(auStack164,&local_bc);
        FUN_800226cc((double)FLOAT_803e7ea4,(double)FLOAT_803e7ea4,(double)FLOAT_803e80dc,auStack164
                     ,psVar6 + 0x12,psVar6 + 0x14,psVar6 + 0x16);
        *(undefined4 *)(psVar6 + 0xc) = *(undefined4 *)(psVar6 + 6);
        *(undefined4 *)(psVar6 + 0xe) = *(undefined4 *)(psVar6 + 8);
        *(undefined4 *)(psVar6 + 0x10) = *(undefined4 *)(psVar6 + 10);
        *psVar6 = *(short *)(iVar13 + 0x478);
        psVar6[1] = psVar4[1] / 2;
        iVar14 = iVar12;
      }
      *(undefined4 *)(psVar6 + 0x7a) = 0x5f;
      *(int *)(psVar6 + 0x7c) = iVar14;
    }
  }
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  FUN_80286124();
  return;
}

