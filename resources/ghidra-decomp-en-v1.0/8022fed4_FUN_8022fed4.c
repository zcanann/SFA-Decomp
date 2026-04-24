// Function: FUN_8022fed4
// Entry: 8022fed4
// Size: 2032 bytes

/* WARNING: Removing unreachable block (ram,0x8023069c) */
/* WARNING: Removing unreachable block (ram,0x8023068c) */
/* WARNING: Removing unreachable block (ram,0x8022ff50) */
/* WARNING: Removing unreachable block (ram,0x80230684) */
/* WARNING: Removing unreachable block (ram,0x80230694) */
/* WARNING: Removing unreachable block (ram,0x802306a4) */

void FUN_8022fed4(void)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  short *psVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  byte *pbVar8;
  undefined4 uVar9;
  double dVar10;
  undefined8 in_f27;
  double dVar11;
  undefined8 in_f28;
  double dVar12;
  undefined8 in_f29;
  double dVar13;
  undefined8 in_f30;
  double dVar14;
  undefined8 in_f31;
  double dVar15;
  int local_f8;
  int local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  undefined auStack228 [12];
  float local_d8;
  float local_d4;
  float local_d0;
  undefined auStack204 [52];
  double local_98;
  double local_90;
  longlong local_88;
  undefined4 local_80;
  uint uStack124;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
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
  psVar4 = (short *)FUN_802860d4();
  pbVar8 = *(byte **)(psVar4 + 0x5c);
  iVar5 = FUN_8022d768();
  iVar7 = *(int *)(psVar4 + 0x26);
  if (iVar5 == 0) {
    iVar5 = FUN_8002b9ec();
  }
  bVar1 = pbVar8[0x15];
  if (bVar1 == 2) {
    if (*(float *)(pbVar8 + 0x18) <= FLOAT_803e70a0) {
      *(float *)(pbVar8 + 0x18) = FLOAT_803e70c0;
    }
    else {
      if (iVar5 != 0) {
        *(float *)(psVar4 + 0x12) =
             FLOAT_803db418 * (*(float *)(iVar5 + 0xc) - *(float *)(psVar4 + 6));
        *(float *)(psVar4 + 0x14) =
             FLOAT_803db418 *
             (*(float *)(pbVar8 + 0x10) + (*(float *)(iVar5 + 0x10) - *(float *)(psVar4 + 8)));
        *(float *)(psVar4 + 0x16) =
             FLOAT_803db418 * (*(float *)(iVar5 + 0x14) - *(float *)(psVar4 + 10));
        FUN_8002b95c((double)(*(float *)(psVar4 + 0x12) * FLOAT_803db414),
                     (double)(*(float *)(psVar4 + 0x14) * FLOAT_803db414),
                     (double)(*(float *)(psVar4 + 0x16) * FLOAT_803db414),psVar4);
      }
      fVar2 = FLOAT_803e70bc;
      if (*(float *)(pbVar8 + 0x18) <= FLOAT_803e70bc) {
        if ((pbVar8[0x14] >> 6 & 1) != 0) {
          for (iVar5 = 0; iVar5 < *(int *)(&DAT_8032b72c + (uint)*pbVar8 * 0x18); iVar5 = iVar5 + 1)
          {
            (**(code **)(*DAT_803dca88 + 8))
                      (psVar4,*(undefined4 *)(&DAT_8032b724 + (uint)*pbVar8 * 0x18),0,2,0xffffffff,0
                      );
          }
        }
        pbVar8[0x14] = pbVar8[0x14] & 0xbf;
        *(undefined *)(psVar4 + 0x1b) = 0;
      }
      else {
        *psVar4 = *psVar4 + (short)*(undefined4 *)(&DAT_8032b730 + (uint)*pbVar8 * 0x18);
        *(float *)(psVar4 + 4) =
             ((*(float *)(pbVar8 + 0x18) - fVar2) / fVar2) * *(float *)(*(int *)(psVar4 + 0x28) + 4)
        ;
        if (FLOAT_803e70c0 != *(float *)(pbVar8 + 0x18)) {
          FUN_8002b47c(psVar4,auStack204,0);
          dVar12 = (double)FLOAT_803e70c8;
          dVar14 = (double)FLOAT_803e70cc;
          dVar15 = (double)FLOAT_803e70c4;
          dVar11 = (double)FLOAT_803e70a0;
          dVar13 = DOUBLE_803e70d0;
          for (iVar5 = -0x7fff; iVar5 < 0x7fff;
              iVar5 = iVar5 + *(int *)(&DAT_8032b728 + (uint)*pbVar8 * 0x18)) {
            local_90 = (double)(longlong)
                               (int)(*(float *)(pbVar8 + 0x18) *
                                    *(float *)(&DAT_8032b734 + (uint)*pbVar8 * 0x18));
            local_98 = (double)CONCAT44(0x43300000,
                                        iVar5 + (int)(*(float *)(pbVar8 + 0x18) *
                                                     *(float *)(&DAT_8032b734 + (uint)*pbVar8 * 0x18
                                                               )) ^ 0x80000000);
            dVar10 = (double)FUN_80294204((double)(float)((double)(float)(dVar12 * (double)(float)(
                                                  local_98 - dVar13)) / dVar14));
            local_f0 = (float)(dVar15 * dVar10);
            local_88 = (longlong)
                       (int)(*(float *)(pbVar8 + 0x18) *
                            *(float *)(&DAT_8032b734 + (uint)*pbVar8 * 0x18));
            uStack124 = iVar5 + (int)(*(float *)(pbVar8 + 0x18) *
                                     *(float *)(&DAT_8032b734 + (uint)*pbVar8 * 0x18)) ^ 0x80000000;
            local_80 = 0x43300000;
            dVar10 = (double)FUN_80293e80((double)(float)((double)(float)(dVar12 * (double)(float)((
                                                  double)CONCAT44(0x43300000,uStack124) - dVar13)) /
                                                  dVar14));
            local_ec = (float)(dVar15 * dVar10);
            local_e8 = (float)dVar11;
            FUN_80247574(auStack204,&local_f0,&local_f0);
            local_d8 = local_f0 + *(float *)(psVar4 + 6);
            local_d4 = local_ec + *(float *)(psVar4 + 8);
            local_d0 = local_e8 + *(float *)(psVar4 + 10);
            (**(code **)(*DAT_803dca88 + 8))
                      (psVar4,*(undefined4 *)(&DAT_8032b720 + (uint)*pbVar8 * 0x18),auStack228,
                       0x200001,0xffffffff,psVar4 + 0x12);
            (**(code **)(*DAT_803dca88 + 8))
                      (psVar4,*(undefined4 *)(&DAT_8032b720 + (uint)*pbVar8 * 0x18),auStack228,
                       0x200001,0xffffffff,psVar4 + 0x12);
            (**(code **)(*DAT_803dca88 + 8))
                      (psVar4,*(undefined4 *)(&DAT_8032b720 + (uint)*pbVar8 * 0x18),auStack228,
                       0x200001,0xffffffff,psVar4 + 0x12);
          }
        }
        pbVar8[0x14] = pbVar8[0x14] & 0xbf | 0x40;
      }
      *(float *)(pbVar8 + 0x18) = *(float *)(pbVar8 + 0x18) - FLOAT_803db414;
      fVar2 = FLOAT_803e70a0;
      if (*(float *)(pbVar8 + 0x18) <= FLOAT_803e70a0) {
        *(float *)(pbVar8 + 0x18) = FLOAT_803e70a0;
        *(undefined4 *)(psVar4 + 6) = *(undefined4 *)(iVar7 + 8);
        *(undefined4 *)(psVar4 + 8) = *(undefined4 *)(iVar7 + 0xc);
        *(undefined4 *)(psVar4 + 10) = *(undefined4 *)(iVar7 + 0x10);
        *psVar4 = 0;
        *(undefined *)(psVar4 + 0x1b) = 0xff;
        *(undefined4 *)(psVar4 + 4) = *(undefined4 *)(*(int *)(psVar4 + 0x28) + 4);
        *(float *)(psVar4 + 0x12) = fVar2;
        *(float *)(psVar4 + 0x14) = fVar2;
        *(float *)(psVar4 + 0x16) = fVar2;
        pbVar8[0x15] = 3;
        psVar4[3] = psVar4[3] | 0x4000;
      }
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      local_98 = (double)CONCAT44(0x43300000,(uint)*(byte *)(psVar4 + 0x1b));
      iVar5 = (int)-(FLOAT_803e70b4 * FLOAT_803db414 - (float)(local_98 - DOUBLE_803e7098));
      local_90 = (double)(longlong)iVar5;
      if (iVar5 < 0) {
        iVar5 = 0;
        psVar4[3] = psVar4[3] | 0x4000;
      }
      *(char *)(psVar4 + 0x1b) = (char)iVar5;
      if (*(short *)(iVar7 + 0x20) < 0) {
        iVar5 = FUN_8022d768();
        if (iVar5 != 0) {
          psVar4[3] = psVar4[3] & 0xbfff;
          pbVar8[0x15] = 1;
        }
      }
      else {
        iVar5 = FUN_8001ffb4();
        if (iVar5 != 0) {
          psVar4[3] = psVar4[3] & 0xbfff;
          pbVar8[0x15] = 1;
        }
      }
      goto LAB_80230684;
    }
    local_90 = (double)CONCAT44(0x43300000,(uint)*(byte *)(psVar4 + 0x1b));
    iVar3 = (int)(FLOAT_803e70b4 * FLOAT_803db414 + (float)(local_90 - DOUBLE_803e7098));
    local_98 = (double)(longlong)iVar3;
    if (0xff < iVar3) {
      iVar3 = 0xff;
    }
    *(char *)(psVar4 + 0x1b) = (char)iVar3;
    if ((-1 < *(short *)(iVar7 + 0x20)) && (iVar7 = FUN_8001ffb4(), iVar7 == 0)) {
      pbVar8[0x15] = 1;
    }
    bVar1 = pbVar8[1];
    if (bVar1 == 3) {
LAB_802300a8:
      iVar7 = FUN_8003687c(psVar4,&local_f4,0,0);
      if (((iVar7 != 0) && (local_f4 != 0)) &&
         ((*(short *)(local_f4 + 0x46) == 0x604 || (*(short *)(local_f4 + 0x46) == 0x605)))) {
        uVar6 = FUN_8022d768();
        FUN_8022d520(uVar6,0xf);
        *(undefined4 *)(psVar4 + 4) = *(undefined4 *)(*(int *)(psVar4 + 0x28) + 4);
        FUN_8002b884(psVar4,0);
        FUN_80035f00(psVar4);
        pbVar8[0x14] = pbVar8[0x14] & 0x7f | 0x80;
        if (*(int *)(pbVar8 + 0x20) != 0) {
          FUN_8001f384();
          *(undefined4 *)(pbVar8 + 0x20) = 0;
        }
      }
      FUN_8022fa00(psVar4,pbVar8);
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
LAB_802301dc:
        FUN_8022fa00(psVar4,pbVar8);
      }
      else if ((((bVar1 != 0) && (iVar7 = FUN_8003687c(psVar4,&local_f8,0,0), iVar7 != 0)) &&
               (local_f8 != 0)) &&
              ((*(short *)(local_f8 + 0x46) == 0x604 || (*(short *)(local_f8 + 0x46) == 0x605)))) {
        uVar6 = FUN_8022d768();
        FUN_8022d520(uVar6,0xf);
        *(undefined4 *)(psVar4 + 4) = *(undefined4 *)(*(int *)(psVar4 + 0x28) + 4);
        FUN_8002b884(psVar4,0);
        FUN_80035f00(psVar4);
        pbVar8[0x14] = pbVar8[0x14] & 0x7f | 0x80;
        if (*(int *)(pbVar8 + 0x20) != 0) {
          FUN_8001f384();
          *(undefined4 *)(pbVar8 + 0x20) = 0;
        }
      }
    }
    else {
      if (bVar1 == 5) goto LAB_802300a8;
      if (bVar1 < 5) goto LAB_802301dc;
    }
    if ((((char)pbVar8[0x14] < '\0') && (iVar7 = FUN_8022d750(iVar5), iVar7 == 0)) &&
       ((iVar7 = FUN_8022d710(iVar5), iVar7 == 0 &&
        (iVar7 = FUN_8022fcd8(psVar4,pbVar8,iVar5), iVar7 != 0)))) {
      FUN_8022fb5c(psVar4,pbVar8,iVar5);
    }
    local_90 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
    iVar5 = (int)(FLOAT_803e70b8 * FLOAT_803db414 + (float)(local_90 - DOUBLE_803e70d0));
    local_98 = (double)(longlong)iVar5;
    *psVar4 = (short)iVar5;
  }
  if ((*(int *)(pbVar8 + 0x20) != 0) && (iVar5 = FUN_8001db64(), iVar5 != 0)) {
    FUN_8001d6b0(*(undefined4 *)(pbVar8 + 0x20));
  }
LAB_80230684:
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  __psq_l0(auStack40,uVar9);
  __psq_l1(auStack40,uVar9);
  __psq_l0(auStack56,uVar9);
  __psq_l1(auStack56,uVar9);
  __psq_l0(auStack72,uVar9);
  __psq_l1(auStack72,uVar9);
  FUN_80286120();
  return;
}

