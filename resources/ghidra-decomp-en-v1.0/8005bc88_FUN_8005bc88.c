// Function: FUN_8005bc88
// Entry: 8005bc88
// Size: 1260 bytes

/* WARNING: Removing unreachable block (ram,0x8005c14c) */
/* WARNING: Removing unreachable block (ram,0x8005c144) */
/* WARNING: Removing unreachable block (ram,0x8005c154) */

void FUN_8005bc88(void)

{
  char *pcVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  undefined4 *puVar11;
  int *piVar12;
  int iVar13;
  undefined4 uVar14;
  undefined8 in_f29;
  double dVar15;
  undefined8 in_f30;
  double dVar16;
  undefined8 in_f31;
  double dVar17;
  undefined8 uVar18;
  int local_1c0;
  int local_1bc;
  int local_1b8;
  int local_1b4;
  int local_1b0;
  int local_1ac;
  int local_1a8;
  int local_1a4;
  int local_1a0;
  int local_19c;
  int local_198;
  int local_194;
  int local_190;
  int local_18c;
  int local_188;
  int local_184;
  char local_180 [256];
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar14 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar18 = FUN_802860b4();
  iVar7 = 4;
  piVar12 = &DAT_803822c4;
  puVar11 = &DAT_8038229c;
  dVar16 = (double)FLOAT_803debb4;
  dVar17 = DOUBLE_803debc0;
  do {
    iVar5 = *piVar12;
    DAT_803dce88 = *puVar11;
    FUN_80057d24(DAT_803dcdd0 + 7,DAT_803dcdd4 + 7,&local_190,&local_1a0,&local_1b0,&local_1c0,iVar7
                 ,1,DAT_803dcec0);
    pcVar1 = local_180;
    iVar13 = 8;
    do {
      *pcVar1 = '\0';
      pcVar1[1] = '\0';
      pcVar1[2] = '\0';
      pcVar1[3] = '\0';
      pcVar1[4] = '\0';
      pcVar1[5] = '\0';
      pcVar1[6] = '\0';
      pcVar1[7] = '\0';
      pcVar1[8] = '\0';
      pcVar1[9] = '\0';
      pcVar1[10] = '\0';
      pcVar1[0xb] = '\0';
      pcVar1[0xc] = '\0';
      pcVar1[0xd] = '\0';
      pcVar1[0xe] = '\0';
      pcVar1[0xf] = '\0';
      pcVar1[0x10] = '\0';
      pcVar1[0x11] = '\0';
      pcVar1[0x12] = '\0';
      pcVar1[0x13] = '\0';
      pcVar1[0x14] = '\0';
      pcVar1[0x15] = '\0';
      pcVar1[0x16] = '\0';
      pcVar1[0x17] = '\0';
      pcVar1[0x18] = '\0';
      pcVar1[0x19] = '\0';
      pcVar1[0x1a] = '\0';
      pcVar1[0x1b] = '\0';
      pcVar1[0x1c] = '\0';
      pcVar1[0x1d] = '\0';
      pcVar1[0x1e] = '\0';
      pcVar1[0x1f] = '\0';
      pcVar1 = pcVar1 + 0x20;
      iVar13 = iVar13 + -1;
      iVar8 = local_188;
    } while (iVar13 != 0);
    for (; iVar13 = local_198, iVar8 <= local_184; iVar8 = iVar8 + 1) {
      pcVar1 = local_180 + (iVar8 + 7) * 0x10 + local_190;
      uVar10 = (local_18c + 1) - local_190;
      if (local_190 <= local_18c) {
        uVar9 = uVar10 >> 3;
        if (uVar9 != 0) {
          do {
            pcVar1[7] = '\x01';
            pcVar1[8] = '\x01';
            pcVar1[9] = '\x01';
            pcVar1[10] = '\x01';
            pcVar1[0xb] = '\x01';
            pcVar1[0xc] = '\x01';
            pcVar1[0xd] = '\x01';
            pcVar1[0xe] = '\x01';
            pcVar1 = pcVar1 + 8;
            uVar9 = uVar9 - 1;
          } while (uVar9 != 0);
          uVar10 = uVar10 & 7;
          if (uVar10 == 0) goto LAB_8005be48;
        }
        do {
          pcVar1[7] = '\x01';
          pcVar1 = pcVar1 + 1;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
LAB_8005be48:
    }
    for (; iVar8 = local_1a8, iVar13 <= local_194; iVar13 = iVar13 + 1) {
      pcVar1 = local_180 + (iVar13 + 7) * 0x10 + local_1a0;
      uVar10 = (local_19c + 1) - local_1a0;
      if (local_1a0 <= local_19c) {
        uVar9 = uVar10 >> 3;
        if (uVar9 != 0) {
          do {
            pcVar1[7] = '\x01';
            pcVar1[8] = '\x01';
            pcVar1[9] = '\x01';
            pcVar1[10] = '\x01';
            pcVar1[0xb] = '\x01';
            pcVar1[0xc] = '\x01';
            pcVar1[0xd] = '\x01';
            pcVar1[0xe] = '\x01';
            pcVar1 = pcVar1 + 8;
            uVar9 = uVar9 - 1;
          } while (uVar9 != 0);
          uVar10 = uVar10 & 7;
          if (uVar10 == 0) goto LAB_8005bedc;
        }
        do {
          pcVar1[7] = '\x01';
          pcVar1 = pcVar1 + 1;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
LAB_8005bedc:
    }
    for (; iVar13 = local_1b8, iVar8 <= local_1a4; iVar8 = iVar8 + 1) {
      pcVar1 = local_180 + (iVar8 + 7) * 0x10 + local_1b0;
      uVar10 = (local_1ac + 1) - local_1b0;
      if (local_1b0 <= local_1ac) {
        uVar9 = uVar10 >> 3;
        if (uVar9 != 0) {
          do {
            pcVar1[7] = '\x01';
            pcVar1[8] = '\x01';
            pcVar1[9] = '\x01';
            pcVar1[10] = '\x01';
            pcVar1[0xb] = '\x01';
            pcVar1[0xc] = '\x01';
            pcVar1[0xd] = '\x01';
            pcVar1[0xe] = '\x01';
            pcVar1 = pcVar1 + 8;
            uVar9 = uVar9 - 1;
          } while (uVar9 != 0);
          uVar10 = uVar10 & 7;
          if (uVar10 == 0) goto LAB_8005bf70;
        }
        do {
          pcVar1[7] = '\x01';
          pcVar1 = pcVar1 + 1;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
LAB_8005bf70:
    }
    for (; iVar13 <= local_1b4; iVar13 = iVar13 + 1) {
      pcVar1 = local_180 + (iVar13 + 7) * 0x10 + local_1c0;
      uVar10 = (local_1bc + 1) - local_1c0;
      if (local_1c0 <= local_1bc) {
        uVar9 = uVar10 >> 3;
        if (uVar9 != 0) {
          do {
            pcVar1[7] = '\x01';
            pcVar1[8] = '\x01';
            pcVar1[9] = '\x01';
            pcVar1[10] = '\x01';
            pcVar1[0xb] = '\x01';
            pcVar1[0xc] = '\x01';
            pcVar1[0xd] = '\x01';
            pcVar1[0xe] = '\x01';
            pcVar1 = pcVar1 + 8;
            uVar9 = uVar9 - 1;
          } while (uVar9 != 0);
          uVar10 = uVar10 & 7;
          if (uVar10 == 0) goto LAB_8005c004;
        }
        do {
          pcVar1[7] = '\x01';
          pcVar1 = pcVar1 + 1;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
LAB_8005c004:
    }
    iVar13 = 0;
    pcVar1 = (char *)uVar18;
    do {
      uVar10 = (uint)*pcVar1;
      iVar8 = 0;
      uStack124 = uVar10 ^ 0x80000000;
      local_80 = 0x43300000;
      dVar15 = (double)(float)(dVar16 * (double)(float)((double)CONCAT44(0x43300000,
                                                                         uVar10 ^ 0x80000000) -
                                                       dVar17));
      pcVar4 = (char *)uVar18;
      do {
        uVar9 = (uint)*pcVar4;
        iVar3 = uVar10 + uVar9 * 0x10;
        iVar2 = (int)*(char *)(iVar5 + iVar3);
        if (iVar2 < 0) {
          iVar6 = 0;
LAB_8005c094:
          if ((-1 < iVar2) && (iVar2 = FUN_8005a728(uVar10,uVar9,iVar6), iVar2 != 0)) {
            FLOAT_803dce58 = (float)dVar15;
            uStack124 = uVar9 ^ 0x80000000;
            local_80 = 0x43300000;
            FLOAT_803dce54 =
                 FLOAT_803debb4 * (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803debc0);
            uStack116 = (int)*(short *)(iVar6 + 0x8e) ^ 0x80000000;
            local_78 = 0x43300000;
            FUN_802472e4(dVar15,(double)(float)((double)CONCAT44(0x43300000,uStack116) -
                                               DOUBLE_803debc0),iVar6 + 0xc);
            FUN_8005fbc4(iVar6,(int)((ulonglong)uVar18 >> 0x20));
          }
        }
        else {
          iVar6 = *(int *)(DAT_803dce9c + iVar2 * 4);
          *(ushort *)(iVar6 + 4) = *(ushort *)(iVar6 + 4) ^ 1;
          if (local_180[iVar3] != '\0') goto LAB_8005c094;
        }
        iVar8 = iVar8 + 1;
        pcVar4 = pcVar4 + 1;
      } while (iVar8 < 0x10);
      iVar13 = iVar13 + 1;
      pcVar1 = pcVar1 + 1;
    } while (iVar13 < 0x10);
    piVar12 = piVar12 + -1;
    puVar11 = puVar11 + -1;
    iVar7 = iVar7 + -1;
    if (iVar7 < 0) {
      __psq_l0(auStack8,uVar14);
      __psq_l1(auStack8,uVar14);
      __psq_l0(auStack24,uVar14);
      __psq_l1(auStack24,uVar14);
      __psq_l0(auStack40,uVar14);
      __psq_l1(auStack40,uVar14);
      FUN_80286100();
      return;
    }
  } while( true );
}

