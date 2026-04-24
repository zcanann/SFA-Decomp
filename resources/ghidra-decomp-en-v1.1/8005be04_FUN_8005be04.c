// Function: FUN_8005be04
// Entry: 8005be04
// Size: 1260 bytes

/* WARNING: Removing unreachable block (ram,0x8005c2d0) */
/* WARNING: Removing unreachable block (ram,0x8005c2c8) */
/* WARNING: Removing unreachable block (ram,0x8005c2c0) */
/* WARNING: Removing unreachable block (ram,0x8005be24) */
/* WARNING: Removing unreachable block (ram,0x8005be1c) */
/* WARNING: Removing unreachable block (ram,0x8005be14) */

void FUN_8005be04(void)

{
  char *extraout_r4;
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
  double in_f29;
  double dVar14;
  double in_f30;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
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
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  FUN_80286818();
  iVar7 = 4;
  piVar12 = &DAT_80382f24;
  puVar11 = &DAT_80382efc;
  dVar15 = (double)FLOAT_803df834;
  dVar16 = DOUBLE_803df840;
  do {
    iVar5 = *piVar12;
    DAT_803ddb08 = *puVar11;
    FUN_80057ea0(DAT_803dda50 + 7,DAT_803dda54 + 7,&local_190,&local_1a0,&local_1b0,&local_1c0,iVar7
                 ,1,DAT_803ddb40);
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
            builtin_strncpy(pcVar1 + 7,"\x01\x01\x01\x01\x01\x01\x01\x01",8);
            pcVar1 = pcVar1 + 8;
            uVar9 = uVar9 - 1;
          } while (uVar9 != 0);
          uVar10 = uVar10 & 7;
          if (uVar10 == 0) goto LAB_8005bfc4;
        }
        do {
          pcVar1[7] = '\x01';
          pcVar1 = pcVar1 + 1;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
LAB_8005bfc4:
    }
    for (; iVar8 = local_1a8, iVar13 <= local_194; iVar13 = iVar13 + 1) {
      pcVar1 = local_180 + (iVar13 + 7) * 0x10 + local_1a0;
      uVar10 = (local_19c + 1) - local_1a0;
      if (local_1a0 <= local_19c) {
        uVar9 = uVar10 >> 3;
        if (uVar9 != 0) {
          do {
            builtin_strncpy(pcVar1 + 7,"\x01\x01\x01\x01\x01\x01\x01\x01",8);
            pcVar1 = pcVar1 + 8;
            uVar9 = uVar9 - 1;
          } while (uVar9 != 0);
          uVar10 = uVar10 & 7;
          if (uVar10 == 0) goto LAB_8005c058;
        }
        do {
          pcVar1[7] = '\x01';
          pcVar1 = pcVar1 + 1;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
LAB_8005c058:
    }
    for (; iVar13 = local_1b8, iVar8 <= local_1a4; iVar8 = iVar8 + 1) {
      pcVar1 = local_180 + (iVar8 + 7) * 0x10 + local_1b0;
      uVar10 = (local_1ac + 1) - local_1b0;
      if (local_1b0 <= local_1ac) {
        uVar9 = uVar10 >> 3;
        if (uVar9 != 0) {
          do {
            builtin_strncpy(pcVar1 + 7,"\x01\x01\x01\x01\x01\x01\x01\x01",8);
            pcVar1 = pcVar1 + 8;
            uVar9 = uVar9 - 1;
          } while (uVar9 != 0);
          uVar10 = uVar10 & 7;
          if (uVar10 == 0) goto LAB_8005c0ec;
        }
        do {
          pcVar1[7] = '\x01';
          pcVar1 = pcVar1 + 1;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
LAB_8005c0ec:
    }
    for (; iVar13 <= local_1b4; iVar13 = iVar13 + 1) {
      pcVar1 = local_180 + (iVar13 + 7) * 0x10 + local_1c0;
      uVar10 = (local_1bc + 1) - local_1c0;
      if (local_1c0 <= local_1bc) {
        uVar9 = uVar10 >> 3;
        if (uVar9 != 0) {
          do {
            builtin_strncpy(pcVar1 + 7,"\x01\x01\x01\x01\x01\x01\x01\x01",8);
            pcVar1 = pcVar1 + 8;
            uVar9 = uVar9 - 1;
          } while (uVar9 != 0);
          uVar10 = uVar10 & 7;
          if (uVar10 == 0) goto LAB_8005c180;
        }
        do {
          pcVar1[7] = '\x01';
          pcVar1 = pcVar1 + 1;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
LAB_8005c180:
    }
    iVar13 = 0;
    pcVar1 = extraout_r4;
    do {
      uVar10 = (uint)*pcVar1;
      iVar8 = 0;
      uStack_7c = uVar10 ^ 0x80000000;
      local_80 = 0x43300000;
      dVar14 = (double)(float)(dVar15 * (double)(float)((double)CONCAT44(0x43300000,
                                                                         uVar10 ^ 0x80000000) -
                                                       dVar16));
      pcVar4 = extraout_r4;
      do {
        uVar9 = (uint)*pcVar4;
        iVar3 = uVar10 + uVar9 * 0x10;
        iVar2 = (int)*(char *)(iVar5 + iVar3);
        if (iVar2 < 0) {
          iVar6 = 0;
LAB_8005c210:
          if ((-1 < iVar2) && (iVar2 = FUN_8005a8a4(uVar10,uVar9,iVar6), iVar2 != 0)) {
            FLOAT_803ddad8 = (float)dVar14;
            uStack_7c = uVar9 ^ 0x80000000;
            local_80 = 0x43300000;
            FLOAT_803ddad4 =
                 FLOAT_803df834 * (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803df840);
            uStack_74 = (int)*(short *)(iVar6 + 0x8e) ^ 0x80000000;
            local_78 = 0x43300000;
            FUN_80247a48(dVar14,(double)(float)((double)CONCAT44(0x43300000,uStack_74) -
                                               DOUBLE_803df840),(double)FLOAT_803ddad4,
                         (undefined4 *)(iVar6 + 0xc));
            FUN_8005fd40();
          }
        }
        else {
          iVar6 = *(int *)(DAT_803ddb1c + iVar2 * 4);
          *(ushort *)(iVar6 + 4) = *(ushort *)(iVar6 + 4) ^ 1;
          if (local_180[iVar3] != '\0') goto LAB_8005c210;
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
      FUN_80286864();
      return;
    }
  } while( true );
}

