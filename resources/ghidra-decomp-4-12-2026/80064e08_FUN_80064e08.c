// Function: FUN_80064e08
// Entry: 80064e08
// Size: 2280 bytes

/* WARNING: Removing unreachable block (ram,0x800656d0) */
/* WARNING: Removing unreachable block (ram,0x800656c4) */
/* WARNING: Removing unreachable block (ram,0x800656b8) */
/* WARNING: Removing unreachable block (ram,0x800656ac) */
/* WARNING: Removing unreachable block (ram,0x800656a0) */
/* WARNING: Removing unreachable block (ram,0x80065694) */
/* WARNING: Removing unreachable block (ram,0x80065688) */
/* WARNING: Removing unreachable block (ram,0x80064e64) */
/* WARNING: Removing unreachable block (ram,0x80064e58) */
/* WARNING: Removing unreachable block (ram,0x80064e4c) */
/* WARNING: Removing unreachable block (ram,0x80064e40) */
/* WARNING: Removing unreachable block (ram,0x80064e34) */
/* WARNING: Removing unreachable block (ram,0x80064e28) */
/* WARNING: Removing unreachable block (ram,0x80064e1c) */

void FUN_80064e08(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  int in_r9;
  int in_r10;
  undefined *puVar7;
  ushort uVar8;
  ushort uVar9;
  uint uVar10;
  uint uVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  undefined *puVar16;
  char *pcVar17;
  int iVar18;
  double dVar19;
  double in_f25;
  double dVar20;
  double in_f26;
  double dVar21;
  double in_f27;
  double dVar22;
  double in_f28;
  double dVar23;
  double in_f29;
  double dVar24;
  double in_f30;
  double dVar25;
  double in_f31;
  double dVar26;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  short local_1be8 [70];
  short local_1b5c [2];
  short asStack_1b58 [3400];
  undefined4 local_c8;
  uint uStack_c4;
  undefined4 local_c0;
  uint uStack_bc;
  undefined4 local_b8;
  uint uStack_b4;
  float fStack_68;
  float fStack_64;
  float fStack_58;
  float fStack_54;
  float fStack_48;
  float fStack_44;
  float fStack_38;
  float fStack_34;
  float fStack_28;
  float fStack_24;
  float fStack_18;
  float fStack_14;
  float fStack_8;
  float fStack_4;
  
  fStack_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  fStack_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  fStack_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  fStack_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  fStack_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  fStack_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  fStack_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  dVar19 = (double)FUN_80286814();
  DAT_803ddbc4 = 0;
  if ((DAT_803ddbcd != '\0') && (iVar3 = FUN_80020800(), iVar3 == 0)) {
    DAT_803ddbcd = DAT_803ddbcd + -1;
  }
  if (DAT_803ddbce == '\x01') {
    DAT_803ddbcf = '\x01';
    DAT_803ddbce = '\0';
  }
  else if (DAT_803ddbcf != '\0') {
    DAT_803ddbcf = '\0';
    iVar3 = FUN_80020800();
    if (iVar3 != 0) {
      DAT_803ddbcd = '\x02';
    }
    iVar3 = 0;
    psVar6 = local_1be8;
    iVar18 = 2;
    do {
      *psVar6 = 0;
      psVar6[1] = 0;
      psVar6[2] = 0;
      psVar6[3] = 0;
      psVar6[4] = 0;
      psVar6[5] = 0;
      psVar6[6] = 0;
      psVar6[7] = 0;
      psVar6[8] = 0;
      psVar6[9] = 0;
      psVar6[10] = 0;
      psVar6[0xb] = 0;
      psVar6[0xc] = 0;
      psVar6[0xd] = 0;
      psVar6[0xe] = 0;
      psVar6[0xf] = 0;
      psVar6[0x10] = 0;
      psVar6[0x11] = 0;
      psVar6[0x12] = 0;
      psVar6[0x13] = 0;
      psVar6[0x14] = 0;
      psVar6[0x15] = 0;
      psVar6[0x16] = 0;
      psVar6[0x17] = 0;
      psVar6[0x18] = 0;
      psVar6[0x19] = 0;
      psVar6[0x1a] = 0;
      psVar6[0x1b] = 0;
      psVar6[0x1c] = 0;
      psVar6[0x1d] = 0;
      psVar6[0x1e] = 0;
      psVar6[0x1f] = 0;
      psVar6 = psVar6 + 0x20;
      iVar3 = iVar3 + 0x20;
      iVar18 = iVar18 + -1;
    } while (iVar18 != 0);
    psVar6 = local_1be8 + iVar3;
    iVar18 = 0x47 - iVar3;
    if (iVar3 < 0x47) {
      do {
        *psVar6 = 0;
        psVar6 = psVar6 + 1;
        iVar18 = iVar18 + -1;
      } while (iVar18 != 0);
    }
    DAT_803ddbde = 0;
    DAT_803ddbdc = 0;
    iVar3 = 0;
    dVar25 = (double)FLOAT_803df960;
    dVar26 = DOUBLE_803df958;
    do {
      iVar18 = FUN_8005b094(iVar3);
      uVar10 = 0;
      iVar14 = 0;
      do {
        uVar11 = 0;
        uStack_c4 = uVar10 ^ 0x80000000;
        local_c8 = 0x43300000;
        dVar24 = (double)(float)(dVar25 * (double)(float)((double)CONCAT44(0x43300000,uStack_c4) -
                                                         dVar26));
        pcVar17 = (char *)(iVar18 + iVar14);
        do {
          if (-1 < *pcVar17) {
            iVar4 = FUN_8005b068((int)*pcVar17);
            iVar15 = 0;
            param_2 = (double)FLOAT_803df960;
            uStack_c4 = uVar11 ^ 0x80000000;
            local_c8 = 0x43300000;
            dVar22 = (double)(float)(param_2 *
                                    (double)(float)((double)CONCAT44(0x43300000,uStack_c4) -
                                                   DOUBLE_803df958));
            dVar19 = DOUBLE_803df958;
            for (iVar13 = 0; iVar13 < (int)(uint)*(ushort *)(iVar4 + 0x9c); iVar13 = iVar13 + 1) {
              if (DAT_803ddbde < 0x5dc) {
                psVar6 = (short *)(*(int *)(iVar4 + 0x70) + iVar15);
                puVar7 = (undefined *)(DAT_803ddbb4 + DAT_803ddbde * 0x10);
                *puVar7 = *(undefined *)(psVar6 + 6);
                puVar7[1] = *(undefined *)((int)psVar6 + 0xd);
                puVar7[3] = *(undefined *)((int)psVar6 + 0xf);
                if ((puVar7[3] & 0x3f) == 0x11) {
                  puVar7[3] = puVar7[3] & 0xc0;
                  puVar7[3] = puVar7[3] | 2;
                }
                puVar7[2] = *(undefined *)(psVar6 + 7);
                puVar7[2] = puVar7[2] ^ 0x10;
                *(short *)(puVar7 + 0xc) = psVar6[8];
                dVar21 = (double)(float)(dVar22 + (double)FLOAT_803dda58);
                dVar20 = (double)(float)(dVar24 + (double)FLOAT_803dda5c);
                iVar12 = 0;
                puVar16 = puVar7;
                dVar23 = DOUBLE_803df958;
                do {
                  uStack_c4 = (int)*psVar6 ^ 0x80000000;
                  local_c8 = 0x43300000;
                  dVar19 = (double)(float)(dVar21 + (double)(float)((double)CONCAT44(0x43300000,
                                                                                     uStack_c4) -
                                                                   dVar23));
                  uStack_bc = (int)psVar6[2] ^ 0x80000000;
                  local_c0 = 0x43300000;
                  param_2 = (double)(float)((double)CONCAT44(0x43300000,uStack_bc) - dVar23);
                  uStack_b4 = (int)psVar6[4] ^ 0x80000000;
                  local_b8 = 0x43300000;
                  param_3 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_b4) -
                                                           dVar23) + dVar20);
                  if (DAT_803ddbdc < 0x6a4) {
                    iVar5 = FUN_8006416c(dVar19,param_2,param_3,DAT_803ddbde,(int)asStack_1b58);
                    *(short *)(puVar16 + 4) = (short)iVar5;
                  }
                  psVar6 = psVar6 + 1;
                  puVar16 = puVar16 + 2;
                  iVar12 = iVar12 + 1;
                } while (iVar12 < 2);
                local_1be8[(int)(char)puVar7[3] & 0x3fU] =
                     local_1be8[(int)(char)puVar7[3] & 0x3fU] + 1;
                DAT_803ddbde = DAT_803ddbde + 1;
              }
              iVar15 = iVar15 + 0x14;
            }
          }
          pcVar17 = pcVar17 + 1;
          uVar11 = uVar11 + 1;
        } while ((int)uVar11 < 0x10);
        iVar14 = iVar14 + 0x10;
        uVar10 = uVar10 + 1;
      } while ((int)uVar10 < 0x10);
      iVar3 = iVar3 + 1;
    } while (iVar3 < 5);
    iVar3 = 0;
    for (iVar18 = 0; iVar18 < DAT_803ddbde; iVar18 = iVar18 + 1) {
      iVar14 = DAT_803ddbb4 + iVar3;
      sVar1 = asStack_1b58[*(short *)(iVar14 + 4) * 2];
      if ((sVar1 < 0) || (sVar1 == iVar18)) {
        sVar1 = asStack_1b58[*(short *)(iVar14 + 4) * 2 + 1];
        if ((sVar1 < 0) || (sVar1 == iVar18)) {
          *(undefined2 *)(iVar14 + 8) = 0xffff;
        }
        else {
          *(short *)(iVar14 + 8) = sVar1;
        }
      }
      else {
        *(short *)(iVar14 + 8) = sVar1;
      }
      sVar1 = asStack_1b58[*(short *)(iVar14 + 6) * 2];
      if ((sVar1 < 0) || (sVar1 == iVar18)) {
        sVar1 = asStack_1b58[*(short *)(iVar14 + 6) * 2 + 1];
        if ((sVar1 < 0) || (sVar1 == iVar18)) {
          *(undefined2 *)(iVar14 + 10) = 0xffff;
        }
        else {
          *(short *)(iVar14 + 10) = sVar1;
        }
      }
      else {
        *(short *)(iVar14 + 10) = sVar1;
      }
      iVar3 = iVar3 + 0x10;
    }
    if (DAT_803ddbc0 != 0) {
      iVar3 = 0;
      for (iVar18 = 0; iVar18 < DAT_803ddbde; iVar18 = iVar18 + 1) {
        *(short *)(DAT_803ddbc0 + iVar3) = (short)iVar18;
        iVar3 = iVar3 + 2;
      }
      bVar2 = false;
      while (!bVar2) {
        bVar2 = true;
        iVar3 = 0;
        for (in_r10 = 0; in_r10 < DAT_803ddbde + -1; in_r10 = in_r10 + 1) {
          psVar6 = (short *)(DAT_803ddbc0 + iVar3);
          sVar1 = *psVar6;
          in_r9 = (int)psVar6[1];
          if ((*(byte *)(DAT_803ddbb4 + sVar1 * 0x10 + 3) & 0x3f) <
              (*(byte *)(DAT_803ddbb4 + in_r9 * 0x10 + 3) & 0x3f)) {
            *psVar6 = psVar6[1];
            *(short *)(DAT_803ddbc0 + iVar3 + 2) = sVar1;
            bVar2 = false;
          }
          iVar3 = iVar3 + 2;
        }
      }
    }
    psVar6 = local_1b5c;
    iVar3 = 7;
    do {
      psVar6[-1] = psVar6[-1] + *psVar6;
      psVar6[-2] = psVar6[-2] + psVar6[-1];
      psVar6[-3] = psVar6[-3] + psVar6[-2];
      psVar6[-4] = psVar6[-4] + psVar6[-3];
      psVar6[-5] = psVar6[-5] + psVar6[-4];
      psVar6[-6] = psVar6[-6] + psVar6[-5];
      psVar6[-7] = psVar6[-7] + psVar6[-6];
      psVar6[-8] = psVar6[-8] + psVar6[-7];
      psVar6[-9] = psVar6[-9] + psVar6[-8];
      psVar6[-10] = psVar6[-10] + psVar6[-9];
      psVar6 = psVar6 + -10;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
    iVar3 = 0;
    psVar6 = local_1be8;
    for (iVar18 = 0; iVar14 = (int)DAT_803ddbde, iVar18 < iVar14; iVar18 = iVar18 + 1) {
      iVar14 = ((int)*(char *)(DAT_803ddbb4 + iVar3 + 3) & 0x3fU) + 1;
      sVar1 = psVar6[iVar14];
      psVar6[iVar14] = sVar1 + 1;
      *(short *)(DAT_803ddbbc + sVar1 * 2) = (short)iVar18;
      iVar3 = iVar3 + 0x10;
    }
    iVar13 = 0;
    iVar4 = iVar14 + -1;
    if (0 < iVar4) {
      if ((8 < iVar4) && (uVar10 = iVar14 - 2U >> 3, 0 < iVar14 + -9)) {
        do {
          iVar13 = iVar13 + 8;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
      iVar14 = iVar4 - iVar13;
      if (iVar13 < iVar4) {
        do {
          iVar14 = iVar14 + -1;
        } while (iVar14 != 0);
      }
    }
    DAT_8038e4a0 = 0xffff;
    DAT_8038e4a2 = 0xffff;
    DAT_8038e4a4 = 0xffff;
    DAT_8038e4a6 = 0xffff;
    DAT_8038e4a8 = 0xffff;
    DAT_8038e4aa = 0xffff;
    DAT_8038e4ac = 0xffff;
    DAT_8038e4ae = 0xffff;
    DAT_8038e4b0 = 0xffff;
    DAT_8038e4b2 = 0xffff;
    DAT_8038e4b4 = 0xffff;
    DAT_8038e4b6 = 0xffff;
    DAT_8038e4b8 = 0xffff;
    DAT_8038e4ba = 0xffff;
    DAT_8038e4bc = 0xffff;
    DAT_8038e4be = 0xffff;
    DAT_8038e4c0 = 0xffff;
    DAT_8038e4c2 = 0xffff;
    DAT_8038e4c4 = 0xffff;
    DAT_8038e4c6 = 0xffff;
    DAT_8038e4c8 = 0xffff;
    DAT_8038e4ca = 0xffff;
    DAT_8038e4cc = 0xffff;
    DAT_8038e4ce = 0xffff;
    DAT_8038e4d0 = 0xffff;
    DAT_8038e4d2 = 0xffff;
    DAT_8038e4d4 = 0xffff;
    DAT_8038e4d6 = 0xffff;
    DAT_8038e4d8 = 0xffff;
    DAT_8038e4da = 0xffff;
    DAT_8038e4dc = 0xffff;
    DAT_8038e4de = 0xffff;
    DAT_8038e4e0 = 0xffff;
    DAT_8038e4e2 = 0xffff;
    DAT_8038e4e4 = 0xffff;
    DAT_8038e4e6 = 0xffff;
    DAT_8038e4e8 = 0xffff;
    DAT_8038e4ea = 0xffff;
    DAT_8038e4ec = 0xffff;
    DAT_8038e4ee = 0xffff;
    uVar8 = 0xffff;
    iVar14 = 0;
    for (iVar4 = 0; iVar4 < DAT_803ddbde; iVar4 = iVar4 + 1) {
      uVar9 = (short)*(char *)(DAT_803ddbb4 + *(short *)(DAT_803ddbbc + iVar14) * 0x10 + 3) & 0x3f;
      if (0x13 < uVar9) {
        uVar9 = 1;
        dVar19 = (double)FUN_80137c30(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,s_trackIntersect__FUNC_OVERFLOW__d_8030f43c,1,iVar13,psVar6,
                                      iVar3,iVar18,in_r9,in_r10);
      }
      iVar13 = (int)(short)uVar8;
      if (iVar13 != (short)uVar9) {
        (&DAT_8038e4a0)[(short)uVar9 * 2] = (short)iVar4;
        uVar8 = uVar9;
        if (iVar13 != -1) {
          (&DAT_8038e4a2)[iVar13 * 2] = (short)iVar4;
        }
      }
      iVar14 = iVar14 + 2;
    }
    if ((short)uVar8 != -1) {
      (&DAT_8038e4a2)[(short)uVar8 * 2] = DAT_803ddbde;
    }
    DAT_803ddbc4 = 1;
  }
  FUN_80286860();
  return;
}

