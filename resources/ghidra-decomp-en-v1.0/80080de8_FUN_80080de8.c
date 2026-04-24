// Function: FUN_80080de8
// Entry: 80080de8
// Size: 2904 bytes

/* WARNING: Removing unreachable block (ram,0x80081918) */
/* WARNING: Removing unreachable block (ram,0x80081910) */
/* WARNING: Removing unreachable block (ram,0x80081920) */

void FUN_80080de8(undefined4 param_1,undefined4 param_2,uint param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  short sVar4;
  bool bVar5;
  bool bVar6;
  undefined4 uVar7;
  int iVar8;
  short **ppsVar9;
  short *psVar10;
  undefined4 *puVar11;
  uint uVar12;
  short *psVar13;
  int iVar14;
  int iVar15;
  undefined4 *puVar16;
  short *psVar17;
  int iVar18;
  uint uVar19;
  int iVar20;
  int iVar21;
  int unaff_r23;
  undefined uVar22;
  short **ppsVar23;
  int iVar24;
  uint uVar25;
  undefined4 uVar26;
  double dVar27;
  undefined8 in_f29;
  double dVar28;
  undefined8 in_f30;
  double dVar29;
  undefined8 in_f31;
  double dVar30;
  longlong lVar31;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar26 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  lVar31 = FUN_802860a8();
  uVar19 = (uint)((ulonglong)lVar31 >> 0x20);
  psVar17 = (short *)lVar31;
  iVar21 = *(int *)(psVar17 + 0x26);
  iVar18 = 0;
  bVar6 = false;
  iVar8 = FUN_8002b9ec();
  if (uVar19 == 0xffffffff) {
    unaff_r23 = -1;
  }
  else if ((lVar31 < 0) || ((int)(uint)*(byte *)(*(int *)(psVar17 + 0x28) + 0x5e) <= (int)uVar19)) {
    unaff_r23 = -1;
  }
  else {
    iVar15 = 0x19;
    while (iVar15 < 0x55) {
      iVar24 = iVar15;
      if ((&DAT_8039a3b0)[iVar15] == 0) {
        (&DAT_8039a3b0)[iVar15] = 1;
        iVar24 = iVar15 * 0x80;
        *(undefined4 *)(&DAT_80396918 + iVar24) = 0;
        *(undefined4 *)(&DAT_80396920 + iVar24) = 0;
        *(undefined4 *)(&DAT_80396928 + iVar24) = 0;
        *(undefined4 *)(&DAT_80396930 + iVar24) = 0;
        *(undefined4 *)(&DAT_80396938 + iVar24) = 0;
        *(undefined4 *)(&DAT_80396940 + iVar24) = 0;
        *(undefined4 *)(&DAT_80396948 + iVar24) = 0;
        *(undefined4 *)(&DAT_80396950 + iVar24) = 0;
        *(undefined4 *)(&DAT_80396958 + iVar24) = 0;
        *(undefined4 *)(iVar24 + -0x7fc696a0) = 0;
        *(undefined4 *)(iVar24 + -0x7fc69698) = 0;
        *(undefined4 *)(iVar24 + -0x7fc69690) = 0;
        *(undefined4 *)(iVar24 + -0x7fc69688) = 0;
        *(undefined4 *)(iVar24 + -0x7fc69680) = 0;
        *(undefined4 *)(iVar24 + -0x7fc69678) = 0;
        *(undefined4 *)(iVar24 + -0x7fc69670) = 0;
        iVar24 = 0x56;
        unaff_r23 = iVar15;
      }
      iVar15 = iVar24 + 1;
    }
    if (iVar15 == 0x55) {
      unaff_r23 = -1;
    }
    else {
      if (*(int *)(*(int *)(psVar17 + 0x28) + 0x1c) != 0) {
        uVar19 = (uint)*(short *)(*(int *)(*(int *)(psVar17 + 0x28) + 0x1c) + uVar19 * 2);
      }
      if ((psVar17[0x5a] != -1) && (DAT_803dd07c == (short *)0x0)) {
        FUN_80080c18();
      }
      (&DAT_8039a3b0)[unaff_r23] = (short)uVar19 + 1;
      DAT_803db714 = 0xffffffff;
      DAT_803db718 = 0xffffffff;
      ppsVar23 = (short **)&DAT_8039a664;
      iVar15 = (int)DAT_803dd124;
      ppsVar9 = ppsVar23;
      if (0 < iVar15) {
        do {
          if (*ppsVar9 == psVar17) {
            bVar5 = true;
            goto LAB_80080fa4;
          }
          ppsVar9 = ppsVar9 + 2;
          iVar15 = iVar15 + -1;
        } while (iVar15 != 0);
      }
      bVar5 = false;
LAB_80080fa4:
      if (!bVar5) {
        DAT_803db714 = uVar19;
      }
      psVar10 = (short *)FUN_80023cc8(0x20,0x11,0);
      FUN_8001f71c(psVar10,0x3c,uVar19 << 1,8);
      sVar4 = *psVar10;
      iVar15 = (int)psVar10[1] - (int)sVar4;
      puVar11 = (undefined4 *)FUN_80023cc8(iVar15 * 8,0x11,0);
      FUN_8001f71c(puVar11,0x3b,(int)sVar4 << 3,iVar15 * 8);
      FUN_80023800(psVar10);
      if (DAT_803dd07c != (short *)0x0) {
        psVar17 = DAT_803dd07c;
      }
      psVar17[0x5a] = (short)unaff_r23;
      psVar10 = *(short **)(psVar17 + 0x18);
      fVar1 = *(float *)(psVar17 + 6);
      fVar2 = *(float *)(psVar17 + 8);
      fVar3 = *(float *)(psVar17 + 10);
      if ((char)DAT_803dd0b4 < '\0') {
        psVar10 = (short *)0x0;
        fVar1 = *(float *)(psVar17 + 0xc);
        fVar2 = *(float *)(psVar17 + 0xe);
        fVar3 = *(float *)(psVar17 + 0x10);
      }
      dVar30 = (double)fVar1;
      dVar29 = (double)fVar2;
      dVar28 = (double)fVar3;
      uVar12 = (uint)*psVar17;
      if (DAT_803dd078 != '\0') {
        dVar27 = (double)FUN_80293e80((double)((FLOAT_803defe8 *
                                               (float)((double)CONCAT44(0x43300000,
                                                                        uVar12 ^ 0x80000000) -
                                                      DOUBLE_803defb8)) / FLOAT_803defec));
        dVar30 = -(double)(float)((double)*(float *)(psVar17 + 4) *
                                  (double)(float)((double)*(float *)(psVar17 + 0x54) * dVar27) -
                                 dVar30);
        dVar27 = (double)FUN_80294204((double)((FLOAT_803defe8 *
                                               (float)((double)CONCAT44(0x43300000,
                                                                        (int)*psVar17 ^ 0x80000000)
                                                      - DOUBLE_803defb8)) / FLOAT_803defec));
        dVar28 = -(double)(float)((double)*(float *)(psVar17 + 4) *
                                  (double)(float)((double)*(float *)(psVar17 + 0x54) * dVar27) -
                                 dVar28);
      }
      (&DAT_80399e50)[psVar17[0x5a]] = 0;
      (&DAT_80399c4c)[psVar17[0x5a]] = 0;
      *(undefined2 *)(&DAT_8030ecf8 + psVar17[0x5a] * 2) = 0;
      (&DAT_80399cfc)[psVar17[0x5a]] = (int)psVar17[0x23];
      puVar16 = puVar11;
      for (iVar24 = 0; iVar24 < iVar15; iVar24 = iVar24 + 1) {
        if ((((param_3 & 1 << iVar24) != 0) && ((*(ushort *)(puVar16 + 1) & 0x4000) != 0)) &&
           ((*(short *)((int)puVar16 + 6) == 0x1f || (*(short *)((int)puVar16 + 6) == 0)))) {
          FUN_8002b9ec();
          iVar14 = FUN_80296c2c();
          if (iVar14 == 0) {
            unaff_r23 = -1;
            goto LAB_80081910;
          }
        }
        puVar16 = puVar16 + 2;
      }
      puVar16 = puVar11;
      for (iVar24 = 0; iVar24 < iVar15; iVar24 = iVar24 + 1) {
        if ((param_3 & 1 << iVar24) != 0) {
          psVar13 = (short *)FUN_8002bdf4(0x28,6);
          sVar4 = *(short *)((int)puVar16 + 6);
          if ((sVar4 == 0x1f) || (sVar4 == 0)) {
            iVar14 = FUN_8002b9ec();
            *(ushort *)(iVar14 + 0xb0) = *(ushort *)(iVar14 + 0xb0) | 0x1000;
          }
          uVar22 = (undefined)unaff_r23;
          if (sVar4 == -1) {
            *psVar13 = 6;
            psVar13[0xe] = psVar17[0x23] + 4;
            if ((psVar17[0x23] == 0x443) && (DAT_803db72c != -1)) {
              psVar13[0xe] = (short)DAT_803db72c + 4;
            }
            *(ushort *)(puVar16 + 1) = *(ushort *)(puVar16 + 1) | 0x8000;
          }
          else if (sVar4 == -2) {
            *psVar13 = 0x1e;
            psVar13[0xe] = 3;
            DAT_803dd08c = uVar22;
          }
          else if ((*(ushort *)(puVar16 + 1) & 0x4000) == 0) {
            *psVar13 = sVar4;
            psVar13[0xe] = 0;
          }
          else {
            *psVar13 = 6;
            if (sVar4 == 0x443) {
              if (DAT_803db72c == -1) {
                psVar13[0xe] = 0x447;
              }
              else {
                psVar13[0xe] = (short)DAT_803db72c + 4;
              }
            }
            else {
              psVar13[0xe] = sVar4 + 4;
            }
          }
          if ((*(ushort *)(puVar16 + 1) & 0x8000) == 0) {
            *(undefined *)(psVar13 + 0x10) = 1;
            *(undefined *)((int)psVar13 + 0x21) = 1;
          }
          else {
            *(undefined *)(psVar13 + 0x10) = 0;
            *(undefined *)((int)psVar13 + 0x21) = 0;
          }
          if (((iVar24 == 0) && ((*(ushort *)(puVar16 + 1) & 0x1000) != 0)) && (iVar8 != 0)) {
            FUN_80297284(iVar8);
          }
          psVar13[0xc] = (ushort)((uVar19 & 0x7ff) << 4) | 0x8000 | (ushort)iVar24 & 0xf;
          psVar13[0xd] = -1;
          if (iVar24 == 0) {
            *(undefined4 *)(psVar13 + 4) = *(undefined4 *)(psVar17 + 6);
            *(undefined4 *)(psVar13 + 6) = *(undefined4 *)(psVar17 + 8);
            *(undefined4 *)(psVar13 + 8) = *(undefined4 *)(psVar17 + 10);
          }
          else if ((DAT_803dd0d9 == '\0') || (*psVar13 != 0x1e)) {
            *(float *)(psVar13 + 4) = (float)dVar30;
            *(float *)(psVar13 + 6) = (float)dVar29;
            *(float *)(psVar13 + 8) = (float)dVar28;
          }
          else {
            *(float *)(psVar13 + 4) = (float)(dVar30 + (double)DAT_803994ec);
            *(float *)(psVar13 + 6) = (float)(dVar29 + (double)DAT_803994f0);
            *(float *)(psVar13 + 8) = (float)(dVar28 + (double)DAT_803994f4);
            DAT_803dd0d9 = '\0';
          }
          *(undefined *)((int)psVar13 + 0x1f) = uVar22;
          *(undefined *)(psVar13 + 0x11) = 1;
          *(byte *)(psVar13 + 0x12) = (byte)((uint)*(ushort *)(puVar16 + 1) >> 8) & 0xf;
          *(undefined *)(psVar13 + 2) = 2;
          *(undefined *)((int)psVar13 + 5) = 1;
          if (iVar21 != 0) {
            *(byte *)((int)psVar13 + 5) = *(byte *)((int)psVar13 + 5) | *(byte *)(iVar21 + 5) & 0x18
            ;
          }
          if (*psVar13 == 0x1e) {
            *(undefined *)(psVar13 + 2) = 1;
          }
          if ((*psVar13 == 0x443) && (DAT_803db72c != -1)) {
            *psVar13 = (short)DAT_803db72c;
          }
          iVar14 = FUN_8002df90(psVar13,5,0xffffffff,0xffffffff,psVar10);
          *(undefined2 *)(iVar14 + 0xb4) = 0xfffe;
          iVar20 = *(int *)(iVar14 + 0xb8);
          *(short *)(iVar20 + 0x1a) = (short)uVar12;
          *(undefined2 *)(iVar20 + 0x6e) = 0xffff;
          *(ushort *)(iVar20 + 0x6e) = *(ushort *)(iVar20 + 0x6e) & 0xfbff;
          *(undefined *)(iVar20 + 300) = 0;
          *(undefined *)(iVar20 + 0x12d) = 0;
          *(undefined *)(iVar20 + 0x12e) = 0;
          *(undefined *)(iVar20 + 0x12f) = 0;
          if ((*(ushort *)(puVar16 + 1) & 1) != 0) {
            *(ushort *)(iVar20 + 0x6e) = *(ushort *)(iVar20 + 0x6e) & 0xfffe;
          }
          if ((*(ushort *)(puVar16 + 1) & 2) != 0) {
            *(ushort *)(iVar20 + 0x6e) = *(ushort *)(iVar20 + 0x6e) & 0xfffd;
          }
          if ((*(ushort *)(puVar16 + 1) & 4) != 0) {
            *(undefined2 *)(iVar20 + 0x1a) = 0;
          }
          if ((*(ushort *)(puVar16 + 1) & 8) != 0) {
            *(ushort *)(iVar20 + 0x6e) = *(ushort *)(iVar20 + 0x6e) & 0xfeff;
          }
          if ((*(ushort *)(puVar16 + 1) & 0x80) != 0) {
            *(byte *)(iVar20 + 0x7f) = *(byte *)(iVar20 + 0x7f) | 4;
          }
          if ((*(ushort *)(puVar16 + 1) & 0x40) != 0) {
            *(byte *)(iVar20 + 0x7f) = *(byte *)(iVar20 + 0x7f) | 2;
          }
          if ((*(ushort *)(puVar16 + 1) & 0x2000) == 0) {
            *(undefined *)(iVar20 + 0x56) = 0xff;
          }
          else {
            if ((iVar24 == 0) && (iVar8 != 0)) {
              FUN_8029726c(iVar8);
            }
            if ((DAT_803dd064 == 0) || (DAT_803dd064 == psVar17[0x5a])) {
              DAT_803dd064 = (int)psVar17[0x5a];
              DAT_803dd08c = uVar22;
            }
            *(undefined *)(iVar20 + 0x56) = 4;
            if (iVar18 == 0) {
              iVar18 = (int)(*(ushort *)(puVar16 + 1) & 0xf00) >> 8;
            }
            bVar6 = true;
          }
          if (((sVar4 == 0x1f) || (sVar4 == 0)) && ((*(ushort *)(iVar20 + 0x6e) & 1) != 0)) {
            FUN_80297254(iVar8);
          }
          *(undefined4 *)(iVar20 + 0x10c) = *puVar16;
          *(undefined2 *)(iVar20 + 0x70) = *(undefined2 *)(iVar20 + 0x6e);
          if (iVar24 == 0) {
            (&DAT_80399e50)[psVar17[0x5a]] = (char)*(undefined2 *)(puVar16 + 1);
            (&DAT_80399cfc)[psVar17[0x5a]] = *(undefined4 *)(*(int *)(iVar14 + 0x4c) + 0x14);
            if (((*(uint *)(*(int *)(psVar17 + 0x28) + 0x44) & 0x40) != 0) &&
               ((*(uint *)(*(int *)(psVar17 + 0x28) + 0x44) & 0x8000) == 0)) {
              dVar28 = (double)FLOAT_803defb0;
              uVar12 = 0;
              psVar10 = psVar17;
              dVar29 = dVar28;
              dVar30 = dVar28;
            }
          }
        }
        puVar16 = puVar16 + 2;
      }
      *(short *)(&DAT_80399f00 + psVar17[0x5a] * 2) = (short)uVar12;
      iVar21 = 0;
      (&DAT_80399ea8)[psVar17[0x5a]] = 0;
      (&DAT_80399ca4)[psVar17[0x5a]] = 0;
      iVar8 = (int)DAT_803dd124;
      if (0 < iVar8) {
        do {
          if (*ppsVar23 == psVar17) {
            uVar12 = (&DAT_8039a668)[iVar21 * 2];
            DAT_803dd124 = DAT_803dd124 + -1;
            puVar16 = &DAT_8039a664 + iVar21 * 2;
            uVar19 = DAT_803dd124 - iVar21;
            if (iVar21 < DAT_803dd124) {
              uVar25 = uVar19 >> 3;
              if (uVar25 != 0) {
                do {
                  uVar7 = puVar16[2];
                  *puVar16 = uVar7;
                  puVar16[1] = uVar7;
                  puVar16[2] = uVar7;
                  puVar16[3] = uVar7;
                  puVar16[4] = uVar7;
                  puVar16[5] = uVar7;
                  puVar16[6] = uVar7;
                  puVar16[7] = uVar7;
                  puVar16[8] = uVar7;
                  puVar16[9] = uVar7;
                  puVar16[10] = uVar7;
                  puVar16[0xb] = uVar7;
                  puVar16[0xc] = uVar7;
                  puVar16[0xd] = uVar7;
                  puVar16[0xe] = uVar7;
                  puVar16[0xf] = uVar7;
                  puVar16 = puVar16 + 0x10;
                  uVar25 = uVar25 - 1;
                } while (uVar25 != 0);
                uVar19 = uVar19 & 7;
                goto joined_r0x80081788;
              }
              do {
                *puVar16 = puVar16[2];
                puVar16[1] = puVar16[2];
                puVar16 = puVar16 + 2;
                uVar19 = uVar19 - 1;
joined_r0x80081788:
              } while (uVar19 != 0);
            }
            goto LAB_800817b8;
          }
          ppsVar23 = ppsVar23 + 2;
          iVar21 = iVar21 + 1;
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
      }
      uVar12 = 0;
LAB_800817b8:
      if (uVar12 == 0) {
        DAT_803dd070 = 0;
        DAT_803dd068 = (int)(short)(&DAT_8039a3b0)[unaff_r23] - 1U & 0x3fff;
        iVar8 = FUN_8000d200(DAT_803dd068,FUN_80080384);
        if (iVar8 == 0) {
          if (DAT_803db714 != 0xffffffff) {
            FUN_8001bbd8();
            DAT_803db714 = 0xffffffff;
          }
        }
        else {
          DAT_803db71c = DAT_803db714;
          DAT_803db724 = 0xffffffff;
          FLOAT_803dd074 = FLOAT_803defb0;
          DAT_803db728 = 0xffffffff;
          DAT_803db720 = unaff_r23;
        }
      }
      else {
        (&DAT_80399e50)[psVar17[0x5a]] = (&DAT_80399e50)[psVar17[0x5a]] | 0x10;
      }
      dVar29 = DOUBLE_803defb8;
      (&DAT_8039a058)[psVar17[0x5a]] =
           (float)((double)CONCAT44(0x43300000,uVar12 ^ 0x80000000) - DOUBLE_803defb8);
      (&DAT_8039a1ac)[psVar17[0x5a]] =
           (float)((double)CONCAT44(0x43300000,uVar12 ^ 0x80000000) - dVar29);
      if (((-1 < unaff_r23) && (unaff_r23 < 0x55)) && (iVar8 = (int)DAT_803dd0bc, iVar8 < 0x1e)) {
        (&DAT_80399398)[iVar8 * 3] = (short)unaff_r23;
        *(short *)(&DAT_8039939c + iVar8 * 6) = (short)iVar15;
        DAT_803dd0bc = DAT_803dd0bc + '\x01';
        (&DAT_8039939a)[iVar8 * 3] = (short)uVar12;
      }
      if (bVar6) {
        FUN_8008046c(iVar18,psVar17);
      }
      FUN_80023800(puVar11);
      DAT_803dd078 = '\0';
      DAT_803dd0b4 = DAT_803dd0b4 & 0x7f;
    }
  }
LAB_80081910:
  __psq_l0(auStack8,uVar26);
  __psq_l1(auStack8,uVar26);
  __psq_l0(auStack24,uVar26);
  __psq_l1(auStack24,uVar26);
  __psq_l0(auStack40,uVar26);
  __psq_l1(auStack40,uVar26);
  FUN_802860f4(unaff_r23);
  return;
}

