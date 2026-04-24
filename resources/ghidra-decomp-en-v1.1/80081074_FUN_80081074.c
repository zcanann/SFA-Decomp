// Function: FUN_80081074
// Entry: 80081074
// Size: 2904 bytes

/* WARNING: Removing unreachable block (ram,0x80081bac) */
/* WARNING: Removing unreachable block (ram,0x80081ba4) */
/* WARNING: Removing unreachable block (ram,0x80081b9c) */
/* WARNING: Removing unreachable block (ram,0x80081094) */
/* WARNING: Removing unreachable block (ram,0x8008108c) */
/* WARNING: Removing unreachable block (ram,0x80081084) */

void FUN_80081074(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  float fVar2;
  float fVar3;
  short sVar4;
  bool bVar5;
  bool bVar6;
  undefined4 uVar7;
  int iVar8;
  short *psVar9;
  undefined4 *puVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  uint *puVar14;
  int iVar15;
  undefined2 uVar16;
  uint uVar17;
  int iVar18;
  uint uVar19;
  uint *puVar20;
  int unaff_r23;
  undefined uVar21;
  undefined4 *puVar22;
  undefined4 *puVar23;
  int iVar24;
  undefined8 extraout_f1;
  undefined8 uVar25;
  double dVar26;
  double extraout_f1_00;
  undefined8 extraout_f1_01;
  double dVar27;
  double dVar28;
  double dVar29;
  longlong lVar30;
  
  lVar30 = FUN_8028680c();
  uVar17 = (uint)((ulonglong)lVar30 >> 0x20);
  puVar14 = (uint *)lVar30;
  uVar19 = puVar14[0x13];
  iVar15 = 0;
  bVar6 = false;
  uVar12 = param_11;
  uVar25 = extraout_f1;
  iVar8 = FUN_8002bac4();
  if (((uVar17 != 0xffffffff) && (-1 < lVar30)) &&
     ((int)uVar17 < (int)(uint)*(byte *)(puVar14[0x14] + 0x5e))) {
    iVar13 = 0x19;
    while (iVar13 < 0x55) {
      iVar24 = iVar13;
      if ((&DAT_8039b010)[iVar13] == 0) {
        (&DAT_8039b010)[iVar13] = 1;
        iVar24 = iVar13 * 0x80;
        *(undefined4 *)(&DAT_80397578 + iVar24) = 0;
        *(undefined4 *)(&DAT_80397580 + iVar24) = 0;
        *(undefined4 *)(&DAT_80397588 + iVar24) = 0;
        *(undefined4 *)(&DAT_80397590 + iVar24) = 0;
        *(undefined4 *)(&DAT_80397598 + iVar24) = 0;
        *(undefined4 *)(&DAT_803975a0 + iVar24) = 0;
        *(undefined4 *)(&DAT_803975a8 + iVar24) = 0;
        *(undefined4 *)(&DAT_803975b0 + iVar24) = 0;
        *(undefined4 *)(&DAT_803975b8 + iVar24) = 0;
        *(undefined4 *)(iVar24 + -0x7fc68a40) = 0;
        *(undefined4 *)(iVar24 + -0x7fc68a38) = 0;
        *(undefined4 *)(iVar24 + -0x7fc68a30) = 0;
        *(undefined4 *)(iVar24 + -0x7fc68a28) = 0;
        *(undefined4 *)(iVar24 + -0x7fc68a20) = 0;
        *(undefined4 *)(iVar24 + -0x7fc68a18) = 0;
        *(undefined4 *)(iVar24 + -0x7fc68a10) = 0;
        iVar24 = 0x56;
        unaff_r23 = iVar13;
      }
      iVar13 = iVar24 + 1;
    }
    if (iVar13 != 0x55) {
      if (*(int *)(puVar14[0x14] + 0x1c) != 0) {
        uVar17 = (uint)*(short *)(*(int *)(puVar14[0x14] + 0x1c) + uVar17 * 2);
      }
      if ((*(short *)(puVar14 + 0x2d) != -1) && (DAT_803ddcfc == (uint *)0x0)) {
        uVar25 = FUN_80080ea4(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              (int)*(short *)(puVar14 + 0x2d),iVar13,uVar12,param_12,param_13,
                              param_14,param_15,param_16);
      }
      (&DAT_8039b010)[unaff_r23] = (short)uVar17 + 1;
      DAT_803dc374 = 0xffffffff;
      DAT_803dc378 = 0xffffffff;
      puVar23 = &DAT_8039b2c4;
      iVar13 = (int)DAT_803ddda4;
      puVar10 = puVar23;
      if (0 < iVar13) {
        do {
          if ((uint *)*puVar10 == puVar14) {
            bVar5 = true;
            goto LAB_80081230;
          }
          puVar10 = puVar10 + 2;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
      }
      bVar5 = false;
LAB_80081230:
      if (!bVar5) {
        DAT_803dc374 = uVar17;
      }
      psVar9 = (short *)FUN_80023d8c(0x20,0x11);
      uVar25 = FUN_8001f7e0(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar9,
                            0x3c,uVar17 << 1,8,param_13,param_14,param_15,param_16);
      sVar4 = *psVar9;
      iVar13 = (int)psVar9[1] - (int)sVar4;
      puVar10 = (undefined4 *)FUN_80023d8c(iVar13 * 8,0x11);
      FUN_8001f7e0(uVar25,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar10,0x3b,
                   (int)sVar4 << 3,iVar13 * 8,param_13,param_14,param_15,param_16);
      dVar26 = (double)FUN_800238c4((uint)psVar9);
      if (DAT_803ddcfc != (uint *)0x0) {
        puVar14 = DAT_803ddcfc;
      }
      *(short *)(puVar14 + 0x2d) = (short)unaff_r23;
      puVar20 = (uint *)puVar14[0xc];
      fVar1 = (float)puVar14[3];
      fVar2 = (float)puVar14[4];
      fVar3 = (float)puVar14[5];
      if ((char)DAT_803ddd34 < '\0') {
        puVar20 = (uint *)0x0;
        fVar1 = (float)puVar14[6];
        fVar2 = (float)puVar14[7];
        fVar3 = (float)puVar14[8];
      }
      dVar29 = (double)fVar1;
      dVar28 = (double)fVar2;
      dVar27 = (double)fVar3;
      uVar16 = *(undefined2 *)puVar14;
      if (DAT_803ddcf8 != '\0') {
        dVar26 = (double)FUN_802945e0();
        dVar29 = -(double)(float)((double)(float)puVar14[2] *
                                  (double)(float)((double)(float)puVar14[0x2a] * dVar26) - dVar29);
        param_2 = (double)FLOAT_803dfc68;
        dVar26 = (double)FUN_80294964();
        dVar26 = (double)(float)((double)(float)puVar14[0x2a] * dVar26);
        dVar27 = -(double)(float)((double)(float)puVar14[2] * dVar26 - dVar27);
      }
      (&DAT_8039aab0)[*(short *)(puVar14 + 0x2d)] = 0;
      (&DAT_8039a8ac)[*(short *)(puVar14 + 0x2d)] = 0;
      *(undefined2 *)(&DAT_8030f8b8 + *(short *)(puVar14 + 0x2d) * 2) = 0;
      (&DAT_8039a95c)[*(short *)(puVar14 + 0x2d)] = (int)*(short *)((int)puVar14 + 0x46);
      puVar22 = puVar10;
      for (iVar24 = 0; iVar24 < iVar13; iVar24 = iVar24 + 1) {
        if ((((param_11 & 1 << iVar24) != 0) && ((*(ushort *)(puVar22 + 1) & 0x4000) != 0)) &&
           ((*(short *)((int)puVar22 + 6) == 0x1f || (*(short *)((int)puVar22 + 6) == 0)))) {
          iVar11 = FUN_8002bac4();
          uVar12 = FUN_8029738c(iVar11);
          if (uVar12 == 0) goto LAB_80081b9c;
        }
        puVar22 = puVar22 + 2;
      }
      puVar22 = puVar10;
      for (iVar24 = 0; iVar24 < iVar13; iVar24 = iVar24 + 1) {
        if ((param_11 & 1 << iVar24) != 0) {
          psVar9 = FUN_8002becc(0x28,6);
          sVar4 = *(short *)((int)puVar22 + 6);
          if ((sVar4 == 0x1f) || (sVar4 == 0)) {
            iVar11 = FUN_8002bac4();
            *(ushort *)(iVar11 + 0xb0) = *(ushort *)(iVar11 + 0xb0) | 0x1000;
          }
          uVar21 = (undefined)unaff_r23;
          if (sVar4 == -1) {
            *psVar9 = 6;
            psVar9[0xe] = *(short *)((int)puVar14 + 0x46) + 4;
            if ((*(short *)((int)puVar14 + 0x46) == 0x443) && (DAT_803dc38c != -1)) {
              psVar9[0xe] = (short)DAT_803dc38c + 4;
            }
            *(ushort *)(puVar22 + 1) = *(ushort *)(puVar22 + 1) | 0x8000;
          }
          else if (sVar4 == -2) {
            *psVar9 = 0x1e;
            psVar9[0xe] = 3;
            DAT_803ddd0c = uVar21;
          }
          else if ((*(ushort *)(puVar22 + 1) & 0x4000) == 0) {
            *psVar9 = sVar4;
            psVar9[0xe] = 0;
          }
          else {
            *psVar9 = 6;
            if (sVar4 == 0x443) {
              if (DAT_803dc38c == -1) {
                psVar9[0xe] = 0x447;
              }
              else {
                psVar9[0xe] = (short)DAT_803dc38c + 4;
              }
            }
            else {
              psVar9[0xe] = sVar4 + 4;
            }
          }
          if ((*(ushort *)(puVar22 + 1) & 0x8000) == 0) {
            *(undefined *)(psVar9 + 0x10) = 1;
            *(undefined *)((int)psVar9 + 0x21) = 1;
          }
          else {
            *(undefined *)(psVar9 + 0x10) = 0;
            *(undefined *)((int)psVar9 + 0x21) = 0;
          }
          if (((iVar24 == 0) && ((*(ushort *)(puVar22 + 1) & 0x1000) != 0)) && (iVar8 != 0)) {
            dVar26 = (double)FUN_802979e4(iVar8);
          }
          psVar9[0xc] = (ushort)((uVar17 & 0x7ff) << 4) | 0x8000 | (ushort)iVar24 & 0xf;
          psVar9[0xd] = -1;
          if (iVar24 == 0) {
            *(uint *)(psVar9 + 4) = puVar14[3];
            *(uint *)(psVar9 + 6) = puVar14[4];
            *(uint *)(psVar9 + 8) = puVar14[5];
          }
          else if ((DAT_803ddd59 == '\0') || (*psVar9 != 0x1e)) {
            *(float *)(psVar9 + 4) = (float)dVar29;
            *(float *)(psVar9 + 6) = (float)dVar28;
            *(float *)(psVar9 + 8) = (float)dVar27;
          }
          else {
            *(float *)(psVar9 + 4) = (float)(dVar29 + (double)DAT_8039a14c);
            *(float *)(psVar9 + 6) = (float)(dVar28 + (double)DAT_8039a150);
            *(float *)(psVar9 + 8) = (float)(dVar27 + (double)DAT_8039a154);
            DAT_803ddd59 = '\0';
          }
          *(undefined *)((int)psVar9 + 0x1f) = uVar21;
          *(undefined *)(psVar9 + 0x11) = 1;
          *(byte *)(psVar9 + 0x12) = (byte)((ushort)*(undefined2 *)(puVar22 + 1) >> 8) & 0xf;
          *(undefined *)(psVar9 + 2) = 2;
          *(undefined *)((int)psVar9 + 5) = 1;
          if (uVar19 != 0) {
            *(byte *)((int)psVar9 + 5) = *(byte *)((int)psVar9 + 5) | *(byte *)(uVar19 + 5) & 0x18;
          }
          if (*psVar9 == 0x1e) {
            *(undefined *)(psVar9 + 2) = 1;
          }
          if ((*psVar9 == 0x443) && (DAT_803dc38c != -1)) {
            *psVar9 = (short)DAT_803dc38c;
          }
          iVar11 = FUN_8002e088(dVar26,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                psVar9,5,0xff,0xffffffff,puVar20,param_14,param_15,param_16);
          *(undefined2 *)(iVar11 + 0xb4) = 0xfffe;
          iVar18 = *(int *)(iVar11 + 0xb8);
          *(undefined2 *)(iVar18 + 0x1a) = uVar16;
          *(undefined2 *)(iVar18 + 0x6e) = 0xffff;
          *(ushort *)(iVar18 + 0x6e) = *(ushort *)(iVar18 + 0x6e) & 0xfbff;
          *(undefined *)(iVar18 + 300) = 0;
          *(undefined *)(iVar18 + 0x12d) = 0;
          *(undefined *)(iVar18 + 0x12e) = 0;
          *(undefined *)(iVar18 + 0x12f) = 0;
          if ((*(ushort *)(puVar22 + 1) & 1) != 0) {
            *(ushort *)(iVar18 + 0x6e) = *(ushort *)(iVar18 + 0x6e) & 0xfffe;
          }
          if ((*(ushort *)(puVar22 + 1) & 2) != 0) {
            *(ushort *)(iVar18 + 0x6e) = *(ushort *)(iVar18 + 0x6e) & 0xfffd;
          }
          if ((*(ushort *)(puVar22 + 1) & 4) != 0) {
            *(undefined2 *)(iVar18 + 0x1a) = 0;
          }
          if ((*(ushort *)(puVar22 + 1) & 8) != 0) {
            *(ushort *)(iVar18 + 0x6e) = *(ushort *)(iVar18 + 0x6e) & 0xfeff;
          }
          if ((*(ushort *)(puVar22 + 1) & 0x80) != 0) {
            *(byte *)(iVar18 + 0x7f) = *(byte *)(iVar18 + 0x7f) | 4;
          }
          if ((*(ushort *)(puVar22 + 1) & 0x40) != 0) {
            *(byte *)(iVar18 + 0x7f) = *(byte *)(iVar18 + 0x7f) | 2;
          }
          dVar26 = extraout_f1_00;
          if ((*(ushort *)(puVar22 + 1) & 0x2000) == 0) {
            *(undefined *)(iVar18 + 0x56) = 0xff;
          }
          else {
            if ((iVar24 == 0) && (iVar8 != 0)) {
              dVar26 = (double)FUN_802979cc(iVar8);
            }
            if ((DAT_803ddce4 == 0) || (DAT_803ddce4 == *(short *)(puVar14 + 0x2d))) {
              DAT_803ddce4 = (int)*(short *)(puVar14 + 0x2d);
              DAT_803ddd0c = uVar21;
            }
            *(undefined *)(iVar18 + 0x56) = 4;
            if (iVar15 == 0) {
              iVar15 = (int)(*(ushort *)(puVar22 + 1) & 0xf00) >> 8;
            }
            bVar6 = true;
          }
          if (((sVar4 == 0x1f) || (sVar4 == 0)) && ((*(ushort *)(iVar18 + 0x6e) & 1) != 0)) {
            dVar26 = (double)FUN_802979b4(iVar8);
          }
          *(undefined4 *)(iVar18 + 0x10c) = *puVar22;
          *(undefined2 *)(iVar18 + 0x70) = *(undefined2 *)(iVar18 + 0x6e);
          if (iVar24 == 0) {
            (&DAT_8039aab0)[*(short *)(puVar14 + 0x2d)] = (char)*(undefined2 *)(puVar22 + 1);
            (&DAT_8039a95c)[*(short *)(puVar14 + 0x2d)] =
                 *(undefined4 *)(*(int *)(iVar11 + 0x4c) + 0x14);
            if (((*(uint *)(puVar14[0x14] + 0x44) & 0x40) != 0) &&
               ((*(uint *)(puVar14[0x14] + 0x44) & 0x8000) == 0)) {
              dVar27 = (double)FLOAT_803dfc30;
              uVar16 = 0;
              puVar20 = puVar14;
              dVar28 = dVar27;
              dVar29 = dVar27;
            }
          }
        }
        puVar22 = puVar22 + 2;
      }
      *(undefined2 *)(&DAT_8039ab60 + *(short *)(puVar14 + 0x2d) * 2) = uVar16;
      iVar24 = 0;
      (&DAT_8039ab08)[*(short *)(puVar14 + 0x2d)] = 0;
      (&DAT_8039a904)[*(short *)(puVar14 + 0x2d)] = 0;
      iVar8 = (int)DAT_803ddda4;
      if (0 < iVar8) {
        do {
          if ((uint *)*puVar23 == puVar14) {
            uVar17 = (&DAT_8039b2c8)[iVar24 * 2];
            DAT_803ddda4 = DAT_803ddda4 + -1;
            puVar23 = &DAT_8039b2c4 + iVar24 * 2;
            uVar12 = DAT_803ddda4 - iVar24;
            if (iVar24 < DAT_803ddda4) {
              uVar19 = uVar12 >> 3;
              if (uVar19 != 0) {
                do {
                  uVar7 = puVar23[2];
                  *puVar23 = uVar7;
                  puVar23[1] = uVar7;
                  puVar23[2] = uVar7;
                  puVar23[3] = uVar7;
                  puVar23[4] = uVar7;
                  puVar23[5] = uVar7;
                  puVar23[6] = uVar7;
                  puVar23[7] = uVar7;
                  puVar23[8] = uVar7;
                  puVar23[9] = uVar7;
                  puVar23[10] = uVar7;
                  puVar23[0xb] = uVar7;
                  puVar23[0xc] = uVar7;
                  puVar23[0xd] = uVar7;
                  puVar23[0xe] = uVar7;
                  puVar23[0xf] = uVar7;
                  puVar23 = puVar23 + 0x10;
                  uVar19 = uVar19 - 1;
                } while (uVar19 != 0);
                uVar12 = uVar12 & 7;
                goto joined_r0x80081a14;
              }
              do {
                *puVar23 = puVar23[2];
                puVar23[1] = puVar23[2];
                puVar23 = puVar23 + 2;
                uVar12 = uVar12 - 1;
joined_r0x80081a14:
              } while (uVar12 != 0);
            }
            goto LAB_80081a44;
          }
          puVar23 = puVar23 + 2;
          iVar24 = iVar24 + 1;
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
      }
      uVar17 = 0;
LAB_80081a44:
      if (uVar17 == 0) {
        DAT_803ddcf0 = 0;
        DAT_803ddce8 = (int)(short)(&DAT_8039b010)[unaff_r23] - 1U & 0x3fff;
        iVar8 = FUN_8000d220(dVar26,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        if (iVar8 == 0) {
          if (DAT_803dc374 != 0xffffffff) {
            FUN_8001bc8c(extraout_f1_01,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         DAT_803dc374);
            DAT_803dc374 = 0xffffffff;
          }
        }
        else {
          DAT_803dc37c = DAT_803dc374;
          DAT_803dc384 = 0xffffffff;
          FLOAT_803ddcf4 = FLOAT_803dfc30;
          DAT_803dc388 = 0xffffffff;
          DAT_803dc380 = unaff_r23;
        }
      }
      else {
        (&DAT_8039aab0)[*(short *)(puVar14 + 0x2d)] =
             (&DAT_8039aab0)[*(short *)(puVar14 + 0x2d)] | 0x10;
      }
      dVar26 = DOUBLE_803dfc38;
      (&DAT_8039acb8)[*(short *)(puVar14 + 0x2d)] =
           (float)((double)CONCAT44(0x43300000,uVar17 ^ 0x80000000) - DOUBLE_803dfc38);
      (&DAT_8039ae0c)[*(short *)(puVar14 + 0x2d)] =
           (float)((double)CONCAT44(0x43300000,uVar17 ^ 0x80000000) - dVar26);
      if (((-1 < unaff_r23) && (unaff_r23 < 0x55)) && (iVar8 = (int)DAT_803ddd3c, iVar8 < 0x1e)) {
        (&DAT_80399ff8)[iVar8 * 3] = (short)unaff_r23;
        *(short *)(&DAT_80399ffc + iVar8 * 6) = (short)iVar13;
        DAT_803ddd3c = DAT_803ddd3c + '\x01';
        (&DAT_80399ffa)[iVar8 * 3] = (short)uVar17;
      }
      if (bVar6) {
        FUN_800806f8(iVar15,(int)puVar14);
      }
      FUN_800238c4((uint)puVar10);
      DAT_803ddcf8 = '\0';
      DAT_803ddd34 = DAT_803ddd34 & 0x7f;
    }
  }
LAB_80081b9c:
  FUN_80286858();
  return;
}

