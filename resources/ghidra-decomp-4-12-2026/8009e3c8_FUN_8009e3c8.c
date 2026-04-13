// Function: FUN_8009e3c8
// Entry: 8009e3c8
// Size: 2984 bytes

/* WARNING: Removing unreachable block (ram,0x8009ef50) */
/* WARNING: Removing unreachable block (ram,0x8009ef48) */
/* WARNING: Removing unreachable block (ram,0x8009ef40) */
/* WARNING: Removing unreachable block (ram,0x8009ef38) */
/* WARNING: Removing unreachable block (ram,0x8009ef30) */
/* WARNING: Removing unreachable block (ram,0x8009ef28) */
/* WARNING: Removing unreachable block (ram,0x8009e400) */
/* WARNING: Removing unreachable block (ram,0x8009e3f8) */
/* WARNING: Removing unreachable block (ram,0x8009e3f0) */
/* WARNING: Removing unreachable block (ram,0x8009e3e8) */
/* WARNING: Removing unreachable block (ram,0x8009e3e0) */
/* WARNING: Removing unreachable block (ram,0x8009e3d8) */
/* WARNING: Removing unreachable block (ram,0x8009ed70) */
/* WARNING: Removing unreachable block (ram,0x8009ed78) */
/* WARNING: Removing unreachable block (ram,0x8009ed80) */

void FUN_8009e3c8(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  byte bVar4;
  short sVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  uint uVar9;
  float *pfVar10;
  int iVar11;
  short *psVar12;
  int iVar13;
  char cVar14;
  char cVar15;
  char cVar16;
  char cVar17;
  int iVar18;
  short *psVar19;
  int iVar20;
  uint uVar21;
  int iVar22;
  short *psVar23;
  uint uVar25;
  uint uVar26;
  double dVar27;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double dVar28;
  double in_f30;
  double dVar29;
  double in_f31;
  double dVar30;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar31;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  undefined4 local_d0;
  uint uStack_cc;
  undefined8 local_c8;
  undefined8 local_c0;
  int local_b8;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  short *psVar24;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  uVar31 = FUN_8028680c();
  uVar9 = FUN_80022b0c();
  local_b8 = FUN_80020800();
  FUN_8000fb14();
  FUN_80022abc(uVar9,(uint)((ulonglong)uVar31 >> 0x20),0x7e);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(0xb,1);
  FUN_802570dc(0xd,1);
  FUN_8025d888(0);
  FUN_8025a608(0,0,0,1,0,0,2);
  FUN_8025a608(2,0,0,1,0,0,2);
  FUN_8025a5bc(1);
  FUN_80259288(0);
  pfVar10 = (float *)FUN_8000f56c();
  FUN_8025d80c(pfVar10,0);
  FUN_802475e4(pfVar10,(float *)&DAT_80397420);
  FUN_8007d7ec();
  FUN_80070540();
  iVar11 = FUN_80008b4c(-1);
  if ((short)iVar11 != 1) {
    psVar12 = FUN_8000facc();
    FUN_8005d264(0,0xff,0xff,0xff,0xff);
    cVar17 = -1;
    cVar16 = -1;
    cVar15 = -1;
    cVar14 = -1;
    iVar11 = 0;
    FUN_80022a88(0);
    iVar22 = 0;
    psVar23 = (short *)(uVar9 - 0xa0);
    do {
      psVar24 = psVar23 + 0x50;
      iVar20 = (&DAT_8039c138)[(uint)(*(byte *)(psVar23 + 0x95) >> 1) * 4];
      iVar18 = (&DAT_8039c140)[(uint)(*(byte *)(psVar23 + 0x95) >> 1) * 4];
      if (((((1 << iVar22 & (&DAT_8039c878)[(int)uVar31]) != 0) &&
           (bVar4 = *(byte *)((int)psVar23 + 299), (bVar4 >> 2 & 3) == 0)) &&
          ((bVar4 >> 1 & 1) != 0)) && ((psVar23[99] != -1 && ((bVar4 & 1) == 0)))) {
        uStack_cc = (int)psVar23[0x5b] ^ 0x80000000;
        fVar1 = FLOAT_803dffd8 * (float)((double)CONCAT44(0x43300000,uStack_cc) - DOUBLE_803dffe0);
        uVar9 = *(uint *)(psVar23 + 0x8e);
        if ((uVar9 & 0x800000) == 0) {
          if ((uVar9 & 0x200) == 0) {
            if ((*(uint *)(psVar23 + 0x90) & 0x400000) != 0) {
              local_c0 = (double)CONCAT44(0x43300000,(int)psVar23[0x53] ^ 0x80000000U);
              if ((float)(local_c0 - DOUBLE_803dffe0) <= fVar1) {
                local_c0 = (double)CONCAT44(0x43300000,(int)psVar23[0x53] ^ 0x80000000U);
                fVar1 = (float)(local_c0 - DOUBLE_803dffe0) / fVar1;
                fVar2 = FLOAT_803dffdc;
                if ((FLOAT_803dffdc <= fVar1) && (fVar2 = fVar1, FLOAT_803dffd4 < fVar1)) {
                  fVar2 = FLOAT_803dffd4;
                }
                local_c0 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)psVar23 + 0xaf));
                uVar21 = (uint)((float)(local_c0 - DOUBLE_803dfff8) * fVar2);
                local_c8 = (double)(longlong)(int)uVar21;
                goto LAB_8009e8e0;
              }
            }
            if ((uVar9 & 0x100) != 0) {
              local_c0 = (double)CONCAT44(0x43300000,(int)psVar23[0x53] ^ 0x80000000U);
              if ((float)(local_c0 - DOUBLE_803dffe0) <= fVar1) {
                local_c0 = (double)CONCAT44(0x43300000,(int)psVar23[0x53] ^ 0x80000000U);
                fVar1 = (float)(local_c0 - DOUBLE_803dffe0) / fVar1;
                fVar2 = FLOAT_803dffdc;
                if ((FLOAT_803dffdc <= fVar1) && (fVar2 = fVar1, FLOAT_803dffd4 < fVar1)) {
                  fVar2 = FLOAT_803dffd4;
                }
                local_c0 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)psVar23 + 0xaf));
                uVar21 = (uint)((float)(local_c0 - DOUBLE_803dfff8) * fVar2);
                local_c8 = (double)(longlong)(int)uVar21;
                goto LAB_8009e8e0;
              }
            }
            if ((uVar9 & 0x100) == 0) {
              uVar21 = (uint)*(byte *)((int)psVar23 + 0xaf);
            }
            else {
              local_c0 = (double)CONCAT44(0x43300000,(int)psVar23[0x53] ^ 0x80000000);
              fVar1 = (fVar1 - ((float)(local_c0 - DOUBLE_803dffe0) - fVar1)) / fVar1;
              fVar2 = FLOAT_803dffdc;
              if ((FLOAT_803dffdc <= fVar1) && (fVar2 = fVar1, FLOAT_803dffd4 < fVar1)) {
                fVar2 = FLOAT_803dffd4;
              }
              local_c0 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)psVar23 + 0xaf));
              uVar21 = (uint)((float)(local_c0 - DOUBLE_803dfff8) * fVar2);
              local_c8 = (double)(longlong)(int)uVar21;
            }
          }
          else {
            local_c0 = (double)CONCAT44(0x43300000,(int)psVar23[0x53] ^ 0x80000000);
            local_c8 = (double)CONCAT44(0x43300000,uStack_cc);
            fVar1 = (float)(local_c0 - DOUBLE_803dffe0) / (float)(local_c8 - DOUBLE_803dffe0);
            fVar2 = FLOAT_803dffdc;
            if ((FLOAT_803dffdc <= fVar1) && (fVar2 = fVar1, FLOAT_803dffd4 < fVar1)) {
              fVar2 = FLOAT_803dffd4;
            }
            local_c0 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)psVar23 + 0xaf));
            uVar21 = (uint)((float)(local_c0 - DOUBLE_803dfff8) * fVar2);
            local_c8 = (double)(longlong)(int)uVar21;
          }
        }
        else {
          local_c8 = (double)CONCAT44(0x43300000,uStack_cc);
          fVar1 = (float)((double)CONCAT44(0x43300000,(int)psVar23[0x53] ^ 0x80000000) -
                         DOUBLE_803dffe0) / (float)(local_c8 - DOUBLE_803dffe0);
          fVar2 = FLOAT_803dffdc;
          if ((FLOAT_803dffdc <= fVar1) && (fVar2 = fVar1, FLOAT_803dffd4 < fVar1)) {
            fVar2 = FLOAT_803dffd4;
          }
          uStack_cc = (uint)*(byte *)((int)psVar23 + 0xaf);
          local_c8 = (double)CONCAT44(0x43300000,uStack_cc - 0xff ^ 0x80000000);
          uVar21 = (uint)((float)(local_c8 - DOUBLE_803dffe0) * fVar2 +
                         (float)((double)CONCAT44(0x43300000,uStack_cc) - DOUBLE_803dfff8));
        }
LAB_8009e8e0:
        local_d0 = 0x43300000;
        uVar26 = 0;
        uVar25 = 0;
        dVar30 = (double)*(float *)(psVar23 + 0x98);
        dVar29 = (double)*(float *)(psVar23 + 0x9a);
        dVar28 = (double)*(float *)(psVar23 + 0x9c);
        local_c0 = (double)CONCAT44(0x43300000,(uint)(ushort)psVar23[0x92]);
        dVar27 = (double)(FLOAT_803e0090 * (float)(local_c0 - DOUBLE_803dfff8));
        if (((uVar9 & 0x400000) != 0) && (local_b8 == 0)) {
          dVar27 = (double)(float)((double)FLOAT_803dffd8 * dVar27);
          uVar9 = FUN_80022264(1,10);
          local_c0 = (double)CONCAT44(0x43300000,uVar9 ^ 0x80000000);
          dVar27 = (double)(float)(dVar27 + (double)(float)(dVar27 / (double)(float)(local_c0 -
                                                                                    DOUBLE_803dffe0)
                                                           ));
        }
        uVar9 = *(uint *)(psVar23 + 0x8e);
        if ((uVar9 & 0x4000000) == 0) {
          uVar26 = 0;
          if ((uVar9 & 0x2000000) == 0) {
            if ((uVar9 & 0x80000) == 0) {
              uVar25 = (uint)-*psVar12;
            }
            else if (((*(uint *)(psVar23 + 0x90) & 0x400) == 0) || (iVar20 == 0)) {
              uVar25 = (uint)-*psVar12;
              uVar26 = (uint)psVar12[1];
            }
            else {
              local_e0 = *(float *)(psVar12 + 6) - *(float *)(iVar20 + 0x18);
              local_dc = *(float *)(psVar12 + 8) - *(float *)(iVar20 + 0x1c);
              local_d8 = *(float *)(psVar12 + 10) - *(float *)(iVar20 + 0x20);
              FUN_80247ef8(&local_e0,&local_e0);
              if (ABS(local_e0) <= ABS(local_d8)) {
                FUN_80021884();
                iVar13 = FUN_80021884();
                sVar5 = (short)iVar13;
              }
              else {
                FUN_80021884();
                iVar13 = FUN_80021884();
                sVar5 = (short)iVar13;
              }
              uVar26 = (uint)(short)(sVar5 + -0x3800);
              iVar13 = FUN_80021884();
              uVar25 = (uint)(short)iVar13;
            }
          }
          else {
            uVar25 = 0;
          }
        }
        FUN_80293674(uVar25 & 0xffff,&local_f0,&local_ec);
        FUN_80293674(uVar26 & 0xffff,&local_e8,&local_e4);
        if ((*(uint *)(psVar23 + 0x90) & 0x4000000) == 0) {
          if ((*(uint *)(psVar23 + 0x90) & 0x8000000) != 0) {
            FUN_80293674((uint)DAT_803ddeea + ((int)psVar24 * 0x100 & 0xff00U) & 0xffff,&local_f4,
                         &local_f8);
          }
        }
        else {
          FUN_80293674((uint)DAT_803ddee8 + ((int)psVar24 * 0x100 & 0xff00U) & 0xffff,&local_f4,
                       &local_f8);
        }
        if ((iVar20 != 0) && ((*(uint *)(psVar23 + 0x90) & 0x80) != 0)) {
          uVar21 = (int)(uVar21 * *(byte *)(iVar20 + 0x36)) >> 8;
        }
        if (iVar11 != iVar18) {
          FUN_8004c460(iVar18,0);
          iVar11 = iVar18;
        }
        uVar9 = *(uint *)(psVar23 + 0x90);
        if ((uVar9 & 0x40) == 0) {
          if ((uVar9 & 0x8000) == 0) {
            if (cVar17 != '\x01') {
              FUN_80079b3c();
              FUN_8007986c();
              FUN_80079980();
              cVar17 = '\x01';
            }
          }
          else if (cVar17 != '\x04') {
            FUN_8007c54c((byte)uVar9 & 0x20);
            cVar17 = '\x04';
          }
        }
        else if (cVar17 != '\0') {
          FUN_80079b3c();
          FUN_800792fc();
          FUN_80079980();
          cVar17 = '\0';
        }
        if ((*(uint *)(psVar23 + 0x90) & 1) == 0) {
          if (cVar14 != '\x01') {
            FUN_80070434(1);
            FUN_8025c754(7,0,0,7,0);
            cVar14 = '\x01';
          }
          if ((*(uint *)(psVar23 + 0x8e) & 0x10) == 0) {
            if (cVar15 != '\x02') {
              FUN_8000f7a0();
              FUN_8007048c(1,3,0);
              cVar15 = '\x02';
            }
          }
          else if (cVar15 != '\x01') {
            FUN_8000f85c();
            FUN_8007048c(1,3,0);
            cVar15 = '\x01';
          }
          if ((*(uint *)(psVar23 + 0x90) & 0x800) == 0) {
            if (cVar16 != '\x02') {
              FUN_8025cce8(1,4,5,5);
              cVar16 = '\x02';
            }
          }
          else if (cVar16 != '\x01') {
            FUN_8025cce8(1,4,1,5);
            cVar16 = '\x01';
          }
        }
        else if (cVar16 != '\0') {
          FUN_8000f7a0();
          FUN_8007048c(1,3,1);
          FUN_8025cce8(0,1,0,5);
          FUN_80070434(0);
          FUN_8025c754(4,0xfe,0,4,0xfe);
          cVar16 = '\0';
          cVar15 = '\0';
          cVar14 = '\0';
        }
        dVar30 = (double)(float)(dVar30 - (double)FLOAT_803dda58);
        dVar28 = (double)(float)(dVar28 - (double)FLOAT_803dda5c);
        FUN_80259000(0x80,4,4);
        iVar18 = 4;
        psVar19 = psVar24;
        do {
          fVar1 = (float)(dVar27 * (double)((longlong)(double)*psVar19 * 0x3ff0000000000000));
          fVar2 = (float)(dVar27 * (double)((longlong)(double)psVar19[1] * 0x3ff0000000000000));
          fVar3 = (float)(dVar27 * (double)((longlong)(double)psVar19[2] * 0x3ff0000000000000));
          if ((*(uint *)(psVar23 + 0x90) & 0xc000000) == 0) {
            fVar8 = local_f0 * fVar3 * local_e4 + fVar1 * local_ec + local_f0 * fVar2 * local_e8;
            fVar6 = fVar2 * local_e4 + -fVar3 * local_e8;
            fVar1 = local_ec * fVar3 * local_e4 + -fVar1 * local_f0 + local_ec * fVar2 * local_e8;
          }
          else {
            fVar7 = fVar1 * local_f8 - fVar2 * local_f4;
            fVar1 = fVar1 * local_f4 + fVar2 * local_f8;
            fVar2 = fVar1 * local_e8;
            fVar8 = local_f0 * fVar3 * local_e4 + fVar7 * local_ec + local_f0 * fVar2;
            fVar6 = fVar1 * local_e4 + -fVar3 * local_e8;
            fVar1 = local_ec * fVar3 * local_e4 + -fVar7 * local_f0 + local_ec * fVar2;
          }
          fVar2 = pfVar10[0xb] +
                  pfVar10[10] * (float)(dVar28 + (double)fVar1) +
                  pfVar10[8] * (float)(dVar30 + (double)fVar8) +
                  pfVar10[9] * (float)(dVar29 + (double)fVar6);
          if (FLOAT_803dc3f0 < fVar2) {
            local_c0 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
            uVar21 = (uint)(((float)(local_c0 - DOUBLE_803dffe0) * (-fVar2 - FLOAT_803e0094)) /
                           (-FLOAT_803dc3f0 - FLOAT_803e0094));
            local_c8 = (double)(longlong)(int)uVar21;
          }
          DAT_cc008000 = (float)(dVar30 + (double)fVar8);
          DAT_cc008000 = (float)(dVar29 + (double)fVar6);
          DAT_cc008000 = (float)(dVar28 + (double)fVar1);
          DAT_cc008000._0_1_ = *(undefined *)(psVar23 + 0x56);
          DAT_cc008000._0_1_ = *(undefined *)((int)psVar23 + 0xad);
          DAT_cc008000._0_1_ = *(undefined *)(psVar23 + 0x57);
          DAT_cc008000._0_1_ = (char)uVar21;
          DAT_cc008000._0_2_ = psVar19[4];
          DAT_cc008000._0_2_ = psVar19[5];
          psVar19 = psVar19 + 8;
          iVar18 = iVar18 + -1;
        } while (iVar18 != 0);
      }
      iVar22 = iVar22 + 1;
      psVar23 = psVar24;
    } while (iVar22 < 0x19);
    if (DAT_803dded4 != '\0') {
      FUN_8009afd0();
      DAT_803dded4 = '\0';
    }
  }
  FUN_80286858();
  return;
}

