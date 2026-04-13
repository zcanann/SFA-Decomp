// Function: FUN_801323ac
// Entry: 801323ac
// Size: 5296 bytes

/* WARNING: Removing unreachable block (ram,0x8013383c) */
/* WARNING: Removing unreachable block (ram,0x80133834) */
/* WARNING: Removing unreachable block (ram,0x8013382c) */
/* WARNING: Removing unreachable block (ram,0x80133824) */
/* WARNING: Removing unreachable block (ram,0x8013381c) */
/* WARNING: Removing unreachable block (ram,0x80133814) */
/* WARNING: Removing unreachable block (ram,0x8013380c) */
/* WARNING: Removing unreachable block (ram,0x80133804) */
/* WARNING: Removing unreachable block (ram,0x801337fc) */
/* WARNING: Removing unreachable block (ram,0x801323fc) */
/* WARNING: Removing unreachable block (ram,0x801323f4) */
/* WARNING: Removing unreachable block (ram,0x801323ec) */
/* WARNING: Removing unreachable block (ram,0x801323e4) */
/* WARNING: Removing unreachable block (ram,0x801323dc) */
/* WARNING: Removing unreachable block (ram,0x801323d4) */
/* WARNING: Removing unreachable block (ram,0x801323cc) */
/* WARNING: Removing unreachable block (ram,0x801323c4) */
/* WARNING: Removing unreachable block (ram,0x801323bc) */

void FUN_801323ac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,short *param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  uint uVar4;
  ushort uVar5;
  short *psVar6;
  byte bVar10;
  int iVar7;
  ushort *puVar8;
  int iVar9;
  short *psVar11;
  undefined4 uVar12;
  undefined4 extraout_r4;
  uint uVar13;
  undefined *puVar14;
  uint uVar15;
  uint uVar16;
  byte bVar18;
  short sVar17;
  uint uVar19;
  double dVar20;
  undefined8 extraout_f1;
  undefined8 uVar21;
  double dVar22;
  double dVar23;
  double dVar24;
  double dVar25;
  double in_f23;
  double dVar26;
  double in_f24;
  double dVar27;
  double in_f25;
  double in_f26;
  double dVar28;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar29;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar30;
  uint local_168;
  uint local_164;
  uint local_160;
  uint local_15c;
  uint local_158;
  uint local_154;
  undefined4 local_150;
  uint local_14c;
  undefined4 local_148;
  undefined8 local_140;
  undefined4 local_138;
  uint uStack_134;
  undefined8 local_130;
  undefined4 local_128;
  uint uStack_124;
  undefined4 local_120;
  uint uStack_11c;
  undefined4 local_118;
  uint uStack_114;
  undefined4 local_110;
  uint uStack_10c;
  undefined4 local_108;
  uint uStack_104;
  undefined4 local_100;
  uint uStack_fc;
  undefined4 local_f8;
  uint uStack_f4;
  undefined4 local_f0;
  uint uStack_ec;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  uint uStack_dc;
  undefined4 local_d8;
  uint uStack_d4;
  undefined4 local_d0;
  uint uStack_cc;
  undefined4 local_c8;
  uint uStack_c4;
  undefined4 local_c0;
  uint uStack_bc;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
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
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  FUN_80286834();
  uVar19 = 0;
  bVar18 = 0;
  bVar10 = 0;
  bVar3 = false;
  dVar28 = (double)FLOAT_803e2e98;
  local_148 = DAT_803e2e94;
  dVar20 = dVar28;
  psVar6 = (short *)FUN_8002bac4();
  if (psVar6 != (short *)0x0) {
    if (*(int *)(psVar6 + 0x18) == 0) {
      param_2 = (double)*(float *)(psVar6 + 10);
      uVar4 = FUN_8005b128();
      uVar4 = uVar4 & 0xff;
    }
    else {
      uVar4 = (uint)*(byte *)(*(int *)(psVar6 + 0x18) + 0xac);
    }
    while ((!bVar3 && (bVar18 < 0x19))) {
      if ((uVar4 == (byte)(&DAT_8031d15e)[(uint)bVar18 * 8]) &&
         (uVar13 = FUN_80020078((uint)(ushort)(&DAT_8031d15c)[(uint)bVar18 * 4]), uVar13 != 0)) {
        bVar3 = true;
      }
      else {
        bVar18 = bVar18 + 1;
      }
    }
    if (bVar3) {
      puVar14 = (&PTR_DAT_8031d158)[(uint)bVar18 * 2];
      if (puVar14[0x12] == '\0') {
        fVar1 = *(float *)(psVar6 + 0xc);
        fVar2 = *(float *)(psVar6 + 0x10);
      }
      else {
        fVar1 = *(float *)(psVar6 + 0x10);
        fVar2 = *(float *)(psVar6 + 0xc);
      }
      DAT_803de5dc = puVar14[0x12] != '\0';
      dVar27 = (double)fVar2;
      dVar26 = (double)fVar1;
      fVar1 = *(float *)(psVar6 + 0xe);
      local_140 = (double)(longlong)(int)fVar1;
      dVar22 = DOUBLE_803e2ee0;
      for (; bVar10 < (byte)(&DAT_8031d15f)[(uint)bVar18 * 8]; bVar10 = bVar10 + 1) {
        iVar7 = (uint)bVar10 * 0x14;
        psVar11 = (short *)(puVar14 + iVar7);
        local_140 = (double)CONCAT44(0x43300000,(int)*psVar11 ^ 0x80000000);
        if ((((((double)(float)(local_140 - dVar22) <= dVar26) &&
              (local_140 = (double)CONCAT44(0x43300000,(int)psVar11[1] ^ 0x80000000),
              dVar26 < (double)(float)(local_140 - dVar22))) &&
             (local_140 = (double)CONCAT44(0x43300000,(int)psVar11[2] ^ 0x80000000),
             (double)(float)(local_140 - dVar22) <= dVar27)) &&
            ((local_140 = (double)CONCAT44(0x43300000,(int)psVar11[3] ^ 0x80000000),
             dVar27 < (double)(float)(local_140 - dVar22) &&
             (sVar17 = (short)(int)fVar1, psVar11[4] <= sVar17)))) &&
           ((sVar17 < psVar11[5] && (uVar4 = FUN_80020078((uint)(ushort)psVar11[6]), uVar4 != 0))))
        {
          bVar10 = 0;
          uVar4 = (uint)*(ushort *)(puVar14 + iVar7 + 0x10);
          if (uVar4 != 0) {
            uVar19 = uVar4;
          }
          if (DAT_803de5ac == uVar4) {
            DAT_803de5c8 = -0x8000;
            DAT_803de5ca = -0x8000;
            DAT_803dc838 = 0x7fff;
            DAT_803dc83a = 0x7fff;
            for (; bVar10 < (byte)(&DAT_8031d15f)[(uint)bVar18 * 8]; bVar10 = bVar10 + 1) {
              param_11 = (short *)(puVar14 + (uint)bVar10 * 0x14);
              if (uVar19 == (ushort)param_11[8]) {
                if (*param_11 < DAT_803dc838) {
                  DAT_803dc838 = *param_11;
                }
                if (DAT_803de5c8 < param_11[1]) {
                  DAT_803de5c8 = param_11[1];
                }
                param_12 = (int)DAT_803dc83a;
                if (param_11[2] < param_12) {
                  DAT_803dc83a = param_11[2];
                }
                psVar11 = param_11 + 3;
                param_11 = (short *)(int)DAT_803de5ca;
                if ((int)param_11 < (int)*psVar11) {
                  DAT_803de5ca = *psVar11;
                }
              }
            }
            DAT_803de5c6 = puVar14[iVar7 + 0xe];
            DAT_803de5c7 = puVar14[iVar7 + 0xf];
          }
          break;
        }
      }
    }
    if (((DAT_803dc818 == '\0') && (DAT_803de43a == '\0')) ||
       (uVar4 = FUN_80020078(0x58d), uVar4 != 0)) {
      uVar19 = 0;
    }
    uVar30 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    uVar12 = (undefined4)uVar30;
    uVar21 = extraout_f1;
    if ((((((int)((ulonglong)uVar30 >> 0x20) == 0x44) ||
          (((DAT_803dc818 == '\0' && (DAT_803de43a == '\0')) ||
           (iVar7 = FUN_8000fb04(), (short)iVar7 != 0)))) ||
         (((psVar6[0x58] & 0x1000U) != 0 || (uVar4 = FUN_80296328((int)psVar6), uVar4 == 0)))) ||
        (DAT_803de400 != '\0')) || (DAT_803de3db != '\0')) {
      uVar19 = 0;
      DAT_803de5b0 = DAT_803de5b0 - 0x20;
      if ((short)DAT_803de5b0 < 0) {
        DAT_803de5b0 = 0;
      }
      else if (0xff < (short)DAT_803de5b0) {
        DAT_803de5b0 = 0xff;
      }
      DAT_803dc828 = DAT_803dc828 - 10;
      if ((int)DAT_803dc828 < 0) {
        DAT_803dc828 = 0;
      }
      else if (500 < (int)DAT_803dc828) {
        DAT_803dc828 = 500;
      }
      DAT_803dc82c = DAT_803dc82c - 10;
      if ((int)DAT_803dc82c < 0) {
        DAT_803dc82c = 0;
      }
      else if (500 < (int)DAT_803dc82c) {
        DAT_803dc82c = 500;
      }
    }
    else {
      DAT_803dc82c = DAT_803dc82c + 10;
      if ((int)DAT_803dc82c < 0) {
        DAT_803dc82c = 0;
      }
      else if (100 < (int)DAT_803dc82c) {
        DAT_803dc82c = 100;
      }
      DAT_803de5b0 = DAT_803de5b0 + 0x20;
      if ((short)DAT_803de5b0 < 0) {
        DAT_803de5b0 = 0;
      }
      else if (0xff < (short)DAT_803de5b0) {
        DAT_803de5b0 = 0xff;
      }
    }
    if (DAT_803de5ac == uVar19) {
      DAT_803de5b2 = DAT_803de5b2 + 0x20;
      if ((short)DAT_803de5b2 < 0) {
        DAT_803de5b2 = 0;
      }
      else if ((short)DAT_803de5b0 < (short)DAT_803de5b2) {
        DAT_803de5b2 = DAT_803de5b0;
      }
    }
    else {
      DAT_803de5b2 = DAT_803de5b2 - 0x20;
      if ((short)DAT_803de5b2 < 0) {
        DAT_803de5b2 = 0;
        if (DAT_803de5bc != 0) {
          uVar21 = FUN_80054484();
          DAT_803de5bc = 0;
          DAT_803de5ac = 0;
          uVar12 = extraout_r4;
        }
        if (uVar19 != 0) {
          DAT_803de5bc = FUN_80054ed0(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,uVar19,uVar12,param_11,param_12,param_13,param_14,param_15,
                                      param_16);
          DAT_803de5ac = uVar19;
        }
      }
    }
    if (DAT_803de5b0 != 0) {
      puVar8 = (ushort *)FUN_80017400(0x83);
      if (((DAT_803de5c4 == '\x02') && (DAT_803de422 != 0)) && (-1 < DAT_803dc6d6)) {
        uVar19 = 200;
      }
      else {
        uVar19 = 0x78;
      }
      if ((int)DAT_803dc828 < (int)uVar19) {
        uVar4 = DAT_803dc828 + (uint)DAT_803dc070 * 8;
        DAT_803dc828 = uVar19;
        if ((int)uVar4 < (int)uVar19) {
          DAT_803dc828 = uVar4;
        }
      }
      else {
        uVar4 = DAT_803dc828 + (uint)DAT_803dc070 * -8;
        DAT_803dc828 = uVar19;
        if ((int)uVar19 < (int)uVar4) {
          DAT_803dc828 = uVar4;
        }
      }
      puVar8[4] = (short)DAT_803dc828 - 8;
      DAT_803de5b8 = 0x1b8 - DAT_803dc82c;
      puVar8[0xb] = (ushort)DAT_803de5b8;
      FUN_8012c9e8(0x32,(int)(short)DAT_803de5b8,(short)DAT_803dc828,(short)DAT_803dc82c,
                   (int)(short)DAT_803de5b0 & 0xff,1);
      FUN_8025da88(0x32,DAT_803de5b8,DAT_803dc828,DAT_803dc82c);
      uVar4 = DAT_803dc82c;
      uVar19 = DAT_803dc828;
      if (DAT_803de5c4 == '\x01') {
        FUN_80133aa0();
        if (DAT_803de5b4 == 0) {
          FUN_801338a4();
          FUN_80019884(puVar8[1],puVar8[5],1);
          FUN_8001983c(1);
          uVar19 = DAT_803dc828;
          if ((int)DAT_803dc828 < 3) {
            uVar19 = 2;
          }
          puVar8[4] = (ushort)uVar19;
          uVar5 = *puVar8;
          if (puVar8[4] < uVar5) {
            uVar5 = puVar8[4];
          }
          puVar8[4] = uVar5;
          uVar19 = DAT_803dc82c;
          if ((int)DAT_803dc82c < 3) {
            uVar19 = 2;
          }
          puVar8[5] = (ushort)uVar19;
          FUN_80019884(*puVar8,puVar8[5],2);
          FUN_80019940(0,0xff,0,(byte)DAT_803de5b0);
          iVar7 = FUN_80019b4c();
          uVar21 = FUN_80019b54(3,3);
          FUN_800168a8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x459);
          FUN_80019b54(iVar7,3);
          FUN_8001983c(2);
        }
      }
      else if (DAT_803de5c4 < '\x01') {
        if (-1 < DAT_803de5c4) {
          if (DAT_803de5bc == 0) {
            FUN_80019884(puVar8[1],puVar8[5],1);
            FUN_8001983c(1);
            uVar19 = DAT_803dc828;
            if ((int)DAT_803dc828 < 3) {
              uVar19 = 2;
            }
            puVar8[4] = (ushort)uVar19;
            uVar5 = *puVar8;
            if (puVar8[4] < uVar5) {
              uVar5 = puVar8[4];
            }
            puVar8[4] = uVar5;
            uVar19 = DAT_803dc82c;
            if ((int)DAT_803dc82c < 3) {
              uVar19 = 2;
            }
            puVar8[5] = (ushort)uVar19;
            FUN_80019884(*puVar8,puVar8[5],2);
            FUN_80019940(0,0xff,0,(byte)DAT_803de5b0);
            iVar7 = FUN_80019b4c();
            uVar21 = FUN_80019b54(3,3);
            FUN_800168a8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x458);
            FUN_80019b54(iVar7,3);
            FUN_8001983c(2);
          }
          else {
            uVar15 = (uint)*(ushort *)(DAT_803de5bc + 10);
            uVar16 = (uint)*(ushort *)(DAT_803de5bc + 0xc);
            local_140 = (double)CONCAT44(0x43300000,uVar15);
            uVar13 = (uint)DAT_803de5c8;
            uStack_134 = uVar13 - (int)DAT_803dc838 ^ 0x80000000;
            local_138 = 0x43300000;
            FLOAT_803dc854 =
                 (float)(local_140 - DOUBLE_803e2ee8) /
                 (float)((double)CONCAT44(0x43300000,uStack_134) - DOUBLE_803e2ee0);
            local_130 = (double)CONCAT44(0x43300000,DAT_803dc828 ^ 0x80000000);
            fVar1 = (float)(local_130 - DOUBLE_803e2ee0) /
                    (float)((double)CONCAT44(0x43300000,uVar15) - DOUBLE_803e2ee8);
            fVar2 = (float)((double)CONCAT44(0x43300000,DAT_803dc82c ^ 0x80000000) - DOUBLE_803e2ee0
                           ) / (float)((double)CONCAT44(0x43300000,uVar16) - DOUBLE_803e2ee8);
            if (fVar1 < fVar2) {
              fVar2 = fVar1;
            }
            FLOAT_803dc820 = FLOAT_803dc824;
            if (fVar2 < FLOAT_803dc824) {
              FLOAT_803dc820 = fVar2;
            }
            if (DAT_803de5dc == '\0') {
              fVar1 = -*(float *)(psVar6 + 0xc) +
                      (float)((double)CONCAT44(0x43300000,uVar13 ^ 0x80000000) - DOUBLE_803e2ee0);
              fVar2 = -*(float *)(psVar6 + 0x10) +
                      (float)((double)CONCAT44(0x43300000,(int)DAT_803de5ca ^ 0x80000000) -
                             DOUBLE_803e2ee0);
            }
            else {
              fVar1 = -*(float *)(psVar6 + 0x10) +
                      (float)((double)CONCAT44(0x43300000,uVar13 ^ 0x80000000) - DOUBLE_803e2ee0);
              fVar2 = *(float *)(psVar6 + 0xc) -
                      (float)((double)CONCAT44(0x43300000,(int)DAT_803dc83a ^ 0x80000000) -
                             DOUBLE_803e2ee0);
            }
            dVar27 = (double)fVar1;
            dVar26 = (double)fVar2;
            uStack_114 = DAT_803dc828 ^ 0x80000000;
            dVar29 = (double)FLOAT_803dc81c;
            fVar1 = (float)((double)(float)((double)CONCAT44(0x43300000,uVar15) - DOUBLE_803e2ee8) *
                           dVar29);
            dVar22 = (double)(((float)((double)CONCAT44(0x43300000,uStack_114) - DOUBLE_803e2ee0) -
                              fVar1) * FLOAT_803e2e9c);
            if (dVar22 < (double)FLOAT_803e2e98) {
              dVar22 = (double)FLOAT_803e2e98;
            }
            dVar22 = -dVar22;
            uStack_124 = DAT_803dc82c ^ 0x80000000;
            local_128 = 0x43300000;
            local_130 = (double)CONCAT44(0x43300000,uVar16);
            fVar2 = (float)((double)(float)(local_130 - DOUBLE_803e2ee8) * dVar29);
            dVar24 = (double)(((float)((double)CONCAT44(0x43300000,uStack_124) - DOUBLE_803e2ee0) -
                              fVar2) * FLOAT_803e2e9c);
            if (dVar24 < (double)FLOAT_803e2e98) {
              dVar24 = (double)FLOAT_803e2e98;
            }
            dVar24 = -dVar24;
            dVar25 = (double)FLOAT_803e2e98;
            uStack_11c = uVar15;
            if (dVar25 == dVar22) {
              uStack_114 = (int)DAT_803dc828 / 2 ^ 0x80000000;
              dVar23 = (double)(float)(dVar29 * (double)(float)(dVar27 * (double)FLOAT_803dc854) -
                                      (double)(float)((double)CONCAT44(0x43300000,uStack_114) -
                                                     DOUBLE_803e2ee0));
              if (dVar23 < dVar25) {
                dVar23 = dVar25;
              }
              uStack_11c = DAT_803dc828 ^ 0x80000000;
              dVar20 = (double)(fVar1 - (float)((double)CONCAT44(0x43300000,uStack_11c) -
                                               DOUBLE_803e2ee0));
              if (dVar23 < dVar20) {
                dVar20 = dVar23;
              }
            }
            dVar25 = (double)FLOAT_803e2e98;
            if (dVar25 == dVar24) {
              uStack_114 = (int)DAT_803dc82c / 2 ^ 0x80000000;
              dVar23 = (double)(float)(dVar29 * (double)(float)(dVar26 * (double)FLOAT_803dc854) -
                                      (double)(float)((double)CONCAT44(0x43300000,uStack_114) -
                                                     DOUBLE_803e2ee0));
              if (dVar23 < dVar25) {
                dVar23 = dVar25;
              }
              uStack_11c = DAT_803dc82c ^ 0x80000000;
              dVar28 = (double)(fVar2 - (float)((double)CONCAT44(0x43300000,uStack_11c) -
                                               DOUBLE_803e2ee0));
              if (dVar23 < dVar28) {
                dVar28 = dVar23;
              }
            }
            local_118 = 0x43300000;
            local_120 = 0x43300000;
            dVar25 = (double)(float)(dVar20 / dVar29);
            iVar7 = FUN_80286718(dVar25);
            local_118 = 0x43300000;
            dVar25 = (double)(float)(dVar29 * (double)(float)(dVar25 - (double)(float)((double)
                                                  CONCAT44(0x43300000,iVar7) - DOUBLE_803e2ee8)));
            dVar23 = (double)(float)(dVar28 / dVar29);
            uStack_114 = iVar7;
            iVar9 = FUN_80286718(dVar23);
            local_148._2_2_ = CONCAT11(0x84,(char)DAT_803de5b2);
            local_148 = CONCAT22(0x204d,local_148._2_2_);
            local_150 = local_148;
            FUN_80075534(0x32,DAT_803de5b8,uVar19 + 0x32,DAT_803de5b8 + uVar4,&local_150);
            uStack_11c = DAT_803de5b8 ^ 0x80000000;
            local_120 = 0x43300000;
            local_128 = 0x43300000;
            local_130 = (double)(longlong)(int)(FLOAT_803e2ea4 * FLOAT_803dc81c);
            uStack_124 = iVar9;
            FUN_80076144((double)(float)((double)(float)((double)FLOAT_803e2ea0 - dVar22) - dVar25),
                         (double)((float)((double)(float)((double)CONCAT44(0x43300000,uStack_11c) -
                                                         DOUBLE_803e2ee0) - dVar24) -
                                 (float)(dVar29 * (double)(float)(dVar23 - (double)(float)((double)
                                                  CONCAT44(0x43300000,iVar9) - DOUBLE_803e2ee8)))),
                         DAT_803de5bc,(int)(short)DAT_803de5b2 & 0xff,
                         (int)(FLOAT_803e2ea4 * FLOAT_803dc81c),uVar15 - iVar7,uVar16 - iVar9,iVar7,
                         iVar9);
            dVar25 = (double)(FLOAT_803e2e9c +
                             (float)((double)(float)((double)(FLOAT_803dc81c *
                                                              (float)(dVar27 * (double)
                                                  FLOAT_803dc854) + FLOAT_803e2ea0) - dVar20) -
                                    dVar22));
            uStack_134 = DAT_803de5b8 ^ 0x80000000;
            local_138 = 0x43300000;
            dVar24 = (double)(FLOAT_803e2e9c +
                             (float)((double)(float)((double)(FLOAT_803dc81c *
                                                              (float)(dVar26 * (double)
                                                  FLOAT_803dc854) +
                                                  (float)((double)CONCAT44(0x43300000,uStack_134) -
                                                         DOUBLE_803e2ee0)) - dVar28) - dVar24));
            local_148._2_2_ = DAT_803de5b2 & 0xff;
            local_148 = (uint)local_148._2_2_;
            FLOAT_803de5d8 = FLOAT_803e2ea8;
            FLOAT_803de5d4 = FLOAT_803e2eac;
            FLOAT_803de5d0 = FLOAT_803e2eac;
            local_140 = (double)CONCAT44(0x43300000,(int)*psVar6 ^ 0x80000000);
            dVar28 = (double)FUN_802945e0();
            dVar22 = (double)(float)((double)FLOAT_803de5d8 * dVar28);
            uStack_10c = (int)*psVar6 ^ 0x80000000;
            local_110 = 0x43300000;
            dVar28 = (double)FUN_80294964();
            dVar26 = (double)(float)((double)FLOAT_803de5d8 * dVar28);
            uStack_104 = (int)*psVar6 + 0x6000U ^ 0x80000000;
            local_108 = 0x43300000;
            dVar28 = (double)FUN_802945e0();
            dVar27 = (double)(float)((double)FLOAT_803de5d4 * dVar28);
            uStack_fc = (int)*psVar6 + 0x6000U ^ 0x80000000;
            local_100 = 0x43300000;
            dVar28 = (double)FUN_80294964();
            dVar29 = (double)(float)((double)FLOAT_803de5d4 * dVar28);
            uStack_f4 = (int)*psVar6 - 0x6000U ^ 0x80000000;
            local_f8 = 0x43300000;
            dVar28 = (double)FUN_802945e0();
            dVar20 = (double)(float)((double)FLOAT_803de5d0 * dVar28);
            uStack_ec = (int)*psVar6 - 0x6000U ^ 0x80000000;
            local_f0 = 0x43300000;
            dVar28 = (double)FUN_80294964();
            local_154 = local_148;
            FUN_80075b98((double)(float)(dVar25 - dVar22),(double)(float)(dVar24 - dVar26),
                         (double)(float)(dVar25 - dVar27),(double)(float)(dVar24 - dVar29),
                         (double)(float)(dVar25 - dVar20),
                         (double)(float)(dVar24 - (double)(float)((double)FLOAT_803de5d0 * dVar28)),
                         &local_154);
            local_148 = CONCAT22(0xffff,DAT_803de5b2) & 0xffff00ff;
            uStack_e4 = (int)*psVar6 ^ 0x80000000;
            local_e8 = 0x43300000;
            dVar28 = (double)FUN_802945e0();
            dVar22 = (double)(float)((double)FLOAT_803e2eb8 * dVar28);
            uStack_dc = (int)*psVar6 ^ 0x80000000;
            local_e0 = 0x43300000;
            dVar28 = (double)FUN_80294964();
            dVar26 = (double)(float)((double)FLOAT_803e2eb8 * dVar28);
            uStack_d4 = (int)*psVar6 + 0x6000U ^ 0x80000000;
            local_d8 = 0x43300000;
            dVar28 = (double)FUN_802945e0();
            dVar27 = (double)(float)((double)FLOAT_803e2ebc * dVar28);
            uStack_cc = (int)*psVar6 + 0x6000U ^ 0x80000000;
            local_d0 = 0x43300000;
            dVar28 = (double)FUN_80294964();
            dVar29 = (double)(float)((double)FLOAT_803e2ebc * dVar28);
            uStack_c4 = (int)*psVar6 - 0x6000U ^ 0x80000000;
            local_c8 = 0x43300000;
            dVar28 = (double)FUN_802945e0();
            dVar20 = (double)(float)((double)FLOAT_803e2ebc * dVar28);
            uStack_bc = (int)*psVar6 - 0x6000U ^ 0x80000000;
            local_c0 = 0x43300000;
            dVar28 = (double)FUN_80294964();
            local_158 = local_148;
            FUN_80075b98((double)(float)(dVar25 - dVar22),(double)(float)(dVar24 - dVar26),
                         (double)(float)(dVar25 - dVar27),(double)(float)(dVar24 - dVar29),
                         (double)(float)(dVar25 - dVar20),
                         (double)(float)(dVar24 - (double)(float)((double)FLOAT_803e2ebc * dVar28)),
                         &local_158);
          }
        }
      }
      else if (DAT_803de5c4 < '\x03') {
        if ((DAT_803de422 == 0) || (DAT_803dc6d6 < 0)) {
          if (DAT_803dc818 != '\0') {
            FUN_801338a4();
            FUN_80019884(puVar8[1],puVar8[5],1);
            FUN_8001983c(1);
            uVar19 = DAT_803dc828;
            if ((int)DAT_803dc828 < 3) {
              uVar19 = 2;
            }
            puVar8[4] = (ushort)uVar19;
            uVar5 = *puVar8;
            if (puVar8[4] < uVar5) {
              uVar5 = puVar8[4];
            }
            puVar8[4] = uVar5;
            uVar19 = DAT_803dc82c;
            if ((int)DAT_803dc82c < 3) {
              uVar19 = 2;
            }
            puVar8[5] = (ushort)uVar19;
            FUN_80019884(*puVar8,puVar8[5],2);
            FUN_80019940(0,0xff,0,(byte)DAT_803de5b0);
            iVar7 = FUN_80019b4c();
            uVar21 = FUN_80019b54(3,3);
            FUN_800168a8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x45a);
            FUN_80019b54(iVar7,3);
            FUN_8001983c(2);
          }
        }
        else if (DAT_803de5a8 == '\0') {
          FUN_80019884(puVar8[1],puVar8[5],1);
          FUN_8001983c(1);
          puVar8[4] = (ushort)DAT_803dc828;
          puVar8[5] = (ushort)DAT_803dc82c;
          FUN_80019884(puVar8[1],puVar8[5],2);
          uVar21 = FUN_80019940(0,0xff,0,(byte)DAT_803de422);
          FUN_800168a8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       DAT_803dc6d6 + 10000);
          FUN_8001983c(2);
        }
      }
      FUN_8025da88(0,0,0x280,0x1e0);
      uStack_bc = DAT_803de5b8 - 0x14 ^ 0x80000000;
      local_c0 = 0x43300000;
      FUN_80077318((double)FLOAT_803e2ec0,
                   (double)(float)((double)CONCAT44(0x43300000,uStack_bc) - DOUBLE_803e2ee0),
                   DAT_803de5c0,(int)(short)DAT_803de5b0 & 0xff,0x100);
      if (DAT_803de5b0 != 0) {
        local_14c = CONCAT22(0xffff,DAT_803de5b2) & 0xffff00ff;
        uVar19 = (uint)(short)((short)DAT_803de5b8 + -4);
        if ((DAT_803de5c4 == '\0') && (DAT_803de5bc != 0)) {
          if (FLOAT_803dc81c < FLOAT_803dc824) {
            uStack_c4 = uVar19 - 0x14 ^ 0x80000000;
            local_c0 = 0x43300000;
            local_15c = local_14c;
            local_c8 = 0x43300000;
            uStack_cc = uVar19 - 0x1a ^ 0x80000000;
            local_d0 = 0x43300000;
            uStack_bc = uStack_c4;
            FUN_80075b98((double)FLOAT_803e2ec4,
                         (double)(float)((double)CONCAT44(0x43300000,uStack_c4) - DOUBLE_803e2ee0),
                         (double)FLOAT_803e2ec8,
                         (double)(float)((double)CONCAT44(0x43300000,uStack_c4) - DOUBLE_803e2ee0),
                         (double)FLOAT_803e2ecc,
                         (double)(float)((double)CONCAT44(0x43300000,uStack_cc) - DOUBLE_803e2ee0),
                         &local_15c);
          }
          if (FLOAT_803dc820 < FLOAT_803dc81c) {
            uStack_c4 = uVar19 + 0x14 ^ 0x80000000;
            local_c0 = 0x43300000;
            local_160 = local_14c;
            local_c8 = 0x43300000;
            uStack_cc = uVar19 + 0x1a ^ 0x80000000;
            local_d0 = 0x43300000;
            uStack_bc = uStack_c4;
            FUN_80075b98((double)FLOAT_803e2ec4,
                         (double)(float)((double)CONCAT44(0x43300000,uStack_c4) - DOUBLE_803e2ee0),
                         (double)FLOAT_803e2ec8,
                         (double)(float)((double)CONCAT44(0x43300000,uStack_c4) - DOUBLE_803e2ee0),
                         (double)FLOAT_803e2ecc,
                         (double)(float)((double)CONCAT44(0x43300000,uStack_cc) - DOUBLE_803e2ee0),
                         &local_160);
          }
        }
        uStack_bc = uVar19 - 4 ^ 0x80000000;
        local_c0 = 0x43300000;
        uStack_c4 = uVar19 + 4 ^ 0x80000000;
        local_c8 = 0x43300000;
        uStack_cc = uVar19 ^ 0x80000000;
        local_d0 = 0x43300000;
        local_164 = local_14c;
        FUN_80075b98((double)FLOAT_803e2ed0,
                     (double)(float)((double)CONCAT44(0x43300000,uStack_bc) - DOUBLE_803e2ee0),
                     (double)FLOAT_803e2ed0,
                     (double)(float)((double)CONCAT44(0x43300000,uStack_c4) - DOUBLE_803e2ee0),
                     (double)FLOAT_803e2ed4,
                     (double)(float)((double)CONCAT44(0x43300000,uStack_cc) - DOUBLE_803e2ee0),
                     &local_164);
        local_168 = local_14c;
        uStack_d4 = uVar19 - 4 ^ 0x80000000;
        local_d8 = 0x43300000;
        uStack_dc = uVar19 + 4 ^ 0x80000000;
        local_e0 = 0x43300000;
        uStack_e4 = uVar19 ^ 0x80000000;
        local_e8 = 0x43300000;
        FUN_80075b98((double)FLOAT_803e2ed8,
                     (double)(float)((double)CONCAT44(0x43300000,uStack_d4) - DOUBLE_803e2ee0),
                     (double)FLOAT_803e2ed8,
                     (double)(float)((double)CONCAT44(0x43300000,uStack_dc) - DOUBLE_803e2ee0),
                     (double)FLOAT_803e2edc,
                     (double)(float)((double)CONCAT44(0x43300000,uStack_e4) - DOUBLE_803e2ee0),
                     &local_168);
      }
    }
  }
  FUN_80286880();
  return;
}

