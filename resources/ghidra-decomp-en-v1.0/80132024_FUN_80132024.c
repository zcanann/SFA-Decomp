// Function: FUN_80132024
// Entry: 80132024
// Size: 5296 bytes

/* WARNING: Removing unreachable block (ram,0x801334ac) */
/* WARNING: Removing unreachable block (ram,0x8013349c) */
/* WARNING: Removing unreachable block (ram,0x8013348c) */
/* WARNING: Removing unreachable block (ram,0x8013347c) */
/* WARNING: Removing unreachable block (ram,0x80133474) */
/* WARNING: Removing unreachable block (ram,0x80133484) */
/* WARNING: Removing unreachable block (ram,0x80133494) */
/* WARNING: Removing unreachable block (ram,0x801334a4) */
/* WARNING: Removing unreachable block (ram,0x801334b4) */
/* WARNING: Could not reconcile some variable overlaps */

void FUN_80132024(void)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  uint uVar4;
  ushort uVar5;
  short *psVar6;
  char cVar12;
  byte bVar13;
  int iVar7;
  short sVar11;
  ushort *puVar8;
  int iVar9;
  undefined4 uVar10;
  short *psVar14;
  uint uVar15;
  undefined *puVar16;
  uint uVar17;
  uint uVar18;
  byte bVar19;
  uint uVar20;
  undefined4 uVar21;
  double dVar22;
  double dVar23;
  double dVar24;
  double dVar25;
  double dVar26;
  double dVar27;
  undefined8 in_f23;
  double dVar28;
  undefined8 in_f24;
  double dVar29;
  undefined8 in_f25;
  undefined8 in_f26;
  double dVar30;
  undefined8 in_f27;
  double dVar31;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar32;
  undefined8 in_f31;
  double dVar33;
  uint local_168;
  uint local_164;
  uint local_160;
  uint local_15c;
  uint local_158;
  uint local_154;
  uint local_150;
  undefined4 local_14c;
  undefined4 local_148;
  double local_140;
  undefined4 local_138;
  uint uStack308;
  double local_130;
  undefined4 local_128;
  uint uStack292;
  undefined4 local_120;
  uint uStack284;
  undefined4 local_118;
  uint uStack276;
  undefined4 local_110;
  uint uStack268;
  undefined4 local_108;
  uint uStack260;
  undefined4 local_100;
  uint uStack252;
  undefined4 local_f8;
  uint uStack244;
  undefined4 local_f0;
  uint uStack236;
  undefined4 local_e8;
  uint uStack228;
  undefined4 local_e0;
  uint uStack220;
  undefined4 local_d8;
  uint uStack212;
  undefined4 local_d0;
  uint uStack204;
  undefined4 local_c8;
  uint uStack196;
  undefined4 local_c0;
  uint uStack188;
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar21 = 0;
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
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  __psq_st0(auStack136,(int)((ulonglong)in_f23 >> 0x20),0);
  __psq_st1(auStack136,(int)in_f23,0);
  FUN_802860d0();
  uVar20 = 0;
  bVar19 = 0;
  bVar13 = 0;
  bVar3 = false;
  dVar30 = (double)FLOAT_803e2208;
  local_148 = DAT_803e2204;
  dVar22 = dVar30;
  psVar6 = (short *)FUN_8002b9ec();
  if (psVar6 != (short *)0x0) {
    if (*(int *)(psVar6 + 0x18) == 0) {
      cVar12 = FUN_8005afac((double)*(float *)(psVar6 + 6),(double)*(float *)(psVar6 + 10));
    }
    else {
      cVar12 = *(char *)(*(int *)(psVar6 + 0x18) + 0xac);
    }
    while ((!bVar3 && (bVar19 < 0x19))) {
      if ((cVar12 == (&DAT_8031c50e)[(uint)bVar19 * 8]) &&
         (iVar7 = FUN_8001ffb4((&DAT_8031c50c)[(uint)bVar19 * 4]), iVar7 != 0)) {
        bVar3 = true;
      }
      else {
        bVar19 = bVar19 + 1;
      }
    }
    if (bVar3) {
      puVar16 = (&PTR_DAT_8031c508)[(uint)bVar19 * 2];
      if (puVar16[0x12] == '\0') {
        fVar1 = *(float *)(psVar6 + 0xc);
        fVar2 = *(float *)(psVar6 + 0x10);
      }
      else {
        fVar1 = *(float *)(psVar6 + 0x10);
        fVar2 = *(float *)(psVar6 + 0xc);
      }
      DAT_803dd95c = puVar16[0x12] != '\0';
      dVar29 = (double)fVar2;
      dVar28 = (double)fVar1;
      fVar2 = *(float *)(psVar6 + 0xe);
      local_140 = (double)(longlong)(int)fVar2;
      dVar23 = DOUBLE_803e2250;
      for (; bVar13 < (byte)(&DAT_8031c50f)[(uint)bVar19 * 8]; bVar13 = bVar13 + 1) {
        iVar7 = (uint)bVar13 * 0x14;
        psVar14 = (short *)(puVar16 + iVar7);
        local_140 = (double)CONCAT44(0x43300000,(int)*psVar14 ^ 0x80000000);
        if ((((((double)(float)(local_140 - dVar23) <= dVar28) &&
              (local_140 = (double)CONCAT44(0x43300000,(int)psVar14[1] ^ 0x80000000),
              dVar28 < (double)(float)(local_140 - dVar23))) &&
             (local_140 = (double)CONCAT44(0x43300000,(int)psVar14[2] ^ 0x80000000),
             (double)(float)(local_140 - dVar23) <= dVar29)) &&
            ((local_140 = (double)CONCAT44(0x43300000,(int)psVar14[3] ^ 0x80000000),
             dVar29 < (double)(float)(local_140 - dVar23) &&
             (sVar11 = (short)(int)fVar2, psVar14[4] <= sVar11)))) &&
           ((sVar11 < psVar14[5] && (iVar9 = FUN_8001ffb4(psVar14[6]), iVar9 != 0)))) {
          bVar13 = 0;
          uVar4 = (uint)*(ushort *)(puVar16 + iVar7 + 0x10);
          if (uVar4 != 0) {
            uVar20 = uVar4;
          }
          if (DAT_803dd92c == uVar4) {
            DAT_803dd948 = -0x8000;
            DAT_803dd94a = -0x8000;
            DAT_803dbbd0 = 0x7fff;
            DAT_803dbbd2 = 0x7fff;
            for (; bVar13 < (byte)(&DAT_8031c50f)[(uint)bVar19 * 8]; bVar13 = bVar13 + 1) {
              psVar14 = (short *)(puVar16 + (uint)bVar13 * 0x14);
              if (uVar20 == (ushort)psVar14[8]) {
                if (*psVar14 < DAT_803dbbd0) {
                  DAT_803dbbd0 = *psVar14;
                }
                if (DAT_803dd948 < psVar14[1]) {
                  DAT_803dd948 = psVar14[1];
                }
                if (psVar14[2] < DAT_803dbbd2) {
                  DAT_803dbbd2 = psVar14[2];
                }
                if (DAT_803dd94a < psVar14[3]) {
                  DAT_803dd94a = psVar14[3];
                }
              }
            }
            DAT_803dd946 = puVar16[iVar7 + 0xe];
            DAT_803dd947 = puVar16[iVar7 + 0xf];
          }
          break;
        }
      }
    }
    if (((DAT_803dbbb0 == '\0') && (DAT_803dd7ba == '\0')) ||
       (iVar7 = FUN_8001ffb4(0x58d), iVar7 != 0)) {
      uVar20 = 0;
    }
    iVar7 = (**(code **)(*DAT_803dca50 + 0x10))();
    if (((((iVar7 == 0x44) ||
          (((DAT_803dbbb0 == '\0' && (DAT_803dd7ba == '\0')) ||
           (sVar11 = FUN_8000fae4(), sVar11 != 0)))) ||
         (((psVar6[0x58] & 0x1000U) != 0 || (iVar7 = FUN_80295bc8(psVar6), iVar7 == 0)))) ||
        (DAT_803dd780 != '\0')) || (DAT_803dd75b != '\0')) {
      uVar20 = 0;
      DAT_803dd930 = DAT_803dd930 - 0x20;
      if ((short)DAT_803dd930 < 0) {
        DAT_803dd930 = 0;
      }
      else if (0xff < (short)DAT_803dd930) {
        DAT_803dd930 = 0xff;
      }
      DAT_803dbbc0 = DAT_803dbbc0 - 10;
      if ((int)DAT_803dbbc0 < 0) {
        DAT_803dbbc0 = 0;
      }
      else if (500 < (int)DAT_803dbbc0) {
        DAT_803dbbc0 = 500;
      }
      DAT_803dbbc4 = DAT_803dbbc4 - 10;
      if ((int)DAT_803dbbc4 < 0) {
        DAT_803dbbc4 = 0;
      }
      else if (500 < (int)DAT_803dbbc4) {
        DAT_803dbbc4 = 500;
      }
    }
    else {
      DAT_803dbbc4 = DAT_803dbbc4 + 10;
      if ((int)DAT_803dbbc4 < 0) {
        DAT_803dbbc4 = 0;
      }
      else if (100 < (int)DAT_803dbbc4) {
        DAT_803dbbc4 = 100;
      }
      DAT_803dd930 = DAT_803dd930 + 0x20;
      if ((short)DAT_803dd930 < 0) {
        DAT_803dd930 = 0;
      }
      else if (0xff < (short)DAT_803dd930) {
        DAT_803dd930 = 0xff;
      }
    }
    if (DAT_803dd92c == uVar20) {
      DAT_803dd932 = DAT_803dd932 + 0x20;
      if ((short)DAT_803dd932 < 0) {
        DAT_803dd932 = 0;
      }
      else if ((short)DAT_803dd930 < (short)DAT_803dd932) {
        DAT_803dd932 = DAT_803dd930;
      }
    }
    else {
      DAT_803dd932 = DAT_803dd932 - 0x20;
      if ((short)DAT_803dd932 < 0) {
        DAT_803dd932 = 0;
        if (DAT_803dd93c != 0) {
          FUN_80054308();
          DAT_803dd93c = 0;
          DAT_803dd92c = 0;
        }
        if (uVar20 != 0) {
          DAT_803dd93c = FUN_80054d54(uVar20);
          DAT_803dd92c = uVar20;
        }
      }
    }
    if (DAT_803dd930 != 0) {
      puVar8 = (ushort *)FUN_800173c8(0x83);
      if (((DAT_803dd944 == '\x02') && (DAT_803dd7a2 != 0)) && (-1 < DAT_803dba6e)) {
        uVar20 = 200;
      }
      else {
        uVar20 = 0x78;
      }
      if ((int)DAT_803dbbc0 < (int)uVar20) {
        uVar4 = DAT_803dbbc0 + (uint)DAT_803db410 * 8;
        DAT_803dbbc0 = uVar20;
        if ((int)uVar4 < (int)uVar20) {
          DAT_803dbbc0 = uVar4;
        }
      }
      else {
        uVar4 = DAT_803dbbc0 + (uint)DAT_803db410 * -8;
        DAT_803dbbc0 = uVar20;
        if ((int)uVar20 < (int)uVar4) {
          DAT_803dbbc0 = uVar4;
        }
      }
      puVar8[4] = (short)DAT_803dbbc0 - 8;
      DAT_803dd938 = 0x1b8 - DAT_803dbbc4;
      puVar8[0xb] = (ushort)DAT_803dd938;
      FUN_8012c6ac(0x32,(int)(short)DAT_803dd938,(int)(short)DAT_803dbbc0,(int)(short)DAT_803dbbc4,
                   DAT_803dd930 & 0xff,1);
      FUN_8025d324(0x32,DAT_803dd938,DAT_803dbbc0,DAT_803dbbc4);
      uVar4 = DAT_803dbbc4;
      uVar20 = DAT_803dbbc0;
      if (DAT_803dd944 == '\x01') {
        FUN_80133718();
        if (DAT_803dd934 == 0) {
          FUN_8013351c();
          FUN_8001984c(puVar8[1],puVar8[5],1);
          FUN_80019804(1);
          uVar20 = DAT_803dbbc0;
          if ((int)DAT_803dbbc0 < 3) {
            uVar20 = 2;
          }
          puVar8[4] = (ushort)uVar20;
          uVar5 = *puVar8;
          if (puVar8[4] < uVar5) {
            uVar5 = puVar8[4];
          }
          puVar8[4] = uVar5;
          uVar20 = DAT_803dbbc4;
          if ((int)DAT_803dbbc4 < 3) {
            uVar20 = 2;
          }
          puVar8[5] = (ushort)uVar20;
          FUN_8001984c(*puVar8,puVar8[5],2);
          FUN_80019908(0,0xff,0,DAT_803dd930 & 0xff);
          uVar10 = FUN_80019b14();
          FUN_80019b1c(3,3);
          FUN_80016870(0x459);
          FUN_80019b1c(uVar10,3);
          FUN_80019804(2);
        }
      }
      else if (DAT_803dd944 < '\x01') {
        if (-1 < DAT_803dd944) {
          if (DAT_803dd93c == 0) {
            FUN_8001984c(puVar8[1],puVar8[5],1);
            FUN_80019804(1);
            uVar20 = DAT_803dbbc0;
            if ((int)DAT_803dbbc0 < 3) {
              uVar20 = 2;
            }
            puVar8[4] = (ushort)uVar20;
            uVar5 = *puVar8;
            if (puVar8[4] < uVar5) {
              uVar5 = puVar8[4];
            }
            puVar8[4] = uVar5;
            uVar20 = DAT_803dbbc4;
            if ((int)DAT_803dbbc4 < 3) {
              uVar20 = 2;
            }
            puVar8[5] = (ushort)uVar20;
            FUN_8001984c(*puVar8,puVar8[5],2);
            FUN_80019908(0,0xff,0,DAT_803dd930 & 0xff);
            uVar10 = FUN_80019b14();
            FUN_80019b1c(3,3);
            FUN_80016870(0x458);
            FUN_80019b1c(uVar10,3);
            FUN_80019804(2);
          }
          else {
            uVar17 = (uint)*(ushort *)(DAT_803dd93c + 10);
            uVar18 = (uint)*(ushort *)(DAT_803dd93c + 0xc);
            local_140 = (double)CONCAT44(0x43300000,uVar17);
            uVar15 = (uint)DAT_803dd948;
            uStack308 = uVar15 - (int)DAT_803dbbd0 ^ 0x80000000;
            local_138 = 0x43300000;
            FLOAT_803dbbec =
                 (float)(local_140 - DOUBLE_803e2258) /
                 (float)((double)CONCAT44(0x43300000,uStack308) - DOUBLE_803e2250);
            local_130 = (double)CONCAT44(0x43300000,DAT_803dbbc0 ^ 0x80000000);
            fVar2 = (float)(local_130 - DOUBLE_803e2250) /
                    (float)((double)CONCAT44(0x43300000,uVar17) - DOUBLE_803e2258);
            fVar1 = (float)((double)CONCAT44(0x43300000,DAT_803dbbc4 ^ 0x80000000) - DOUBLE_803e2250
                           ) / (float)((double)CONCAT44(0x43300000,uVar18) - DOUBLE_803e2258);
            if (fVar2 < fVar1) {
              fVar1 = fVar2;
            }
            FLOAT_803dbbb8 = FLOAT_803dbbbc;
            if (fVar1 < FLOAT_803dbbbc) {
              FLOAT_803dbbb8 = fVar1;
            }
            if (DAT_803dd95c == '\0') {
              fVar2 = -*(float *)(psVar6 + 0xc) +
                      (float)((double)CONCAT44(0x43300000,uVar15 ^ 0x80000000) - DOUBLE_803e2250);
              fVar1 = -*(float *)(psVar6 + 0x10) +
                      (float)((double)CONCAT44(0x43300000,(int)DAT_803dd94a ^ 0x80000000) -
                             DOUBLE_803e2250);
            }
            else {
              fVar2 = -*(float *)(psVar6 + 0x10) +
                      (float)((double)CONCAT44(0x43300000,uVar15 ^ 0x80000000) - DOUBLE_803e2250);
              fVar1 = *(float *)(psVar6 + 0xc) -
                      (float)((double)CONCAT44(0x43300000,(int)DAT_803dbbd2 ^ 0x80000000) -
                             DOUBLE_803e2250);
            }
            dVar32 = (double)fVar2;
            dVar29 = (double)fVar1;
            uStack276 = DAT_803dbbc0 ^ 0x80000000;
            dVar33 = (double)FLOAT_803dbbb4;
            dVar28 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar17) -
                                                    DOUBLE_803e2258) * dVar33);
            dVar23 = (double)((float)((double)(float)((double)CONCAT44(0x43300000,uStack276) -
                                                     DOUBLE_803e2250) - dVar28) * FLOAT_803e220c);
            if (dVar23 < (double)FLOAT_803e2208) {
              dVar23 = (double)FLOAT_803e2208;
            }
            dVar23 = -dVar23;
            uStack292 = DAT_803dbbc4 ^ 0x80000000;
            local_128 = 0x43300000;
            local_130 = (double)CONCAT44(0x43300000,uVar18);
            fVar2 = (float)((double)(float)(local_130 - DOUBLE_803e2258) * dVar33);
            dVar26 = (double)(((float)((double)CONCAT44(0x43300000,uStack292) - DOUBLE_803e2250) -
                              fVar2) * FLOAT_803e220c);
            dVar25 = dVar26;
            if (dVar26 < (double)FLOAT_803e2208) {
              dVar25 = (double)FLOAT_803e2208;
            }
            dVar31 = -dVar25;
            dVar27 = (double)FLOAT_803e2208;
            uStack284 = uVar17;
            if (dVar27 == dVar23) {
              uStack276 = (int)DAT_803dbbc0 / 2 ^ 0x80000000;
              dVar24 = (double)(float)(dVar33 * (double)(float)(dVar32 * (double)FLOAT_803dbbec) -
                                      (double)(float)((double)CONCAT44(0x43300000,uStack276) -
                                                     DOUBLE_803e2250));
              if (dVar24 < dVar27) {
                dVar24 = dVar27;
              }
              uStack284 = DAT_803dbbc0 ^ 0x80000000;
              dVar25 = (double)(float)((double)CONCAT44(0x43300000,uStack284) - DOUBLE_803e2250);
              dVar22 = (double)(float)(dVar28 - dVar25);
              dVar26 = DOUBLE_803e2250;
              if (dVar24 < dVar22) {
                dVar22 = dVar24;
              }
            }
            dVar28 = (double)FLOAT_803e2208;
            if (dVar28 == dVar31) {
              dVar26 = (double)(float)(dVar29 * (double)FLOAT_803dbbec);
              uStack276 = (int)DAT_803dbbc4 / 2 ^ 0x80000000;
              dVar27 = (double)(float)(dVar33 * dVar26 -
                                      (double)(float)((double)CONCAT44(0x43300000,uStack276) -
                                                     DOUBLE_803e2250));
              if (dVar27 < dVar28) {
                dVar27 = dVar28;
              }
              uStack284 = DAT_803dbbc4 ^ 0x80000000;
              dVar28 = (double)(fVar2 - (float)((double)CONCAT44(0x43300000,uStack284) -
                                               DOUBLE_803e2250));
              dVar25 = DOUBLE_803e2250;
              dVar30 = dVar28;
              if (dVar27 < dVar28) {
                dVar28 = dVar27;
                dVar30 = dVar27;
              }
            }
            local_118 = 0x43300000;
            local_120 = 0x43300000;
            dVar27 = (double)(float)(dVar22 / dVar33);
            iVar7 = FUN_80285fb4(dVar27,dVar25,dVar26,dVar28);
            local_118 = 0x43300000;
            dVar28 = (double)(float)(dVar33 * (double)(float)(dVar27 - (double)(float)((double)
                                                  CONCAT44(0x43300000,iVar7) - DOUBLE_803e2258)));
            dVar25 = (double)(float)(dVar30 / dVar33);
            uStack276 = iVar7;
            iVar9 = FUN_80285fb4(dVar25);
            local_148._2_2_ = DAT_803dd932 & 0xff;
            local_148._1_3_ = CONCAT12(0x4d,local_148._2_2_);
            local_148 = CONCAT13(0x20,local_148._1_3_);
            local_148._2_2_ = CONCAT11(0x84,(byte)local_148);
            local_148 = local_148 & 0xffff0000 | (uint)local_148._2_2_;
            local_150 = local_148;
            FUN_800753b8(0x32,DAT_803dd938,uVar20 + 0x32,DAT_803dd938 + uVar4,&local_150);
            uStack284 = DAT_803dd938 ^ 0x80000000;
            local_120 = 0x43300000;
            local_128 = 0x43300000;
            local_130 = (double)(longlong)(int)(FLOAT_803e2214 * FLOAT_803dbbb4);
            uStack292 = iVar9;
            FUN_80075fc8((double)(float)((double)(float)((double)FLOAT_803e2210 - dVar23) - dVar28),
                         (double)((float)((double)(float)((double)CONCAT44(0x43300000,uStack284) -
                                                         DOUBLE_803e2250) - dVar31) -
                                 (float)(dVar33 * (double)(float)(dVar25 - (double)(float)((double)
                                                  CONCAT44(0x43300000,iVar9) - DOUBLE_803e2258)))),
                         DAT_803dd93c,DAT_803dd932 & 0xff,(int)(FLOAT_803e2214 * FLOAT_803dbbb4),
                         uVar17 - iVar7,uVar18 - iVar9,iVar7,iVar9);
            dVar25 = (double)(FLOAT_803e220c +
                             (float)((double)(float)((double)(FLOAT_803dbbb4 *
                                                              (float)(dVar32 * (double)
                                                  FLOAT_803dbbec) + FLOAT_803e2210) - dVar22) -
                                    dVar23));
            uStack308 = DAT_803dd938 ^ 0x80000000;
            local_138 = 0x43300000;
            dVar33 = (double)(FLOAT_803e220c +
                             (float)((double)(float)((double)(FLOAT_803dbbb4 *
                                                              (float)(dVar29 * (double)
                                                  FLOAT_803dbbec) +
                                                  (float)((double)CONCAT44(0x43300000,uStack308) -
                                                         DOUBLE_803e2250)) - dVar30) - dVar31));
            local_148._2_2_ = DAT_803dd932 & 0xff;
            local_148 = (uint)local_148._2_2_;
            FLOAT_803dd958 = FLOAT_803e2218;
            FLOAT_803dd954 = FLOAT_803e221c;
            FLOAT_803dd950 = FLOAT_803e221c;
            local_140 = (double)CONCAT44(0x43300000,(int)*psVar6 ^ 0x80000000);
            dVar30 = (double)FUN_80293e80((double)((FLOAT_803e2220 *
                                                   (float)(local_140 - DOUBLE_803e2250)) /
                                                  FLOAT_803e2224));
            dVar23 = (double)(float)((double)FLOAT_803dd958 * dVar30);
            uStack268 = (int)*psVar6 ^ 0x80000000;
            local_110 = 0x43300000;
            dVar30 = (double)FUN_80294204((double)((FLOAT_803e2220 *
                                                   (float)((double)CONCAT44(0x43300000,uStack268) -
                                                          DOUBLE_803e2250)) / FLOAT_803e2224));
            dVar28 = (double)(float)((double)FLOAT_803dd958 * dVar30);
            uStack260 = (int)*psVar6 + 0x6000U ^ 0x80000000;
            local_108 = 0x43300000;
            dVar30 = (double)FUN_80293e80((double)((FLOAT_803e2220 *
                                                   (float)((double)CONCAT44(0x43300000,uStack260) -
                                                          DOUBLE_803e2250)) / FLOAT_803e2224));
            dVar29 = (double)(float)((double)FLOAT_803dd954 * dVar30);
            uStack252 = (int)*psVar6 + 0x6000U ^ 0x80000000;
            local_100 = 0x43300000;
            dVar30 = (double)FUN_80294204((double)((FLOAT_803e2220 *
                                                   (float)((double)CONCAT44(0x43300000,uStack252) -
                                                          DOUBLE_803e2250)) / FLOAT_803e2224));
            dVar32 = (double)(float)((double)FLOAT_803dd954 * dVar30);
            uStack244 = (int)*psVar6 - 0x6000U ^ 0x80000000;
            local_f8 = 0x43300000;
            dVar30 = (double)FUN_80293e80((double)((FLOAT_803e2220 *
                                                   (float)((double)CONCAT44(0x43300000,uStack244) -
                                                          DOUBLE_803e2250)) / FLOAT_803e2224));
            dVar22 = (double)(float)((double)FLOAT_803dd950 * dVar30);
            uStack236 = (int)*psVar6 - 0x6000U ^ 0x80000000;
            local_f0 = 0x43300000;
            dVar30 = (double)FUN_80294204((double)((FLOAT_803e2220 *
                                                   (float)((double)CONCAT44(0x43300000,uStack236) -
                                                          DOUBLE_803e2250)) / FLOAT_803e2224));
            local_154 = local_148;
            FUN_80075a1c((double)(float)(dVar25 - dVar23),(double)(float)(dVar33 - dVar28),
                         (double)(float)(dVar25 - dVar29),(double)(float)(dVar33 - dVar32),
                         (double)(float)(dVar25 - dVar22),
                         (double)(float)(dVar33 - (double)(float)((double)FLOAT_803dd950 * dVar30)),
                         &local_154);
            local_148._2_2_ = DAT_803dd932 & 0xff;
            local_148._1_3_ = CONCAT12(0xff,local_148._2_2_);
            local_148 = CONCAT13(0xff,local_148._1_3_);
            local_148 = local_148 & 0xffff0000 | (uint)(byte)local_148;
            uStack228 = (int)*psVar6 ^ 0x80000000;
            local_e8 = 0x43300000;
            dVar30 = (double)FUN_80293e80((double)((FLOAT_803e2220 *
                                                   (float)((double)CONCAT44(0x43300000,uStack228) -
                                                          DOUBLE_803e2250)) / FLOAT_803e2224));
            dVar23 = (double)(float)((double)FLOAT_803e2228 * dVar30);
            uStack220 = (int)*psVar6 ^ 0x80000000;
            local_e0 = 0x43300000;
            dVar30 = (double)FUN_80294204((double)((FLOAT_803e2220 *
                                                   (float)((double)CONCAT44(0x43300000,uStack220) -
                                                          DOUBLE_803e2250)) / FLOAT_803e2224));
            dVar28 = (double)(float)((double)FLOAT_803e2228 * dVar30);
            uStack212 = (int)*psVar6 + 0x6000U ^ 0x80000000;
            local_d8 = 0x43300000;
            dVar30 = (double)FUN_80293e80((double)((FLOAT_803e2220 *
                                                   (float)((double)CONCAT44(0x43300000,uStack212) -
                                                          DOUBLE_803e2250)) / FLOAT_803e2224));
            dVar29 = (double)(float)((double)FLOAT_803e222c * dVar30);
            uStack204 = (int)*psVar6 + 0x6000U ^ 0x80000000;
            local_d0 = 0x43300000;
            dVar30 = (double)FUN_80294204((double)((FLOAT_803e2220 *
                                                   (float)((double)CONCAT44(0x43300000,uStack204) -
                                                          DOUBLE_803e2250)) / FLOAT_803e2224));
            dVar32 = (double)(float)((double)FLOAT_803e222c * dVar30);
            uStack196 = (int)*psVar6 - 0x6000U ^ 0x80000000;
            local_c8 = 0x43300000;
            dVar30 = (double)FUN_80293e80((double)((FLOAT_803e2220 *
                                                   (float)((double)CONCAT44(0x43300000,uStack196) -
                                                          DOUBLE_803e2250)) / FLOAT_803e2224));
            dVar22 = (double)(float)((double)FLOAT_803e222c * dVar30);
            uStack188 = (int)*psVar6 - 0x6000U ^ 0x80000000;
            local_c0 = 0x43300000;
            dVar30 = (double)FUN_80294204((double)((FLOAT_803e2220 *
                                                   (float)((double)CONCAT44(0x43300000,uStack188) -
                                                          DOUBLE_803e2250)) / FLOAT_803e2224));
            local_158 = local_148;
            FUN_80075a1c((double)(float)(dVar25 - dVar23),(double)(float)(dVar33 - dVar28),
                         (double)(float)(dVar25 - dVar29),(double)(float)(dVar33 - dVar32),
                         (double)(float)(dVar25 - dVar22),
                         (double)(float)(dVar33 - (double)(float)((double)FLOAT_803e222c * dVar30)),
                         &local_158);
          }
        }
      }
      else if (DAT_803dd944 < '\x03') {
        if ((DAT_803dd7a2 == 0) || (DAT_803dba6e < 0)) {
          if (DAT_803dbbb0 != '\0') {
            FUN_8013351c();
            FUN_8001984c(puVar8[1],puVar8[5],1);
            FUN_80019804(1);
            uVar20 = DAT_803dbbc0;
            if ((int)DAT_803dbbc0 < 3) {
              uVar20 = 2;
            }
            puVar8[4] = (ushort)uVar20;
            uVar5 = *puVar8;
            if (puVar8[4] < uVar5) {
              uVar5 = puVar8[4];
            }
            puVar8[4] = uVar5;
            uVar20 = DAT_803dbbc4;
            if ((int)DAT_803dbbc4 < 3) {
              uVar20 = 2;
            }
            puVar8[5] = (ushort)uVar20;
            FUN_8001984c(*puVar8,puVar8[5],2);
            FUN_80019908(0,0xff,0,DAT_803dd930 & 0xff);
            uVar10 = FUN_80019b14();
            FUN_80019b1c(3,3);
            FUN_80016870(0x45a);
            FUN_80019b1c(uVar10,3);
            FUN_80019804(2);
          }
        }
        else if (DAT_803dd928 == '\0') {
          FUN_8001984c(puVar8[1],puVar8[5],1);
          FUN_80019804(1);
          puVar8[4] = (ushort)DAT_803dbbc0;
          puVar8[5] = (ushort)DAT_803dbbc4;
          FUN_8001984c(puVar8[1],puVar8[5],2);
          FUN_80019908(0,0xff,0,DAT_803dd7a2 & 0xff);
          FUN_80016870(DAT_803dba6e + 10000);
          FUN_80019804(2);
        }
      }
      FUN_8025d324(0,0,0x280,0x1e0);
      uStack188 = DAT_803dd938 - 0x14 ^ 0x80000000;
      local_c0 = 0x43300000;
      FUN_8007719c((double)FLOAT_803e2230,
                   (double)(float)((double)CONCAT44(0x43300000,uStack188) - DOUBLE_803e2250),
                   DAT_803dd940,DAT_803dd930 & 0xff,0x100);
      if (DAT_803dd930 != 0) {
        local_14c._2_2_ = DAT_803dd932 & 0xff;
        local_14c = CONCAT13(0xff,CONCAT12(0xff,local_14c._2_2_));
        local_14c = local_14c & 0xffff0000 | (uint)(byte)local_14c;
        uVar20 = (uint)(short)((short)DAT_803dd938 + -4);
        if ((DAT_803dd944 == '\0') && (DAT_803dd93c != 0)) {
          if (FLOAT_803dbbb4 < FLOAT_803dbbbc) {
            uStack196 = uVar20 - 0x14 ^ 0x80000000;
            local_c0 = 0x43300000;
            local_15c = local_14c;
            local_c8 = 0x43300000;
            uStack204 = uVar20 - 0x1a ^ 0x80000000;
            local_d0 = 0x43300000;
            uStack188 = uStack196;
            FUN_80075a1c((double)FLOAT_803e2234,
                         (double)(float)((double)CONCAT44(0x43300000,uStack196) - DOUBLE_803e2250),
                         (double)FLOAT_803e2238,
                         (double)(float)((double)CONCAT44(0x43300000,uStack196) - DOUBLE_803e2250),
                         (double)FLOAT_803e223c,
                         (double)(float)((double)CONCAT44(0x43300000,uStack204) - DOUBLE_803e2250),
                         &local_15c);
          }
          if (FLOAT_803dbbb8 < FLOAT_803dbbb4) {
            uStack196 = uVar20 + 0x14 ^ 0x80000000;
            local_c0 = 0x43300000;
            local_160 = local_14c;
            local_c8 = 0x43300000;
            uStack204 = uVar20 + 0x1a ^ 0x80000000;
            local_d0 = 0x43300000;
            uStack188 = uStack196;
            FUN_80075a1c((double)FLOAT_803e2234,
                         (double)(float)((double)CONCAT44(0x43300000,uStack196) - DOUBLE_803e2250),
                         (double)FLOAT_803e2238,
                         (double)(float)((double)CONCAT44(0x43300000,uStack196) - DOUBLE_803e2250),
                         (double)FLOAT_803e223c,
                         (double)(float)((double)CONCAT44(0x43300000,uStack204) - DOUBLE_803e2250),
                         &local_160);
          }
        }
        uStack188 = uVar20 - 4 ^ 0x80000000;
        local_c0 = 0x43300000;
        uStack196 = uVar20 + 4 ^ 0x80000000;
        local_c8 = 0x43300000;
        uStack204 = uVar20 ^ 0x80000000;
        local_d0 = 0x43300000;
        local_164 = local_14c;
        FUN_80075a1c((double)FLOAT_803e2240,
                     (double)(float)((double)CONCAT44(0x43300000,uStack188) - DOUBLE_803e2250),
                     (double)FLOAT_803e2240,
                     (double)(float)((double)CONCAT44(0x43300000,uStack196) - DOUBLE_803e2250),
                     (double)FLOAT_803e2244,
                     (double)(float)((double)CONCAT44(0x43300000,uStack204) - DOUBLE_803e2250),
                     &local_164);
        local_168 = local_14c;
        uStack212 = uVar20 - 4 ^ 0x80000000;
        local_d8 = 0x43300000;
        uStack220 = uVar20 + 4 ^ 0x80000000;
        local_e0 = 0x43300000;
        uStack228 = uVar20 ^ 0x80000000;
        local_e8 = 0x43300000;
        FUN_80075a1c((double)FLOAT_803e2248,
                     (double)(float)((double)CONCAT44(0x43300000,uStack212) - DOUBLE_803e2250),
                     (double)FLOAT_803e2248,
                     (double)(float)((double)CONCAT44(0x43300000,uStack220) - DOUBLE_803e2250),
                     (double)FLOAT_803e224c,
                     (double)(float)((double)CONCAT44(0x43300000,uStack228) - DOUBLE_803e2250),
                     &local_168);
      }
    }
  }
  __psq_l0(auStack8,uVar21);
  __psq_l1(auStack8,uVar21);
  __psq_l0(auStack24,uVar21);
  __psq_l1(auStack24,uVar21);
  __psq_l0(auStack40,uVar21);
  __psq_l1(auStack40,uVar21);
  __psq_l0(auStack56,uVar21);
  __psq_l1(auStack56,uVar21);
  __psq_l0(auStack72,uVar21);
  __psq_l1(auStack72,uVar21);
  __psq_l0(auStack88,uVar21);
  __psq_l1(auStack88,uVar21);
  __psq_l0(auStack104,uVar21);
  __psq_l1(auStack104,uVar21);
  __psq_l0(auStack120,uVar21);
  __psq_l1(auStack120,uVar21);
  __psq_l0(auStack136,uVar21);
  __psq_l1(auStack136,uVar21);
  FUN_8028611c(0);
  return;
}

