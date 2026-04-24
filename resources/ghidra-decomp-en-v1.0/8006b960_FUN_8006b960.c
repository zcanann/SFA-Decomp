// Function: FUN_8006b960
// Entry: 8006b960
// Size: 2596 bytes

/* WARNING: Removing unreachable block (ram,0x8006c35c) */
/* WARNING: Removing unreachable block (ram,0x8006c34c) */
/* WARNING: Removing unreachable block (ram,0x8006c33c) */
/* WARNING: Removing unreachable block (ram,0x8006c32c) */
/* WARNING: Removing unreachable block (ram,0x8006c31c) */
/* WARNING: Removing unreachable block (ram,0x8006c314) */
/* WARNING: Removing unreachable block (ram,0x8006c324) */
/* WARNING: Removing unreachable block (ram,0x8006c334) */
/* WARNING: Removing unreachable block (ram,0x8006c344) */
/* WARNING: Removing unreachable block (ram,0x8006c354) */
/* WARNING: Removing unreachable block (ram,0x8006c364) */

void FUN_8006b960(void)

{
  undefined2 uVar1;
  undefined2 uVar2;
  uint uVar3;
  int iVar4;
  undefined2 *puVar5;
  byte bVar10;
  uint uVar6;
  undefined4 uVar7;
  int iVar8;
  int iVar9;
  undefined *puVar11;
  float *pfVar12;
  uint uVar13;
  uint uVar14;
  char cVar15;
  byte bVar16;
  uint uVar17;
  int *piVar18;
  int *piVar19;
  undefined4 uVar20;
  undefined8 uVar21;
  double dVar22;
  undefined8 in_f21;
  undefined8 in_f22;
  double dVar23;
  undefined8 in_f23;
  double dVar24;
  undefined8 in_f24;
  undefined8 in_f25;
  double dVar25;
  undefined8 in_f26;
  double dVar26;
  undefined8 in_f27;
  double dVar27;
  undefined8 in_f28;
  double dVar28;
  undefined8 in_f29;
  double dVar29;
  undefined8 in_f30;
  double dVar30;
  undefined8 in_f31;
  double dVar31;
  undefined auStack608 [4];
  undefined auStack604 [4];
  float local_258;
  float local_254;
  float local_250;
  float local_24c;
  float local_248;
  float local_244;
  float local_240;
  float local_23c;
  float local_238;
  float local_234;
  float local_230;
  float local_22c;
  undefined auStack552 [12];
  undefined auStack540 [12];
  undefined auStack528 [64];
  float local_1d0;
  float local_1cc;
  float local_1c8;
  float local_1c4;
  float local_1c0;
  float local_1bc;
  float local_1b8;
  float local_1b4;
  float local_1b0;
  float local_1ac;
  float local_1a8;
  float local_1a4;
  undefined auStack416 [48];
  undefined auStack368 [96];
  undefined4 local_110;
  uint uStack268;
  undefined4 local_108;
  uint uStack260;
  int local_100;
  undefined auStack168 [16];
  undefined auStack152 [16];
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar20 = 0;
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
  __psq_st0(auStack152,(int)((ulonglong)in_f22 >> 0x20),0);
  __psq_st1(auStack152,(int)in_f22,0);
  __psq_st0(auStack168,(int)((ulonglong)in_f21 >> 0x20),0);
  __psq_st1(auStack168,(int)in_f21,0);
  FUN_802860a8();
  if (DAT_803dcf78 != 0) {
    FUN_8000facc();
    FUN_8006b830(&DAT_8038e2a8,DAT_803dcf78);
    FUN_8000f458(1);
    puVar5 = (undefined2 *)FUN_8000faac();
    uVar21 = FUN_8000fc34();
    FUN_8000fc3c((double)FLOAT_803ded30);
    FUN_8000fc2c((double)FLOAT_803ded2c);
    dVar27 = (double)*(float *)(puVar5 + 6);
    dVar26 = (double)*(float *)(puVar5 + 8);
    dVar25 = (double)*(float *)(puVar5 + 10);
    local_100 = (int)(short)puVar5[1];
    uVar1 = *puVar5;
    uVar2 = puVar5[2];
    puVar5[1] = 0;
    local_240 = FLOAT_803ded28;
    local_23c = FLOAT_803ded2c;
    local_238 = FLOAT_803ded28;
    FUN_80061094((double)FLOAT_803ded34,&local_240,auStack368);
    FUN_80060b98(auStack604,auStack608);
    bVar16 = 0;
    uVar17 = 0;
    piVar19 = &DAT_8038e2a8;
    for (cVar15 = '\0'; ((int)cVar15 < (int)(uint)DAT_803dcf78 && (cVar15 < 100));
        cVar15 = cVar15 + '\x01') {
      iVar9 = *piVar19;
      pfVar12 = *(float **)(iVar9 + 100);
      FUN_8000f458(0);
      bVar10 = FUN_800626c8(iVar9,DAT_803db410);
      FUN_8000f458(1);
      if (4 < bVar10) {
        if (((uint)pfVar12[0xc] & 0x20) != 0) {
          FUN_80003494(auStack552,iVar9 + 0xc,0xc);
          FUN_80003494(auStack540,iVar9 + 0x18,0xc);
          FUN_80003494(iVar9 + 0xc,pfVar12 + 8,0xc);
          FUN_80003494(iVar9 + 0x18,pfVar12 + 8,0xc);
        }
        uVar3 = uVar17 & 0xff;
        iVar4 = uVar3 * 0x68;
        puVar11 = &DAT_8038f0b8 + iVar4;
        (&DAT_8038f11c)[iVar4] = bVar10;
        if ((bVar16 < 8) && (*(char *)(piVar19 + 2) != '\0')) {
          if (bVar16 < 3) {
            uVar13 = 0x100;
            dVar24 = (double)FLOAT_803ded38;
          }
          else if (bVar16 < 5) {
            uVar13 = 0x80;
            dVar24 = (double)FLOAT_803ded3c;
          }
          else {
            uVar13 = 0x40;
            dVar24 = (double)FLOAT_803ded40;
          }
          uVar14 = uVar13;
          if (bVar16 == 0) {
            uVar14 = uVar13 << 1;
          }
          if (*(char *)(piVar19 + 2) == '\x02') {
            uVar14 = (uint)*(ushort *)(*(int *)(*(int *)(iVar9 + 100) + 4) + 10);
            uVar13 = uVar14;
          }
          FUN_8008923c(iVar9,&local_234,&local_230,&local_22c);
          local_24c = -pfVar12[5];
          local_248 = -pfVar12[6];
          local_244 = -pfVar12[7];
          dVar22 = (double)FUN_8024782c(&local_24c,&local_234);
          if ((dVar22 < (double)FLOAT_803ded2c) && ((double)FLOAT_803ded44 < dVar22)) {
            local_258 = FLOAT_803ded48 * local_24c + FLOAT_803ded4c * local_234;
            local_254 = FLOAT_803ded48 * local_248 + FLOAT_803ded4c * local_230;
            local_250 = FLOAT_803ded48 * local_244 + FLOAT_803ded4c * local_22c;
            dVar22 = (double)FUN_802477f0(&local_258);
            if ((double)FLOAT_803ded28 < dVar22) {
              FUN_80247778((double)(float)((double)FLOAT_803ded2c / dVar22),&local_258,&local_234);
            }
          }
          if (FLOAT_803ded50 < local_230) {
            local_230 = FLOAT_803ded50;
            FUN_80247794(&local_234,&local_234);
          }
          dVar23 = (double)local_234;
          dVar28 = -dVar23;
          dVar29 = (double)local_230;
          dVar31 = -dVar29;
          dVar22 = (double)local_22c;
          dVar30 = -dVar22;
          uVar6 = FUN_800217c0(dVar28,dVar22);
          DAT_803dcf84 = uVar6 & 0xffff;
          dVar22 = (double)((float)(dVar23 * dVar23) + (float)(dVar22 * dVar22));
          if ((double)FLOAT_803ded28 < dVar22) {
            dVar23 = 1.0 / SQRT(dVar22);
            dVar23 = DOUBLE_803ded58 * dVar23 * -(dVar22 * dVar23 * dVar23 - DOUBLE_803ded60);
            dVar23 = DOUBLE_803ded58 * dVar23 * -(dVar22 * dVar23 * dVar23 - DOUBLE_803ded60);
            dVar22 = (double)(float)(dVar22 * DOUBLE_803ded58 * dVar23 *
                                              -(dVar22 * dVar23 * dVar23 - DOUBLE_803ded60));
          }
          uVar6 = FUN_800217c0(dVar22,dVar29);
          DAT_803dcf88 = (uVar6 & 0xffff) - 0x3fc8;
          puVar5[1] = (short)DAT_803dcf88;
          *puVar5 = (short)DAT_803dcf84;
          dVar22 = (double)(float)(dVar30 * dVar30 +
                                  (double)(float)(dVar28 * dVar28 + (double)(float)(dVar31 * dVar31)
                                                 ));
          if ((double)FLOAT_803ded28 < dVar22) {
            dVar23 = 1.0 / SQRT(dVar22);
            dVar23 = DOUBLE_803ded58 * dVar23 * -(dVar22 * dVar23 * dVar23 - DOUBLE_803ded60);
            dVar23 = DOUBLE_803ded58 * dVar23 * -(dVar22 * dVar23 * dVar23 - DOUBLE_803ded60);
            dVar22 = (double)(float)(dVar22 * DOUBLE_803ded58 * dVar23 *
                                              -(dVar22 * dVar23 * dVar23 - DOUBLE_803ded60));
          }
          if ((double)FLOAT_803ded28 < dVar22) {
            dVar22 = (double)(float)((double)FLOAT_803ded68 / dVar22);
            dVar28 = (double)(float)(dVar28 * dVar22);
            dVar31 = (double)(float)(dVar31 * dVar22);
            dVar30 = (double)(float)(dVar30 * dVar22);
          }
          *(undefined4 *)(puVar5 + 0x20) = 0;
          pfVar12[5] = -local_234;
          pfVar12[6] = -local_230;
          pfVar12[7] = -local_22c;
          FUN_8006fef8(uVar14);
          uVar7 = FUN_8002b588(iVar9);
          iVar8 = FUN_8002856c(uVar7,0);
          *(float *)(puVar5 + 6) = (float)(dVar28 + (double)*(float *)(iVar8 + 0xc));
          *(float *)(puVar5 + 8) = (float)(dVar31 + (double)*(float *)(iVar8 + 0x1c));
          *(float *)(puVar5 + 10) = (float)(dVar30 + (double)*(float *)(iVar8 + 0x2c));
          if (*(int *)(iVar9 + 0x30) == 0) {
            *(float *)(puVar5 + 6) = *(float *)(puVar5 + 6) + FLOAT_803dced0;
            *(float *)(puVar5 + 10) = *(float *)(puVar5 + 10) + FLOAT_803dcecc;
          }
          dVar22 = (double)*pfVar12;
          dVar23 = -dVar22;
          if (*(int *)(iVar9 + 0x30) != 0) {
            *(float *)(puVar5 + 6) = *(float *)(puVar5 + 6) + FLOAT_803dcdd8;
            *(float *)(puVar5 + 10) = *(float *)(puVar5 + 10) + FLOAT_803dcddc;
          }
          FUN_8025d324(2,2,uVar14 - 4,uVar14 - 4);
          dVar28 = (double)FLOAT_803ded28;
          local_110 = 0x43300000;
          local_108 = 0x43300000;
          uStack268 = uVar14;
          uStack260 = uVar14;
          FUN_8025d300(dVar28,dVar28,
                       (double)(float)((double)CONCAT44(0x43300000,uVar14) - DOUBLE_803ded88),
                       (double)(float)((double)CONCAT44(0x43300000,uVar14) - DOUBLE_803ded88),dVar28
                       ,(double)FLOAT_803ded2c);
          FUN_80247698(dVar23,dVar22,dVar23,dVar22,(double)FLOAT_803ded2c,(double)FLOAT_803ded6c,
                       auStack528);
          FUN_8025cf48(auStack528,1);
          FUN_8000f564();
          FUN_8024740c(dVar22,dVar23,dVar23,dVar22,dVar24,dVar24,dVar24,dVar24,puVar11);
          uVar7 = FUN_8000f54c();
          FUN_80246e80(uVar7,&DAT_8038f0e8 + iVar4);
          FUN_80246eb4(puVar11,uVar7,puVar11);
          *(undefined **)(*(int *)(iVar9 + 100) + 0xc) = puVar11;
          piVar18 = &DAT_80391958 + bVar16;
          (&DAT_8038f118)[uVar3 * 0x1a] = *piVar18;
          (&DAT_8038f11d)[iVar4] = (&DAT_803db668)[bVar16];
          FUN_8003b8b8(iVar9,0,0,0,0,0);
          if (*(char *)(piVar19 + 2) == '\x02') {
            FUN_80070310(1,3,1);
            dVar24 = (double)FLOAT_803ded28;
            FUN_80247318(dVar24,dVar24,dVar24,&DAT_8038f0e8 + iVar4);
            (&DAT_8038f0f0)[uVar3 * 0x1a] = FLOAT_803ded70;
            (&DAT_8038f0f4)[uVar3 * 0x1a] = FLOAT_803ded74;
            (&DAT_8038f114)[uVar3 * 0x1a] = FLOAT_803ded2c;
            FUN_80246eb4(&DAT_8038f0e8 + iVar4,uVar7,&DAT_8038f0e8 + iVar4);
            FUN_80258c9c(0,0,uVar14,uVar14);
            FUN_80258da0(uVar14,uVar14,0x11,0);
            FUN_802590f4(0,DAT_803dccf0 + 0x1a,0,DAT_803dccf0 + 0x32);
            FUN_802594a8(*(int *)(*(int *)(iVar9 + 100) + 4) + 0x60,1);
            FUN_8004a3d4();
            (&DAT_8038f118)[uVar3 * 0x1a] = *(undefined4 *)(*(int *)(iVar9 + 100) + 4);
          }
          else {
            if (bVar16 == 0) {
              FUN_80070310(1,3,1);
              FUN_80258c9c(0,0,uVar14,uVar14);
              FUN_80258da0(uVar13,uVar13,0x20,1);
              FUN_802594a8(*piVar18 + 0x60,1);
              (&DAT_8038f118)[uVar3 * 0x1a] = *piVar18;
            }
            bVar16 = bVar16 + 1;
          }
        }
        else {
          (&DAT_8038f118)[uVar3 * 0x1a] = *(undefined4 *)(*(int *)(iVar9 + 100) + 4);
          dVar24 = (double)*(float *)(iVar9 + 0xc);
          dVar22 = (double)*(float *)(iVar9 + 0x14);
          if (*(int *)(iVar9 + 0x30) == 0) {
            dVar24 = (double)(float)(dVar24 - (double)FLOAT_803dcdd8);
            dVar22 = (double)(float)(dVar22 - (double)FLOAT_803dcddc);
          }
          FUN_802472e4(-dVar24,-(double)*(float *)(iVar9 + 0x10),-dVar22,auStack416);
          local_1d0 = FLOAT_803ded38 / *pfVar12;
          local_1cc = FLOAT_803ded28;
          local_1c8 = FLOAT_803ded28;
          local_1c4 = FLOAT_803ded38;
          local_1c0 = FLOAT_803ded28;
          local_1bc = FLOAT_803ded28;
          local_1b4 = FLOAT_803ded38;
          local_1b0 = FLOAT_803ded28;
          local_1ac = FLOAT_803ded28;
          local_1a8 = FLOAT_803ded28;
          local_1a4 = FLOAT_803ded2c;
          local_1b8 = local_1d0;
          FUN_80246eb4(&local_1d0,auStack416,puVar11);
          pfVar12[5] = local_240;
          pfVar12[6] = local_23c;
          pfVar12[7] = local_238;
          *(undefined **)(*(int *)(iVar9 + 100) + 0xc) = puVar11;
        }
        uVar17 = uVar17 + 1;
        if (((uint)pfVar12[0xc] & 0x20) != 0) {
          FUN_80003494(iVar9 + 0xc,auStack552,0xc);
          FUN_80003494(iVar9 + 0x18,auStack540,0xc);
        }
      }
      piVar19 = piVar19 + 3;
    }
    if (1 < bVar16) {
      FUN_80070310(1,3,1);
      FUN_802590f4(0,DAT_803dccf0 + 0x1a,0,DAT_803dccf0 + 0x32);
      FUN_80258c9c(0,0,0x100,0x100);
      FUN_80258da0(0x100,0x100,0x28,0);
      FUN_802594a8(DAT_8039195c + 0x60,1);
      FUN_802584c0();
      FUN_8004a3d4();
    }
    FUN_8006ff00();
    *(float *)(puVar5 + 6) = (float)dVar27;
    *(float *)(puVar5 + 8) = (float)dVar26;
    *(float *)(puVar5 + 10) = (float)dVar25;
    puVar5[1] = (short)local_100;
    *puVar5 = uVar1;
    puVar5[2] = uVar2;
    iVar9 = FUN_8005cd48();
    if (iVar9 == 0) {
      iVar9 = FUN_8005cdb0();
      if (iVar9 == 0) {
        FUN_8000f458(0);
        FUN_8000fc3c(uVar21);
        FUN_8000fc2c((double)FLOAT_803db670);
        FUN_8000f0fc(0,0);
      }
      else {
        FUN_8000f458(0);
        FUN_8000fc3c(uVar21);
        FUN_8000fc2c((double)FLOAT_803ded80);
        FUN_8000f0fc(0,0);
      }
    }
    else {
      FUN_8000f458(0);
      FUN_8000fc3c(uVar21);
      iVar9 = FUN_8005cdb0();
      if (iVar9 == 0) {
        FUN_8000fc2c((double)FLOAT_803ded7c);
      }
      else {
        FUN_8000fc2c((double)FLOAT_803ded78);
      }
      FUN_8000f0fc(0,0);
    }
    FUN_8000f564();
    FUN_8000fb00();
    FUN_8000f780();
    FUN_8000fad8();
  }
  __psq_l0(auStack8,uVar20);
  __psq_l1(auStack8,uVar20);
  __psq_l0(auStack24,uVar20);
  __psq_l1(auStack24,uVar20);
  __psq_l0(auStack40,uVar20);
  __psq_l1(auStack40,uVar20);
  __psq_l0(auStack56,uVar20);
  __psq_l1(auStack56,uVar20);
  __psq_l0(auStack72,uVar20);
  __psq_l1(auStack72,uVar20);
  __psq_l0(auStack88,uVar20);
  __psq_l1(auStack88,uVar20);
  __psq_l0(auStack104,uVar20);
  __psq_l1(auStack104,uVar20);
  __psq_l0(auStack120,uVar20);
  __psq_l1(auStack120,uVar20);
  __psq_l0(auStack136,uVar20);
  __psq_l1(auStack136,uVar20);
  __psq_l0(auStack152,uVar20);
  __psq_l1(auStack152,uVar20);
  __psq_l0(auStack168,uVar20);
  __psq_l1(auStack168,uVar20);
  FUN_802860f4();
  return;
}

