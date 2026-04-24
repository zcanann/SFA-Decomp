// Function: FUN_8020c9cc
// Entry: 8020c9cc
// Size: 3136 bytes

/* WARNING: Removing unreachable block (ram,0x8020d5e4) */
/* WARNING: Removing unreachable block (ram,0x8020d5d4) */
/* WARNING: Removing unreachable block (ram,0x8020d5c4) */
/* WARNING: Removing unreachable block (ram,0x8020d5b4) */
/* WARNING: Removing unreachable block (ram,0x8020d1d4) */
/* WARNING: Removing unreachable block (ram,0x8020d5ac) */
/* WARNING: Removing unreachable block (ram,0x8020d5bc) */
/* WARNING: Removing unreachable block (ram,0x8020d5cc) */
/* WARNING: Removing unreachable block (ram,0x8020d5dc) */
/* WARNING: Removing unreachable block (ram,0x8020d5ec) */

void FUN_8020c9cc(void)

{
  uint uVar1;
  bool bVar2;
  bool bVar3;
  short sVar4;
  undefined2 *puVar5;
  undefined2 uVar12;
  char cVar15;
  int iVar6;
  uint uVar7;
  undefined2 *puVar8;
  ushort uVar13;
  undefined2 *puVar9;
  short sVar14;
  undefined4 uVar10;
  short *psVar11;
  char *pcVar16;
  byte bVar18;
  int *piVar17;
  undefined4 *puVar19;
  uint uVar20;
  int iVar21;
  int iVar22;
  undefined4 uVar23;
  double dVar24;
  double dVar25;
  undefined8 in_f23;
  undefined8 in_f24;
  undefined8 in_f25;
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
  double dVar32;
  undefined uStack264;
  char local_107 [3];
  undefined4 local_104;
  undefined auStack256 [6];
  undefined2 local_fa;
  float local_f4;
  float local_f0;
  float local_ec;
  double local_e8;
  undefined4 local_e0;
  uint uStack220;
  longlong local_d8;
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar23 = 0;
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
  puVar5 = (undefined2 *)FUN_802860bc();
  iVar22 = *(int *)(puVar5 + 0x5c);
  bVar3 = false;
  *(short *)(iVar22 + 6) = *(short *)(iVar22 + 6) + -1;
  if (*(short *)(iVar22 + 6) == 1) {
    uVar12 = FUN_800221a0(0x708,3000);
    *(undefined2 *)(iVar22 + 6) = uVar12;
    iVar21 = *(int *)(puVar5 + 0x26);
    cVar15 = FUN_8002e04c();
    if (cVar15 != '\0') {
      iVar6 = FUN_8002bdf4(0x20,0x80f);
      *(undefined *)(iVar6 + 4) = *(undefined *)(iVar21 + 4);
      *(undefined *)(iVar6 + 6) = *(undefined *)(iVar21 + 6);
      *(undefined *)(iVar6 + 5) = *(undefined *)(iVar21 + 5);
      *(undefined *)(iVar6 + 7) = *(undefined *)(iVar21 + 7);
      *(undefined4 *)(iVar6 + 8) = *(undefined4 *)(puVar5 + 6);
      *(undefined4 *)(iVar6 + 0xc) = *(undefined4 *)(puVar5 + 8);
      *(undefined4 *)(iVar6 + 0x10) = *(undefined4 *)(puVar5 + 10);
      FUN_8002df90(iVar6,5,(int)*(char *)(puVar5 + 0x56),0xffffffff,0);
    }
  }
  if (*(short *)(iVar22 + 6) < 0) {
    *(undefined2 *)(iVar22 + 6) = 0;
  }
  FUN_8020c5ec(puVar5);
  if (DAT_803ddd0a != 0) {
    DAT_803ddd0a = DAT_803ddd0a + -1;
  }
  if (DAT_803ddd08 == '\0') {
    FUN_800202c4(1);
    if ((*(byte *)(iVar22 + 8) & 4) == 0) {
      (**(code **)(*DAT_803dca50 + 0x1c))(0x4e,1,0,0,0,0,0xff);
      (**(code **)(*DAT_803dca50 + 0x28))(puVar5,0);
      *(byte *)(iVar22 + 8) = *(byte *)(iVar22 + 8) | 4;
    }
    else if ((*(byte *)(iVar22 + 8) & 8) == 0) {
      local_104 = (&DAT_8032a178)[(byte)(&DAT_803dc1c8)[*(char *)(iVar22 + 0x10)]];
      (**(code **)(*DAT_803dca50 + 0x60))(&local_104,2);
      *(byte *)(iVar22 + 8) = *(byte *)(iVar22 + 8) | 8;
      iVar21 = FUN_8002e0b4(0x43077);
      *(undefined *)(*(int *)(iVar21 + 0xb8) + 0x27c) = (&DAT_803dc1e8)[*(char *)(iVar22 + 0x10)];
      FUN_8000d01c();
    }
    if ((*(byte *)(iVar22 + 8) & 1) == 0) {
      *(byte *)(iVar22 + 8) = *(byte *)(iVar22 + 8) | 1;
      FUN_80008cbc(0,0,0x21f,0);
      FUN_8005cea8(0);
      FUN_8005cdf8(0);
    }
    uVar7 = FUN_80014e70(0);
    local_fa = 100;
    local_f4 = FLOAT_803e661c;
    local_f0 = FLOAT_803e6620;
    local_ec = FLOAT_803e6624;
    (**(code **)(*DAT_803dca88 + 8))(puVar5,0x6f2,auStack256,2,0xffffffff,0);
    FUN_8020d60c(puVar5,local_107,&uStack264);
    puVar5[2] = puVar5[2] + -10;
    puVar5[1] = 0x3448;
    *puVar5 = 0x4000;
    puVar8 = (undefined2 *)FUN_8002e0b4(0x42ff5);
    puVar8[2] = puVar5[2];
    puVar8[1] = puVar5[1];
    *puVar8 = *puVar5;
    puVar8 = (undefined2 *)FUN_8002e0b4(0x4300c);
    *(undefined *)(*(int *)(puVar8 + 0x5c) + 0x27d) = *(undefined *)(iVar22 + 9);
    bVar18 = *(byte *)(iVar22 + 0x10);
    uVar20 = 0;
    iVar21 = 0;
    puVar19 = &DAT_8032a1b4;
    pcVar16 = &DAT_803dc1b8;
    do {
      iVar6 = FUN_8001ffb4(*puVar19);
      if (iVar6 != 0) {
        bVar2 = true;
        if ((*pcVar16 != '\0') && (uVar13 = FUN_800ea2bc(), 0xad < uVar13)) {
          bVar2 = false;
        }
        if (bVar2) {
          uVar20 = uVar20 | 1 << iVar21;
        }
      }
      puVar19 = puVar19 + 1;
      pcVar16 = pcVar16 + 1;
      iVar21 = iVar21 + 1;
    } while (iVar21 < 5);
    *(char *)(iVar22 + 0x11) = (char)uVar20;
    if ((DAT_803ddd04 == 0) && (*(char *)(iVar22 + 9) == '\0')) {
      while (!bVar3) {
        *(char *)(iVar22 + 0x10) = *(char *)(iVar22 + 0x10) + local_107[0];
        if (*(char *)(iVar22 + 0x10) < '\0') {
          *(undefined *)(iVar22 + 0x10) = 4;
        }
        else if ('\x04' < *(char *)(iVar22 + 0x10)) {
          *(undefined *)(iVar22 + 0x10) = 0;
        }
        bVar3 = true;
      }
      FUN_8012ddd8(0x2a7,(&DAT_803dc1d0)[*(char *)(iVar22 + 0x10)],0x19,0);
      if (((uint)bVar18 != (int)*(char *)(iVar22 + 0x10)) || (*(int *)(puVar5 + 0x7a) == 0)) {
        if (*(int *)(puVar5 + 0x7a) != 0) {
          local_104 = (&DAT_8032a178)[(byte)(&DAT_803dc1c8)[*(char *)(iVar22 + 0x10)]];
          (**(code **)(*DAT_803dca50 + 0x60))(&local_104,1);
          FUN_8000bb18(0,0x97);
        }
        FLOAT_803ddd2c = FLOAT_803e65f8;
        iVar21 = FUN_8002e0b4((&DAT_8032a178)[(byte)(&DAT_803dc1c8)[bVar18]]);
        *(undefined *)(*(int *)(iVar21 + 0xb8) + 0x27d) = 0;
        iVar21 = FUN_8002e0b4((&DAT_8032a178)[(byte)(&DAT_803dc1c8)[*(char *)(iVar22 + 0x10)]]);
        *(undefined *)(*(int *)(iVar21 + 0xb8) + 0x27d) = 1;
        *(undefined4 *)(puVar5 + 0x7a) = 1;
      }
    }
    FLOAT_803ddd2c = FLOAT_803ddd2c + FLOAT_803e6628;
    if (FLOAT_803e662c <= FLOAT_803ddd2c) {
      FLOAT_803ddd2c = FLOAT_803e65f8;
    }
    for (uVar20 = 0; (uVar20 & 0xff) < 5; uVar20 = uVar20 + 1) {
      puVar9 = (undefined2 *)FUN_8002e0b4((&DAT_8032a1a0)[uVar20 & 0xff]);
      iVar21 = *(int *)(puVar9 + 0x5c);
      puVar9[1] = puVar5[1];
      *puVar9 = *puVar5;
      if ((*(char *)(iVar22 + 9) == '\0') &&
         (((int)(uint)*(byte *)(iVar22 + 0x11) >> (uVar20 & 0x3f) & 1U) != 0)) {
        if ((uVar20 & 0xff) == (int)*(char *)(iVar22 + 0x10)) {
          local_e8 = (double)(longlong)(int)FLOAT_803ddd2c;
          uStack220 = (int)FLOAT_803ddd2c & 0xff;
          uVar1 = uStack220 + 2 & 0xff;
          local_e0 = 0x43300000;
          dVar30 = (double)(FLOAT_803ddd2c -
                           (float)((double)CONCAT44(0x43300000,uStack220) - DOUBLE_803e6638));
          iVar6 = iVar21 + uStack220 * 0x18;
          dVar27 = (double)*(float *)(iVar6 + 0x10);
          dVar26 = (double)*(float *)(iVar6 + 0x28);
          dVar25 = (double)*(float *)(iVar6 + 0x14);
          dVar24 = (double)*(float *)(iVar6 + 0x2c);
          dVar31 = (double)*(float *)(iVar6 + 0x18);
          dVar32 = (double)*(float *)(iVar6 + 0x30);
          *(undefined *)(iVar21 + 0x27d) = 2;
          dVar29 = (double)(float)(dVar26 - dVar27);
          dVar28 = (double)(float)(dVar32 - dVar31);
          sVar14 = FUN_800217c0(dVar29,dVar28);
          sVar4 = sVar14;
          if (uVar1 < 0x16) {
            iVar21 = iVar21 + uVar1 * 0x18;
            sVar4 = FUN_800217c0((double)(float)((double)*(float *)(iVar21 + 0x10) - dVar26),
                                 (double)(float)((double)*(float *)(iVar21 + 0x18) - dVar32));
          }
          sVar4 = sVar4 - sVar14;
          if (0x8000 < sVar4) {
            sVar4 = sVar4 + 1;
          }
          if (sVar4 < -0x8000) {
            sVar4 = sVar4 + -1;
          }
          cVar15 = FUN_8012ddac();
          if (cVar15 == '\0') {
            puVar8[3] = puVar8[3] & 0xbfff;
          }
          else {
            puVar8[3] = puVar8[3] | 0x4000;
          }
          uStack220 = (int)sVar4 ^ 0x80000000;
          local_e0 = 0x43300000;
          local_e8 = (double)CONCAT44(0x43300000,(int)sVar14 ^ 0x80000000);
          iVar21 = (int)(dVar30 * (double)(float)((double)CONCAT44(0x43300000,uStack220) -
                                                 DOUBLE_803e6610) +
                        (double)(float)(local_e8 - DOUBLE_803e6610));
          local_d8 = (longlong)iVar21;
          *puVar8 = (short)iVar21;
          *(float *)(puVar8 + 6) = (float)(dVar30 * dVar29 + dVar27);
          *(float *)(puVar8 + 8) = (float)(dVar30 * (double)(float)(dVar24 - dVar25) + dVar25);
          *(float *)(puVar8 + 10) = (float)(dVar30 * dVar28 + dVar31);
        }
        else {
          *(undefined *)(iVar21 + 0x27d) = 1;
        }
      }
      else {
        *(undefined *)(iVar21 + 0x27d) = 0;
        if ((uVar20 & 0xff) == (int)*(char *)(iVar22 + 0x10)) {
          puVar8[3] = puVar8[3] | 0x4000;
        }
      }
    }
    uVar10 = FUN_8002e0b4((&DAT_8032a178)[(byte)(&DAT_803dc1c8)[*(char *)(iVar22 + 0x10)]]);
    iVar21 = FUN_800430ac(0);
    if ((iVar21 == 0) && (DAT_803ddd0a == 0)) {
      if (*(char *)(iVar22 + 9) == '\x01') {
        FUN_8012fdc0();
        uVar20 = countLeadingZeros(((uint)(byte)((FLOAT_803ddd00 == FLOAT_803e65f8) << 1) << 0x1c)
                                   >> 0x1d ^ 1);
        if (uVar20 >> 5 != 0) {
          FLOAT_803ddd00 = FLOAT_803e6618;
        }
        if ((uVar7 & 0x200) == 0) {
          if ((uVar7 & 0x100) != 0) {
            (**(code **)(*DAT_803dca4c + 8))(4,1);
            FUN_8000a380(3,1,0);
            FUN_8000d01c();
            FUN_8000bb18(0,0x98);
            FUN_8012dd7c(0);
            DAT_803ddd08 = '\x05';
            DAT_803ddd10 = 0;
            FUN_800437bc(DAT_803ddd28,0x10000000);
          }
        }
        else {
          FUN_8000d01c();
          FUN_8000bb18(0,0x99);
          FUN_8000a380(2,2,1000);
          (**(code **)(*DAT_803dca50 + 0x28))(puVar5,0x50);
          *(undefined *)(iVar22 + 9) = 0;
          DAT_803ddd0c = 0x1e;
          (**(code **)(*DAT_803dca50 + 0x60))(iVar22 + 9,0);
          FUN_8004350c(DAT_803ddd28,1,0);
          FUN_800437bc(DAT_803ddd28,0x20000000);
          DAT_803ddd0a = 10;
        }
      }
      else if (*(char *)(iVar22 + 9) == '\0') {
        if (DAT_803ddd0c == 0) {
          if (((DAT_803ddd04 == 0) &&
              (((uint)*(byte *)(iVar22 + 0x11) & 1 << (int)*(char *)(iVar22 + 0x10)) != 0)) &&
             ((uVar7 & 0x100) != 0)) {
            DAT_803ddd04 = 10;
            FUN_800437bc(DAT_803ddd28,0x20000000);
          }
        }
        else {
          DAT_803ddd0c = DAT_803ddd0c + -1;
        }
        if (DAT_803ddd04 != 0) {
          FUN_8012fdc0();
          DAT_803ddd04 = DAT_803ddd04 + -1;
          if (DAT_803ddd04 < 2) {
            DAT_803ddd04 = 0;
            FUN_8000bb18(0,0x98);
            (**(code **)(*DAT_803dca50 + 0x28))(uVar10,0x50);
            *(undefined *)(iVar22 + 9) = 1;
            (**(code **)(*DAT_803dca50 + 0x60))(iVar22 + 9,0);
            iVar21 = FUN_8002e0b4(0x43077);
            *(undefined *)(*(int *)(iVar21 + 0xb8) + 0x27c) =
                 (&DAT_803dc1e8)[*(char *)(iVar22 + 0x10)];
            DAT_803ddd28 = FUN_80042f78((&DAT_803dc1e0)
                                        [(byte)(&DAT_803dc1c8)[*(char *)(iVar22 + 0x10)]]);
            FUN_80043560(DAT_803ddd28,1);
            FUN_80026ef4();
            FLOAT_803ddd00 = FLOAT_803e65f8;
            DAT_803dc1f0 = (int)*(char *)(iVar22 + 0x10);
          }
        }
      }
    }
    else {
      FUN_8012fdc0();
    }
    uVar7 = -(int)(short)puVar5[2] & 0xffff;
    for (bVar18 = 0; bVar18 < 5; bVar18 = bVar18 + 1) {
      iVar21 = FUN_8002e0b4((&DAT_8032a1a0)[bVar18]);
      *(short *)(iVar21 + 4) = -(short)uVar7;
    }
    dVar32 = (double)FLOAT_803e6630;
    for (bVar18 = 0; bVar18 < 5; bVar18 = bVar18 + 1) {
      psVar11 = (short *)FUN_8002e0b4((&DAT_8032a178)[bVar18]);
      if ((&DAT_8032a178)[bVar18] == 0x4300d) {
        *psVar11 = (short)uVar7 + (short)(&DAT_8032a18c)[bVar18] + 0x4000;
      }
      else {
        *psVar11 = *psVar11 + 0x3c;
      }
      if (2 < *(uint *)(iVar22 + 0x14)) {
        FUN_8000da58(psVar11,0x96);
      }
      dVar24 = (double)FUN_8029374c(3000);
      piVar17 = &DAT_8032a18c + bVar18;
      dVar25 = (double)FUN_80293234(uVar7 + *piVar17 & 0xffff);
      *(float *)(psVar11 + 6) =
           (float)((double)(float)(dVar32 * dVar25) * dVar24 + (double)*(float *)(puVar5 + 6));
      dVar24 = (double)FUN_80293234(3000);
      dVar25 = (double)FUN_80293234(uVar7 + *piVar17 & 0xffff);
      *(float *)(psVar11 + 8) =
           (float)((double)(float)(dVar32 * dVar25) * dVar24 + (double)*(float *)(puVar5 + 8));
      dVar24 = (double)FUN_8029374c(uVar7 + *piVar17 & 0xffff);
      *(float *)(psVar11 + 10) = (float)(dVar32 * dVar24 + (double)*(float *)(puVar5 + 10));
    }
    *(int *)(iVar22 + 0x14) = *(int *)(iVar22 + 0x14) + 1;
  }
  else {
    DAT_803ddd08 = DAT_803ddd08 + -1;
    if (DAT_803ddd08 == '\0') {
      FUN_8005cea8(1);
      FUN_8005cef0(1);
      FUN_8005cdf8(1);
      FUN_800552e8((&DAT_803dc1d8)[(byte)(&DAT_803dc1c8)[*(char *)(iVar22 + 0x10)]],0);
    }
  }
  __psq_l0(auStack8,uVar23);
  __psq_l1(auStack8,uVar23);
  __psq_l0(auStack24,uVar23);
  __psq_l1(auStack24,uVar23);
  __psq_l0(auStack40,uVar23);
  __psq_l1(auStack40,uVar23);
  __psq_l0(auStack56,uVar23);
  __psq_l1(auStack56,uVar23);
  __psq_l0(auStack72,uVar23);
  __psq_l1(auStack72,uVar23);
  __psq_l0(auStack88,uVar23);
  __psq_l1(auStack88,uVar23);
  __psq_l0(auStack104,uVar23);
  __psq_l1(auStack104,uVar23);
  __psq_l0(auStack120,uVar23);
  __psq_l1(auStack120,uVar23);
  __psq_l0(auStack136,uVar23);
  __psq_l1(auStack136,uVar23);
  FUN_80286108();
  return;
}

