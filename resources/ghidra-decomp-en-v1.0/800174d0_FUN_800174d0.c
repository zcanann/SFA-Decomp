// Function: FUN_800174d0
// Entry: 800174d0
// Size: 4104 bytes

/* WARNING: Removing unreachable block (ram,0x800184b0) */
/* WARNING: Removing unreachable block (ram,0x800184a0) */
/* WARNING: Removing unreachable block (ram,0x80018490) */
/* WARNING: Removing unreachable block (ram,0x80018480) */
/* WARNING: Removing unreachable block (ram,0x80018470) */
/* WARNING: Removing unreachable block (ram,0x80017a1c) */
/* WARNING: Removing unreachable block (ram,0x80018478) */
/* WARNING: Removing unreachable block (ram,0x80018488) */
/* WARNING: Removing unreachable block (ram,0x80018498) */
/* WARNING: Removing unreachable block (ram,0x800184a8) */
/* WARNING: Removing unreachable block (ram,0x800184b8) */

void FUN_800174d0(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6)

{
  byte bVar1;
  undefined *puVar2;
  bool bVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  uint *puVar8;
  uint uVar9;
  int iVar10;
  uint *puVar11;
  uint uVar12;
  uint *unaff_r28;
  uint uVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  uint uVar18;
  undefined4 uVar19;
  double extraout_f1;
  double dVar20;
  double dVar21;
  double dVar22;
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
  undefined8 uVar32;
  int local_158;
  undefined4 local_154;
  undefined4 local_150;
  uint local_14c;
  undefined4 local_148;
  undefined auStack324 [4];
  float local_140;
  int local_13c;
  uint local_138 [8];
  double local_118;
  double local_110;
  double local_108;
  double local_100;
  double local_f8;
  double local_f0;
  double local_e8;
  undefined4 local_e0;
  uint uStack220;
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
  
  uVar19 = 0;
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
  uVar32 = FUN_802860c0();
  iVar5 = (int)((ulonglong)uVar32 >> 0x20);
  iVar10 = (int)uVar32;
  iVar14 = 0;
  dVar25 = (double)FLOAT_803de704;
  if (DAT_803dc9e8 == 2) {
    uVar13 = 6;
  }
  else {
    uVar13 = (uint)(byte)(&DAT_802c73d4)[DAT_803dc9e4 * 8];
  }
  uVar12 = 0xffffffff;
  bVar4 = true;
  if ((iVar5 != 0) && (DAT_803dc9ec[7] == (uint *)&DAT_00000002)) {
    dVar23 = extraout_f1;
    if ((DAT_803dc9e4 != 4) &&
       (((param_6 == 1 && (iVar6 = FUN_800e7e94(3), iVar6 != 0)) && (iVar10 == -0x7fd38ac0)))) {
      FUN_800184d8(iVar5);
    }
    FUN_800186f0((double)FLOAT_803dc9a0,iVar5,&local_140,auStack324,0,0,0xffffffff);
    if (DAT_803dc9bc == 0) {
      FUN_8005d118(0,DAT_803dc9a7,DAT_803dc9a6,DAT_803dc9a5,DAT_803dc9a4);
      FUN_8005d0e8(0,DAT_803dc9a7,DAT_803dc9a6,DAT_803dc9a5,DAT_803dc9a4);
      FUN_800799c0();
      FUN_80078fa4();
      FUN_80079804();
      FUN_80078a7c();
    }
    local_118 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0x14) ^ 0x80000000);
    dVar23 = (double)(float)(dVar23 + (double)(float)(local_118 - DOUBLE_803de6f8));
    local_110 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0x16) ^ 0x80000000);
    dVar24 = (double)(float)(param_2 + (double)(float)(local_110 - DOUBLE_803de6f8));
LAB_80018454:
    iVar6 = iVar5 + iVar14;
    uVar9 = FUN_80015cb8(iVar6,&local_13c);
    if (uVar9 != 0) {
      iVar14 = iVar14 + local_13c;
      bVar3 = false;
      if ((0xdfff < uVar9) && (uVar9 < 0xf900)) goto code_r0x800176b8;
      if (param_6 == 0) {
        DAT_803dc998 = DAT_803dc998 + 1;
      }
      goto LAB_800179f8;
    }
  }
  __psq_l0(auStack8,uVar19);
  __psq_l1(auStack8,uVar19);
  __psq_l0(auStack24,uVar19);
  __psq_l1(auStack24,uVar19);
  __psq_l0(auStack40,uVar19);
  __psq_l1(auStack40,uVar19);
  __psq_l0(auStack56,uVar19);
  __psq_l1(auStack56,uVar19);
  __psq_l0(auStack72,uVar19);
  __psq_l1(auStack72,uVar19);
  __psq_l0(auStack88,uVar19);
  __psq_l1(auStack88,uVar19);
  __psq_l0(auStack104,uVar19);
  __psq_l1(auStack104,uVar19);
  __psq_l0(auStack120,uVar19);
  __psq_l1(auStack120,uVar19);
  __psq_l0(auStack136,uVar19);
  __psq_l1(auStack136,uVar19);
  __psq_l0(auStack152,uVar19);
  __psq_l1(auStack152,uVar19);
  FUN_8028610c();
  return;
code_r0x800176b8:
  puVar11 = &DAT_802c86f0;
  iVar17 = 0x17;
  do {
    if (*puVar11 == uVar9) {
      uVar7 = puVar11[1];
      goto LAB_80017708;
    }
    if (puVar11[2] == uVar9) {
      uVar7 = puVar11[3];
      goto LAB_80017708;
    }
    puVar11 = puVar11 + 4;
    iVar17 = iVar17 + -1;
  } while (iVar17 != 0);
  uVar7 = 0;
LAB_80017708:
  iVar17 = 0;
  if (0 < (int)uVar7) {
    if (8 < (int)uVar7) {
      puVar11 = local_138;
      uVar18 = uVar7 - 1 >> 3;
      if (0 < (int)(uVar7 - 8)) {
        do {
          *puVar11 = (uint)CONCAT11(*(undefined *)(iVar5 + iVar14),
                                    *(undefined *)(iVar5 + iVar14 + 1));
          puVar11[1] = (uint)CONCAT11(*(undefined *)(iVar5 + iVar14 + 2),
                                      *(undefined *)(iVar5 + iVar14 + 3));
          puVar11[2] = (uint)CONCAT11(*(undefined *)(iVar5 + iVar14 + 4),
                                      *(undefined *)(iVar5 + iVar14 + 5));
          puVar11[3] = (uint)CONCAT11(*(undefined *)(iVar5 + iVar14 + 6),
                                      *(undefined *)(iVar5 + iVar14 + 7));
          puVar11[4] = (uint)CONCAT11(*(undefined *)(iVar5 + iVar14 + 8),
                                      *(undefined *)(iVar5 + iVar14 + 9));
          puVar11[5] = (uint)CONCAT11(*(undefined *)(iVar5 + iVar14 + 10),
                                      *(undefined *)(iVar5 + iVar14 + 0xb));
          iVar15 = iVar14 + 0xe;
          puVar11[6] = (uint)CONCAT11(*(undefined *)(iVar5 + iVar14 + 0xc),
                                      *(undefined *)(iVar5 + iVar14 + 0xd));
          iVar16 = iVar14 + 0xf;
          iVar14 = iVar14 + 0x10;
          puVar11[7] = (uint)CONCAT11(*(undefined *)(iVar5 + iVar15),*(undefined *)(iVar5 + iVar16))
          ;
          puVar11 = puVar11 + 8;
          iVar17 = iVar17 + 8;
          uVar18 = uVar18 - 1;
        } while (uVar18 != 0);
      }
    }
    puVar11 = local_138 + iVar17;
    iVar15 = uVar7 - iVar17;
    if (iVar17 < (int)uVar7) {
      do {
        iVar17 = iVar14 + 1;
        puVar2 = (undefined *)(iVar5 + iVar14);
        iVar14 = iVar14 + 2;
        *puVar11 = (uint)CONCAT11(*puVar2,*(undefined *)(iVar5 + iVar17));
        puVar11 = puVar11 + 1;
        iVar15 = iVar15 + -1;
      } while (iVar15 != 0);
    }
  }
  switch(uVar9) {
  case 0xf8f4:
    local_110 = (double)CONCAT44(0x43300000,local_138[0] ^ 0x80000000);
    FLOAT_803dc9a0 = (float)(local_110 - DOUBLE_803de6f8) * FLOAT_803de708;
    break;
  case 0xf8f7:
    uVar13 = local_138[0];
    break;
  case 0xf8f8:
    *(undefined *)(iVar10 + 0x12) = 0;
    bVar4 = true;
    break;
  case 0xf8f9:
    *(undefined *)(iVar10 + 0x12) = 1;
    bVar4 = true;
    break;
  case 0xf8fa:
    *(undefined *)(iVar10 + 0x12) = 2;
    bVar4 = true;
    break;
  case 0xf8fb:
    *(undefined *)(iVar10 + 0x12) = 3;
    bVar4 = true;
    break;
  case 0xf8ff:
    if (param_6 == 0) {
      DAT_803dc9a4 = (byte)(local_138[3] * (DAT_803dc9a4 + 1) >> 8);
      DAT_803dc9a5 = (undefined)local_138[2];
      DAT_803dc9a6 = (undefined)local_138[1];
      DAT_803dc9a7 = (undefined)local_138[0];
      if (DAT_803dc9bc == 0) {
        FUN_8005d118(0);
        FUN_8005d0e8(0,DAT_803dc9a7,DAT_803dc9a6,DAT_803dc9a5,DAT_803dc9a4);
        FUN_800799c0();
        FUN_80078fa4();
        FUN_80079804();
        FUN_80078a7c();
      }
    }
    bVar3 = true;
  }
  if (!bVar3) {
LAB_800179f8:
    if (bVar4) {
      bVar1 = *(byte *)(iVar10 + 0x12);
      if (bVar1 == 2) {
        dVar25 = (double)FLOAT_803de704;
        FUN_800186f0((double)FLOAT_803dc9a0,iVar6,&local_140,0,0,0,0xffffffff);
        local_110 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar10 + 8));
        local_118 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0x14) ^ 0x80000000);
        dVar23 = (double)(((float)(local_110 - DOUBLE_803de6f0) - local_140) * FLOAT_803de70c +
                         (float)(local_118 - DOUBLE_803de6f8));
      }
      else if (bVar1 < 2) {
        if (bVar1 == 0) {
          dVar25 = (double)FLOAT_803de704;
        }
        else {
          dVar25 = (double)FLOAT_803de704;
          FUN_800186f0((double)FLOAT_803dc9a0,iVar6,&local_140,0,0,0,0xffffffff);
          local_110 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0x14) ^ 0x80000000);
          local_118 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar10 + 8));
          dVar23 = (double)((float)(local_110 - DOUBLE_803de6f8) +
                           ((float)(local_118 - DOUBLE_803de6f0) - local_140));
        }
      }
      else if (bVar1 < 4) {
        FUN_800186f0((double)FLOAT_803dc9a0,iVar6,&local_140,0,0,0,0xffffffff);
        iVar17 = 0;
        uVar7 = 0;
        while (uVar18 = FUN_80015cb8(iVar6 + iVar17,&local_158), uVar18 != 0) {
          iVar17 = iVar17 + local_158;
          if (uVar18 == 0x20) {
            uVar7 = uVar7 + 1;
          }
          if ((0xdfff < uVar18) && (uVar18 < 0xf900)) {
            puVar11 = &DAT_802c86f0;
            iVar15 = 0x17;
            do {
              if (*puVar11 == uVar18) {
                uVar18 = puVar11[1];
                goto LAB_80017bb0;
              }
              if (puVar11[2] == uVar18) {
                uVar18 = puVar11[3];
                goto LAB_80017bb0;
              }
              puVar11 = puVar11 + 4;
              iVar15 = iVar15 + -1;
            } while (iVar15 != 0);
            uVar18 = 0;
LAB_80017bb0:
            iVar17 = iVar17 + uVar18 * 2;
          }
        }
        local_110 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar10 + 8));
        local_118 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        dVar25 = (double)(((float)(local_110 - DOUBLE_803de6f0) - local_140) /
                         (float)(local_118 - DOUBLE_803de6f8));
      }
      bVar4 = false;
    }
    puVar11 = *DAT_803dc9ec;
    for (puVar8 = DAT_803dc9ec[2]; puVar8 != (uint *)0x0; puVar8 = (uint *)((int)puVar8 + -1)) {
      if ((*puVar11 == uVar9) && (*(byte *)((int)puVar11 + 0xe) == uVar13)) goto LAB_80017c54;
      puVar11 = puVar11 + 4;
    }
    puVar11 = (uint *)0x0;
LAB_80017c54:
    if (puVar11 != (uint *)0x0) {
      if (uVar9 == 10) {
        dVar23 = (double)FLOAT_803de704;
        dVar24 = (double)(float)(dVar24 + param_3);
      }
      else if (uVar9 == 0x20) {
        local_110 = (double)CONCAT44(0x43300000,
                                     (uint)*(byte *)(puVar11 + 3) +
                                     (int)*(char *)(puVar11 + 2) + (int)*(char *)((int)puVar11 + 9)
                                     ^ 0x80000000);
        dVar23 = (double)(float)((double)(float)((double)FLOAT_803dc9a0 *
                                                 (double)(float)(local_110 - DOUBLE_803de6f8) +
                                                dVar23) + dVar25);
      }
      else {
        local_110 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(puVar11 + 1) << 5 ^ 0x80000000);
        dVar27 = (double)(float)(local_110 - DOUBLE_803de6f8);
        local_118 = (double)CONCAT44(0x43300000,
                                     (uint)*(ushort *)((int)puVar11 + 6) << 5 ^ 0x80000000);
        dVar26 = (double)(float)(local_118 - DOUBLE_803de6f8);
        dVar20 = (double)FLOAT_803de710;
        local_108 = (double)CONCAT44(0x43300000,(int)*(char *)(puVar11 + 2) ^ 0x80000000);
        dVar31 = (double)(float)(dVar20 * (double)(float)(dVar23 + (double)((float)(local_108 -
                                                                                   DOUBLE_803de6f8)
                                                                           * FLOAT_803dc9a0)));
        local_100 = (double)CONCAT44(0x43300000,(int)*(char *)((int)puVar11 + 10) ^ 0x80000000);
        dVar30 = (double)(float)(dVar20 * (double)(float)(dVar24 + (double)((float)(local_100 -
                                                                                   DOUBLE_803de6f8)
                                                                           * FLOAT_803dc9a0)));
        local_f8 = (double)CONCAT44(0x43300000,(uint)*(byte *)(puVar11 + 3));
        dVar22 = dVar20 * (double)((float)(local_f8 - DOUBLE_803de6f0) * FLOAT_803dc9a0) + dVar31;
        dVar29 = (double)(float)dVar22;
        local_f0 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)puVar11 + 0xd));
        dVar20 = dVar20 * (double)((float)(local_f0 - DOUBLE_803de6f0) * FLOAT_803dc9a0) + dVar30;
        dVar28 = (double)(float)dVar20;
        dVar21 = (double)FLOAT_803de704;
        if ((dVar31 < dVar21) && (dVar21 < dVar29)) {
          dVar27 = (double)(float)((double)FLOAT_803de714 * -dVar31 + dVar27);
          dVar31 = dVar21;
        }
        dVar21 = (double)FLOAT_803de704;
        if ((dVar30 < dVar21) && (dVar21 < dVar28)) {
          dVar26 = (double)(float)((double)FLOAT_803de714 * -dVar30 + dVar26);
          dVar30 = dVar21;
        }
        if (DAT_803dc9bc == 0) {
          if (*(char *)((int)puVar11 + 0xe) == '\x03') {
            uVar9 = DAT_803db3cc << 2 ^ 0x80000000;
            local_e8 = (double)CONCAT44(0x43300000,uVar9);
            dVar30 = (double)(float)(dVar30 - (double)(float)(local_e8 - DOUBLE_803de6f8));
            local_f0 = (double)CONCAT44(0x43300000,uVar9);
            dVar28 = (double)(float)(dVar28 - (double)(float)(local_f0 - DOUBLE_803de6f8));
            FUN_8025d3d4(&local_148,&local_14c,&local_150,&local_154);
            if (local_14c < DAT_803db3cc) {
              iVar6 = 0;
            }
            else {
              iVar6 = local_14c - DAT_803db3cc;
            }
            FUN_8025d324(local_148,iVar6,local_150,local_154);
          }
          if (*(char *)((int)puVar11 + 0xe) == '\x05') {
            uVar7 = (uint)*(byte *)(puVar11 + 3) +
                    (int)*(char *)(puVar11 + 2) + (int)*(char *)((int)puVar11 + 9);
            uVar18 = (uint)*(byte *)((int)puVar11 + 0xd) +
                     (int)*(char *)((int)puVar11 + 10) + (int)*(char *)((int)puVar11 + 0xb);
            FUN_8025d3d4(&local_148,&local_14c,&local_150,&local_154);
            FUN_800550d0(0,0,(int)DAT_802c83d4,(int)DAT_802c83d6,
                         (int)DAT_802c83d4 + (uint)DAT_802c83c8,
                         (int)DAT_802c83d6 + (uint)DAT_802c83ca);
            uVar9 = (int)DAT_802c83d4 + ((int)(DAT_802c83c8 - uVar7) >> 1) ^ 0x80000000;
            local_e8 = (double)CONCAT44(0x43300000,uVar9);
            local_f0 = (double)CONCAT44(0x43300000,uVar9);
            local_f8 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            uVar9 = (int)DAT_802c83d6 + ((int)(DAT_802c83ca - uVar18) >> 1) ^ 0x80000000;
            local_100 = (double)CONCAT44(0x43300000,uVar9);
            local_108 = (double)CONCAT44(0x43300000,uVar9);
            local_110 = (double)CONCAT44(0x43300000,uVar18 ^ 0x80000000);
            dVar31 = (double)((float)(local_e8 - DOUBLE_803de6f8) * FLOAT_803de710);
            dVar29 = (double)(((float)(local_f0 - DOUBLE_803de6f8) +
                              (float)(local_f8 - DOUBLE_803de6f8)) * FLOAT_803de710);
            dVar30 = (double)((float)(local_100 - DOUBLE_803de6f8) * FLOAT_803de710);
            dVar28 = (double)(((float)(local_108 - DOUBLE_803de6f8) +
                              (float)(local_110 - DOUBLE_803de6f8)) * FLOAT_803de710);
          }
          if (param_6 != 0) {
            local_e8 = (double)CONCAT44(0x43300000,DAT_803dc98c ^ 0x80000000);
            dVar31 = (double)(float)(dVar31 + (double)(float)(local_e8 - DOUBLE_803de6f8));
            local_f0 = (double)CONCAT44(0x43300000,DAT_803dc98c ^ 0x80000000);
            dVar29 = (double)(float)(dVar29 + (double)(float)(local_f0 - DOUBLE_803de6f8));
            local_f8 = (double)CONCAT44(0x43300000,DAT_803dc988 ^ 0x80000000);
            dVar30 = (double)(float)(dVar30 + (double)(float)(local_f8 - DOUBLE_803de6f8));
            local_100 = (double)CONCAT44(0x43300000,DAT_803dc988 ^ 0x80000000);
            dVar28 = (double)(float)(dVar28 + (double)(float)(local_100 - DOUBLE_803de6f8));
          }
          if ((DAT_803dc9bc == 0) && (uVar9 = (uint)*(byte *)((int)puVar11 + 0xf), uVar12 != uVar9))
          {
            unaff_r28 = DAT_803dc9ec[uVar9 + 4];
            FUN_8004c2e4(unaff_r28,0);
            uVar12 = uVar9;
            if ((&DAT_802c8686)[(uint)*(byte *)((int)puVar11 + 0xe) * 0x10] == '\x01') {
              if (param_6 == 0) {
                FUN_8005d118(0,0xff,0xff,0xff,DAT_803dc9a4);
                FUN_800799c0();
                FUN_800795e8();
                FUN_80079804();
              }
              else {
                FUN_8005d118(0,0,0,0,DAT_803dc9a4);
              }
            }
            else {
              FUN_8005d118(0,DAT_803dc9a7,DAT_803dc9a6,DAT_803dc9a5,DAT_803dc9a4);
              FUN_8005d0e8(0,DAT_803dc9a7,DAT_803dc9a6,DAT_803dc9a5,DAT_803dc9a4);
              FUN_800799c0();
              FUN_80078fa4();
              FUN_80079804();
            }
          }
          if ((((DAT_803dc99c != 0) && (param_6 == 0)) && (*(char *)((int)puVar11 + 0xe) != '\x05'))
             && (local_e8 = (double)CONCAT44(0x43300000,DAT_803dc998 ^ 0x80000000),
                FLOAT_803dc994 <= (float)(local_e8 - DOUBLE_803de6f8))) {
            FUN_8005d118(0,0,0,0,0);
          }
          if (DAT_803dc96c == (code *)0x0) {
            uStack220 = (uint)*(ushort *)(unaff_r28 + 3);
            local_e0 = 0x43300000;
            dVar20 = (double)(FLOAT_803de718 *
                             (float)((double)CONCAT44(0x43300000,uStack220) - DOUBLE_803de6f0));
            local_e8 = (double)CONCAT44(0x43300000,(uint)*(ushort *)((int)unaff_r28 + 10));
            dVar22 = (double)(FLOAT_803de718 * (float)(local_e8 - DOUBLE_803de6f0));
            local_f0 = (double)(longlong)(int)dVar31;
            local_f8 = (double)(longlong)(int)dVar30;
            local_100 = (double)(longlong)(int)dVar29;
            local_108 = (double)(longlong)(int)dVar28;
            local_110 = (double)CONCAT44(0x43300000,(uint)*(byte *)(puVar11 + 3) << 5 ^ 0x80000000);
            local_118 = (double)CONCAT44(0x43300000,
                                         (uint)*(byte *)((int)puVar11 + 0xd) << 5 ^ 0x80000000);
            FUN_80075e8c((double)(float)(dVar27 / dVar22),(double)(float)(dVar26 / dVar20),
                         (double)(float)((double)(float)(dVar27 + (double)(float)(local_110 -
                                                                                 DOUBLE_803de6f8)) /
                                        dVar22),
                         (double)(float)((double)(float)(dVar26 + (double)(float)(local_118 -
                                                                                 DOUBLE_803de6f8)) /
                                        dVar20),(int)dVar31,(int)dVar30,(int)dVar29,(int)dVar28);
          }
          else {
            local_e8 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(unaff_r28 + 3));
            dVar20 = (double)(FLOAT_803de718 * (float)(local_e8 - DOUBLE_803de6f0));
            local_f0 = (double)CONCAT44(0x43300000,(uint)*(ushort *)((int)unaff_r28 + 10));
            dVar22 = (double)(FLOAT_803de718 * (float)(local_f0 - DOUBLE_803de6f0));
            local_f8 = (double)(longlong)(int)dVar31;
            local_100 = (double)(longlong)(int)dVar30;
            local_108 = (double)(longlong)(int)dVar29;
            local_110 = (double)(longlong)(int)dVar28;
            local_118 = (double)CONCAT44(0x43300000,(uint)*(byte *)(puVar11 + 3) << 5 ^ 0x80000000);
            uStack220 = (uint)*(byte *)((int)puVar11 + 0xd) << 5 ^ 0x80000000;
            local_e0 = 0x43300000;
            (*DAT_803dc96c)((double)(float)(dVar27 / dVar22),(double)(float)(dVar26 / dVar20),
                            (double)(float)((double)(float)(dVar27 + (double)(float)(local_118 -
                                                                                    DOUBLE_803de6f8)
                                                           ) / dVar22),
                            (double)(float)((double)(float)(dVar26 + (double)(float)((double)
                                                  CONCAT44(0x43300000,uStack220) - DOUBLE_803de6f8))
                                           / dVar20),(int)dVar31,(int)dVar30,(int)dVar29,(int)dVar28
                           );
          }
          if ((*(char *)((int)puVar11 + 0xe) == '\x03') || (*(char *)((int)puVar11 + 0xe) == '\x05')
             ) {
            FUN_8025d324(local_148,local_14c,local_150,local_154);
          }
        }
        else {
          local_f0 = (double)CONCAT44(0x43300000,DAT_803dc9b0 ^ 0x80000000);
          if (dVar31 < (double)(float)(local_f0 - DOUBLE_803de6f8)) {
            DAT_803dc9b0 = (uint)dVar31;
            local_f8 = (double)(longlong)(int)DAT_803dc9b0;
          }
          local_100 = (double)CONCAT44(0x43300000,DAT_803dc9ac ^ 0x80000000);
          if ((double)(float)(local_100 - DOUBLE_803de6f8) < dVar29) {
            DAT_803dc9ac = (uint)dVar22;
            local_108 = (double)(longlong)(int)DAT_803dc9ac;
          }
          local_110 = (double)CONCAT44(0x43300000,DAT_803dc9b8 ^ 0x80000000);
          if (dVar30 < (double)(float)(local_110 - DOUBLE_803de6f8)) {
            DAT_803dc9b8 = (uint)dVar30;
            local_118 = (double)(longlong)(int)DAT_803dc9b8;
          }
          local_e8 = (double)CONCAT44(0x43300000,DAT_803dc9b4 ^ 0x80000000);
          if ((double)(float)(local_e8 - DOUBLE_803de6f8) < dVar28) {
            DAT_803dc9b4 = (uint)dVar20;
            local_e8 = (double)(longlong)(int)DAT_803dc9b4;
          }
        }
        if (*(char *)((int)puVar11 + 0xe) != '\x05') {
          uStack220 = (uint)*(byte *)(puVar11 + 3) +
                      (int)*(char *)(puVar11 + 2) + (int)*(char *)((int)puVar11 + 9) ^ 0x80000000;
          local_e0 = 0x43300000;
          dVar23 = (double)(float)((double)FLOAT_803dc9a0 *
                                   (double)(float)((double)CONCAT44(0x43300000,uStack220) -
                                                  DOUBLE_803de6f8) + dVar23);
        }
      }
    }
  }
  goto LAB_80018454;
}

