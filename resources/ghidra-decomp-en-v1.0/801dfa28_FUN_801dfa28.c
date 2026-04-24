// Function: FUN_801dfa28
// Entry: 801dfa28
// Size: 5732 bytes

/* WARNING: Removing unreachable block (ram,0x801e1064) */
/* WARNING: Removing unreachable block (ram,0x801e1054) */
/* WARNING: Removing unreachable block (ram,0x801e1044) */
/* WARNING: Removing unreachable block (ram,0x801e1034) */
/* WARNING: Removing unreachable block (ram,0x801e1024) */
/* WARNING: Removing unreachable block (ram,0x801e102c) */
/* WARNING: Removing unreachable block (ram,0x801e103c) */
/* WARNING: Removing unreachable block (ram,0x801e104c) */
/* WARNING: Removing unreachable block (ram,0x801e105c) */
/* WARNING: Removing unreachable block (ram,0x801e106c) */

void FUN_801dfa28(void)

{
  char cVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  short *psVar7;
  int iVar8;
  uint uVar9;
  undefined4 uVar10;
  uint uVar11;
  float fVar12;
  float *pfVar13;
  int iVar14;
  undefined unaff_r31;
  undefined4 uVar15;
  double dVar16;
  double dVar17;
  undefined8 in_f22;
  undefined8 in_f23;
  undefined8 in_f24;
  double in_f25;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double dVar18;
  double in_f30;
  double in_f31;
  double dVar19;
  float local_148;
  int local_144;
  int local_140;
  short local_13c;
  short local_13a;
  short local_138;
  float local_134;
  float local_130;
  float local_12c;
  float local_128;
  undefined auStack292 [68];
  double local_e0;
  double local_d8;
  double local_d0;
  undefined4 local_c8;
  uint uStack196;
  double local_c0;
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
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,SUB84(in_f30,0),0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,SUB84(in_f29,0),0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,SUB84(in_f28,0),0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,SUB84(in_f27,0),0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,SUB84(in_f26,0),0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,SUB84(in_f25,0),0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  __psq_st0(auStack136,(int)((ulonglong)in_f23 >> 0x20),0);
  __psq_st1(auStack136,(int)in_f23,0);
  __psq_st0(auStack152,(int)((ulonglong)in_f22 >> 0x20),0);
  __psq_st1(auStack152,(int)in_f22,0);
  psVar7 = (short *)FUN_802860dc();
  iVar14 = *(int *)(psVar7 + 0x26);
  pfVar13 = *(float **)(psVar7 + 0x5c);
  local_148 = FLOAT_803e56c8;
  *(undefined *)(psVar7 + 0x56) = 0xff;
  if ((pfVar13[0x12] != 0.0) && ((*(ushort *)((int)pfVar13[0x12] + 6) & 0x40) != 0)) {
    pfVar13[0x12] = 0.0;
  }
  if (pfVar13[0x12] == 0.0) {
    iVar8 = FUN_8002e0fc(&local_140,&local_144);
    for (; local_140 < local_144; local_140 = local_140 + 1) {
      fVar12 = *(float *)(iVar8 + local_140 * 4);
      if (*(short *)((int)fVar12 + 0x46) == 0x8c) {
        pfVar13[0x12] = fVar12;
        local_140 = local_144;
      }
    }
  }
  if (*(char *)((int)pfVar13 + 0x29) < '\x02') {
    FUN_8000b824(psVar7,0x143);
  }
  else {
    FUN_8000bb18(psVar7,0x143);
  }
  fVar12 = pfVar13[0x12];
  if (fVar12 == 0.0) goto LAB_801e1024;
  if ((fVar12 != 0.0) && (*(int *)((int)fVar12 + 0xf4) == 0)) {
    FUN_801eed5c(fVar12,pfVar13 + 0x14,pfVar13 + 0x15,pfVar13 + 0x16);
  }
  *(ushort *)((int)pfVar13 + 0x26) = *(short *)((int)pfVar13 + 0x26) - (ushort)DAT_803db410;
  if (*(short *)((int)pfVar13 + 0x26) < 0) {
    *(undefined2 *)((int)pfVar13 + 0x26) = 0;
  }
  cVar1 = *(char *)((int)pfVar13 + 0x2b);
  if (cVar1 == '\a') {
    *(undefined *)((int)pfVar13 + 0x79) = 3;
  }
  else if (cVar1 == '\b') {
    *(undefined *)((int)pfVar13 + 0x79) = 4;
  }
  else if (cVar1 == '\t') {
    *(undefined *)((int)pfVar13 + 0x79) = 5;
  }
  fVar2 = FLOAT_803e56d4;
  if (*(char *)((int)pfVar13 + 0x29) < '\x02') {
    pfVar13[0x24] = pfVar13[0x24] - FLOAT_803db414;
    if (pfVar13[0x24] <= FLOAT_803e56cc) {
      *(byte *)(pfVar13 + 0x28) = *(byte *)(pfVar13 + 0x28) ^ 1;
      uVar9 = FUN_800221a0(0xb4,300);
      local_e0 = (double)CONCAT44(0x43300000,uVar9 ^ 0x80000000);
      pfVar13[0x24] = (float)(local_e0 - DOUBLE_803e57c0);
    }
    if (*(char *)(pfVar13 + 0x28) == '\0') {
      pfVar13[0x22] = pfVar13[0x22] - FLOAT_803db414;
    }
    else {
      pfVar13[0x22] = FLOAT_803e56d0 * FLOAT_803db414 + pfVar13[0x22];
    }
    pfVar13[0x25] = pfVar13[0x25] - FLOAT_803db414;
    if (pfVar13[0x25] <= FLOAT_803e56cc) {
      *(byte *)((int)pfVar13 + 0xa1) = *(byte *)((int)pfVar13 + 0xa1) ^ 1;
      uVar9 = FUN_800221a0(0xb4,300);
      local_e0 = (double)CONCAT44(0x43300000,uVar9 ^ 0x80000000);
      pfVar13[0x25] = (float)(local_e0 - DOUBLE_803e57c0);
    }
    if (*(char *)((int)pfVar13 + 0xa1) == '\0') {
      pfVar13[0x23] = pfVar13[0x23] - FLOAT_803db414;
    }
    else {
      pfVar13[0x23] = FLOAT_803e56d0 * FLOAT_803db414 + pfVar13[0x23];
    }
  }
  else {
    pfVar13[0x22] = -(FLOAT_803e56d4 * FLOAT_803db414 - pfVar13[0x22]);
    pfVar13[0x23] = -(fVar2 * FLOAT_803db414 - pfVar13[0x23]);
  }
  fVar2 = pfVar13[0x22];
  fVar3 = FLOAT_803e56cc;
  if ((FLOAT_803e56cc <= fVar2) && (fVar3 = fVar2, FLOAT_803e56d8 < fVar2)) {
    fVar3 = FLOAT_803e56d8;
  }
  pfVar13[0x22] = fVar3;
  fVar2 = pfVar13[0x23];
  fVar3 = FLOAT_803e56cc;
  if ((FLOAT_803e56cc <= fVar2) && (fVar3 = fVar2, FLOAT_803e56d8 < fVar2)) {
    fVar3 = FLOAT_803e56d8;
  }
  pfVar13[0x23] = fVar3;
  cVar1 = *(char *)((int)pfVar13 + 0x29);
  if (cVar1 == '\x01') {
    *(undefined4 *)(psVar7 + 0x7a) = 2;
    local_148 = FLOAT_803e56c8;
    (**(code **)(*DAT_803dca50 + 0x60))(&local_148,0);
    if (*(short *)((int)pfVar13 + 0x82) != 0) {
      *(short *)((int)pfVar13 + 0x82) = *(short *)((int)pfVar13 + 0x82) + -1;
    }
    cVar1 = *(char *)((int)pfVar13 + 0x7a);
    if (cVar1 == '\x03') {
      dVar18 = (double)(*(float *)((int)fVar12 + 0xc) - FLOAT_803e571c);
      dVar17 = (double)(FLOAT_803e5718 + *(float *)((int)fVar12 + 0x10));
      dVar16 = (double)(FLOAT_803e5720 + pfVar13[0x16] +
                       (*(float *)((int)fVar12 + 0x14) - pfVar13[0xd]));
      *(undefined *)((int)pfVar13 + 0x7b) = 0;
    }
    else if (cVar1 < '\x03') {
      if (cVar1 == '\x01') {
        dVar18 = (double)(pfVar13[0x14] - FLOAT_803e5710);
        dVar16 = (double)pfVar13[0x16];
        dVar17 = (double)(FLOAT_803e56ec + *(float *)((int)fVar12 + 0x10));
      }
      else if (cVar1 < '\x01') {
        if (cVar1 < '\0') goto LAB_801e0288;
        dVar18 = (double)(pfVar13[0x14] - FLOAT_803e570c);
        dVar16 = (double)pfVar13[0x16];
        dVar17 = (double)(FLOAT_803e56ec + *(float *)((int)fVar12 + 0x10));
        if ((*(short *)((int)pfVar13 + 0x82) < 1) &&
           ((*(char *)(pfVar13 + 0x1f) == '\0' || (*(char *)(pfVar13 + 0x1f) == '\x05')))) {
          *(undefined2 *)((int)pfVar13 + 0x82) = 200;
        }
        FUN_8000b578(psVar7,2);
      }
      else {
        dVar18 = (double)(*(float *)((int)fVar12 + 0xc) - FLOAT_803e5714);
        dVar16 = (double)pfVar13[0x16];
        dVar17 = (double)(FLOAT_803e5718 + *(float *)((int)fVar12 + 0x10));
      }
    }
    else if (cVar1 == '\x05') {
      dVar18 = (double)(*(float *)((int)fVar12 + 0xc) - FLOAT_803e571c);
      dVar17 = (double)(FLOAT_803e5718 + *(float *)((int)fVar12 + 0x10));
      dVar16 = (double)((pfVar13[0x16] - FLOAT_803e5720) +
                       (*(float *)((int)fVar12 + 0x14) - pfVar13[0xd]));
      *(undefined *)((int)pfVar13 + 0x7b) = 0;
    }
    else if (cVar1 < '\x05') {
      dVar18 = (double)(*(float *)((int)fVar12 + 0xc) - FLOAT_803e571c);
      dVar16 = (double)(FLOAT_803e5724 + pfVar13[0x16]);
      dVar17 = (double)(FLOAT_803e5718 + *(float *)((int)fVar12 + 0x10));
      *(undefined *)((int)pfVar13 + 0x7b) = 0;
    }
    else {
LAB_801e0288:
      *(undefined *)((int)pfVar13 + 0x7b) = 0;
      dVar18 = (double)(pfVar13[0x14] - FLOAT_803e5728);
      dVar16 = (double)pfVar13[0x16];
      dVar17 = (double)(FLOAT_803e572c + *(float *)((int)fVar12 + 0x10));
    }
    dVar19 = (double)(float)(dVar18 - (double)*(float *)(psVar7 + 6));
    dVar18 = (double)(float)(dVar17 - (double)*(float *)(psVar7 + 8));
    dVar16 = (double)(float)(dVar16 - (double)*(float *)(psVar7 + 10));
    pfVar13[7] = FLOAT_803e56f4;
    dVar17 = (double)FUN_802931a0((double)(float)(dVar16 * dVar16 +
                                                 (double)(float)(dVar19 * dVar19 +
                                                                (double)(float)(dVar18 * dVar18))));
    fVar2 = (float)(dVar18 * (double)FLOAT_803e56f8);
    fVar3 = (float)(dVar16 * (double)FLOAT_803e56f8);
    fVar4 = (float)(dVar19 * (double)FLOAT_803e56fc);
    if (FLOAT_803e5730 < (float)(dVar19 * (double)FLOAT_803e56fc)) {
      fVar4 = FLOAT_803e5730;
    }
    if (fVar4 < FLOAT_803e5734) {
      fVar4 = FLOAT_803e5734;
    }
    if (FLOAT_803e5738 < fVar2) {
      fVar2 = FLOAT_803e5738;
    }
    if (fVar2 < FLOAT_803e573c) {
      fVar2 = FLOAT_803e573c;
    }
    if (FLOAT_803e5740 < fVar3) {
      fVar3 = FLOAT_803e5740;
    }
    if (fVar3 < FLOAT_803e5744) {
      fVar3 = FLOAT_803e5744;
    }
    *(ushort *)((int)pfVar13 + 0x6e) = *(short *)((int)pfVar13 + 0x6e) + (ushort)DAT_803db410;
    *pfVar13 = (fVar4 - *pfVar13) * FLOAT_803e5748 + *pfVar13;
    pfVar13[1] = pfVar13[1] + (fVar2 - pfVar13[1]) / FLOAT_803e574c;
    pfVar13[2] = pfVar13[2] + (fVar3 - pfVar13[2]) / FLOAT_803e5750;
    in_f28 = (double)FLOAT_803e5754;
    in_f29 = (double)FLOAT_803e5758;
    in_f27 = (double)FLOAT_803e56cc;
    cVar1 = *(char *)((int)pfVar13 + 0x7a);
    if (cVar1 == '\x03') {
      if ((dVar17 < (double)FLOAT_803e5708) || (0x78 < *(short *)((int)pfVar13 + 0x6e))) {
        *(undefined *)((int)pfVar13 + 0x7a) = 0;
        *(undefined2 *)((int)pfVar13 + 0x6e) = 0;
      }
    }
    else if (cVar1 < '\x03') {
      if (cVar1 == '\x01') {
        if (dVar17 < (double)FLOAT_803e5708) {
          *(undefined *)((int)pfVar13 + 0x7a) = 2;
          *(undefined2 *)((int)pfVar13 + 0x6e) = 0;
        }
      }
      else if (cVar1 < '\x01') {
        if (cVar1 < '\0') goto LAB_801e04d0;
        if (dVar17 < (double)FLOAT_803e575c) {
          *(undefined *)((int)pfVar13 + 0x7a) = 1;
          *(undefined2 *)((int)pfVar13 + 0x6e) = 0;
        }
      }
      else if ((0xf0 < *(short *)((int)pfVar13 + 0x6e)) || (dVar17 < (double)FLOAT_803e5708)) {
        *(undefined *)((int)pfVar13 + 0x7a) = 0;
        *(undefined2 *)((int)pfVar13 + 0x6e) = 0;
      }
    }
    else if (cVar1 == '\x05') {
      if ((dVar17 < (double)FLOAT_803e5708) || (0x78 < *(short *)((int)pfVar13 + 0x6e))) {
        *(undefined *)((int)pfVar13 + 0x7a) = 0;
        *(undefined2 *)((int)pfVar13 + 0x6e) = 0;
      }
    }
    else if (cVar1 < '\x05') {
      if ((dVar17 < (double)FLOAT_803e5708) || (0x78 < *(short *)((int)pfVar13 + 0x6e))) {
        *(undefined *)((int)pfVar13 + 0x7a) = 5;
        *(undefined2 *)((int)pfVar13 + 0x6e) = 3;
      }
    }
    else {
LAB_801e04d0:
      if (dVar17 < (double)FLOAT_803e5760) {
        if (*(char *)((int)pfVar13 + 0x2b) == '\x02') {
          *(undefined2 *)((int)pfVar13 + 0x6e) = 0;
          *(undefined *)((int)pfVar13 + 0x29) = 0;
          *(undefined *)((int)pfVar13 + 0x2b) = 3;
        }
        else if (*(char *)((int)pfVar13 + 0x2b) == '\x05') {
          *(undefined *)((int)pfVar13 + 0x29) = 2;
          *(undefined *)((int)pfVar13 + 0x2b) = 6;
        }
      }
    }
    *(undefined2 *)((int)pfVar13 + 0x26) = 300;
    if ((*(char *)(pfVar13 + 0x1f) < '\x04') || ('\x02' < *(char *)((int)pfVar13 + 0x2b))) {
      if ('\x03' < *(char *)(pfVar13 + 0x1f)) {
        *(undefined *)((int)pfVar13 + 0x29) = 2;
        *(undefined *)(pfVar13 + 10) = 3;
        *(undefined *)((int)pfVar13 + 0x2b) = 6;
        *(undefined2 *)((int)pfVar13 + 0x82) = 200;
        pfVar13[3] = *(float *)((int)fVar12 + 0x14);
      }
    }
    else {
      *(undefined *)((int)pfVar13 + 0x29) = 0;
      *(undefined *)(pfVar13 + 10) = 1;
      *(undefined *)((int)pfVar13 + 0x2b) = 3;
      *(undefined *)(pfVar13 + 0x1f) = 5;
      *(undefined2 *)((int)pfVar13 + 0x82) = 200;
      uVar10 = FUN_801e2570();
      FUN_8000b824(uVar10,0x2c6);
      FUN_8000bb18(uVar10,0x146);
      FUN_800200e8(0xf1e,0);
    }
  }
  else if (cVar1 < '\x01') {
    if (cVar1 < '\0') {
LAB_801e0d90:
      *(undefined4 *)(psVar7 + 0x7a) = 7;
    }
    else {
      local_148 = FLOAT_803e56c8;
      FUN_8000b7bc(psVar7,1);
      (**(code **)(*DAT_803dca50 + 0x60))(&local_148,0);
      *(undefined4 *)(psVar7 + 0x7a) = 1;
      dVar18 = (double)(pfVar13[0x14] - FLOAT_803e56dc);
      local_e0 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar13 + 8) ^ 0x80000000);
      dVar17 = (double)FUN_80294204((double)((FLOAT_803e56e4 * (float)(local_e0 - DOUBLE_803e57c0))
                                            / FLOAT_803e56e8));
      dVar19 = (double)(float)((double)FLOAT_803e56e0 * dVar17 + (double)pfVar13[0x16]);
      local_d8 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar13 + 8) ^ 0x80000000);
      dVar17 = (double)FUN_80293e80((double)((FLOAT_803e56e4 * (float)(local_d8 - DOUBLE_803e57c0))
                                            / FLOAT_803e56e8));
      dVar16 = (double)FLOAT_803e56f0;
      fVar5 = pfVar13[0x15] - FLOAT_803e56ec;
      *(ushort *)(pfVar13 + 8) = *(short *)(pfVar13 + 8) + (ushort)DAT_803db410 * 0xb6;
      fVar2 = *(float *)(psVar7 + 6);
      fVar3 = *(float *)(psVar7 + 8);
      fVar4 = *(float *)(psVar7 + 10);
      pfVar13[7] = FLOAT_803e56f4;
      fVar6 = (float)(dVar18 - (double)fVar2) * FLOAT_803e56f8;
      fVar3 = ((float)(dVar16 * dVar17 + (double)fVar5) - fVar3) * FLOAT_803e56f8;
      fVar4 = (float)(dVar19 - (double)fVar4) * FLOAT_803e56f8;
      fVar2 = pfVar13[7];
      if (fVar2 < fVar6) {
        fVar6 = fVar2;
      }
      fVar5 = -fVar2;
      if (fVar6 < fVar5) {
        fVar6 = fVar5;
      }
      if (fVar2 < fVar3) {
        fVar3 = fVar2;
      }
      if (fVar3 < fVar5) {
        fVar3 = fVar5;
      }
      if (fVar2 < fVar4) {
        fVar4 = fVar2;
      }
      if (fVar4 < fVar5) {
        fVar4 = fVar5;
      }
      iVar14 = (int)*(short *)((int)pfVar13 + 0x6e);
      fVar2 = FLOAT_803e56cc;
      if ((0x77 < iVar14) && (fVar2 = fVar3, iVar14 < 0xb4)) {
        local_d8 = (double)CONCAT44(0x43300000,iVar14 - 0x78U ^ 0x80000000);
        fVar2 = fVar3 * ((float)(local_d8 - DOUBLE_803e57c0) / FLOAT_803e56f0);
      }
      *(ushort *)((int)pfVar13 + 0x6e) = *(short *)((int)pfVar13 + 0x6e) + (ushort)DAT_803db410;
      fVar3 = FLOAT_803e56fc;
      *pfVar13 = (fVar6 - *pfVar13) * FLOAT_803e56fc + *pfVar13;
      pfVar13[1] = (fVar2 - pfVar13[1]) * fVar3 + pfVar13[1];
      pfVar13[2] = (fVar4 - pfVar13[2]) * fVar3 + pfVar13[2];
      in_f28 = (double)FLOAT_803e5700;
      in_f29 = (double)FLOAT_803e5704;
      in_f27 = (double)FLOAT_803e5708;
      if (*(char *)(pfVar13 + 10) == '\0') {
        if ((*(char *)((int)pfVar13 + 0x2b) < '\x02') && (-1 < *(char *)((int)pfVar13 + 0x2b))) {
          if ((*(short *)((int)pfVar13 + 0x82) != 0) &&
             (*(short *)((int)pfVar13 + 0x82) = *(short *)((int)pfVar13 + 0x82) + -1,
             *(short *)((int)pfVar13 + 0x82) < 1)) {
            *(undefined2 *)((int)pfVar13 + 0x82) = 200;
          }
        }
        else {
          *(undefined *)((int)pfVar13 + 0x2b) = 2;
          *(undefined2 *)((int)pfVar13 + 0x6e) = 0;
          *(undefined *)((int)pfVar13 + 0x29) = 1;
          *(undefined *)(pfVar13 + 10) = 1;
          *(undefined *)(pfVar13 + 0x1f) = 0;
          *(undefined *)((int)pfVar13 + 0x7a) = 0;
          *(undefined2 *)((int)pfVar13 + 0x82) = 200;
          FUN_800200e8(0xf1e,1);
        }
      }
      else if ((*(char *)((int)pfVar13 + 0x2b) < '\x05') &&
              ('\x02' < *(char *)((int)pfVar13 + 0x2b))) {
        if ((*(short *)((int)pfVar13 + 0x82) != 0) &&
           (*(short *)((int)pfVar13 + 0x82) = *(short *)((int)pfVar13 + 0x82) + -1,
           *(short *)((int)pfVar13 + 0x82) < 1)) {
          *(undefined2 *)((int)pfVar13 + 0x82) = 200;
        }
      }
      else {
        *(undefined *)((int)pfVar13 + 0x2b) = 5;
        *(undefined2 *)((int)pfVar13 + 0x6e) = 0;
        *(undefined *)((int)pfVar13 + 0x29) = 1;
        *(undefined *)(pfVar13 + 10) = 2;
        *(undefined *)((int)pfVar13 + 0x7a) = 0;
        *(undefined2 *)((int)pfVar13 + 0x82) = 200;
      }
    }
  }
  else {
    if ('\b' < cVar1) goto LAB_801e0d90;
    local_148 = FLOAT_803e56c8;
    FUN_8000b7bc(psVar7,2);
    (**(code **)(*DAT_803dca50 + 0x60))(&local_148,0);
    *(undefined4 *)(psVar7 + 0x7a) = 3;
    if (*(short *)((int)pfVar13 + 0x82) != 0) {
      *(short *)((int)pfVar13 + 0x82) = *(short *)((int)pfVar13 + 0x82) + -1;
    }
    switch(*(undefined *)((int)pfVar13 + 0x29)) {
    case 2:
      in_f25 = (double)FLOAT_803e5764;
      in_f29 = (double)(pfVar13[0x14] - FLOAT_803e5768);
      local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)((int)pfVar13 + 0x2a) ^ 0x80000000);
      in_f31 = -(double)(FLOAT_803e576c * (float)(local_d8 - DOUBLE_803e57c0) - pfVar13[0x16]);
      in_f30 = (double)pfVar13[0x15];
      in_f26 = (double)FLOAT_803e5770;
      unaff_r31 = 3;
      break;
    case 3:
      in_f25 = (double)FLOAT_803e5774;
      in_f29 = (double)(pfVar13[0x14] - FLOAT_803e5778);
      local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)((int)pfVar13 + 0x2a) ^ 0x80000000);
      in_f31 = -(double)(FLOAT_803e5770 * (float)(local_d8 - DOUBLE_803e57c0) - pfVar13[0x16]);
      in_f30 = (double)(FLOAT_803e5724 + pfVar13[0x15]);
      unaff_r31 = 4;
      in_f26 = (double)FLOAT_803e577c;
      break;
    case 4:
      in_f25 = (double)FLOAT_803e5774;
      in_f29 = (double)(pfVar13[0x14] - FLOAT_803e5768);
      local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)((int)pfVar13 + 0x2a) ^ 0x80000000);
      in_f31 = -(double)(FLOAT_803e5708 * (float)(local_d8 - DOUBLE_803e57c0) - pfVar13[0x16]);
      in_f30 = (double)(FLOAT_803e5724 + pfVar13[0x15]);
      unaff_r31 = 5;
      in_f26 = (double)FLOAT_803e577c;
      break;
    case 5:
      in_f25 = (double)FLOAT_803e5708;
      *(undefined4 *)(psVar7 + 0x7a) = 4;
      in_f29 = (double)(pfVar13[0x14] - FLOAT_803e5780);
      in_f31 = (double)pfVar13[0x16];
      in_f30 = (double)(pfVar13[0x15] - FLOAT_803e5724);
      unaff_r31 = 6;
      in_f26 = (double)FLOAT_803e577c;
      if ((*(short *)((int)pfVar13 + 0x82) < 1) && (*(char *)((int)pfVar13 + 0x2b) == '\x06')) {
        *(undefined2 *)((int)pfVar13 + 0x82) = 200;
      }
      break;
    case 6:
      in_f25 = (double)FLOAT_803e56d0;
      in_f29 = (double)(FLOAT_803e5784 + pfVar13[0x14]);
      local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)((int)pfVar13 + 0x2a) ^ 0x80000000);
      in_f31 = -(double)(FLOAT_803e576c * (float)(local_d8 - DOUBLE_803e57c0) - pfVar13[0x16]);
      in_f30 = (double)(FLOAT_803e5718 + pfVar13[0x15]);
      unaff_r31 = 7;
      in_f26 = (double)FLOAT_803e5724;
      break;
    case 7:
      in_f25 = (double)FLOAT_803e56d0;
      in_f29 = (double)(FLOAT_803e5788 + pfVar13[0x14]);
      in_f31 = (double)pfVar13[0x16];
      in_f30 = (double)(FLOAT_803e578c + *(float *)((int)fVar12 + 0x10));
      unaff_r31 = 8;
      in_f26 = (double)FLOAT_803e5724;
      break;
    case 8:
      in_f25 = (double)FLOAT_803e5790;
      in_f29 = (double)(pfVar13[0x14] - FLOAT_803e5794);
      in_f31 = (double)pfVar13[0x16];
      in_f30 = (double)(FLOAT_803e5724 + *(float *)((int)fVar12 + 0x10));
      unaff_r31 = 2;
      in_f26 = (double)FLOAT_803e5784;
    }
    dVar19 = (double)(float)(in_f29 - (double)pfVar13[0xb]);
    dVar18 = (double)(float)(in_f30 - (double)pfVar13[0xc]);
    dVar16 = (double)(float)(in_f31 - (double)pfVar13[0xd]);
    pfVar13[7] = (float)((double)pfVar13[7] +
                        (double)((float)(in_f25 - (double)pfVar13[7]) / FLOAT_803e5798));
    dVar17 = (double)FUN_802931a0((double)(float)(dVar19 * dVar19 + (double)(float)(dVar16 * dVar16)
                                                 ));
    if ((*(char *)((int)pfVar13 + 0x29) == '\x05') && (dVar17 < (double)FLOAT_803e579c)) {
      *(undefined4 *)(psVar7 + 0x7a) = 5;
    }
    if (dVar17 < in_f26) {
      if (*(char *)((int)pfVar13 + 0x29) == '\x05') {
        *(char *)((int)pfVar13 + 0x2a) = -*(char *)((int)pfVar13 + 0x2a);
      }
      *(undefined *)((int)pfVar13 + 0x29) = unaff_r31;
    }
    uVar9 = FUN_800217c0(dVar19,dVar16);
    uVar11 = FUN_800217c0(dVar18,dVar17);
    iVar8 = ((uVar9 & 0xffff) + 0x8000) - ((int)*psVar7 & 0xffffU);
    if (0x8000 < iVar8) {
      iVar8 = iVar8 + -0xffff;
    }
    if (iVar8 < -0x8000) {
      iVar8 = iVar8 + 0xffff;
    }
    *(short *)(pfVar13 + 9) =
         *(short *)(pfVar13 + 9) +
         (short)((int)((uint)DAT_803db410 * (iVar8 - *(short *)(pfVar13 + 9))) >> 4);
    cVar1 = *(char *)((int)pfVar13 + 0x29);
    if ((cVar1 == '\x03') || (cVar1 == '\x04')) {
      iVar8 = (int)((int)*(short *)(pfVar13 + 9) * (uint)DAT_803db410) / 0x3c +
              ((int)((int)*(short *)(pfVar13 + 9) * (uint)DAT_803db410) >> 0x1f);
      *psVar7 = *psVar7 + ((short)iVar8 - (short)(iVar8 >> 0x1f));
    }
    else if ((cVar1 == '\x06') || (cVar1 == '\x02')) {
      iVar8 = (int)((int)*(short *)(pfVar13 + 9) * (uint)DAT_803db410) / 0x78 +
              ((int)((int)*(short *)(pfVar13 + 9) * (uint)DAT_803db410) >> 0x1f);
      *psVar7 = *psVar7 + ((short)iVar8 - (short)(iVar8 >> 0x1f));
    }
    else {
      iVar8 = (int)((int)*(short *)(pfVar13 + 9) * (uint)DAT_803db410) / 0x3c +
              ((int)((int)*(short *)(pfVar13 + 9) * (uint)DAT_803db410) >> 0x1f);
      *psVar7 = *psVar7 + ((short)iVar8 - (short)(iVar8 >> 0x1f));
    }
    iVar8 = (uVar11 & 0xffff) - ((int)psVar7[1] & 0xffffU);
    if (0x8000 < iVar8) {
      iVar8 = iVar8 + -0xffff;
    }
    if (iVar8 < -0x8000) {
      iVar8 = iVar8 + 0xffff;
    }
    psVar7[1] = psVar7[1] + (short)((int)(iVar8 * (uint)DAT_803db410) >> 6);
    FUN_802931a0((double)((pfVar13[0x14] - *(float *)(psVar7 + 6)) *
                          (pfVar13[0x14] - *(float *)(psVar7 + 6)) +
                         (pfVar13[0x16] - *(float *)(psVar7 + 10)) *
                         (pfVar13[0x16] - *(float *)(psVar7 + 10))));
    local_d8 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar13 + 9) ^ 0x80000000);
    iVar8 = (int)(FLOAT_803e57a0 * (float)(local_d8 - DOUBLE_803e57c0));
    local_e0 = (double)(longlong)iVar8;
    uVar9 = iVar8 - psVar7[2] >> 3;
    if (0x3c < (int)uVar9) {
      uVar9 = 0x3c;
    }
    if ((int)uVar9 < -0x3c) {
      uVar9 = 0xffffffc4;
    }
    local_d0 = (double)CONCAT44(0x43300000,uVar9 ^ 0x80000000);
    uStack196 = (int)psVar7[2] ^ 0x80000000;
    local_c8 = 0x43300000;
    iVar8 = (int)((float)(local_d0 - DOUBLE_803e57c0) * FLOAT_803db414 +
                 (float)((double)CONCAT44(0x43300000,uStack196) - DOUBLE_803e57c0));
    local_c0 = (double)(longlong)iVar8;
    psVar7[2] = (short)iVar8;
    local_130 = FLOAT_803e56cc;
    local_12c = FLOAT_803e56cc;
    local_128 = FLOAT_803e56cc;
    local_134 = FLOAT_803e57a4;
    local_13c = *psVar7;
    local_13a = psVar7[1];
    local_138 = psVar7[2];
    FUN_80021ee8(auStack292,&local_13c);
    FUN_800226cc((double)FLOAT_803e56cc,(double)FLOAT_803e56cc,
                 (double)(-pfVar13[7] * FLOAT_803db414),auStack292,pfVar13,pfVar13 + 1,pfVar13 + 2);
    if (*(char *)((int)pfVar13 + 0x29) == '\a') {
      pfVar13[0xb] = (float)in_f29;
      pfVar13[0xc] = (float)in_f30;
      pfVar13[0xd] = (float)in_f31;
      fVar2 = FLOAT_803e56cc;
      pfVar13[0xe] = FLOAT_803e56cc;
      pfVar13[0xf] = fVar2;
      pfVar13[0x10] = fVar2;
    }
    else {
      pfVar13[0xb] = pfVar13[0xb] + *pfVar13;
      pfVar13[0xc] = pfVar13[0xc] + pfVar13[1];
      pfVar13[0xd] = pfVar13[0xd] + pfVar13[2];
    }
    in_f29 = (double)FLOAT_803e57a8;
    *(float *)(psVar7 + 6) = pfVar13[0xb] + pfVar13[0xe];
    *(float *)(psVar7 + 8) = pfVar13[0xc] + pfVar13[0xf];
    *(float *)(psVar7 + 10) =
         pfVar13[0xd] + pfVar13[0x10] + (*(float *)((int)fVar12 + 0x14) - pfVar13[3]);
    if ('\x06' < *(char *)((int)pfVar13 + 0x2b)) {
      if (*(short *)(pfVar13 + 0x1b) == 0) {
        FUN_80035f00(psVar7);
        (**(code **)(*DAT_803dca4c + 8))(0x41,1);
      }
      *(ushort *)(pfVar13 + 0x1b) = *(short *)(pfVar13 + 0x1b) + (ushort)DAT_803db410;
      if (0x41 < *(short *)(pfVar13 + 0x1b)) {
        *psVar7 = 0;
        *(undefined *)((int)pfVar13 + 0x29) = 6;
        (**(code **)(*DAT_803dca64 + 0x20))(0);
        (**(code **)(*DAT_803dca64 + 0x24))(0);
        (**(code **)(*DAT_803dca64 + 0x28))((double)FLOAT_803e56cc,(double)FLOAT_803e5760);
        if (*(char *)(pfVar13 + 0x20) == '\0') {
          *(undefined *)(pfVar13 + 0x20) = 1;
        }
        *(undefined *)(pfVar13 + 0x1c) = 1;
        *(undefined4 *)(psVar7 + 6) = *(undefined4 *)(iVar14 + 8);
        *(float *)(psVar7 + 8) = FLOAT_803e57ac;
        *(undefined4 *)(psVar7 + 10) = *(undefined4 *)(iVar14 + 0x10);
        FUN_8000b7bc(psVar7,1);
        (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(psVar7 + 0x1a),2,1);
        (**(code **)(*DAT_803dca54 + 0x48))(0,psVar7,0xffffffff);
        goto LAB_801e1024;
      }
    }
  }
  if (*(char *)((int)pfVar13 + 0x29) < '\x02') {
    pfVar13[0xb] = pfVar13[0x11] * *pfVar13 * FLOAT_803db414 + pfVar13[0xb];
    pfVar13[0xc] = pfVar13[0x11] * pfVar13[1] * FLOAT_803db414 + pfVar13[0xc];
    pfVar13[0xd] = pfVar13[0x11] * pfVar13[2] * FLOAT_803db414 + pfVar13[0xd];
    pfVar13[0x11] = pfVar13[0x11] + FLOAT_803e57b0;
    if (FLOAT_803e57a4 < pfVar13[0x11]) {
      pfVar13[0x11] = FLOAT_803e57a4;
    }
    dVar17 = (double)FLOAT_803e57b4;
    pfVar13[0x17] =
         (float)(dVar17 * (double)(FLOAT_803db414 * (float)(in_f28 - (double)pfVar13[0x17])) +
                (double)pfVar13[0x17]);
    pfVar13[0x18] =
         (float)(dVar17 * (double)(FLOAT_803db414 * (float)(in_f27 - (double)pfVar13[0x18])) +
                (double)pfVar13[0x18]);
    pfVar13[0x19] =
         (float)(dVar17 * (double)(FLOAT_803db414 * (float)(in_f29 - (double)pfVar13[0x19])) +
                (double)pfVar13[0x19]);
    if (*(char *)((int)pfVar13 + 0x29) == '\0') {
      local_c0 = (double)CONCAT44(0x43300000,(int)*(short *)((int)fVar12 + 2) ^ 0x80000000);
      dVar17 = local_c0 - DOUBLE_803e57c0;
      uStack196 = -(int)*(short *)((int)fVar12 + 4) ^ 0x80000000;
      local_c8 = 0x43300000;
      pfVar13[0x10] =
           FLOAT_803db414 *
           pfVar13[0x19] *
           ((float)((double)CONCAT44(0x43300000,uStack196) - DOUBLE_803e57c0) / pfVar13[0x17] -
           pfVar13[0x10]) + pfVar13[0x10];
      pfVar13[0xf] = FLOAT_803db414 * pfVar13[0x19] * ((float)dVar17 / pfVar13[0x17] - pfVar13[0xf])
                     + pfVar13[0xf];
      fVar12 = FLOAT_803e56cc;
      pfVar13[0xe] = FLOAT_803e56cc;
      pfVar13[0xf] = fVar12;
      iVar14 = (int)(-pfVar13[0x10] * pfVar13[0x18]);
      local_d0 = (double)(longlong)iVar14;
      iVar14 = (int)(short)iVar14;
      iVar8 = (int)(FLOAT_803e57b8 * -pfVar13[0xf] * pfVar13[0x18]);
      local_d8 = (double)(longlong)iVar8;
      iVar8 = (int)(short)iVar8;
    }
    else {
      pfVar13[0x10] = -(FLOAT_803db414 * pfVar13[0x10] * pfVar13[0x19] - pfVar13[0x10]);
      pfVar13[0xf] = -(FLOAT_803db414 * pfVar13[0xf] * pfVar13[0x19] - pfVar13[0xf]);
      iVar14 = 0;
      iVar8 = 0;
    }
    *(float *)(psVar7 + 6) = pfVar13[0xe] * pfVar13[0x11] + pfVar13[0xb];
    *(float *)(psVar7 + 8) = pfVar13[0xf] * pfVar13[0x11] + pfVar13[0xc];
    *(float *)(psVar7 + 10) = pfVar13[0x10] * pfVar13[0x11] + pfVar13[0xd];
    *(short *)((int)pfVar13 + 0x22) =
         *(short *)((int)pfVar13 + 0x22) +
         (short)((int)((uint)DAT_803db410 * (iVar14 - *(short *)((int)pfVar13 + 0x22))) >> 5);
    psVar7[1] = psVar7[1] + (short)((int)((uint)DAT_803db410 * (iVar8 - psVar7[1])) >> 5);
    *psVar7 = *(short *)((int)pfVar13 + 0x22) + 0x4000;
    psVar7[2] = *psVar7 + -0x4000;
  }
LAB_801e1024:
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  __psq_l0(auStack40,uVar15);
  __psq_l1(auStack40,uVar15);
  __psq_l0(auStack56,uVar15);
  __psq_l1(auStack56,uVar15);
  __psq_l0(auStack72,uVar15);
  __psq_l1(auStack72,uVar15);
  __psq_l0(auStack88,uVar15);
  __psq_l1(auStack88,uVar15);
  __psq_l0(auStack104,uVar15);
  __psq_l1(auStack104,uVar15);
  __psq_l0(auStack120,uVar15);
  __psq_l1(auStack120,uVar15);
  __psq_l0(auStack136,uVar15);
  __psq_l1(auStack136,uVar15);
  __psq_l0(auStack152,uVar15);
  __psq_l1(auStack152,uVar15);
  FUN_80286128();
  return;
}

