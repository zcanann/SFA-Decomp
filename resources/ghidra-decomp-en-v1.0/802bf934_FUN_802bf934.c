// Function: FUN_802bf934
// Entry: 802bf934
// Size: 3100 bytes

/* WARNING: Removing unreachable block (ram,0x802c0528) */
/* WARNING: Removing unreachable block (ram,0x802c0518) */
/* WARNING: Removing unreachable block (ram,0x802c0510) */
/* WARNING: Removing unreachable block (ram,0x802c0520) */
/* WARNING: Removing unreachable block (ram,0x802c0530) */

void FUN_802bf934(void)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  ushort uVar5;
  int iVar4;
  undefined2 *puVar6;
  short *psVar7;
  short sVar9;
  undefined4 uVar8;
  uint *puVar10;
  float *pfVar11;
  int iVar12;
  int iVar13;
  uint uVar14;
  undefined4 uVar15;
  double extraout_f1;
  double dVar16;
  double dVar17;
  undefined8 in_f27;
  double dVar18;
  undefined8 in_f28;
  double dVar19;
  double in_f29;
  undefined8 in_f30;
  double dVar20;
  undefined8 in_f31;
  undefined8 uVar21;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  undefined2 local_ac;
  short local_aa;
  undefined2 local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  longlong local_90;
  longlong local_88;
  longlong local_80;
  longlong local_78;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,SUB84(in_f29,0),0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  uVar21 = FUN_802860d0();
  puVar6 = (undefined2 *)((ulonglong)uVar21 >> 0x20);
  puVar10 = (uint *)uVar21;
  local_b8 = DAT_802c2d18;
  local_b4 = DAT_802c2d1c;
  local_b0 = DAT_802c2d20;
  local_c4 = DAT_802c2d24;
  local_c0 = DAT_802c2d28;
  local_bc = DAT_802c2d2c;
  local_dc = DAT_802c2d30;
  local_d8 = DAT_802c2d34;
  local_d4 = DAT_802c2d38;
  iVar12 = -1;
  iVar13 = *(int *)(puVar6 + 0x5c);
  *puVar10 = *puVar10 | 0x200000;
  *(undefined *)((int)puVar10 + 0x25f) = 0;
  bVar1 = *(char *)((int)puVar10 + 0x346) != '\0';
  if (bVar1) {
    *(byte *)(iVar13 + 0xbc0) = *(byte *)(iVar13 + 0xbc0) & 0x7f;
    *(byte *)(iVar13 + 0xbc0) = *(byte *)(iVar13 + 0xbc0) & 0xf7;
  }
  dVar19 = extraout_f1;
  FUN_8003393c(puVar6);
  if (*(char *)((int)puVar10 + 0x27a) != '\0') {
    if ((*(byte *)(iVar13 + 0xbc0) >> 5 & 1) == 0) {
      *(byte *)(iVar13 + 0xbc0) = *(byte *)(iVar13 + 0xbc0) & 0xdf | 0x20;
      FUN_802bf0c8(puVar6,puVar10,*(byte *)(iVar13 + 0xbc0) >> 5 & 1);
    }
    FUN_80030334((double)FLOAT_803e83a4,puVar6,(int)DAT_80335758,0);
    *(undefined2 *)(iVar13 + 0xbbc) = DAT_80335764;
    *(undefined2 *)(iVar13 + 0xbba) = *puVar6;
    *(undefined2 *)(iVar13 + 0xbbe) = puVar6[2];
    fVar2 = FLOAT_803e83a4;
    puVar10[0xa5] = (uint)FLOAT_803e83a4;
    puVar10[0xa1] = (uint)fVar2;
    puVar10[0xa0] = (uint)fVar2;
    *(float *)(puVar6 + 0x12) = fVar2;
    *(float *)(puVar6 + 0x14) = fVar2;
    *(float *)(puVar6 + 0x16) = fVar2;
    bVar1 = true;
    *(byte *)(iVar13 + 0xbc0) = *(byte *)(iVar13 + 0xbc0) & 0x7f | 0x80;
    *(undefined4 *)(iVar13 + 0xaf4) = *(undefined4 *)(puVar6 + 6);
    *(undefined4 *)(iVar13 + 0xaf8) = *(undefined4 *)(puVar6 + 8);
    *(undefined4 *)(iVar13 + 0xafc) = *(undefined4 *)(puVar6 + 10);
  }
  *puVar10 = *puVar10 | 0x1000000;
  if ((float)puVar10[0xa6] < FLOAT_803e83bc) {
    *(undefined2 *)(puVar10 + 0xcd) = 0;
    *(undefined2 *)((int)puVar10 + 0x336) = 0;
    fVar2 = FLOAT_803e83a4;
    puVar10[0xa4] = (uint)FLOAT_803e83a4;
    puVar10[0xa3] = (uint)fVar2;
    puVar10[0xa6] = (uint)fVar2;
  }
  dVar20 = (double)*(float *)(puVar6 + 0x4c);
  psVar7 = &DAT_80335750;
  for (uVar14 = 0; (puVar6[0x50] != *psVar7 && (uVar14 < 6)); uVar14 = uVar14 + 1) {
    psVar7 = psVar7 + 1;
  }
  if (5 < uVar14) {
    uVar14 = 4;
  }
  dVar16 = (double)FUN_802931a0((double)(*(float *)(puVar6 + 0x12) * *(float *)(puVar6 + 0x12) +
                                        *(float *)(puVar6 + 0x16) * *(float *)(puVar6 + 0x16)));
  dVar17 = (double)FLOAT_803e83a4;
  if ((dVar17 <= dVar16) && (dVar17 = dVar16, (double)FLOAT_803e83c0 < dVar16)) {
    dVar17 = (double)FLOAT_803e83c0;
  }
  dVar16 = (double)FLOAT_803e83c4;
  dVar18 = (double)((float)(dVar16 * dVar17) / FLOAT_803e83c0);
  *(float *)(puVar6 + 0x14) = (float)((double)*(float *)(puVar6 + 0x14) + dVar18);
  *(float *)(puVar6 + 0x14) = (float)((double)*(float *)(puVar6 + 0x14) - dVar16);
  if ((double)FLOAT_803e83a4 < dVar17) {
    if ((int)uVar14 < 4) {
      local_a8 = puVar6[2];
      local_aa = *(short *)(iVar13 + 0xbbc);
      local_ac = *puVar6;
      local_a0 = FLOAT_803e83a4;
      local_9c = FLOAT_803e83a4;
      local_98 = FLOAT_803e83a4;
      local_a4 = FLOAT_803e83a8;
      FUN_80021ac8(&local_ac,&local_dc);
      local_d0 = -*(float *)(puVar6 + 0x12);
      local_cc = -*(float *)(puVar6 + 0x14);
      local_c8 = -*(float *)(puVar6 + 0x16);
      dVar17 = (double)(local_d4 * local_c8 + local_dc * local_d0 + local_d8 * local_cc);
      if (dVar17 < (double)FLOAT_803e83a4) {
        dVar17 = -dVar17;
      }
      FUN_8002282c(&local_d0);
      fVar2 = (float)((double)FLOAT_803e83cc * dVar17 +
                     (double)(FLOAT_803e83c4 *
                             ((float)((double)FLOAT_803e83d0 * dVar17) / FLOAT_803e83c0)));
      local_d0 = local_d0 * fVar2;
      local_cc = local_cc * fVar2;
      local_c8 = local_c8 * fVar2;
      *(float *)(puVar6 + 0x12) = *(float *)(puVar6 + 0x12) + local_d0;
      *(float *)(puVar6 + 0x14) = *(float *)(puVar6 + 0x14) + local_cc;
      *(float *)(puVar6 + 0x16) = *(float *)(puVar6 + 0x16) + local_c8;
    }
    else {
      local_a8 = puVar6[2];
      local_aa = *(short *)(iVar13 + 0xbbc) + -0x4000;
      local_ac = *puVar6;
      local_a0 = FLOAT_803e83a4;
      local_9c = FLOAT_803e83a4;
      local_98 = FLOAT_803e83a4;
      local_a4 = FLOAT_803e83a8;
      local_d4 = FLOAT_803e83c8;
      FUN_80021ac8(&local_ac,&local_c4);
      FUN_80021ac8(&local_ac,&local_dc);
      local_c4 = (float)((double)local_c4 * dVar18);
      local_c0 = (float)((double)local_c0 * dVar18);
      local_bc = (float)((double)local_bc * dVar18);
      *(float *)(puVar6 + 0x12) = *(float *)(puVar6 + 0x12) + local_c4;
      *(float *)(puVar6 + 0x16) = *(float *)(puVar6 + 0x16) + local_bc;
    }
  }
  if (FLOAT_803e83bc < (float)puVar10[0xa6]) {
    local_a8 = 0;
    local_aa = 0;
    local_ac = *puVar6;
    local_a0 = FLOAT_803e83a4;
    local_9c = FLOAT_803e83a4;
    local_98 = FLOAT_803e83a4;
    local_a4 = FLOAT_803e83a8;
    iVar4 = ((int)uVar14 >> 1) * 4;
    local_c4 = (float)puVar10[0xa4] * FLOAT_803e83d4 * *(float *)(iVar4 + -0x7fcca880);
    local_c0 = -(float)puVar10[0xa3] * FLOAT_803e83d4 * *(float *)(iVar4 + -0x7fcca874);
    local_bc = FLOAT_803e83a4;
    FUN_80021ac8(&local_ac,&local_c4);
    *(float *)(puVar6 + 0x12) = *(float *)(puVar6 + 0x12) + local_c4;
    *(float *)(puVar6 + 0x14) = *(float *)(puVar6 + 0x14) + local_c0;
    *(float *)(puVar6 + 0x16) = *(float *)(puVar6 + 0x16) + local_bc;
  }
  if (((uint)(*(byte *)(iVar13 + 0xbc0) >> 7) &
      ((uint)(byte)((*(float *)(puVar6 + 0x4c) < FLOAT_803e83d8) << 3) << 0x1c) >> 0x1f) != 0) {
    local_a8 = puVar6[2];
    local_aa = *(short *)(iVar13 + 0xbbc);
    local_ac = *puVar6;
    local_a0 = FLOAT_803e83a4;
    local_9c = FLOAT_803e83a4;
    local_98 = FLOAT_803e83a4;
    local_a4 = FLOAT_803e83a8;
    FUN_80021ac8(&local_ac,&local_b8);
    *(float *)(puVar6 + 0x12) = *(float *)(puVar6 + 0x12) + local_b8;
    *(float *)(puVar6 + 0x14) = *(float *)(puVar6 + 0x14) + local_b4;
    *(float *)(puVar6 + 0x16) = *(float *)(puVar6 + 0x16) + local_b0;
  }
  dVar17 = (double)FUN_802931a0((double)(*(float *)(puVar6 + 0x16) * *(float *)(puVar6 + 0x16) +
                                        *(float *)(puVar6 + 0x12) * *(float *)(puVar6 + 0x12) +
                                        *(float *)(puVar6 + 0x14) * *(float *)(puVar6 + 0x14)));
  iVar4 = ((int)uVar14 >> 1) * 4;
  pfVar11 = (float *)(iVar4 + -0x7fcca868);
  if (dVar17 <= (double)*pfVar11) {
    pfVar11 = (float *)(iVar4 + -0x7fcca85c);
    if (dVar17 < (double)*pfVar11) {
      FUN_8002282c(puVar6 + 0x12);
      fVar2 = FLOAT_803e83d8;
      *(float *)(puVar6 + 0x12) =
           *(float *)(puVar6 + 0x12) * (float)(dVar17 + (double)*pfVar11) * FLOAT_803e83d8;
      *(float *)(puVar6 + 0x14) =
           *(float *)(puVar6 + 0x14) * (float)(dVar17 + (double)*pfVar11) * fVar2;
      *(float *)(puVar6 + 0x16) =
           *(float *)(puVar6 + 0x16) * (float)(dVar17 + (double)*pfVar11) * fVar2;
    }
  }
  else {
    FUN_8002282c(puVar6 + 0x12);
    fVar2 = FLOAT_803e83d8;
    *(float *)(puVar6 + 0x12) =
         *(float *)(puVar6 + 0x12) * (float)(dVar17 + (double)*pfVar11) * FLOAT_803e83d8;
    *(float *)(puVar6 + 0x14) =
         *(float *)(puVar6 + 0x14) * (float)(dVar17 + (double)*pfVar11) * fVar2;
    *(float *)(puVar6 + 0x16) =
         *(float *)(puVar6 + 0x16) * (float)(dVar17 + (double)*pfVar11) * fVar2;
  }
  if ((int)uVar14 < 4) {
    local_78 = (longlong)(int)(float)puVar10[0xa4];
    *(short *)(iVar13 + 0xbba) =
         *(short *)(iVar13 + 0xbba) - (short)((int)(float)puVar10[0xa4] << 3);
    local_80 = (longlong)(int)(float)puVar10[0xa4];
    *(short *)(iVar13 + 0xbbe) = *(short *)(iVar13 + 0xbbe) - (short)(int)(float)puVar10[0xa4];
    local_88 = (longlong)(int)(float)puVar10[0xa3];
    puVar6[1] = puVar6[1] + (short)(int)(float)puVar10[0xa3] * -6;
    local_90 = (longlong)(int)(float)puVar10[0xa3];
    *(short *)(iVar13 + 0xbbc) =
         *(short *)(iVar13 + 0xbbc) - (short)((int)(float)puVar10[0xa3] << 2);
  }
  else {
    local_90 = (longlong)(int)(float)puVar10[0xa4];
    *(short *)(iVar13 + 0xbba) = *(short *)(iVar13 + 0xbba) - (short)(int)(float)puVar10[0xa4];
    local_88 = (longlong)(int)(float)puVar10[0xa4];
    *(short *)(iVar13 + 0xbbe) =
         *(short *)(iVar13 + 0xbbe) - (short)((int)(float)puVar10[0xa4] << 3);
    local_80 = (longlong)(int)(float)puVar10[0xa3];
    puVar6[1] = puVar6[1] + (short)(int)(float)puVar10[0xa3] * -3;
    local_78 = (longlong)(int)(float)puVar10[0xa3];
    *(short *)(iVar13 + 0xbbc) = *(short *)(iVar13 + 0xbbc) + (short)(int)(float)puVar10[0xa3] * -3;
    sVar9 = FUN_800217c0((double)*(float *)(puVar6 + 0x12),(double)*(float *)(puVar6 + 0x16));
    uVar5 = (sVar9 + -0x8000) - *(short *)(iVar13 + 0xbba);
    if (0x8000 < (short)uVar5) {
      uVar5 = uVar5 + 1;
    }
    if ((short)uVar5 < -0x8000) {
      uVar5 = uVar5 - 1;
    }
    *(ushort *)(iVar13 + 0xbba) =
         *(short *)(iVar13 + 0xbba) +
         ((short)uVar5 >> 6) + (ushort)((short)uVar5 < 0 && (uVar5 & 0x3f) != 0);
    *(ushort *)(iVar13 + 0xbbe) =
         *(short *)(iVar13 + 0xbbe) +
         ((short)uVar5 >> 7) + (ushort)((short)uVar5 < 0 && (uVar5 & 0x7f) != 0);
  }
  sVar9 = *(short *)(&DAT_803dc794 + (uVar14 & 0xfffffffe));
  if ((int)sVar9 < (int)*(short *)(iVar13 + 0xbbe)) {
    *(short *)(iVar13 + 0xbbe) = sVar9;
  }
  else {
    iVar4 = -(int)sVar9;
    if (*(short *)(iVar13 + 0xbbe) < iVar4) {
      *(short *)(iVar13 + 0xbbe) = (short)iVar4;
    }
  }
  if (*(short *)(iVar13 + 0xbbc) < 0x4001) {
    if (*(short *)(iVar13 + 0xbbc) < -0x4000) {
      *(undefined2 *)(iVar13 + 0xbbc) = 0xc000;
    }
  }
  else {
    *(undefined2 *)(iVar13 + 0xbbc) = 0x4000;
  }
  *puVar6 = *(undefined2 *)(iVar13 + 0xbba);
  puVar6[2] = *(undefined2 *)(iVar13 + 0xbbe);
  dVar17 = (double)FUN_802931a0((double)(*(float *)(puVar6 + 0x16) * *(float *)(puVar6 + 0x16) +
                                        *(float *)(puVar6 + 0x12) * *(float *)(puVar6 + 0x12) +
                                        *(float *)(puVar6 + 0x14) * *(float *)(puVar6 + 0x14)));
  if ((-1 < *(char *)(iVar13 + 0xbc0)) && ((puVar10[199] & 0x200) != 0)) {
    FUN_8000bb18(puVar6,0x11d);
    *(byte *)(iVar13 + 0xbc0) = *(byte *)(iVar13 + 0xbc0) & 0x7f | 0x80;
    dVar20 = (double)FLOAT_803e83a4;
    bVar1 = true;
  }
  if ((*puVar10 & 0x400000) == 0) {
    FUN_8002b95c((double)*(float *)(puVar6 + 0x12),(double)*(float *)(puVar6 + 0x14),
                 (double)*(float *)(puVar6 + 0x16),puVar6);
  }
  else {
    local_e8 = *(float *)(puVar6 + 0x40) - *(float *)(iVar13 + 0xaf4);
    local_e4 = *(float *)(puVar6 + 0x42) - *(float *)(iVar13 + 0xaf8);
    local_e0 = *(float *)(puVar6 + 0x44) - *(float *)(iVar13 + 0xafc);
    dVar18 = (double)FUN_802931a0((double)(local_e0 * local_e0 +
                                          local_e8 * local_e8 + local_e4 * local_e4));
    dVar16 = (double)FLOAT_803e83a4;
    if ((dVar16 <= dVar18) && (dVar16 = dVar18, (double)FLOAT_803e83dc < dVar18)) {
      dVar16 = (double)FLOAT_803e83dc;
    }
    FUN_8002282c(&local_e8);
    fVar2 = (float)((double)((float)(dVar16 / (double)FLOAT_803e83dc) *
                            (FLOAT_803e83e0 +
                            (float)(dVar17 / (double)FLOAT_803e83c0) *
                            (float)(dVar17 / (double)FLOAT_803e83c0))) / dVar19);
    local_e4 = local_e4 * fVar2;
    if (local_e4 < FLOAT_803e83a4) {
      local_e4 = FLOAT_803e83a4;
    }
    local_e4 = local_e4 * FLOAT_803e83e4;
    fVar3 = local_e4;
    if (local_e4 < FLOAT_803e83a4) {
      fVar3 = -local_e4;
    }
    fVar3 = (FLOAT_803e83e8 - fVar3) / FLOAT_803e83e8;
    if (fVar3 < FLOAT_803e83a4) {
      fVar3 = FLOAT_803e83a4;
    }
    local_e8 = local_e8 * fVar2 * fVar3;
    local_e4 = local_e4 * fVar3;
    local_e0 = local_e0 * fVar2 * fVar3;
    *(float *)(puVar6 + 0x12) = local_e8 + *(float *)(puVar6 + 0x12);
    *(float *)(puVar6 + 0x14) = local_e4 + *(float *)(puVar6 + 0x14);
    *(float *)(puVar6 + 0x16) = local_e0 + *(float *)(puVar6 + 0x16);
    *(undefined4 *)(puVar6 + 6) = *(undefined4 *)(iVar13 + 0xaf4);
    *(undefined4 *)(puVar6 + 8) = *(undefined4 *)(iVar13 + 0xaf8);
    *(undefined4 *)(puVar6 + 10) = *(undefined4 *)(iVar13 + 0xafc);
    FUN_8002b95c((double)*(float *)(puVar6 + 0x12),(double)*(float *)(puVar6 + 0x14),
                 (double)*(float *)(puVar6 + 0x16),puVar6);
    if (((*(byte *)(puVar10 + 0x99) & 0x10) != 0) && ((uVar14 & 0xfe) == 0)) {
      *(float *)(puVar6 + 0x14) = FLOAT_803e83ec;
      uVar8 = 3;
      goto LAB_802c0510;
    }
    *(undefined4 *)(iVar13 + 0xaf4) = *(undefined4 *)(puVar6 + 6);
    *(undefined4 *)(iVar13 + 0xaf8) = *(undefined4 *)(puVar6 + 8);
    *(undefined4 *)(iVar13 + 0xafc) = *(undefined4 *)(puVar6 + 10);
  }
  if (((*(byte *)(iVar13 + 0xbc0) >> 3 & 1) == 0) && ((puVar10[199] & 0x100) != 0)) {
    FUN_80014b3c(0,0x100);
    iVar12 = 0x20d;
    in_f29 = (double)FLOAT_803e83f0;
    *(byte *)(iVar13 + 0xbc0) = *(byte *)(iVar13 + 0xbc0) & 0xf7 | 8;
    bVar1 = true;
    dVar20 = (double)FLOAT_803e83a4;
  }
  if (bVar1) {
    if (iVar12 == -1) {
      FUN_80030334(dVar20,puVar6,
                   (int)(short)(&DAT_80335750)
                               [(uVar14 & 0xfe) + (uint)(*(byte *)(iVar13 + 0xbc0) >> 7)],0);
      puVar10[0xa8] = *(uint *)(((int)(uVar14 & 0xfe) >> 1) * 4 + -0x7fcca850);
    }
    else {
      FUN_80030334(dVar20,puVar6,iVar12,0);
      puVar10[0xa8] = (uint)(float)in_f29;
    }
  }
  uVar8 = 0;
LAB_802c0510:
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
  FUN_8028611c(uVar8);
  return;
}

