// Function: FUN_802c00a4
// Entry: 802c00a4
// Size: 3100 bytes

/* WARNING: Removing unreachable block (ram,0x802c0ca0) */
/* WARNING: Removing unreachable block (ram,0x802c0c98) */
/* WARNING: Removing unreachable block (ram,0x802c0c90) */
/* WARNING: Removing unreachable block (ram,0x802c0c88) */
/* WARNING: Removing unreachable block (ram,0x802c0c80) */
/* WARNING: Removing unreachable block (ram,0x802c00d4) */
/* WARNING: Removing unreachable block (ram,0x802c00cc) */
/* WARNING: Removing unreachable block (ram,0x802c00c4) */
/* WARNING: Removing unreachable block (ram,0x802c00bc) */
/* WARNING: Removing unreachable block (ram,0x802c00b4) */

void FUN_802c00a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,double param_5
                 ,double param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  float fVar2;
  short sVar3;
  float fVar4;
  ushort uVar5;
  ushort *puVar6;
  ushort *puVar7;
  int iVar8;
  uint *puVar9;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar10;
  int iVar11;
  int iVar12;
  uint uVar13;
  double extraout_f1;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double in_f27;
  double dVar18;
  double in_f28;
  double in_f29;
  double in_f30;
  double dVar19;
  double in_f31;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar20;
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
  ushort local_ac;
  short local_aa;
  ushort local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  longlong local_90;
  longlong local_88;
  longlong local_80;
  longlong local_78;
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
  uVar20 = FUN_80286834();
  puVar6 = (ushort *)((ulonglong)uVar20 >> 0x20);
  puVar9 = (uint *)uVar20;
  local_b8 = DAT_802c3498;
  local_b4 = DAT_802c349c;
  local_b0 = DAT_802c34a0;
  local_c4 = DAT_802c34a4;
  local_c0 = DAT_802c34a8;
  local_bc = DAT_802c34ac;
  local_dc = DAT_802c34b0;
  local_d8 = DAT_802c34b4;
  local_d4 = DAT_802c34b8;
  iVar11 = -1;
  iVar12 = *(int *)(puVar6 + 0x5c);
  *puVar9 = *puVar9 | 0x200000;
  *(undefined *)((int)puVar9 + 0x25f) = 0;
  bVar1 = *(char *)((int)puVar9 + 0x346) != '\0';
  if (bVar1) {
    *(byte *)(iVar12 + 0xbc0) = *(byte *)(iVar12 + 0xbc0) & 0x7f;
    *(byte *)(iVar12 + 0xbc0) = *(byte *)(iVar12 + 0xbc0) & 0xf7;
  }
  dVar16 = extraout_f1;
  FUN_80033a34(puVar6);
  if (*(char *)((int)puVar9 + 0x27a) != '\0') {
    if ((*(byte *)(iVar12 + 0xbc0) >> 5 & 1) == 0) {
      *(byte *)(iVar12 + 0xbc0) = *(byte *)(iVar12 + 0xbc0) & 0xdf | 0x20;
      FUN_802bf838(puVar6,(int)puVar9,*(byte *)(iVar12 + 0xbc0) >> 5 & 1);
    }
    FUN_8003042c((double)FLOAT_803e903c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 puVar6,(int)DAT_803363b8,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined2 *)(iVar12 + 0xbbc) = DAT_803363c4;
    *(ushort *)(iVar12 + 0xbba) = *puVar6;
    *(ushort *)(iVar12 + 0xbbe) = puVar6[2];
    fVar2 = FLOAT_803e903c;
    puVar9[0xa5] = (uint)FLOAT_803e903c;
    puVar9[0xa1] = (uint)fVar2;
    puVar9[0xa0] = (uint)fVar2;
    *(float *)(puVar6 + 0x12) = fVar2;
    *(float *)(puVar6 + 0x14) = fVar2;
    *(float *)(puVar6 + 0x16) = fVar2;
    bVar1 = true;
    *(byte *)(iVar12 + 0xbc0) = *(byte *)(iVar12 + 0xbc0) & 0x7f | 0x80;
    *(undefined4 *)(iVar12 + 0xaf4) = *(undefined4 *)(puVar6 + 6);
    *(undefined4 *)(iVar12 + 0xaf8) = *(undefined4 *)(puVar6 + 8);
    *(undefined4 *)(iVar12 + 0xafc) = *(undefined4 *)(puVar6 + 10);
  }
  *puVar9 = *puVar9 | 0x1000000;
  if ((float)puVar9[0xa6] < FLOAT_803e9054) {
    *(undefined2 *)(puVar9 + 0xcd) = 0;
    *(undefined2 *)((int)puVar9 + 0x336) = 0;
    fVar2 = FLOAT_803e903c;
    puVar9[0xa4] = (uint)FLOAT_803e903c;
    puVar9[0xa3] = (uint)fVar2;
    puVar9[0xa6] = (uint)fVar2;
  }
  dVar19 = (double)*(float *)(puVar6 + 0x4c);
  puVar7 = &DAT_803363b0;
  for (uVar13 = 0; (puVar6[0x50] != *puVar7 && (uVar13 < 6)); uVar13 = uVar13 + 1) {
    puVar7 = puVar7 + 1;
  }
  if (5 < uVar13) {
    uVar13 = 4;
  }
  dVar14 = FUN_80293900((double)(*(float *)(puVar6 + 0x12) * *(float *)(puVar6 + 0x12) +
                                *(float *)(puVar6 + 0x16) * *(float *)(puVar6 + 0x16)));
  dVar17 = (double)FLOAT_803e903c;
  if ((dVar17 <= dVar14) && (dVar17 = dVar14, (double)FLOAT_803e9058 < dVar14)) {
    dVar17 = (double)FLOAT_803e9058;
  }
  dVar14 = (double)FLOAT_803e905c;
  dVar18 = (double)((float)(dVar14 * dVar17) / FLOAT_803e9058);
  *(float *)(puVar6 + 0x14) = (float)((double)*(float *)(puVar6 + 0x14) + dVar18);
  *(float *)(puVar6 + 0x14) = (float)((double)*(float *)(puVar6 + 0x14) - dVar14);
  if ((double)FLOAT_803e903c < dVar17) {
    if ((int)uVar13 < 4) {
      local_a8 = puVar6[2];
      local_aa = *(short *)(iVar12 + 0xbbc);
      local_ac = *puVar6;
      local_a0 = FLOAT_803e903c;
      local_9c = FLOAT_803e903c;
      local_98 = FLOAT_803e903c;
      local_a4 = FLOAT_803e9040;
      FUN_80021b8c(&local_ac,&local_dc);
      local_d0 = -*(float *)(puVar6 + 0x12);
      param_6 = -(double)*(float *)(puVar6 + 0x14);
      local_cc = (float)param_6;
      local_c8 = -*(float *)(puVar6 + 0x16);
      param_5 = (double)local_d4;
      dVar14 = (double)(float)(param_5 * (double)local_c8 +
                              (double)(local_dc * local_d0 + local_d8 * (float)param_6));
      if (dVar14 < (double)FLOAT_803e903c) {
        dVar14 = -dVar14;
      }
      FUN_800228f0(&local_d0);
      dVar17 = (double)local_d0;
      dVar14 = (double)(float)((double)FLOAT_803e9064 * dVar14 +
                              (double)(FLOAT_803e905c *
                                      ((float)((double)FLOAT_803e9068 * dVar14) / FLOAT_803e9058)));
      local_d0 = (float)(dVar17 * dVar14);
      local_cc = (float)((double)local_cc * dVar14);
      local_c8 = (float)((double)local_c8 * dVar14);
      *(float *)(puVar6 + 0x12) = *(float *)(puVar6 + 0x12) + local_d0;
      *(float *)(puVar6 + 0x14) = *(float *)(puVar6 + 0x14) + local_cc;
      *(float *)(puVar6 + 0x16) = *(float *)(puVar6 + 0x16) + local_c8;
    }
    else {
      local_a8 = puVar6[2];
      local_aa = *(short *)(iVar12 + 0xbbc) + -0x4000;
      local_ac = *puVar6;
      local_a0 = FLOAT_803e903c;
      local_9c = FLOAT_803e903c;
      local_98 = FLOAT_803e903c;
      local_a4 = FLOAT_803e9040;
      local_d4 = FLOAT_803e9060;
      FUN_80021b8c(&local_ac,&local_c4);
      FUN_80021b8c(&local_ac,&local_dc);
      local_c4 = (float)((double)local_c4 * dVar18);
      local_c0 = (float)((double)local_c0 * dVar18);
      local_bc = (float)((double)local_bc * dVar18);
      *(float *)(puVar6 + 0x12) = *(float *)(puVar6 + 0x12) + local_c4;
      *(float *)(puVar6 + 0x16) = *(float *)(puVar6 + 0x16) + local_bc;
    }
  }
  if (FLOAT_803e9054 < (float)puVar9[0xa6]) {
    local_a8 = 0;
    local_aa = 0;
    local_ac = *puVar6;
    local_a0 = FLOAT_803e903c;
    local_9c = FLOAT_803e903c;
    local_98 = FLOAT_803e903c;
    local_a4 = FLOAT_803e9040;
    iVar8 = ((int)uVar13 >> 1) * 4;
    local_c4 = (float)puVar9[0xa4] * FLOAT_803e906c * *(float *)(iVar8 + -0x7fcc9c20);
    local_c0 = -(float)puVar9[0xa3] * FLOAT_803e906c * *(float *)(iVar8 + -0x7fcc9c14);
    local_bc = FLOAT_803e903c;
    FUN_80021b8c(&local_ac,&local_c4);
    *(float *)(puVar6 + 0x12) = *(float *)(puVar6 + 0x12) + local_c4;
    *(float *)(puVar6 + 0x14) = *(float *)(puVar6 + 0x14) + local_c0;
    *(float *)(puVar6 + 0x16) = *(float *)(puVar6 + 0x16) + local_bc;
  }
  if (((uint)(*(byte *)(iVar12 + 0xbc0) >> 7) &
      ((uint)(byte)((*(float *)(puVar6 + 0x4c) < FLOAT_803e9070) << 3) << 0x1c) >> 0x1f) != 0) {
    local_a8 = puVar6[2];
    local_aa = *(short *)(iVar12 + 0xbbc);
    local_ac = *puVar6;
    local_a0 = FLOAT_803e903c;
    local_9c = FLOAT_803e903c;
    local_98 = FLOAT_803e903c;
    local_a4 = FLOAT_803e9040;
    FUN_80021b8c(&local_ac,&local_b8);
    *(float *)(puVar6 + 0x12) = *(float *)(puVar6 + 0x12) + local_b8;
    *(float *)(puVar6 + 0x14) = *(float *)(puVar6 + 0x14) + local_b4;
    *(float *)(puVar6 + 0x16) = *(float *)(puVar6 + 0x16) + local_b0;
  }
  dVar14 = FUN_80293900((double)(*(float *)(puVar6 + 0x16) * *(float *)(puVar6 + 0x16) +
                                *(float *)(puVar6 + 0x12) * *(float *)(puVar6 + 0x12) +
                                *(float *)(puVar6 + 0x14) * *(float *)(puVar6 + 0x14)));
  iVar8 = ((int)uVar13 >> 1) * 4;
  pfVar10 = (float *)(iVar8 + -0x7fcc9c08);
  if (dVar14 <= (double)*pfVar10) {
    pfVar10 = (float *)(iVar8 + -0x7fcc9bfc);
    if (dVar14 < (double)*pfVar10) {
      FUN_800228f0((float *)(puVar6 + 0x12));
      fVar2 = FLOAT_803e9070;
      *(float *)(puVar6 + 0x12) =
           *(float *)(puVar6 + 0x12) * (float)(dVar14 + (double)*pfVar10) * FLOAT_803e9070;
      *(float *)(puVar6 + 0x14) =
           *(float *)(puVar6 + 0x14) * (float)(dVar14 + (double)*pfVar10) * fVar2;
      *(float *)(puVar6 + 0x16) =
           *(float *)(puVar6 + 0x16) * (float)(dVar14 + (double)*pfVar10) * fVar2;
    }
  }
  else {
    FUN_800228f0((float *)(puVar6 + 0x12));
    fVar2 = FLOAT_803e9070;
    *(float *)(puVar6 + 0x12) =
         *(float *)(puVar6 + 0x12) * (float)(dVar14 + (double)*pfVar10) * FLOAT_803e9070;
    *(float *)(puVar6 + 0x14) =
         *(float *)(puVar6 + 0x14) * (float)(dVar14 + (double)*pfVar10) * fVar2;
    *(float *)(puVar6 + 0x16) =
         *(float *)(puVar6 + 0x16) * (float)(dVar14 + (double)*pfVar10) * fVar2;
  }
  if ((int)uVar13 < 4) {
    local_78 = (longlong)(int)(float)puVar9[0xa4];
    *(short *)(iVar12 + 0xbba) = *(short *)(iVar12 + 0xbba) - (short)((int)(float)puVar9[0xa4] << 3)
    ;
    local_80 = (longlong)(int)(float)puVar9[0xa4];
    *(short *)(iVar12 + 0xbbe) = *(short *)(iVar12 + 0xbbe) - (short)(int)(float)puVar9[0xa4];
    local_88 = (longlong)(int)(float)puVar9[0xa3];
    puVar6[1] = puVar6[1] + (short)(int)(float)puVar9[0xa3] * -6;
    local_90 = (longlong)(int)(float)puVar9[0xa3];
    *(short *)(iVar12 + 0xbbc) = *(short *)(iVar12 + 0xbbc) - (short)((int)(float)puVar9[0xa3] << 2)
    ;
  }
  else {
    local_90 = (longlong)(int)(float)puVar9[0xa4];
    *(short *)(iVar12 + 0xbba) = *(short *)(iVar12 + 0xbba) - (short)(int)(float)puVar9[0xa4];
    local_88 = (longlong)(int)(float)puVar9[0xa4];
    *(short *)(iVar12 + 0xbbe) = *(short *)(iVar12 + 0xbbe) - (short)((int)(float)puVar9[0xa4] << 3)
    ;
    local_80 = (longlong)(int)(float)puVar9[0xa3];
    puVar6[1] = puVar6[1] + (short)(int)(float)puVar9[0xa3] * -3;
    local_78 = (longlong)(int)(float)puVar9[0xa3];
    *(short *)(iVar12 + 0xbbc) = *(short *)(iVar12 + 0xbbc) + (short)(int)(float)puVar9[0xa3] * -3;
    iVar8 = FUN_80021884();
    uVar5 = ((short)iVar8 + -0x8000) - *(short *)(iVar12 + 0xbba);
    if (0x8000 < (short)uVar5) {
      uVar5 = uVar5 + 1;
    }
    if ((short)uVar5 < -0x8000) {
      uVar5 = uVar5 - 1;
    }
    *(ushort *)(iVar12 + 0xbba) =
         *(short *)(iVar12 + 0xbba) +
         ((short)uVar5 >> 6) + (ushort)((short)uVar5 < 0 && (uVar5 & 0x3f) != 0);
    *(ushort *)(iVar12 + 0xbbe) =
         *(short *)(iVar12 + 0xbbe) +
         ((short)uVar5 >> 7) + (ushort)((short)uVar5 < 0 && (uVar5 & 0x7f) != 0);
  }
  sVar3 = *(short *)(&DAT_803dd3fc + (uVar13 & 0xfffffffe));
  if ((int)sVar3 < (int)*(short *)(iVar12 + 0xbbe)) {
    *(short *)(iVar12 + 0xbbe) = sVar3;
  }
  else {
    iVar8 = -(int)sVar3;
    if (*(short *)(iVar12 + 0xbbe) < iVar8) {
      *(short *)(iVar12 + 0xbbe) = (short)iVar8;
    }
  }
  if (*(short *)(iVar12 + 0xbbc) < 0x4001) {
    if (*(short *)(iVar12 + 0xbbc) < -0x4000) {
      *(undefined2 *)(iVar12 + 0xbbc) = 0xc000;
    }
  }
  else {
    *(undefined2 *)(iVar12 + 0xbbc) = 0x4000;
  }
  *puVar6 = *(ushort *)(iVar12 + 0xbba);
  puVar6[2] = *(ushort *)(iVar12 + 0xbbe);
  dVar14 = FUN_80293900((double)(*(float *)(puVar6 + 0x16) * *(float *)(puVar6 + 0x16) +
                                *(float *)(puVar6 + 0x12) * *(float *)(puVar6 + 0x12) +
                                *(float *)(puVar6 + 0x14) * *(float *)(puVar6 + 0x14)));
  if ((-1 < *(char *)(iVar12 + 0xbc0)) && ((puVar9[199] & 0x200) != 0)) {
    FUN_8000bb38((uint)puVar6,0x11d);
    *(byte *)(iVar12 + 0xbc0) = *(byte *)(iVar12 + 0xbc0) & 0x7f | 0x80;
    dVar19 = (double)FLOAT_803e903c;
    bVar1 = true;
  }
  if ((*puVar9 & 0x400000) == 0) {
    dVar16 = (double)*(float *)(puVar6 + 0x14);
    dVar14 = (double)*(float *)(puVar6 + 0x16);
    FUN_8002ba34((double)*(float *)(puVar6 + 0x12),dVar16,dVar14,(int)puVar6);
  }
  else {
    local_e8 = *(float *)(puVar6 + 0x40) - *(float *)(iVar12 + 0xaf4);
    dVar17 = (double)local_e8;
    local_e4 = *(float *)(puVar6 + 0x42) - *(float *)(iVar12 + 0xaf8);
    local_e0 = *(float *)(puVar6 + 0x44) - *(float *)(iVar12 + 0xafc);
    dVar15 = FUN_80293900((double)(local_e0 * local_e0 +
                                  (float)(dVar17 * dVar17) + local_e4 * local_e4));
    dVar18 = (double)FLOAT_803e903c;
    if ((dVar18 <= dVar15) && (dVar18 = dVar15, (double)FLOAT_803e9074 < dVar15)) {
      dVar18 = (double)FLOAT_803e9074;
    }
    FUN_800228f0(&local_e8);
    fVar2 = (float)((double)((float)(dVar18 / (double)FLOAT_803e9074) *
                            (FLOAT_803e9078 +
                            (float)(dVar14 / (double)FLOAT_803e9058) *
                            (float)(dVar14 / (double)FLOAT_803e9058))) / dVar16);
    local_e4 = local_e4 * fVar2;
    if (local_e4 < FLOAT_803e903c) {
      local_e4 = FLOAT_803e903c;
    }
    local_e4 = local_e4 * FLOAT_803e907c;
    fVar4 = local_e4;
    if (local_e4 < FLOAT_803e903c) {
      fVar4 = -local_e4;
    }
    fVar4 = (FLOAT_803e9080 - fVar4) / FLOAT_803e9080;
    if (fVar4 < FLOAT_803e903c) {
      fVar4 = FLOAT_803e903c;
    }
    local_e8 = local_e8 * fVar2 * fVar4;
    local_e4 = local_e4 * fVar4;
    local_e0 = local_e0 * fVar2 * fVar4;
    *(float *)(puVar6 + 0x12) = local_e8 + *(float *)(puVar6 + 0x12);
    *(float *)(puVar6 + 0x14) = local_e4 + *(float *)(puVar6 + 0x14);
    *(float *)(puVar6 + 0x16) = local_e0 + *(float *)(puVar6 + 0x16);
    *(undefined4 *)(puVar6 + 6) = *(undefined4 *)(iVar12 + 0xaf4);
    *(undefined4 *)(puVar6 + 8) = *(undefined4 *)(iVar12 + 0xaf8);
    *(undefined4 *)(puVar6 + 10) = *(undefined4 *)(iVar12 + 0xafc);
    dVar16 = (double)*(float *)(puVar6 + 0x14);
    dVar14 = (double)*(float *)(puVar6 + 0x16);
    FUN_8002ba34((double)*(float *)(puVar6 + 0x12),dVar16,dVar14,(int)puVar6);
    if (((*(byte *)(puVar9 + 0x99) & 0x10) != 0) && ((uVar13 & 0xfe) == 0)) {
      *(float *)(puVar6 + 0x14) = FLOAT_803e9084;
      goto LAB_802c0c80;
    }
    *(undefined4 *)(iVar12 + 0xaf4) = *(undefined4 *)(puVar6 + 6);
    *(undefined4 *)(iVar12 + 0xaf8) = *(undefined4 *)(puVar6 + 8);
    *(undefined4 *)(iVar12 + 0xafc) = *(undefined4 *)(puVar6 + 10);
  }
  if (((*(byte *)(iVar12 + 0xbc0) >> 3 & 1) == 0) && ((puVar9[199] & 0x100) != 0)) {
    FUN_80014b68(0,0x100);
    iVar11 = 0x20d;
    in_f29 = (double)FLOAT_803e9088;
    *(byte *)(iVar12 + 0xbc0) = *(byte *)(iVar12 + 0xbc0) & 0xf7 | 8;
    bVar1 = true;
    dVar19 = (double)FLOAT_803e903c;
  }
  if (bVar1) {
    if (iVar11 == -1) {
      FUN_8003042c(dVar19,dVar16,dVar14,dVar17,param_5,param_6,param_7,param_8,puVar6,
                   (int)(short)(&DAT_803363b0)
                               [(uVar13 & 0xfe) + (uint)(*(byte *)(iVar12 + 0xbc0) >> 7)],0,in_r6,
                   in_r7,in_r8,in_r9,in_r10);
      puVar9[0xa8] = *(uint *)(((int)(uVar13 & 0xfe) >> 1) * 4 + -0x7fcc9bf0);
    }
    else {
      FUN_8003042c(dVar19,dVar16,dVar14,dVar17,param_5,param_6,param_7,param_8,puVar6,iVar11,0,in_r6
                   ,in_r7,in_r8,in_r9,in_r10);
      puVar9[0xa8] = (uint)(float)in_f29;
    }
  }
LAB_802c0c80:
  FUN_80286880();
  return;
}

