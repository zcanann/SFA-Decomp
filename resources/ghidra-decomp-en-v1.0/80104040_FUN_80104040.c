// Function: FUN_80104040
// Entry: 80104040
// Size: 1280 bytes

/* WARNING: Removing unreachable block (ram,0x80104518) */
/* WARNING: Removing unreachable block (ram,0x80104508) */
/* WARNING: Removing unreachable block (ram,0x801044f8) */
/* WARNING: Removing unreachable block (ram,0x801044f0) */
/* WARNING: Removing unreachable block (ram,0x80104500) */
/* WARNING: Removing unreachable block (ram,0x80104510) */
/* WARNING: Removing unreachable block (ram,0x80104520) */

void FUN_80104040(void)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  float *pfVar4;
  char cVar5;
  short *psVar6;
  float *pfVar7;
  int iVar8;
  short sVar9;
  undefined4 uVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f25;
  double dVar14;
  undefined8 in_f26;
  undefined8 in_f27;
  double dVar15;
  undefined8 in_f28;
  double dVar16;
  undefined8 in_f29;
  double dVar17;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar18;
  undefined8 uVar19;
  undefined auStack680 [8];
  undefined auStack672 [8];
  float local_298;
  float local_294;
  float local_290;
  undefined auStack652 [24];
  float local_274;
  float local_270;
  float local_26c;
  float local_268;
  float local_264;
  float local_260;
  float local_25c;
  float local_258;
  float local_254;
  float local_250;
  float local_24c;
  float local_248;
  float local_244;
  undefined auStack576 [112];
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
  float local_1a0;
  float local_19c;
  float local_198;
  float local_194;
  float local_190;
  float local_18c;
  float local_188;
  float local_184;
  float local_180;
  float local_17c;
  float local_178;
  float local_174;
  float local_170;
  float local_16c;
  float local_168;
  float local_164;
  float local_160;
  float local_15c;
  float local_158;
  float local_154;
  float local_150;
  float local_14c;
  float local_148;
  float local_144;
  float local_140 [3];
  float local_134;
  undefined4 local_130;
  float local_12c;
  float local_128 [36];
  undefined4 local_98;
  uint uStack148;
  double local_90;
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
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
  uVar19 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar19 >> 0x20);
  psVar6 = (short *)uVar19;
  FUN_8000e0a0((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
               (double)*(float *)(iVar3 + 0x14),iVar3 + 0x18,iVar3 + 0x1c,iVar3 + 0x20,
               *(undefined4 *)(iVar3 + 0x30));
  DAT_803dd528 = 0;
  if (psVar6[0x22] == 1) {
    FUN_80296bd4(psVar6,&local_298,&local_294,&local_290);
  }
  else {
    local_298 = *(float *)(psVar6 + 0xc);
    local_294 = *(float *)(psVar6 + 0xe) + *(float *)(DAT_803dd530 + 0x8c);
    local_290 = *(float *)(psVar6 + 0x10);
  }
  local_134 = *(float *)(iVar3 + 0x18);
  local_130 = *(undefined4 *)(iVar3 + 0x1c);
  local_12c = *(float *)(iVar3 + 0x20);
  dVar16 = (double)(local_134 - local_298);
  dVar15 = (double)(local_12c - local_290);
  iVar8 = 1;
  sVar9 = 0xaaa;
  pfVar4 = local_128;
  dVar17 = (double)FLOAT_803e168c;
  dVar18 = (double)FLOAT_803e1690;
  dVar12 = DOUBLE_803e1698;
  do {
    uStack148 = (int)sVar9 ^ 0x80000000;
    local_98 = 0x43300000;
    dVar14 = (double)(float)((double)(float)(dVar17 * (double)(float)((double)CONCAT44(0x43300000,
                                                                                       uStack148) -
                                                                     dVar12)) / dVar18);
    dVar11 = (double)FUN_80293e80(dVar14);
    dVar14 = (double)FUN_80294204(dVar14);
    dVar13 = (double)(float)(dVar16 * dVar14 - (double)(float)(dVar15 * dVar11));
    fVar1 = *(float *)(psVar6 + 0x10);
    *pfVar4 = (float)(dVar13 + (double)*(float *)(psVar6 + 0xc));
    pfVar4[1] = *(float *)(iVar3 + 0x1c);
    pfVar4[2] = (float)(dVar13 * dVar11 + (double)(float)(dVar15 * dVar14)) + fVar1;
    local_90 = (double)CONCAT44(0x43300000,(int)(short)((short)iVar8 * -0xaaa) ^ 0x80000000);
    dVar14 = (double)(float)((double)(float)(dVar17 * (double)(float)(local_90 - dVar12)) / dVar18);
    dVar11 = (double)FUN_80293e80(dVar14);
    dVar14 = (double)FUN_80294204(dVar14);
    dVar13 = (double)(float)(dVar16 * dVar14 - (double)(float)(dVar15 * dVar11));
    fVar1 = *(float *)(psVar6 + 0x10);
    pfVar4[3] = (float)(dVar13 + (double)*(float *)(psVar6 + 0xc));
    pfVar4[4] = *(float *)(iVar3 + 0x1c);
    pfVar4[5] = (float)(dVar13 * dVar11 + (double)(float)(dVar15 * dVar14)) + fVar1;
    sVar9 = sVar9 + 0x1554;
    pfVar4 = pfVar4 + 6;
    iVar8 = iVar8 + 2;
  } while (iVar8 < 0xd);
  local_1d0 = local_298;
  local_1cc = local_294;
  local_1c8 = local_290;
  local_274 = FLOAT_803e16a0;
  local_1c4 = local_298;
  local_1c0 = local_294;
  local_1bc = local_290;
  local_270 = FLOAT_803e16a0;
  local_1b8 = local_298;
  local_1b4 = local_294;
  local_1b0 = local_290;
  local_26c = FLOAT_803e16a0;
  local_1ac = local_298;
  local_1a8 = local_294;
  local_1a4 = local_290;
  local_268 = FLOAT_803e16a0;
  local_1a0 = local_298;
  local_19c = local_294;
  local_198 = local_290;
  local_264 = FLOAT_803e16a0;
  local_194 = local_298;
  local_190 = local_294;
  local_18c = local_290;
  local_260 = FLOAT_803e16a0;
  local_188 = local_298;
  local_184 = local_294;
  local_180 = local_290;
  local_25c = FLOAT_803e16a0;
  local_17c = local_298;
  local_178 = local_294;
  local_174 = local_290;
  local_258 = FLOAT_803e16a0;
  local_170 = local_298;
  local_16c = local_294;
  local_168 = local_290;
  local_254 = FLOAT_803e16a0;
  local_164 = local_298;
  local_160 = local_294;
  local_15c = local_290;
  local_250 = FLOAT_803e16a0;
  local_158 = local_298;
  local_154 = local_294;
  local_150 = local_290;
  local_24c = FLOAT_803e16a0;
  local_14c = local_298;
  local_148 = local_294;
  local_144 = local_290;
  local_248 = FLOAT_803e16a0;
  pfVar4 = local_140;
  pfVar7 = &local_244;
  iVar8 = 1;
  do {
    *pfVar4 = local_298;
    pfVar4[1] = local_294;
    pfVar4[2] = local_290;
    *pfVar7 = FLOAT_803e16a0;
    pfVar4 = pfVar4 + 3;
    pfVar7 = pfVar7 + 1;
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  FUN_8006961c(auStack652,&local_134,&local_1d0,&local_274,0xd);
  FUN_800691c0(0,auStack652,0x248,1);
  cVar5 = FUN_80103524((double)FLOAT_803e16a0,&local_298,iVar3 + 0x18,0,auStack576,7,0,0);
  *(bool *)(DAT_803dd530 + 0xc0) = cVar5 == '\0';
  if (cVar5 == '\0') {
    *(byte *)(DAT_803dd530 + 0xc6) = *(byte *)(DAT_803dd530 + 0xc6) & 0x7f;
    iVar8 = FUN_80103b40(iVar3,auStack680,auStack672,(int)*psVar6);
    if (iVar8 == 0) {
      *(float *)(DAT_803dd530 + 0x28) = FLOAT_803e16ac;
    }
  }
  if (FLOAT_803e16ac != *(float *)(DAT_803dd530 + 0x28)) {
    iVar8 = (int)*(float *)(DAT_803dd530 + 0x28);
    local_90 = (double)(longlong)iVar8;
    uVar2 = (uint)(short)iVar8;
    if (((int)uVar2 < -0x1e) || (0x1e < (int)uVar2)) {
      local_90 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      dVar17 = (double)((FLOAT_803e168c * (float)(local_90 - DOUBLE_803e1698)) / FLOAT_803e1690);
      dVar12 = (double)FUN_80293e80(dVar17);
      dVar17 = (double)FUN_80294204(dVar17);
      dVar16 = (double)(float)(dVar16 * dVar17 - (double)(float)(dVar15 * dVar12));
      *(float *)(iVar3 + 0x18) = (float)(dVar16 + (double)*(float *)(psVar6 + 0xc));
      *(float *)(iVar3 + 0x20) =
           (float)(dVar16 * dVar12 + (double)(float)(dVar15 * dVar17)) + *(float *)(psVar6 + 0x10);
    }
    *(float *)(DAT_803dd530 + 0x28) = *(float *)(DAT_803dd530 + 0x28) * FLOAT_803e16c4;
    if ((*(float *)(DAT_803dd530 + 0x28) < FLOAT_803e16c8) &&
       (FLOAT_803e16cc < *(float *)(DAT_803dd530 + 0x28))) {
      *(float *)(DAT_803dd530 + 0x28) = FLOAT_803e16ac;
    }
  }
  FUN_8000e034((double)*(float *)(iVar3 + 0x18),(double)*(float *)(iVar3 + 0x1c),
               (double)*(float *)(iVar3 + 0x20),iVar3 + 0xc,iVar3 + 0x10,iVar3 + 0x14,
               *(undefined4 *)(iVar3 + 0x30));
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  __psq_l0(auStack40,uVar10);
  __psq_l1(auStack40,uVar10);
  __psq_l0(auStack56,uVar10);
  __psq_l1(auStack56,uVar10);
  __psq_l0(auStack72,uVar10);
  __psq_l1(auStack72,uVar10);
  __psq_l0(auStack88,uVar10);
  __psq_l1(auStack88,uVar10);
  __psq_l0(auStack104,uVar10);
  __psq_l1(auStack104,uVar10);
  FUN_80286124();
  return;
}

