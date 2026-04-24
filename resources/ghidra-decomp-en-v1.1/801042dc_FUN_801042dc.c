// Function: FUN_801042dc
// Entry: 801042dc
// Size: 1280 bytes

/* WARNING: Removing unreachable block (ram,0x801047bc) */
/* WARNING: Removing unreachable block (ram,0x801047b4) */
/* WARNING: Removing unreachable block (ram,0x801047ac) */
/* WARNING: Removing unreachable block (ram,0x801047a4) */
/* WARNING: Removing unreachable block (ram,0x8010479c) */
/* WARNING: Removing unreachable block (ram,0x80104794) */
/* WARNING: Removing unreachable block (ram,0x8010478c) */
/* WARNING: Removing unreachable block (ram,0x8010431c) */
/* WARNING: Removing unreachable block (ram,0x80104314) */
/* WARNING: Removing unreachable block (ram,0x8010430c) */
/* WARNING: Removing unreachable block (ram,0x80104304) */
/* WARNING: Removing unreachable block (ram,0x801042fc) */
/* WARNING: Removing unreachable block (ram,0x801042f4) */
/* WARNING: Removing unreachable block (ram,0x801042ec) */

void FUN_801042dc(void)

{
  float fVar1;
  bool bVar2;
  int iVar3;
  float *pfVar4;
  uint uVar5;
  int iVar6;
  float *pfVar7;
  int iVar8;
  short sVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double in_f25;
  double in_f26;
  double in_f27;
  double dVar13;
  double in_f28;
  double dVar14;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar15;
  float local_298;
  float local_294;
  float local_290;
  uint auStack_28c [6];
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
  undefined auStack_240 [112];
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
  uint uStack_94;
  undefined8 local_90;
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
  uVar15 = FUN_8028683c();
  iVar3 = (int)((ulonglong)uVar15 >> 0x20);
  iVar6 = (int)uVar15;
  FUN_8000e0c0((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
               (double)*(float *)(iVar3 + 0x14),(float *)(iVar3 + 0x18),(float *)(iVar3 + 0x1c),
               (float *)(iVar3 + 0x20),*(int *)(iVar3 + 0x30));
  DAT_803de1a0 = 0;
  if (*(short *)(iVar6 + 0x44) == 1) {
    FUN_80297334(iVar6,&local_298,&local_294,&local_290);
  }
  else {
    local_298 = *(float *)(iVar6 + 0x18);
    local_294 = *(float *)(iVar6 + 0x1c) + *(float *)(DAT_803de1a8 + 0x8c);
    local_290 = *(float *)(iVar6 + 0x20);
  }
  local_134 = *(float *)(iVar3 + 0x18);
  local_130 = *(undefined4 *)(iVar3 + 0x1c);
  local_12c = *(float *)(iVar3 + 0x20);
  dVar14 = (double)(local_134 - local_298);
  dVar13 = (double)(local_12c - local_290);
  iVar8 = 1;
  sVar9 = 0xaaa;
  pfVar4 = local_128;
  do {
    uStack_94 = (int)sVar9 ^ 0x80000000;
    local_98 = 0x43300000;
    dVar10 = (double)FUN_802945e0();
    dVar11 = (double)FUN_80294964();
    dVar12 = (double)(float)(dVar14 * dVar11 - (double)(float)(dVar13 * dVar10));
    fVar1 = *(float *)(iVar6 + 0x20);
    *pfVar4 = (float)(dVar12 + (double)*(float *)(iVar6 + 0x18));
    pfVar4[1] = *(float *)(iVar3 + 0x1c);
    pfVar4[2] = (float)(dVar12 * dVar10 + (double)(float)(dVar13 * dVar11)) + fVar1;
    local_90 = CONCAT44(0x43300000,(int)(short)((short)iVar8 * -0xaaa) ^ 0x80000000);
    dVar10 = (double)FUN_802945e0();
    dVar11 = (double)FUN_80294964();
    dVar12 = (double)(float)(dVar14 * dVar11 - (double)(float)(dVar13 * dVar10));
    fVar1 = *(float *)(iVar6 + 0x20);
    pfVar4[3] = (float)(dVar12 + (double)*(float *)(iVar6 + 0x18));
    pfVar4[4] = *(float *)(iVar3 + 0x1c);
    pfVar4[5] = (float)(dVar12 * dVar10 + (double)(float)(dVar13 * dVar11)) + fVar1;
    sVar9 = sVar9 + 0x1554;
    pfVar4 = pfVar4 + 6;
    iVar8 = iVar8 + 2;
  } while (iVar8 < 0xd);
  local_1d0 = local_298;
  local_1cc = local_294;
  local_1c8 = local_290;
  local_274 = FLOAT_803e2320;
  local_1c4 = local_298;
  local_1c0 = local_294;
  local_1bc = local_290;
  local_270 = FLOAT_803e2320;
  local_1b8 = local_298;
  local_1b4 = local_294;
  local_1b0 = local_290;
  local_26c = FLOAT_803e2320;
  local_1ac = local_298;
  local_1a8 = local_294;
  local_1a4 = local_290;
  local_268 = FLOAT_803e2320;
  local_1a0 = local_298;
  local_19c = local_294;
  local_198 = local_290;
  local_264 = FLOAT_803e2320;
  local_194 = local_298;
  local_190 = local_294;
  local_18c = local_290;
  local_260 = FLOAT_803e2320;
  local_188 = local_298;
  local_184 = local_294;
  local_180 = local_290;
  local_25c = FLOAT_803e2320;
  local_17c = local_298;
  local_178 = local_294;
  local_174 = local_290;
  local_258 = FLOAT_803e2320;
  local_170 = local_298;
  local_16c = local_294;
  local_168 = local_290;
  local_254 = FLOAT_803e2320;
  local_164 = local_298;
  local_160 = local_294;
  local_15c = local_290;
  local_250 = FLOAT_803e2320;
  local_158 = local_298;
  local_154 = local_294;
  local_150 = local_290;
  local_24c = FLOAT_803e2320;
  local_14c = local_298;
  local_148 = local_294;
  local_144 = local_290;
  local_248 = FLOAT_803e2320;
  pfVar4 = local_140;
  pfVar7 = &local_244;
  iVar8 = 1;
  do {
    *pfVar4 = local_298;
    pfVar4[1] = local_294;
    pfVar4[2] = local_290;
    *pfVar7 = FLOAT_803e2320;
    pfVar4 = pfVar4 + 3;
    pfVar7 = pfVar7 + 1;
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  FUN_80069798(auStack_28c,&local_134,&local_1d0,&local_274,0xd);
  FUN_8006933c(0,auStack_28c,0x248,'\x01');
  uVar5 = FUN_801037c0((double)FLOAT_803e2320,&local_298,(float *)(iVar3 + 0x18),(float *)0x0,
                       (int)auStack_240,7,'\0','\0');
  bVar2 = (uVar5 & 0xff) == 0;
  *(bool *)(DAT_803de1a8 + 0xc0) = bVar2;
  if (bVar2) {
    *(byte *)(DAT_803de1a8 + 0xc6) = *(byte *)(DAT_803de1a8 + 0xc6) & 0x7f;
    iVar8 = FUN_80103ddc();
    if (iVar8 == 0) {
      *(float *)(DAT_803de1a8 + 0x28) = FLOAT_803e232c;
    }
  }
  if (FLOAT_803e232c != *(float *)(DAT_803de1a8 + 0x28)) {
    iVar8 = (int)*(float *)(DAT_803de1a8 + 0x28);
    local_90 = (longlong)iVar8;
    uVar5 = (uint)(short)iVar8;
    if (((int)uVar5 < -0x1e) || (0x1e < (int)uVar5)) {
      local_90 = CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      dVar10 = (double)FUN_802945e0();
      dVar11 = (double)FUN_80294964();
      dVar14 = (double)(float)(dVar14 * dVar11 - (double)(float)(dVar13 * dVar10));
      *(float *)(iVar3 + 0x18) = (float)(dVar14 + (double)*(float *)(iVar6 + 0x18));
      *(float *)(iVar3 + 0x20) =
           (float)(dVar14 * dVar10 + (double)(float)(dVar13 * dVar11)) + *(float *)(iVar6 + 0x20);
    }
    *(float *)(DAT_803de1a8 + 0x28) = *(float *)(DAT_803de1a8 + 0x28) * FLOAT_803e2344;
    if ((*(float *)(DAT_803de1a8 + 0x28) < FLOAT_803e2348) &&
       (FLOAT_803e234c < *(float *)(DAT_803de1a8 + 0x28))) {
      *(float *)(DAT_803de1a8 + 0x28) = FLOAT_803e232c;
    }
  }
  FUN_8000e054((double)*(float *)(iVar3 + 0x18),(double)*(float *)(iVar3 + 0x1c),
               (double)*(float *)(iVar3 + 0x20),(float *)(iVar3 + 0xc),(float *)(iVar3 + 0x10),
               (float *)(iVar3 + 0x14),*(int *)(iVar3 + 0x30));
  FUN_80286888();
  return;
}

