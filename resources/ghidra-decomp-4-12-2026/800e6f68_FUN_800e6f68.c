// Function: FUN_800e6f68
// Entry: 800e6f68
// Size: 2472 bytes

/* WARNING: Removing unreachable block (ram,0x800e78f0) */
/* WARNING: Removing unreachable block (ram,0x800e6f78) */

void FUN_800e6f68(void)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  ushort *puVar4;
  ushort uVar6;
  undefined uVar7;
  uint uVar5;
  uint *puVar8;
  float *pfVar9;
  uint *puVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  double extraout_f1;
  double in_f31;
  double dVar14;
  double in_ps31_1;
  undefined8 uVar15;
  ushort local_1e8;
  ushort local_1e6;
  ushort local_1e4;
  float local_1e0;
  undefined4 local_1dc;
  undefined4 local_1d8;
  undefined4 local_1d4;
  ushort local_1d0;
  ushort local_1ce;
  ushort local_1cc;
  float local_1c8;
  undefined4 local_1c4;
  undefined4 local_1c0;
  undefined4 local_1bc;
  ushort local_1b8;
  ushort local_1b6;
  ushort local_1b4;
  float local_1b0;
  undefined4 local_1ac;
  undefined4 local_1a8;
  undefined4 local_1a4;
  ushort local_1a0;
  ushort local_19e;
  ushort local_19c;
  float local_198;
  undefined4 local_194;
  undefined4 local_190;
  undefined4 local_18c;
  ushort local_188;
  ushort local_186;
  ushort local_184;
  float local_180;
  undefined4 local_17c;
  undefined4 local_178;
  undefined4 local_174;
  float afStack_170 [16];
  float afStack_130 [16];
  float afStack_f0 [16];
  float afStack_b0 [16];
  float afStack_70 [26];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar15 = FUN_8028683c();
  fVar3 = FLOAT_803e130c;
  puVar4 = (ushort *)((ulonglong)uVar15 >> 0x20);
  puVar8 = (uint *)uVar15;
  if ((*puVar8 & 0x4000000) == 0) goto LAB_800e78f0;
  dVar14 = (double)(float)((double)FLOAT_803e130c / extraout_f1);
  puVar8[0x36] = 0;
  fVar2 = FLOAT_803e12e8;
  if (*(char *)((int)puVar8 + 0x25b) == '\x01') {
    DAT_803de0fc = 0;
    DAT_803de0f8 = 0;
    puVar8[0x68] = (uint)FLOAT_803e12e8;
    puVar8[0x69] = (uint)fVar3;
    puVar8[0x6a] = (uint)fVar2;
    if (((*puVar8 & 8) != 0) && ((*(byte *)(puVar8 + 0x97) & 0xf) != 0)) {
      local_188 = *puVar4;
      if ((*puVar8 & 0x20) == 0) {
        local_186 = puVar4[1];
        local_184 = puVar4[2];
      }
      else {
        local_186 = 0;
        local_184 = 0;
      }
      local_180 = FLOAT_803e130c;
      local_17c = *(undefined4 *)(puVar4 + 6);
      local_178 = *(undefined4 *)(puVar4 + 8);
      local_174 = *(undefined4 *)(puVar4 + 10);
      FUN_80021fac(afStack_70,&local_188);
      iVar13 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar12 = 0; iVar12 < (int)(*(byte *)(puVar8 + 0x97) & 0xf); iVar12 = iVar12 + 1) {
        pfVar9 = (float *)(puVar8[0x37] + iVar11);
        FUN_80022790((double)*pfVar9,(double)pfVar9[1],(double)pfVar9[2],afStack_70,
                     (float *)(puVar10 + 0x39),(float *)(puVar8 + iVar13 + 0x3a),
                     (float *)(puVar8 + iVar13 + 0x3b));
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar13 = iVar13 + 3;
      }
      FUN_800e6410();
      iVar11 = *(int *)(puVar4 + 0x18);
      if (iVar11 == 0) {
        *(undefined4 *)(puVar4 + 0xc) = *(undefined4 *)(puVar4 + 6);
        *(undefined4 *)(puVar4 + 0xe) = *(undefined4 *)(puVar4 + 8);
        *(undefined4 *)(puVar4 + 0x10) = *(undefined4 *)(puVar4 + 10);
      }
      else if ((*(int *)(iVar11 + 0x58) == 0) || (uVar6 = FUN_80036074(iVar11), uVar6 == 0)) {
        FUN_8000e0c0((double)*(float *)(puVar4 + 6),(double)*(float *)(puVar4 + 8),
                     (double)*(float *)(puVar4 + 10),(float *)(puVar4 + 0xc),(float *)(puVar4 + 0xe)
                     ,(float *)(puVar4 + 0x10),*(int *)(puVar4 + 0x18));
      }
      else {
        FUN_80022790((double)*(float *)(puVar4 + 6),(double)*(float *)(puVar4 + 8),
                     (double)*(float *)(puVar4 + 10),
                     (float *)(*(int *)(*(int *)(puVar4 + 0x18) + 0x58) +
                              (*(byte *)(*(int *)(*(int *)(puVar4 + 0x18) + 0x58) + 0x10c) + 2) *
                              0x40),(float *)(puVar4 + 0xc),(float *)(puVar4 + 0xe),
                     (float *)(puVar4 + 0x10));
      }
    }
    if (((*puVar8 & 0x2000) != 0) && ((*(byte *)(puVar8 + 0x97) & 0xf0) != 0)) {
      local_1a0 = *puVar4;
      if ((*puVar8 & 0x20) == 0) {
        local_19e = puVar4[1];
        local_19c = puVar4[2];
      }
      else {
        local_19e = 0;
        local_19c = 0;
      }
      local_198 = FLOAT_803e130c;
      local_194 = *(undefined4 *)(puVar4 + 0xc);
      local_190 = *(undefined4 *)(puVar4 + 0xe);
      local_18c = *(undefined4 *)(puVar4 + 0x10);
      FUN_80021fac(afStack_b0,&local_1a0);
      iVar12 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar13 = 0; iVar13 < (int)(uint)*(byte *)(puVar8 + 0x97) >> 4; iVar13 = iVar13 + 1) {
        pfVar9 = (float *)(puVar8[1] + iVar11);
        FUN_80022790((double)*pfVar9,(double)pfVar9[1],(double)pfVar9[2],afStack_b0,
                     (float *)(puVar10 + 2),(float *)(puVar8 + iVar12 + 3),
                     (float *)(puVar8 + iVar12 + 4));
        *(undefined *)((int)puVar8 + iVar13 + 0xb8) = 0xff;
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar12 = iVar12 + 3;
      }
      if ((*puVar8 & 2) != 0) {
        uVar7 = FUN_80067ad4();
        *(undefined *)(puVar8 + 0x98) = uVar7;
        *(char *)((int)puVar8 + 0x261) = (char)*(undefined2 *)(puVar8 + 0x35);
        *(undefined *)((int)puVar8 + 0x25f) = 0;
      }
      bVar1 = *(byte *)((int)puVar8 + 0x262);
      if (bVar1 == 3) {
        FUN_800e56b8();
      }
      else if (bVar1 < 3) {
        if (bVar1 == 1) {
          FUN_800e5928((int)puVar4,puVar8);
        }
        else {
LAB_800e7350:
          FUN_800e5b80();
        }
      }
      else {
        if (4 < bVar1) goto LAB_800e7350;
        puVar8[0x68] = puVar8[0x1a];
        puVar8[0x69] = puVar8[0x1b];
        puVar8[0x6a] = puVar8[0x1c];
        if (((*(byte *)(puVar8 + 0x98) & 1) != 0) && (*(char *)(puVar8 + 0x2e) == '!')) {
          *(uint *)(puVar4 + 0xc) = puVar8[2];
          *(uint *)(puVar4 + 0xe) = puVar8[3];
          *(uint *)(puVar4 + 0x10) = puVar8[4];
        }
      }
      if ((*puVar8 & 0x100) != 0) {
        FUN_800e60bc((int)puVar4,(int)puVar8);
      }
      if ((*puVar8 & 0x80) != 0) {
        FUN_800e5f40((short *)puVar4,(int)puVar8);
      }
      if ((*puVar8 & 1) != 0) {
        FUN_800e61a0((int)puVar4,(int)puVar8);
      }
      FUN_80003494((uint)(puVar8 + 0xe),(uint)(puVar8 + 2),
                   ((int)(uint)*(byte *)(puVar8 + 0x97) >> 4) * 0xc);
    }
    if ((*puVar8 & 0x800) != 0) {
      if (0x3400 < (short)puVar4[1]) {
        puVar4[1] = 0x3400;
      }
      if ((short)puVar4[1] < -0x3400) {
        puVar4[1] = 0xcc00;
      }
    }
    if ((*puVar8 & 0x1000) != 0) {
      if (0x3400 < (short)puVar4[2]) {
        puVar4[2] = 0x3400;
      }
      if ((short)puVar4[2] < -0x3400) {
        puVar4[2] = 0xcc00;
      }
    }
    if ((*puVar8 & 0x40000) == 0) {
      iVar11 = *(int *)(puVar4 + 0x2a);
      if ((iVar11 == 0) || ((*(ushort *)(iVar11 + 0x60) & 1) == 0)) {
        *(float *)(puVar4 + 0x14) =
             (float)(dVar14 * (double)(*(float *)(puVar4 + 0xe) - *(float *)(puVar4 + 0x48)));
      }
      else {
        *(float *)(puVar4 + 0x14) =
             (float)(dVar14 * (double)(*(float *)(puVar4 + 0xe) - *(float *)(iVar11 + 0x20)));
        if (*(float *)(*(int *)(puVar4 + 0x2a) + 0x20) < *(float *)(puVar4 + 0xe)) {
          *(float *)(puVar4 + 0x14) = FLOAT_803e12e8;
        }
      }
    }
  }
  else if (*(char *)((int)puVar8 + 0x25b) == '\x02') {
    FUN_800e6778();
    uVar5 = *puVar8;
    if (((uVar5 & 0x4000000) != 0) && ((uVar5 & 8) != 0)) {
      local_1d0 = *puVar4;
      if ((uVar5 & 0x20) == 0) {
        local_1ce = puVar4[1];
        local_1cc = puVar4[2];
      }
      else {
        local_1ce = 0;
        local_1cc = 0;
      }
      local_1c8 = FLOAT_803e130c;
      local_1c4 = *(undefined4 *)(puVar4 + 6);
      local_1c0 = *(undefined4 *)(puVar4 + 8);
      local_1bc = *(undefined4 *)(puVar4 + 10);
      FUN_80021fac(afStack_130,&local_1d0);
      iVar12 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar13 = 0; fVar3 = FLOAT_803e130c, iVar13 < (int)(*(byte *)(puVar8 + 0x97) & 0xf);
          iVar13 = iVar13 + 1) {
        pfVar9 = (float *)(puVar8[0x37] + iVar11);
        FUN_80022790((double)*pfVar9,(double)pfVar9[1],(double)pfVar9[2],afStack_130,
                     (float *)(puVar10 + 0x39),(float *)(puVar8 + iVar12 + 0x3a),
                     (float *)(puVar8 + iVar12 + 0x3b));
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar12 = iVar12 + 3;
      }
      puVar10 = puVar8;
      for (iVar11 = 0; iVar11 < (int)(*(byte *)(puVar8 + 0x97) & 0xf); iVar11 = iVar11 + 1) {
        puVar10[0x45] = puVar10[0x39];
        puVar10[0x46] = (uint)(fVar3 + (float)puVar10[0x3a]);
        puVar10[0x47] = puVar10[0x3b];
        puVar10 = puVar10 + 3;
      }
      FUN_800634e4((int)puVar4);
    }
    if ((*puVar8 & 0x2000) != 0) {
      local_1b8 = *puVar4;
      if ((*puVar8 & 0x20) == 0) {
        local_1b6 = puVar4[1];
        local_1b4 = puVar4[2];
      }
      else {
        local_1b6 = 0;
        local_1b4 = 0;
      }
      local_1b0 = FLOAT_803e130c;
      local_1ac = *(undefined4 *)(puVar4 + 0xc);
      local_1a8 = *(undefined4 *)(puVar4 + 0xe);
      local_1a4 = *(undefined4 *)(puVar4 + 0x10);
      FUN_80021fac(afStack_f0,&local_1b8);
      iVar12 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar13 = 0; iVar13 < (int)(uint)*(byte *)(puVar8 + 0x97) >> 4; iVar13 = iVar13 + 1) {
        pfVar9 = (float *)(puVar8[1] + iVar11);
        FUN_80022790((double)*pfVar9,(double)pfVar9[1],(double)pfVar9[2],afStack_f0,
                     (float *)(puVar10 + 2),(float *)(puVar8 + iVar12 + 3),
                     (float *)(puVar8 + iVar12 + 4));
        *(undefined *)((int)puVar8 + iVar13 + 0xb8) = 0xff;
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar12 = iVar12 + 3;
      }
      FUN_80003494((uint)(puVar8 + 0xe),(uint)(puVar8 + 2),
                   ((int)(uint)*(byte *)(puVar8 + 0x97) >> 4) * 0xc);
      if ((*puVar8 & 1) != 0) {
        FUN_800e61a0((int)puVar4,(int)puVar8);
      }
    }
  }
  else {
    FUN_800e6778();
    uVar5 = *puVar8;
    if (((uVar5 & 0x4000000) != 0) && ((uVar5 & 8) != 0)) {
      local_1e8 = *puVar4;
      if ((uVar5 & 0x20) == 0) {
        local_1e6 = puVar4[1];
        local_1e4 = puVar4[2];
      }
      else {
        local_1e6 = 0;
        local_1e4 = 0;
      }
      local_1e0 = FLOAT_803e130c;
      local_1dc = *(undefined4 *)(puVar4 + 6);
      local_1d8 = *(undefined4 *)(puVar4 + 8);
      local_1d4 = *(undefined4 *)(puVar4 + 10);
      FUN_80021fac(afStack_170,&local_1e8);
      iVar12 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar13 = 0; fVar3 = FLOAT_803e130c, iVar13 < (int)(*(byte *)(puVar8 + 0x97) & 0xf);
          iVar13 = iVar13 + 1) {
        pfVar9 = (float *)(puVar8[0x37] + iVar11);
        FUN_80022790((double)*pfVar9,(double)pfVar9[1],(double)pfVar9[2],afStack_170,
                     (float *)(puVar10 + 0x39),(float *)(puVar8 + iVar12 + 0x3a),
                     (float *)(puVar8 + iVar12 + 0x3b));
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar12 = iVar12 + 3;
      }
      puVar10 = puVar8;
      for (iVar11 = 0; iVar11 < (int)(*(byte *)(puVar8 + 0x97) & 0xf); iVar11 = iVar11 + 1) {
        puVar10[0x45] = puVar10[0x39];
        puVar10[0x46] = (uint)(fVar3 + (float)puVar10[0x3a]);
        puVar10[0x47] = puVar10[0x3b];
        puVar10 = puVar10 + 3;
      }
      FUN_800634e4((int)puVar4);
    }
  }
  iVar11 = *(int *)(puVar4 + 0x18);
  if (iVar11 == 0) {
    *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(puVar4 + 0xc);
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(puVar4 + 0xe);
    *(undefined4 *)(puVar4 + 10) = *(undefined4 *)(puVar4 + 0x10);
  }
  else if ((*(int *)(iVar11 + 0x58) == 0) || (uVar6 = FUN_80036074(iVar11), uVar6 == 0)) {
    FUN_8000e054((double)*(float *)(puVar4 + 0xc),(double)*(float *)(puVar4 + 0xe),
                 (double)*(float *)(puVar4 + 0x10),(float *)(puVar4 + 6),(float *)(puVar4 + 8),
                 (float *)(puVar4 + 10),*(int *)(puVar4 + 0x18));
  }
  else {
    FUN_80022790((double)*(float *)(puVar4 + 0xc),(double)*(float *)(puVar4 + 0xe),
                 (double)*(float *)(puVar4 + 0x10),
                 (float *)(*(int *)(*(int *)(puVar4 + 0x18) + 0x58) +
                          (uint)*(byte *)(*(int *)(*(int *)(puVar4 + 0x18) + 0x58) + 0x10c) * 0x40),
                 (float *)(puVar4 + 6),(float *)(puVar4 + 8),(float *)(puVar4 + 10));
  }
LAB_800e78f0:
  FUN_80286888();
  return;
}

