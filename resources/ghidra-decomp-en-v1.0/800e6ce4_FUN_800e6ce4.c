// Function: FUN_800e6ce4
// Entry: 800e6ce4
// Size: 2472 bytes

/* WARNING: Removing unreachable block (ram,0x800e766c) */

void FUN_800e6ce4(void)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  undefined2 *puVar4;
  undefined uVar6;
  uint uVar5;
  uint *puVar7;
  float *pfVar8;
  uint *puVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined4 uVar13;
  double extraout_f1;
  undefined8 in_f31;
  double dVar14;
  undefined8 uVar15;
  undefined2 local_1e8;
  undefined2 local_1e6;
  undefined2 local_1e4;
  float local_1e0;
  undefined4 local_1dc;
  undefined4 local_1d8;
  undefined4 local_1d4;
  undefined2 local_1d0;
  undefined2 local_1ce;
  undefined2 local_1cc;
  float local_1c8;
  undefined4 local_1c4;
  undefined4 local_1c0;
  undefined4 local_1bc;
  undefined2 local_1b8;
  undefined2 local_1b6;
  undefined2 local_1b4;
  float local_1b0;
  undefined4 local_1ac;
  undefined4 local_1a8;
  undefined4 local_1a4;
  undefined2 local_1a0;
  undefined2 local_19e;
  undefined2 local_19c;
  float local_198;
  undefined4 local_194;
  undefined4 local_190;
  undefined4 local_18c;
  undefined2 local_188;
  undefined2 local_186;
  undefined2 local_184;
  float local_180;
  undefined4 local_17c;
  undefined4 local_178;
  undefined4 local_174;
  undefined auStack368 [64];
  undefined auStack304 [64];
  undefined auStack240 [64];
  undefined auStack176 [64];
  undefined auStack112 [104];
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar15 = FUN_802860d8();
  fVar3 = FLOAT_803e068c;
  puVar4 = (undefined2 *)((ulonglong)uVar15 >> 0x20);
  puVar7 = (uint *)uVar15;
  if ((*puVar7 & 0x4000000) == 0) goto LAB_800e766c;
  dVar14 = (double)(float)((double)FLOAT_803e068c / extraout_f1);
  puVar7[0x36] = 0;
  fVar2 = FLOAT_803e0668;
  if (*(char *)((int)puVar7 + 0x25b) == '\x01') {
    DAT_803dd484 = 0;
    DAT_803dd480 = 0;
    puVar7[0x68] = (uint)FLOAT_803e0668;
    puVar7[0x69] = (uint)fVar3;
    puVar7[0x6a] = (uint)fVar2;
    if (((*puVar7 & 8) != 0) && ((*(byte *)(puVar7 + 0x97) & 0xf) != 0)) {
      local_188 = *puVar4;
      if ((*puVar7 & 0x20) == 0) {
        local_186 = puVar4[1];
        local_184 = puVar4[2];
      }
      else {
        local_186 = 0;
        local_184 = 0;
      }
      local_180 = FLOAT_803e068c;
      local_17c = *(undefined4 *)(puVar4 + 6);
      local_178 = *(undefined4 *)(puVar4 + 8);
      local_174 = *(undefined4 *)(puVar4 + 10);
      FUN_80021ee8(auStack112,&local_188);
      iVar12 = 0;
      iVar10 = 0;
      puVar9 = puVar7;
      for (iVar11 = 0; iVar11 < (int)(*(byte *)(puVar7 + 0x97) & 0xf); iVar11 = iVar11 + 1) {
        pfVar8 = (float *)(puVar7[0x37] + iVar10);
        FUN_800226cc((double)*pfVar8,(double)pfVar8[1],(double)pfVar8[2],auStack112,puVar9 + 0x39,
                     puVar7 + iVar12 + 0x3a,puVar7 + iVar12 + 0x3b);
        puVar9 = puVar9 + 3;
        iVar10 = iVar10 + 0xc;
        iVar12 = iVar12 + 3;
      }
      FUN_800e618c(puVar4,puVar7);
      if (*(int *)(puVar4 + 0x18) == 0) {
        *(undefined4 *)(puVar4 + 0xc) = *(undefined4 *)(puVar4 + 6);
        *(undefined4 *)(puVar4 + 0xe) = *(undefined4 *)(puVar4 + 8);
        *(undefined4 *)(puVar4 + 0x10) = *(undefined4 *)(puVar4 + 10);
      }
      else if ((*(int *)(*(int *)(puVar4 + 0x18) + 0x58) == 0) ||
              (iVar10 = FUN_80035f7c(), iVar10 == 0)) {
        FUN_8000e0a0((double)*(float *)(puVar4 + 6),(double)*(float *)(puVar4 + 8),
                     (double)*(float *)(puVar4 + 10),puVar4 + 0xc,puVar4 + 0xe,puVar4 + 0x10,
                     *(undefined4 *)(puVar4 + 0x18));
      }
      else {
        FUN_800226cc((double)*(float *)(puVar4 + 6),(double)*(float *)(puVar4 + 8),
                     (double)*(float *)(puVar4 + 10),
                     *(int *)(*(int *)(puVar4 + 0x18) + 0x58) +
                     (*(byte *)(*(int *)(*(int *)(puVar4 + 0x18) + 0x58) + 0x10c) + 2) * 0x40,
                     puVar4 + 0xc,puVar4 + 0xe,puVar4 + 0x10);
      }
    }
    if (((*puVar7 & 0x2000) != 0) && ((*(byte *)(puVar7 + 0x97) & 0xf0) != 0)) {
      local_1a0 = *puVar4;
      if ((*puVar7 & 0x20) == 0) {
        local_19e = puVar4[1];
        local_19c = puVar4[2];
      }
      else {
        local_19e = 0;
        local_19c = 0;
      }
      local_198 = FLOAT_803e068c;
      local_194 = *(undefined4 *)(puVar4 + 0xc);
      local_190 = *(undefined4 *)(puVar4 + 0xe);
      local_18c = *(undefined4 *)(puVar4 + 0x10);
      FUN_80021ee8(auStack176,&local_1a0);
      iVar11 = 0;
      iVar10 = 0;
      puVar9 = puVar7;
      for (iVar12 = 0; iVar12 < (int)(uint)*(byte *)(puVar7 + 0x97) >> 4; iVar12 = iVar12 + 1) {
        pfVar8 = (float *)(puVar7[1] + iVar10);
        FUN_800226cc((double)*pfVar8,(double)pfVar8[1],(double)pfVar8[2],auStack176,puVar9 + 2,
                     puVar7 + iVar11 + 3,puVar7 + iVar11 + 4);
        *(undefined *)((int)puVar7 + iVar12 + 0xb8) = 0xff;
        puVar9 = puVar9 + 3;
        iVar10 = iVar10 + 0xc;
        iVar11 = iVar11 + 3;
      }
      if ((*puVar7 & 2) != 0) {
        uVar6 = FUN_80067958(puVar4,puVar7 + 0xe,puVar7 + 2,(int)(uint)*(byte *)(puVar7 + 0x97) >> 4
                             ,puVar7 + 0x1a,0);
        *(undefined *)(puVar7 + 0x98) = uVar6;
        *(char *)((int)puVar7 + 0x261) = (char)*(undefined2 *)(puVar7 + 0x35);
        *(undefined *)((int)puVar7 + 0x25f) = 0;
      }
      bVar1 = *(byte *)((int)puVar7 + 0x262);
      if (bVar1 == 3) {
        FUN_800e5434(puVar4,puVar7);
      }
      else if (bVar1 < 3) {
        if (bVar1 == 1) {
          FUN_800e56a4(puVar4,puVar7);
        }
        else {
LAB_800e70cc:
          FUN_800e58fc(puVar4,puVar7);
        }
      }
      else {
        if (4 < bVar1) goto LAB_800e70cc;
        puVar7[0x68] = puVar7[0x1a];
        puVar7[0x69] = puVar7[0x1b];
        puVar7[0x6a] = puVar7[0x1c];
        if (((*(byte *)(puVar7 + 0x98) & 1) != 0) && (*(char *)(puVar7 + 0x2e) == '!')) {
          *(uint *)(puVar4 + 0xc) = puVar7[2];
          *(uint *)(puVar4 + 0xe) = puVar7[3];
          *(uint *)(puVar4 + 0x10) = puVar7[4];
        }
      }
      if ((*puVar7 & 0x100) != 0) {
        FUN_800e5e38(puVar4,puVar7);
      }
      if ((*puVar7 & 0x80) != 0) {
        FUN_800e5cbc(puVar4,puVar7);
      }
      if ((*puVar7 & 1) != 0) {
        FUN_800e5f1c(puVar4,puVar7);
      }
      FUN_80003494(puVar7 + 0xe,puVar7 + 2,((int)(uint)*(byte *)(puVar7 + 0x97) >> 4) * 0xc);
    }
    if ((*puVar7 & 0x800) != 0) {
      if (0x3400 < (short)puVar4[1]) {
        puVar4[1] = 0x3400;
      }
      if ((short)puVar4[1] < -0x3400) {
        puVar4[1] = 0xcc00;
      }
    }
    if ((*puVar7 & 0x1000) != 0) {
      if (0x3400 < (short)puVar4[2]) {
        puVar4[2] = 0x3400;
      }
      if ((short)puVar4[2] < -0x3400) {
        puVar4[2] = 0xcc00;
      }
    }
    if ((*puVar7 & 0x40000) == 0) {
      iVar10 = *(int *)(puVar4 + 0x2a);
      if ((iVar10 == 0) || ((*(ushort *)(iVar10 + 0x60) & 1) == 0)) {
        *(float *)(puVar4 + 0x14) =
             (float)(dVar14 * (double)(*(float *)(puVar4 + 0xe) - *(float *)(puVar4 + 0x48)));
      }
      else {
        *(float *)(puVar4 + 0x14) =
             (float)(dVar14 * (double)(*(float *)(puVar4 + 0xe) - *(float *)(iVar10 + 0x20)));
        if (*(float *)(*(int *)(puVar4 + 0x2a) + 0x20) < *(float *)(puVar4 + 0xe)) {
          *(float *)(puVar4 + 0x14) = FLOAT_803e0668;
        }
      }
    }
  }
  else if (*(char *)((int)puVar7 + 0x25b) == '\x02') {
    FUN_800e64f4();
    uVar5 = *puVar7;
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
      local_1c8 = FLOAT_803e068c;
      local_1c4 = *(undefined4 *)(puVar4 + 6);
      local_1c0 = *(undefined4 *)(puVar4 + 8);
      local_1bc = *(undefined4 *)(puVar4 + 10);
      FUN_80021ee8(auStack304,&local_1d0);
      iVar11 = 0;
      iVar10 = 0;
      puVar9 = puVar7;
      for (iVar12 = 0; fVar3 = FLOAT_803e068c, iVar12 < (int)(*(byte *)(puVar7 + 0x97) & 0xf);
          iVar12 = iVar12 + 1) {
        pfVar8 = (float *)(puVar7[0x37] + iVar10);
        FUN_800226cc((double)*pfVar8,(double)pfVar8[1],(double)pfVar8[2],auStack304,puVar9 + 0x39,
                     puVar7 + iVar11 + 0x3a,puVar7 + iVar11 + 0x3b);
        puVar9 = puVar9 + 3;
        iVar10 = iVar10 + 0xc;
        iVar11 = iVar11 + 3;
      }
      puVar9 = puVar7;
      for (iVar10 = 0; iVar10 < (int)(*(byte *)(puVar7 + 0x97) & 0xf); iVar10 = iVar10 + 1) {
        puVar9[0x45] = puVar9[0x39];
        puVar9[0x46] = (uint)(fVar3 + (float)puVar9[0x3a]);
        puVar9[0x47] = puVar9[0x3b];
        puVar9 = puVar9 + 3;
      }
      FUN_80063368(puVar4);
    }
    if ((*puVar7 & 0x2000) != 0) {
      local_1b8 = *puVar4;
      if ((*puVar7 & 0x20) == 0) {
        local_1b6 = puVar4[1];
        local_1b4 = puVar4[2];
      }
      else {
        local_1b6 = 0;
        local_1b4 = 0;
      }
      local_1b0 = FLOAT_803e068c;
      local_1ac = *(undefined4 *)(puVar4 + 0xc);
      local_1a8 = *(undefined4 *)(puVar4 + 0xe);
      local_1a4 = *(undefined4 *)(puVar4 + 0x10);
      FUN_80021ee8(auStack240,&local_1b8);
      iVar11 = 0;
      iVar10 = 0;
      puVar9 = puVar7;
      for (iVar12 = 0; iVar12 < (int)(uint)*(byte *)(puVar7 + 0x97) >> 4; iVar12 = iVar12 + 1) {
        pfVar8 = (float *)(puVar7[1] + iVar10);
        FUN_800226cc((double)*pfVar8,(double)pfVar8[1],(double)pfVar8[2],auStack240,puVar9 + 2,
                     puVar7 + iVar11 + 3,puVar7 + iVar11 + 4);
        *(undefined *)((int)puVar7 + iVar12 + 0xb8) = 0xff;
        puVar9 = puVar9 + 3;
        iVar10 = iVar10 + 0xc;
        iVar11 = iVar11 + 3;
      }
      FUN_80003494(puVar7 + 0xe,puVar7 + 2,((int)(uint)*(byte *)(puVar7 + 0x97) >> 4) * 0xc);
      if ((*puVar7 & 1) != 0) {
        FUN_800e5f1c(puVar4,puVar7);
      }
    }
  }
  else {
    FUN_800e64f4();
    uVar5 = *puVar7;
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
      local_1e0 = FLOAT_803e068c;
      local_1dc = *(undefined4 *)(puVar4 + 6);
      local_1d8 = *(undefined4 *)(puVar4 + 8);
      local_1d4 = *(undefined4 *)(puVar4 + 10);
      FUN_80021ee8(auStack368,&local_1e8);
      iVar11 = 0;
      iVar10 = 0;
      puVar9 = puVar7;
      for (iVar12 = 0; fVar3 = FLOAT_803e068c, iVar12 < (int)(*(byte *)(puVar7 + 0x97) & 0xf);
          iVar12 = iVar12 + 1) {
        pfVar8 = (float *)(puVar7[0x37] + iVar10);
        FUN_800226cc((double)*pfVar8,(double)pfVar8[1],(double)pfVar8[2],auStack368,puVar9 + 0x39,
                     puVar7 + iVar11 + 0x3a,puVar7 + iVar11 + 0x3b);
        puVar9 = puVar9 + 3;
        iVar10 = iVar10 + 0xc;
        iVar11 = iVar11 + 3;
      }
      puVar9 = puVar7;
      for (iVar10 = 0; iVar10 < (int)(*(byte *)(puVar7 + 0x97) & 0xf); iVar10 = iVar10 + 1) {
        puVar9[0x45] = puVar9[0x39];
        puVar9[0x46] = (uint)(fVar3 + (float)puVar9[0x3a]);
        puVar9[0x47] = puVar9[0x3b];
        puVar9 = puVar9 + 3;
      }
      FUN_80063368(puVar4);
    }
  }
  if (*(int *)(puVar4 + 0x18) == 0) {
    *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(puVar4 + 0xc);
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(puVar4 + 0xe);
    *(undefined4 *)(puVar4 + 10) = *(undefined4 *)(puVar4 + 0x10);
  }
  else if ((*(int *)(*(int *)(puVar4 + 0x18) + 0x58) == 0) || (iVar10 = FUN_80035f7c(), iVar10 == 0)
          ) {
    FUN_8000e034((double)*(float *)(puVar4 + 0xc),(double)*(float *)(puVar4 + 0xe),
                 (double)*(float *)(puVar4 + 0x10),puVar4 + 6,puVar4 + 8,puVar4 + 10,
                 *(undefined4 *)(puVar4 + 0x18));
  }
  else {
    FUN_800226cc((double)*(float *)(puVar4 + 0xc),(double)*(float *)(puVar4 + 0xe),
                 (double)*(float *)(puVar4 + 0x10),
                 *(int *)(*(int *)(puVar4 + 0x18) + 0x58) +
                 (uint)*(byte *)(*(int *)(*(int *)(puVar4 + 0x18) + 0x58) + 0x10c) * 0x40,puVar4 + 6
                 ,puVar4 + 8,puVar4 + 10);
  }
LAB_800e766c:
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  FUN_80286124();
  return;
}

