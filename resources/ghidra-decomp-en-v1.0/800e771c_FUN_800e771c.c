// Function: FUN_800e771c
// Entry: 800e771c
// Size: 972 bytes

/* WARNING: Removing unreachable block (ram,0x800e7ac8) */

void FUN_800e771c(void)

{
  uint uVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  uint *puVar10;
  int iVar11;
  undefined2 *puVar12;
  int iVar13;
  uint *puVar14;
  float *pfVar15;
  int iVar16;
  float *pfVar17;
  float *pfVar18;
  float *pfVar19;
  uint *puVar20;
  int iVar21;
  float *pfVar22;
  undefined4 uVar23;
  double dVar24;
  undefined8 in_f31;
  double dVar25;
  undefined8 uVar26;
  float local_118 [4];
  undefined2 local_108;
  undefined2 local_106;
  undefined2 local_104;
  float local_100;
  undefined4 local_fc;
  undefined4 local_f8;
  undefined4 local_f4;
  float local_f0 [12];
  undefined auStack192 [64];
  longlong local_80;
  longlong local_78;
  undefined4 local_70;
  uint uStack108;
  longlong local_68;
  undefined4 local_60;
  uint uStack92;
  longlong local_58;
  longlong local_50;
  longlong local_48;
  undefined auStack8 [8];
  
  uVar23 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar26 = FUN_802860cc();
  puVar12 = (undefined2 *)((ulonglong)uVar26 >> 0x20);
  puVar14 = (uint *)uVar26;
  if (((*(char *)((int)puVar14 + 0x25b) != '\0') && ((*puVar14 & 0x4000000) != 0)) &&
     ((*puVar14 & 0x2000) != 0)) {
    if (*(int *)(puVar12 + 0x18) == 0) {
      *(undefined4 *)(puVar12 + 0xc) = *(undefined4 *)(puVar12 + 6);
      *(undefined4 *)(puVar12 + 0xe) = *(undefined4 *)(puVar12 + 8);
      *(undefined4 *)(puVar12 + 0x10) = *(undefined4 *)(puVar12 + 10);
    }
    else if ((*(int *)(*(int *)(puVar12 + 0x18) + 0x58) == 0) ||
            (iVar13 = FUN_80035f7c(), iVar13 == 0)) {
      FUN_8000e0a0((double)*(float *)(puVar12 + 6),(double)*(float *)(puVar12 + 8),
                   (double)*(float *)(puVar12 + 10),puVar12 + 0xc,puVar12 + 0xe,puVar12 + 0x10,
                   *(undefined4 *)(puVar12 + 0x18));
    }
    else {
      FUN_800226cc((double)*(float *)(puVar12 + 6),(double)*(float *)(puVar12 + 8),
                   (double)*(float *)(puVar12 + 10),
                   *(int *)(*(int *)(puVar12 + 0x18) + 0x58) +
                   (*(byte *)(*(int *)(*(int *)(puVar12 + 0x18) + 0x58) + 0x10c) + 2) * 0x40,
                   puVar12 + 0xc,puVar12 + 0xe,puVar12 + 0x10);
    }
    local_108 = *puVar12;
    if ((*puVar14 & 0x20) == 0) {
      local_106 = puVar12[1];
      local_104 = puVar12[2];
    }
    else {
      local_106 = 0;
      local_104 = 0;
    }
    local_100 = FLOAT_803e068c;
    local_fc = *(undefined4 *)(puVar12 + 0xc);
    local_f8 = *(undefined4 *)(puVar12 + 0xe);
    local_f4 = *(undefined4 *)(puVar12 + 0x10);
    FUN_80021ee8(auStack192,&local_108);
    iVar13 = 0;
    pfVar17 = local_f0;
    iVar21 = 0;
    pfVar18 = local_118;
    dVar25 = (double)FLOAT_803e06c0;
    pfVar19 = pfVar18;
    puVar20 = puVar14;
    pfVar22 = pfVar17;
    for (iVar16 = 0; iVar11 = (int)(uint)*(byte *)(puVar14 + 0x97) >> 4, puVar10 = puVar14,
        fVar3 = FLOAT_803e06a4, fVar4 = FLOAT_803e06a4, fVar5 = FLOAT_803e06a4,
        fVar6 = FLOAT_803e06a8, fVar7 = FLOAT_803e06a8, fVar8 = FLOAT_803e06a8, iVar16 < iVar11;
        iVar16 = iVar16 + 1) {
      pfVar15 = (float *)(puVar14[1] + iVar21);
      FUN_800226cc((double)*pfVar15,(double)pfVar15[1],(double)pfVar15[2],auStack192,pfVar22,
                   local_f0 + iVar13 + 1,local_f0 + iVar13 + 2);
      *pfVar19 = (float)puVar20[0x2a];
      dVar24 = (double)FUN_802931a0((double)(float)((double)(float)(dVar25 * (double)*pfVar19) *
                                                   (double)*pfVar19));
      *pfVar19 = (float)dVar24;
      pfVar22 = pfVar22 + 3;
      iVar21 = iVar21 + 0xc;
      iVar13 = iVar13 + 3;
      puVar20 = puVar20 + 1;
      pfVar19 = pfVar19 + 1;
    }
    for (; iVar11 != 0; iVar11 = iVar11 + -1) {
      fVar2 = *pfVar18;
      fVar9 = *pfVar17 + fVar2;
      if (fVar3 < fVar9) {
        fVar3 = fVar9;
      }
      fVar9 = *pfVar17 - fVar2;
      if (fVar9 < fVar6) {
        fVar6 = fVar9;
      }
      fVar9 = pfVar17[1] + fVar2;
      if (fVar5 < fVar9) {
        fVar5 = fVar9;
      }
      fVar9 = pfVar17[1] - fVar2;
      if (fVar9 < fVar8) {
        fVar8 = fVar9;
      }
      fVar9 = pfVar17[2] + fVar2;
      if (fVar4 < fVar9) {
        fVar4 = fVar9;
      }
      fVar9 = pfVar17[2] - fVar2;
      if (fVar9 < fVar7) {
        fVar7 = fVar9;
      }
      fVar9 = (float)puVar10[0xe] + fVar2;
      if (fVar3 < fVar9) {
        fVar3 = fVar9;
      }
      fVar9 = (float)puVar10[0xe] - fVar2;
      if (fVar9 < fVar6) {
        fVar6 = fVar9;
      }
      fVar9 = (float)puVar10[0xf] + fVar2;
      if (fVar5 < fVar9) {
        fVar5 = fVar9;
      }
      fVar9 = (float)puVar10[0xf] - fVar2;
      if (fVar9 < fVar8) {
        fVar8 = fVar9;
      }
      fVar9 = (float)puVar10[0x10] + fVar2;
      if (fVar4 < fVar9) {
        fVar4 = fVar9;
      }
      fVar2 = (float)puVar10[0x10] - fVar2;
      if (fVar2 < fVar7) {
        fVar7 = fVar2;
      }
      pfVar17 = pfVar17 + 3;
      pfVar18 = pfVar18 + 1;
      puVar10 = puVar10 + 3;
    }
    local_80 = (longlong)(int)fVar6;
    puVar14[0x90] = (int)fVar6;
    local_78 = (longlong)(int)fVar3;
    puVar14[0x93] = (int)fVar3;
    dVar25 = DOUBLE_803e0698;
    uStack108 = (uint)*(byte *)(puVar14 + 0x96);
    local_70 = 0x43300000;
    uVar1 = (uint)(fVar8 - (float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e0698));
    local_68 = (longlong)(int)uVar1;
    puVar14[0x91] = uVar1;
    uStack92 = (uint)*(byte *)(puVar14 + 0x96);
    local_60 = 0x43300000;
    uVar1 = (uint)(fVar5 + (float)((double)CONCAT44(0x43300000,uStack92) - dVar25));
    local_58 = (longlong)(int)uVar1;
    puVar14[0x94] = uVar1;
    local_50 = (longlong)(int)fVar7;
    puVar14[0x92] = (int)fVar7;
    local_48 = (longlong)(int)fVar4;
    puVar14[0x95] = (int)fVar4;
  }
  __psq_l0(auStack8,uVar23);
  __psq_l1(auStack8,uVar23);
  FUN_80286118();
  return;
}

