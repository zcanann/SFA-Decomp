// Function: FUN_800e79a0
// Entry: 800e79a0
// Size: 972 bytes

/* WARNING: Removing unreachable block (ram,0x800e7d4c) */
/* WARNING: Removing unreachable block (ram,0x800e79b0) */

void FUN_800e79a0(void)

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
  ushort *puVar12;
  int iVar13;
  ushort uVar14;
  uint *puVar15;
  float *pfVar16;
  int iVar17;
  float *pfVar18;
  float *pfVar19;
  float *pfVar20;
  uint *puVar21;
  int iVar22;
  float *pfVar23;
  double dVar24;
  double in_f31;
  double dVar25;
  double in_ps31_1;
  undefined8 uVar26;
  float local_118 [4];
  ushort local_108;
  ushort local_106;
  ushort local_104;
  float local_100;
  undefined4 local_fc;
  undefined4 local_f8;
  undefined4 local_f4;
  float local_f0 [12];
  float afStack_c0 [16];
  longlong local_80;
  longlong local_78;
  undefined4 local_70;
  uint uStack_6c;
  longlong local_68;
  undefined4 local_60;
  uint uStack_5c;
  longlong local_58;
  longlong local_50;
  longlong local_48;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar26 = FUN_80286830();
  puVar12 = (ushort *)((ulonglong)uVar26 >> 0x20);
  puVar15 = (uint *)uVar26;
  if (((*(char *)((int)puVar15 + 0x25b) != '\0') && ((*puVar15 & 0x4000000) != 0)) &&
     ((*puVar15 & 0x2000) != 0)) {
    iVar13 = *(int *)(puVar12 + 0x18);
    if (iVar13 == 0) {
      *(undefined4 *)(puVar12 + 0xc) = *(undefined4 *)(puVar12 + 6);
      *(undefined4 *)(puVar12 + 0xe) = *(undefined4 *)(puVar12 + 8);
      *(undefined4 *)(puVar12 + 0x10) = *(undefined4 *)(puVar12 + 10);
    }
    else if ((*(int *)(iVar13 + 0x58) == 0) || (uVar14 = FUN_80036074(iVar13), uVar14 == 0)) {
      FUN_8000e0c0((double)*(float *)(puVar12 + 6),(double)*(float *)(puVar12 + 8),
                   (double)*(float *)(puVar12 + 10),(float *)(puVar12 + 0xc),
                   (float *)(puVar12 + 0xe),(float *)(puVar12 + 0x10),*(int *)(puVar12 + 0x18));
    }
    else {
      FUN_80022790((double)*(float *)(puVar12 + 6),(double)*(float *)(puVar12 + 8),
                   (double)*(float *)(puVar12 + 10),
                   (float *)(*(int *)(*(int *)(puVar12 + 0x18) + 0x58) +
                            (*(byte *)(*(int *)(*(int *)(puVar12 + 0x18) + 0x58) + 0x10c) + 2) *
                            0x40),(float *)(puVar12 + 0xc),(float *)(puVar12 + 0xe),
                   (float *)(puVar12 + 0x10));
    }
    local_108 = *puVar12;
    if ((*puVar15 & 0x20) == 0) {
      local_106 = puVar12[1];
      local_104 = puVar12[2];
    }
    else {
      local_106 = 0;
      local_104 = 0;
    }
    local_100 = FLOAT_803e130c;
    local_fc = *(undefined4 *)(puVar12 + 0xc);
    local_f8 = *(undefined4 *)(puVar12 + 0xe);
    local_f4 = *(undefined4 *)(puVar12 + 0x10);
    FUN_80021fac(afStack_c0,&local_108);
    iVar13 = 0;
    pfVar18 = local_f0;
    iVar22 = 0;
    pfVar19 = local_118;
    dVar25 = (double)FLOAT_803e1340;
    pfVar20 = pfVar19;
    puVar21 = puVar15;
    pfVar23 = pfVar18;
    for (iVar17 = 0; iVar11 = (int)(uint)*(byte *)(puVar15 + 0x97) >> 4, puVar10 = puVar15,
        fVar3 = FLOAT_803e1324, fVar4 = FLOAT_803e1324, fVar5 = FLOAT_803e1324,
        fVar6 = FLOAT_803e1328, fVar7 = FLOAT_803e1328, fVar8 = FLOAT_803e1328, iVar17 < iVar11;
        iVar17 = iVar17 + 1) {
      pfVar16 = (float *)(puVar15[1] + iVar22);
      FUN_80022790((double)*pfVar16,(double)pfVar16[1],(double)pfVar16[2],afStack_c0,pfVar23,
                   local_f0 + iVar13 + 1,local_f0 + iVar13 + 2);
      *pfVar20 = (float)puVar21[0x2a];
      dVar24 = FUN_80293900((double)(float)((double)(float)(dVar25 * (double)*pfVar20) *
                                           (double)*pfVar20));
      *pfVar20 = (float)dVar24;
      pfVar23 = pfVar23 + 3;
      iVar22 = iVar22 + 0xc;
      iVar13 = iVar13 + 3;
      puVar21 = puVar21 + 1;
      pfVar20 = pfVar20 + 1;
    }
    for (; iVar11 != 0; iVar11 = iVar11 + -1) {
      fVar2 = *pfVar19;
      fVar9 = *pfVar18 + fVar2;
      if (fVar3 < fVar9) {
        fVar3 = fVar9;
      }
      fVar9 = *pfVar18 - fVar2;
      if (fVar9 < fVar6) {
        fVar6 = fVar9;
      }
      fVar9 = pfVar18[1] + fVar2;
      if (fVar5 < fVar9) {
        fVar5 = fVar9;
      }
      fVar9 = pfVar18[1] - fVar2;
      if (fVar9 < fVar8) {
        fVar8 = fVar9;
      }
      fVar9 = pfVar18[2] + fVar2;
      if (fVar4 < fVar9) {
        fVar4 = fVar9;
      }
      fVar9 = pfVar18[2] - fVar2;
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
      pfVar18 = pfVar18 + 3;
      pfVar19 = pfVar19 + 1;
      puVar10 = puVar10 + 3;
    }
    local_80 = (longlong)(int)fVar6;
    puVar15[0x90] = (int)fVar6;
    local_78 = (longlong)(int)fVar3;
    puVar15[0x93] = (int)fVar3;
    dVar25 = DOUBLE_803e1318;
    uStack_6c = (uint)*(byte *)(puVar15 + 0x96);
    local_70 = 0x43300000;
    uVar1 = (uint)(fVar8 - (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e1318));
    local_68 = (longlong)(int)uVar1;
    puVar15[0x91] = uVar1;
    uStack_5c = (uint)*(byte *)(puVar15 + 0x96);
    local_60 = 0x43300000;
    uVar1 = (uint)(fVar5 + (float)((double)CONCAT44(0x43300000,uStack_5c) - dVar25));
    local_58 = (longlong)(int)uVar1;
    puVar15[0x94] = uVar1;
    local_50 = (longlong)(int)fVar7;
    puVar15[0x92] = (int)fVar7;
    local_48 = (longlong)(int)fVar4;
    puVar15[0x95] = (int)fVar4;
  }
  FUN_8028687c();
  return;
}

