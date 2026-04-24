// Function: FUN_800e58fc
// Entry: 800e58fc
// Size: 960 bytes

void FUN_800e58fc(void)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  short *psVar5;
  uint *puVar6;
  short sVar7;
  undefined2 uVar8;
  uint *puVar9;
  uint *puVar10;
  float *pfVar11;
  char cVar12;
  float *pfVar13;
  char cVar14;
  float *pfVar15;
  undefined8 uVar16;
  float local_b8 [4];
  float local_a8 [4];
  float local_98 [4];
  short local_88;
  short local_86;
  short local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  undefined auStack112 [64];
  undefined4 local_30;
  int iStack44;
  
  uVar16 = FUN_802860d0();
  psVar5 = (short *)((ulonglong)uVar16 >> 0x20);
  puVar9 = (uint *)uVar16;
  puVar9[0x68] = puVar9[0x1a];
  puVar9[0x69] = puVar9[0x1b];
  puVar9[0x6a] = puVar9[0x1c];
  fVar3 = FLOAT_803e0668;
  iVar4 = (int)(uint)*(byte *)(puVar9 + 0x97) >> 4;
  if ((iVar4 == 2) || (iVar4 == 4)) {
    *(float *)(psVar5 + 0xc) = FLOAT_803e0668;
    *(float *)(psVar5 + 0xe) = fVar3;
    *(float *)(psVar5 + 0x10) = fVar3;
    puVar6 = puVar9;
    puVar10 = puVar9;
    for (sVar7 = 0; fVar3 = FLOAT_803e068c, (int)sVar7 < iVar4 * 3; sVar7 = sVar7 + 3) {
      *(float *)(psVar5 + 0xc) = *(float *)(psVar5 + 0xc) + (float)puVar6[2];
      *(float *)(psVar5 + 0xe) = *(float *)(psVar5 + 0xe) + (float)puVar10[3];
      *(float *)(psVar5 + 0x10) = *(float *)(psVar5 + 0x10) + (float)puVar10[4];
      puVar6 = puVar6 + 3;
      puVar10 = puVar10 + 3;
    }
    local_30 = 0x43300000;
    fVar2 = FLOAT_803e068c / (float)((double)CONCAT44(0x43300000,iVar4) - DOUBLE_803e0698);
    *(float *)(psVar5 + 0xc) = *(float *)(psVar5 + 0xc) * fVar2;
    *(float *)(psVar5 + 0xe) = *(float *)(psVar5 + 0xe) * fVar2;
    *(float *)(psVar5 + 0x10) = *(float *)(psVar5 + 0x10) * fVar2;
    iStack44 = iVar4;
    if ((*puVar9 & 0x8600) != 0) {
      local_88 = -*psVar5;
      local_86 = -psVar5[1];
      local_84 = -psVar5[2];
      local_80 = fVar3;
      local_7c = -*(float *)(psVar5 + 0xc);
      local_78 = -*(float *)(psVar5 + 0xe);
      local_74 = -*(float *)(psVar5 + 0x10);
      FUN_80021ba0(auStack112,&local_88);
      pfVar15 = local_b8;
      pfVar11 = local_a8;
      pfVar13 = local_98;
      puVar6 = puVar9;
      for (sVar7 = 0; sVar7 < iVar4; sVar7 = sVar7 + 1) {
        FUN_800226cc((double)(float)puVar6[2],(double)(float)puVar6[3],(double)(float)puVar6[4],
                     auStack112,pfVar13,pfVar11,pfVar15);
        puVar6 = puVar6 + 3;
        pfVar15 = pfVar15 + 1;
        pfVar11 = pfVar11 + 1;
        pfVar13 = pfVar13 + 1;
      }
      cVar14 = '\x02';
      cVar12 = '\x03';
      bVar1 = iVar4 != 2;
      if (!bVar1) {
        cVar14 = '\x01';
        cVar12 = '\x01';
      }
      if ((*puVar9 & 0x8000) != 0) {
        sVar7 = FUN_800217c0((double)((local_98[0] + local_98[bVar1]) -
                                     (local_98[cVar14] + local_98[cVar12])),
                             (double)((local_b8[0] + local_b8[bVar1]) -
                                     (local_b8[cVar14] + local_b8[cVar12])));
        *psVar5 = *psVar5 + ((short)(sVar7 + -0x8000) >> 2);
      }
      if ((*puVar9 & 0x200) != 0) {
        sVar7 = FUN_800217c0((double)(((local_a8[cVar14] - local_a8[bVar1]) +
                                      (local_a8[cVar12] - local_a8[0])) * FLOAT_803e0690),
                             (double)(((local_b8[cVar14] - local_b8[bVar1]) +
                                      (local_b8[cVar12] - local_b8[0])) * FLOAT_803e0690));
        *(short *)(puVar9 + 0x66) = -sVar7;
      }
      if ((iVar4 == 4) && ((*puVar9 & 0x400) != 0)) {
        uVar8 = FUN_800217c0((double)(((local_a8[bVar1] - local_a8[0]) +
                                      (local_a8[cVar14] - local_a8[cVar12])) * FLOAT_803e0690),
                             (double)(((local_98[bVar1] - local_98[0]) +
                                      (local_98[cVar14] - local_98[cVar12])) * FLOAT_803e0690));
        *(undefined2 *)((int)puVar9 + 0x19a) = uVar8;
      }
    }
  }
  else {
    *(uint *)(psVar5 + 0xc) = puVar9[2];
    *(uint *)(psVar5 + 0xe) = puVar9[3];
    *(uint *)(psVar5 + 0x10) = puVar9[4];
  }
  FUN_8028611c();
  return;
}

