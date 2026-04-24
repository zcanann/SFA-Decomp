// Function: FUN_800e6778
// Entry: 800e6778
// Size: 696 bytes

void FUN_800e6778(void)

{
  uint uVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  ushort *puVar5;
  int iVar6;
  ushort uVar8;
  uint *puVar7;
  uint *puVar9;
  float *pfVar10;
  uint *puVar11;
  int iVar12;
  int iVar13;
  undefined8 uVar14;
  ushort local_78;
  ushort local_76;
  ushort local_74;
  float local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  float afStack_60 [24];
  
  uVar14 = FUN_8028683c();
  puVar5 = (ushort *)((ulonglong)uVar14 >> 0x20);
  puVar9 = (uint *)uVar14;
  if ((*puVar9 & 0x4000000) != 0) {
    iVar6 = *(int *)(puVar5 + 0x18);
    if (iVar6 == 0) {
      *(undefined4 *)(puVar5 + 0xc) = *(undefined4 *)(puVar5 + 6);
      *(undefined4 *)(puVar5 + 0xe) = *(undefined4 *)(puVar5 + 8);
      *(undefined4 *)(puVar5 + 0x10) = *(undefined4 *)(puVar5 + 10);
    }
    else if ((*(int *)(iVar6 + 0x58) == 0) || (uVar8 = FUN_80036074(iVar6), uVar8 == 0)) {
      FUN_8000e0c0((double)*(float *)(puVar5 + 6),(double)*(float *)(puVar5 + 8),
                   (double)*(float *)(puVar5 + 10),(float *)(puVar5 + 0xc),(float *)(puVar5 + 0xe),
                   (float *)(puVar5 + 0x10),*(int *)(puVar5 + 0x18));
    }
    else {
      FUN_80022790((double)*(float *)(puVar5 + 6),(double)*(float *)(puVar5 + 8),
                   (double)*(float *)(puVar5 + 10),
                   (float *)(*(int *)(*(int *)(puVar5 + 0x18) + 0x58) +
                            (*(byte *)(*(int *)(*(int *)(puVar5 + 0x18) + 0x58) + 0x10c) + 2) * 0x40
                            ),(float *)(puVar5 + 0xc),(float *)(puVar5 + 0xe),
                   (float *)(puVar5 + 0x10));
    }
    if ((*puVar9 & 0x2000) != 0) {
      local_78 = *puVar5;
      if ((*puVar9 & 0x20) == 0) {
        local_76 = puVar5[1];
        local_74 = puVar5[2];
      }
      else {
        local_76 = 0;
        local_74 = 0;
      }
      local_70 = FLOAT_803e130c;
      local_6c = *(undefined4 *)(puVar5 + 0xc);
      local_68 = *(undefined4 *)(puVar5 + 0xe);
      local_64 = *(undefined4 *)(puVar5 + 0x10);
      FUN_80021fac(afStack_60,&local_78);
      iVar13 = 0;
      iVar6 = 0;
      puVar7 = puVar9;
      for (iVar12 = 0; fVar2 = FLOAT_803e1338, iVar12 < (int)(uint)*(byte *)(puVar9 + 0x97) >> 4;
          iVar12 = iVar12 + 1) {
        pfVar10 = (float *)(puVar9[1] + iVar6);
        FUN_80022790((double)*pfVar10,(double)pfVar10[1],(double)pfVar10[2],afStack_60,
                     (float *)(puVar7 + 2),(float *)(puVar9 + iVar13 + 3),
                     (float *)(puVar9 + iVar13 + 4));
        *(undefined *)((int)puVar9 + iVar12 + 0xb8) = 0xff;
        puVar7 = puVar7 + 3;
        iVar6 = iVar6 + 0xc;
        iVar13 = iVar13 + 3;
      }
      puVar7 = puVar9;
      puVar11 = puVar9;
      for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(puVar9 + 0x97) >> 4; iVar6 = iVar6 + 1) {
        puVar7[0xe] = puVar7[2];
        puVar7[0xf] = (uint)(fVar2 + (float)puVar7[3] + (float)puVar11[0x2a]);
        puVar7[0x10] = puVar7[4];
        puVar7 = puVar7 + 3;
        puVar11 = puVar11 + 1;
      }
    }
    if (puVar5[0x22] == 1) {
      uVar1 = *(uint *)(puVar5 + 0xc);
      puVar9[8] = uVar1;
      puVar9[0x14] = uVar1;
      fVar2 = FLOAT_803e133c + *(float *)(puVar5 + 0xe);
      puVar9[9] = (uint)fVar2;
      puVar9[0x15] = (uint)fVar2;
      uVar1 = *(uint *)(puVar5 + 0x10);
      puVar9[10] = uVar1;
      puVar9[0x16] = uVar1;
    }
    *(undefined *)(puVar9 + 0x98) = 0;
    *(undefined *)((int)puVar9 + 0x25f) = 0;
    fVar3 = FLOAT_803e1324;
    puVar9[0x6f] = (uint)FLOAT_803e1324;
    puVar9[0x6e] = (uint)fVar3;
    fVar4 = FLOAT_803e1328;
    puVar9[0x6c] = (uint)FLOAT_803e1328;
    fVar2 = FLOAT_803e12e8;
    puVar9[0x6d] = (uint)FLOAT_803e12e8;
    puVar9[0x6b] = (uint)fVar2;
    puVar9[0x36] = 0;
    puVar7 = puVar9;
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(puVar9 + 0x97) >> 4; iVar6 = iVar6 + 1) {
      puVar7[0x80] = (uint)fVar3;
      puVar7[0x7c] = (uint)fVar3;
      puVar7[0x74] = (uint)fVar4;
      puVar7 = puVar7 + 1;
    }
  }
  FUN_80286888();
  return;
}

