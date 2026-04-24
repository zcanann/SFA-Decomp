// Function: FUN_800e5b80
// Entry: 800e5b80
// Size: 960 bytes

void FUN_800e5b80(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  short *psVar4;
  uint *puVar5;
  int iVar6;
  uint *puVar7;
  uint *puVar8;
  short sVar9;
  float *pfVar10;
  float *pfVar11;
  float *pfVar12;
  undefined8 uVar13;
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
  float afStack_70 [16];
  undefined4 local_30;
  int iStack_2c;
  
  uVar13 = FUN_80286834();
  psVar4 = (short *)((ulonglong)uVar13 >> 0x20);
  puVar7 = (uint *)uVar13;
  puVar7[0x68] = puVar7[0x1a];
  puVar7[0x69] = puVar7[0x1b];
  puVar7[0x6a] = puVar7[0x1c];
  fVar2 = FLOAT_803e12e8;
  iVar3 = (int)(uint)*(byte *)(puVar7 + 0x97) >> 4;
  if ((iVar3 == 2) || (iVar3 == 4)) {
    *(float *)(psVar4 + 0xc) = FLOAT_803e12e8;
    *(float *)(psVar4 + 0xe) = fVar2;
    *(float *)(psVar4 + 0x10) = fVar2;
    puVar5 = puVar7;
    puVar8 = puVar7;
    for (sVar9 = 0; fVar2 = FLOAT_803e130c, (int)sVar9 < iVar3 * 3; sVar9 = sVar9 + 3) {
      *(float *)(psVar4 + 0xc) = *(float *)(psVar4 + 0xc) + (float)puVar5[2];
      *(float *)(psVar4 + 0xe) = *(float *)(psVar4 + 0xe) + (float)puVar8[3];
      *(float *)(psVar4 + 0x10) = *(float *)(psVar4 + 0x10) + (float)puVar8[4];
      puVar5 = puVar5 + 3;
      puVar8 = puVar8 + 3;
    }
    local_30 = 0x43300000;
    fVar1 = FLOAT_803e130c / (float)((double)CONCAT44(0x43300000,iVar3) - DOUBLE_803e1318);
    *(float *)(psVar4 + 0xc) = *(float *)(psVar4 + 0xc) * fVar1;
    *(float *)(psVar4 + 0xe) = *(float *)(psVar4 + 0xe) * fVar1;
    *(float *)(psVar4 + 0x10) = *(float *)(psVar4 + 0x10) * fVar1;
    iStack_2c = iVar3;
    if ((*puVar7 & 0x8600) != 0) {
      local_88 = -*psVar4;
      local_86 = -psVar4[1];
      local_84 = -psVar4[2];
      local_80 = fVar2;
      local_7c = -*(float *)(psVar4 + 0xc);
      local_78 = -*(float *)(psVar4 + 0xe);
      local_74 = -*(float *)(psVar4 + 0x10);
      FUN_80021c64(afStack_70,(int)&local_88);
      pfVar12 = local_b8;
      pfVar10 = local_a8;
      pfVar11 = local_98;
      puVar5 = puVar7;
      for (sVar9 = 0; sVar9 < iVar3; sVar9 = sVar9 + 1) {
        FUN_80022790((double)(float)puVar5[2],(double)(float)puVar5[3],(double)(float)puVar5[4],
                     afStack_70,pfVar11,pfVar10,pfVar12);
        puVar5 = puVar5 + 3;
        pfVar12 = pfVar12 + 1;
        pfVar10 = pfVar10 + 1;
        pfVar11 = pfVar11 + 1;
      }
      if ((*puVar7 & 0x8000) != 0) {
        iVar6 = FUN_80021884();
        *psVar4 = *psVar4 + ((short)((short)iVar6 + -0x8000) >> 2);
      }
      if ((*puVar7 & 0x200) != 0) {
        iVar6 = FUN_80021884();
        *(short *)(puVar7 + 0x66) = -(short)iVar6;
      }
      if ((iVar3 == 4) && ((*puVar7 & 0x400) != 0)) {
        iVar3 = FUN_80021884();
        *(short *)((int)puVar7 + 0x19a) = (short)iVar3;
      }
    }
  }
  else {
    *(uint *)(psVar4 + 0xc) = puVar7[2];
    *(uint *)(psVar4 + 0xe) = puVar7[3];
    *(uint *)(psVar4 + 0x10) = puVar7[4];
  }
  FUN_80286880();
  return;
}

