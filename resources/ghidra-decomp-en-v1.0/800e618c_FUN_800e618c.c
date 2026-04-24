// Function: FUN_800e618c
// Entry: 800e618c
// Size: 872 bytes

void FUN_800e618c(void)

{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  uint uVar4;
  uint *puVar5;
  uint *puVar6;
  float *pfVar7;
  undefined4 uVar8;
  int iVar9;
  int iVar10;
  uint uVar11;
  uint uVar12;
  undefined8 uVar13;
  undefined auStack144 [4];
  undefined auStack140 [4];
  undefined2 local_88;
  undefined2 local_86;
  undefined2 local_84;
  float local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined auStack112 [64];
  undefined4 local_30;
  uint uStack44;
  
  uVar13 = FUN_802860d4();
  puVar2 = (undefined2 *)((ulonglong)uVar13 >> 0x20);
  puVar5 = (uint *)uVar13;
  uVar11 = *(byte *)(puVar5 + 0x97) & 0xf;
  iVar10 = 0;
  *(undefined *)((int)puVar5 + 0x25e) = 0;
  puVar6 = puVar5;
  for (iVar9 = 0; fVar1 = FLOAT_803e0668, iVar9 < (int)uVar11; iVar9 = iVar9 + 1) {
    if ((*puVar5 & 0x200000) == 0) {
      uVar8 = 4;
    }
    else {
      uVar8 = 2;
    }
    iVar3 = FUN_800640cc((double)*(float *)(puVar5[0x38] + iVar10),puVar6 + 0x45,puVar6 + 0x39,uVar8
                         ,puVar5 + 0x51,puVar2,*(undefined *)((int)puVar5 + 0x25d),0xffffffff,0,
                         (int)*(char *)(puVar5 + 0x99));
    *(byte *)((int)puVar5 + 0x25e) = *(byte *)((int)puVar5 + 0x25e) | (byte)(iVar3 << iVar9);
    if ((*puVar5 & 0x2000000) != 0) {
      if ((*puVar5 & 0x200000) == 0) {
        uVar8 = 4;
      }
      else {
        uVar8 = 2;
      }
      FUN_800640cc((double)*(float *)(puVar5[0x38] + iVar10),puVar6 + 0x45,puVar6 + 0x39,uVar8,
                   puVar5 + 0x51,puVar2,*(undefined *)((int)puVar5 + 0x263),0xffffffff,0,
                   (int)*(char *)(puVar5 + 0x99));
    }
    iVar10 = iVar10 + 4;
    puVar6 = puVar6 + 3;
  }
  if (uVar11 < 2) {
    if ((*puVar5 & 0x100000) == 0) {
      *(uint *)(puVar2 + 6) = puVar5[0x39];
      *(uint *)(puVar2 + 10) = puVar5[0x3b];
    }
    goto LAB_800e640c;
  }
  if ((*puVar5 & 0x100000) != 0) goto LAB_800e640c;
  *(float *)(puVar2 + 6) = FLOAT_803e0668;
  *(float *)(puVar2 + 10) = fVar1;
  uVar4 = (uVar11 * 3 + 2) / 3;
  if (uVar11 * 3 != 0) {
    uVar12 = uVar4 >> 2;
    puVar6 = puVar5;
    if (uVar12 != 0) {
      do {
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar6[0x39];
        *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar6[0x3b];
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar6[0x3c];
        *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar6[0x3e];
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar6[0x3f];
        *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar6[0x41];
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar6[0x42];
        *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar6[0x44];
        puVar6 = puVar6 + 0xc;
        uVar12 = uVar12 - 1;
      } while (uVar12 != 0);
      uVar4 = uVar4 & 3;
      if (uVar4 == 0) goto LAB_800e63ac;
    }
    do {
      *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar6[0x39];
      *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar6[0x3b];
      uVar4 = uVar4 - 1;
      puVar6 = puVar6 + 3;
    } while (uVar4 != 0);
  }
LAB_800e63ac:
  local_30 = 0x43300000;
  fVar1 = FLOAT_803e068c / (float)((double)CONCAT44(0x43300000,uVar11) - DOUBLE_803e0698);
  *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) * fVar1;
  *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) * fVar1;
  uStack44 = uVar11;
LAB_800e640c:
  local_88 = *puVar2;
  if ((*puVar5 & 0x20) == 0) {
    local_86 = puVar2[1];
    local_84 = puVar2[2];
  }
  else {
    local_86 = 0;
    local_84 = 0;
  }
  local_80 = FLOAT_803e068c;
  local_7c = *(undefined4 *)(puVar2 + 6);
  local_78 = *(undefined4 *)(puVar2 + 8);
  local_74 = *(undefined4 *)(puVar2 + 10);
  FUN_80021ee8(auStack112,&local_88);
  iVar9 = 0;
  puVar6 = puVar5;
  for (iVar10 = 0; iVar10 < (int)(uVar11 * 3); iVar10 = iVar10 + 3) {
    puVar6[0x45] = puVar6[0x39];
    puVar6[0x47] = puVar6[0x3b];
    pfVar7 = (float *)(puVar5[0x37] + iVar9);
    FUN_800226cc((double)*pfVar7,(double)pfVar7[1],(double)pfVar7[2],auStack112,auStack140,
                 puVar5 + iVar10 + 0x46,auStack144);
    puVar6 = puVar6 + 3;
    iVar9 = iVar9 + 0xc;
  }
  FUN_80286120();
  return;
}

