// Function: FUN_8022a748
// Entry: 8022a748
// Size: 524 bytes

void FUN_8022a748(void)

{
  float fVar1;
  bool bVar2;
  double dVar3;
  undefined2 *puVar4;
  int *piVar5;
  int iVar6;
  float *pfVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  float *pfVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_80286838();
  puVar4 = (undefined2 *)((ulonglong)uVar13 >> 0x20);
  iVar8 = (int)uVar13;
  *puVar4 = (short)((int)*(char *)(iVar8 + 0x18) << 8);
  *(undefined *)((int)puVar4 + 0xad) = *(undefined *)(iVar8 + 0x19);
  if (*(char *)(*(int *)(puVar4 + 0x28) + 0x55) <= *(char *)((int)puVar4 + 0xad)) {
    *(undefined *)((int)puVar4 + 0xad) = 0;
  }
  *(code **)(puVar4 + 0x5e) = FUN_8022a170;
  pfVar12 = *(float **)(puVar4 + 0x5c);
  uVar10 = 0;
  piVar5 = (int *)FUN_8002b660((int)puVar4);
  iVar9 = *piVar5;
  for (iVar11 = 0; dVar3 = DOUBLE_803e7b18, iVar11 < (int)(uint)*(ushort *)(iVar9 + 0xe4);
      iVar11 = iVar11 + 1) {
    iVar6 = FUN_80028568((int)piVar5,iVar11);
    if ((int)*(short *)(iVar6 + 4) < (int)uVar10) {
      uVar10 = (int)*(short *)(iVar6 + 4);
    }
  }
  bVar2 = false;
  while (!bVar2) {
    bVar2 = true;
    pfVar7 = pfVar12;
    for (iVar9 = 0; iVar9 < (int)(*(byte *)((int)pfVar12 + 0x4f) - 1); iVar9 = iVar9 + 1) {
      fVar1 = pfVar7[1];
      if (fVar1 < pfVar7[2]) {
        pfVar7[1] = pfVar7[2];
        pfVar7[2] = (float)((double)CONCAT44(0x43300000,(int)fVar1 ^ 0x80000000) - dVar3);
        bVar2 = false;
      }
      pfVar7 = pfVar7 + 1;
    }
  }
  *(undefined *)((int)pfVar12 + 0x4f) = 10;
  *pfVar12 = (float)((double)CONCAT44(0x43300000,uVar10 ^ 0x80000000) - DOUBLE_803e7b18);
  uVar10 = FUN_80020078((int)*(short *)(iVar8 + 0x1e));
  if (uVar10 != 0) {
    *(undefined *)((int)pfVar12 + 0x5f) = 1;
    *(byte *)((int)pfVar12 + 0x66) = *(byte *)((int)pfVar12 + 0x66) | 1;
  }
  if (*(char *)((int)pfVar12 + 0x5f) == '\0') {
    FUN_80035ff8((int)puVar4);
    *(undefined *)(puVar4 + 0x1b) = 0;
  }
  else {
    for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)((int)pfVar12 + 0x4f); iVar8 = iVar8 + 1) {
      *(undefined *)((int)pfVar12 + iVar8 + 0x50) = 0xff;
      *(undefined *)((int)pfVar12 + iVar8 + 0x40) = 1;
    }
    *(undefined *)(puVar4 + 0x1b) = 0xff;
  }
  puVar4[0x58] = puVar4[0x58] | 0x6000;
  FUN_800285f0((int)piVar5,FUN_80028590);
  FUN_80286884();
  return;
}

