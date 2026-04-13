// Function: FUN_801b6808
// Entry: 801b6808
// Size: 408 bytes

void FUN_801b6808(void)

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
  float *pfVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_80286840();
  puVar4 = (undefined2 *)((ulonglong)uVar12 >> 0x20);
  *puVar4 = (short)((int)*(char *)((int)uVar12 + 0x18) << 8);
  *(code **)(puVar4 + 0x5e) = FUN_801b65e0;
  pfVar11 = *(float **)(puVar4 + 0x5c);
  uVar10 = 0;
  piVar5 = (int *)FUN_8002b660((int)puVar4);
  iVar8 = *piVar5;
  for (iVar9 = 0; dVar3 = DOUBLE_803e56a8, iVar9 < (int)(uint)*(ushort *)(iVar8 + 0xe4);
      iVar9 = iVar9 + 1) {
    iVar6 = FUN_80028568((int)piVar5,iVar9);
    if ((int)*(short *)(iVar6 + 4) < (int)uVar10) {
      uVar10 = (int)*(short *)(iVar6 + 4);
    }
  }
  bVar2 = false;
  while (!bVar2) {
    bVar2 = true;
    pfVar7 = pfVar11;
    for (iVar8 = 0; iVar8 < (int)(*(byte *)((int)pfVar11 + 0x4f) - 1); iVar8 = iVar8 + 1) {
      fVar1 = pfVar7[1];
      if (fVar1 < pfVar7[2]) {
        pfVar7[1] = pfVar7[2];
        pfVar7[2] = (float)((double)CONCAT44(0x43300000,(int)fVar1 ^ 0x80000000) - dVar3);
        bVar2 = false;
      }
      pfVar7 = pfVar7 + 1;
    }
  }
  *(undefined *)((int)pfVar11 + 0x4f) = 10;
  *pfVar11 = (float)((double)CONCAT44(0x43300000,uVar10 ^ 0x80000000) - DOUBLE_803e56a8);
  uVar10 = FUN_80020078(0x1e9);
  if (uVar10 != 0) {
    *(undefined *)((int)pfVar11 + 0x5f) = 1;
  }
  if (*(char *)((int)pfVar11 + 0x5f) != '\0') {
    for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)((int)pfVar11 + 0x4f); iVar8 = iVar8 + 1) {
      *(undefined *)((int)pfVar11 + iVar8 + 0x50) = 0xff;
      *(undefined *)((int)pfVar11 + iVar8 + 0x40) = 1;
      FUN_800656f0(0x11,0,0);
    }
  }
  FUN_8028688c();
  return;
}

