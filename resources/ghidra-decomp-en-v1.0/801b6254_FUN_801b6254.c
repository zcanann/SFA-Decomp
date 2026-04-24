// Function: FUN_801b6254
// Entry: 801b6254
// Size: 408 bytes

void FUN_801b6254(void)

{
  float fVar1;
  double dVar2;
  undefined2 *puVar3;
  int *piVar4;
  int iVar5;
  float *pfVar6;
  bool bVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  float *pfVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_802860dc();
  puVar3 = (undefined2 *)((ulonglong)uVar12 >> 0x20);
  *puVar3 = (short)((int)*(char *)((int)uVar12 + 0x18) << 8);
  *(code **)(puVar3 + 0x5e) = FUN_801b602c;
  pfVar11 = *(float **)(puVar3 + 0x5c);
  uVar10 = 0;
  piVar4 = (int *)FUN_8002b588();
  iVar8 = *piVar4;
  for (iVar9 = 0; dVar2 = DOUBLE_803e4a10, iVar9 < (int)(uint)*(ushort *)(iVar8 + 0xe4);
      iVar9 = iVar9 + 1) {
    iVar5 = FUN_800284a4(piVar4,iVar9);
    if ((int)*(short *)(iVar5 + 4) < (int)uVar10) {
      uVar10 = (int)*(short *)(iVar5 + 4);
    }
  }
  bVar7 = false;
  while (!bVar7) {
    bVar7 = true;
    pfVar6 = pfVar11;
    for (iVar8 = 0; iVar8 < (int)(*(byte *)((int)pfVar11 + 0x4f) - 1); iVar8 = iVar8 + 1) {
      fVar1 = pfVar6[1];
      if (fVar1 < pfVar6[2]) {
        pfVar6[1] = pfVar6[2];
        pfVar6[2] = (float)((double)CONCAT44(0x43300000,(int)fVar1 ^ 0x80000000) - dVar2);
        bVar7 = false;
      }
      pfVar6 = pfVar6 + 1;
    }
  }
  *(undefined *)((int)pfVar11 + 0x4f) = 10;
  *pfVar11 = (float)((double)CONCAT44(0x43300000,uVar10 ^ 0x80000000) - DOUBLE_803e4a10);
  iVar8 = FUN_8001ffb4(0x1e9);
  if (iVar8 != 0) {
    *(undefined *)((int)pfVar11 + 0x5f) = 1;
  }
  if (*(char *)((int)pfVar11 + 0x5f) != '\0') {
    for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)((int)pfVar11 + 0x4f); iVar8 = iVar8 + 1) {
      *(undefined *)((int)pfVar11 + iVar8 + 0x50) = 0xff;
      *(undefined *)((int)pfVar11 + iVar8 + 0x40) = 1;
      FUN_80065574(0x11,0,0);
    }
  }
  FUN_80286128();
  return;
}

