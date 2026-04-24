// Function: FUN_8022a084
// Entry: 8022a084
// Size: 524 bytes

void FUN_8022a084(void)

{
  float fVar1;
  double dVar2;
  undefined2 *puVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  bool bVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  float *pfVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_802860d4();
  puVar3 = (undefined2 *)((ulonglong)uVar13 >> 0x20);
  iVar6 = (int)uVar13;
  *puVar3 = (short)((int)*(char *)(iVar6 + 0x18) << 8);
  *(undefined *)((int)puVar3 + 0xad) = *(undefined *)(iVar6 + 0x19);
  if (*(char *)(*(int *)(puVar3 + 0x28) + 0x55) <= *(char *)((int)puVar3 + 0xad)) {
    *(undefined *)((int)puVar3 + 0xad) = 0;
  }
  *(code **)(puVar3 + 0x5e) = FUN_80229aac;
  pfVar12 = *(float **)(puVar3 + 0x5c);
  uVar10 = 0;
  piVar4 = (int *)FUN_8002b588(puVar3);
  iVar9 = *piVar4;
  for (iVar11 = 0; dVar2 = DOUBLE_803e6e80, iVar11 < (int)(uint)*(ushort *)(iVar9 + 0xe4);
      iVar11 = iVar11 + 1) {
    iVar5 = FUN_800284a4(piVar4,iVar11);
    if ((int)*(short *)(iVar5 + 4) < (int)uVar10) {
      uVar10 = (int)*(short *)(iVar5 + 4);
    }
  }
  bVar8 = false;
  while (!bVar8) {
    bVar8 = true;
    pfVar7 = pfVar12;
    for (iVar9 = 0; iVar9 < (int)(*(byte *)((int)pfVar12 + 0x4f) - 1); iVar9 = iVar9 + 1) {
      fVar1 = pfVar7[1];
      if (fVar1 < pfVar7[2]) {
        pfVar7[1] = pfVar7[2];
        pfVar7[2] = (float)((double)CONCAT44(0x43300000,(int)fVar1 ^ 0x80000000) - dVar2);
        bVar8 = false;
      }
      pfVar7 = pfVar7 + 1;
    }
  }
  *(undefined *)((int)pfVar12 + 0x4f) = 10;
  *pfVar12 = (float)((double)CONCAT44(0x43300000,uVar10 ^ 0x80000000) - DOUBLE_803e6e80);
  iVar6 = FUN_8001ffb4((int)*(short *)(iVar6 + 0x1e));
  if (iVar6 != 0) {
    *(undefined *)((int)pfVar12 + 0x5f) = 1;
    *(byte *)((int)pfVar12 + 0x66) = *(byte *)((int)pfVar12 + 0x66) | 1;
  }
  if (*(char *)((int)pfVar12 + 0x5f) == '\0') {
    FUN_80035f00(puVar3);
    *(undefined *)(puVar3 + 0x1b) = 0;
  }
  else {
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)((int)pfVar12 + 0x4f); iVar6 = iVar6 + 1) {
      *(undefined *)((int)pfVar12 + iVar6 + 0x50) = 0xff;
      *(undefined *)((int)pfVar12 + iVar6 + 0x40) = 1;
    }
    *(undefined *)(puVar3 + 0x1b) = 0xff;
  }
  puVar3[0x58] = puVar3[0x58] | 0x6000;
  FUN_8002852c(piVar4,FUN_800284cc);
  FUN_80286120();
  return;
}

