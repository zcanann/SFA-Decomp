// Function: FUN_801d4cd0
// Entry: 801d4cd0
// Size: 432 bytes

void FUN_801d4cd0(void)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  undefined4 uVar7;
  int iVar8;
  char cVar9;
  double dVar10;
  int local_28 [10];
  
  iVar1 = FUN_802860d0();
  uVar7 = 0;
  cVar9 = -1;
  cVar6 = '\0';
  iVar2 = *(int *)(*(int *)(iVar1 + 0x4c) + 0x14);
  if (iVar2 == DAT_80326e98) {
    cVar9 = '\0';
  }
  else if (iVar2 == DAT_80326ea8) {
    cVar9 = '\x01';
  }
  else if (iVar2 == DAT_80326eb8) {
    cVar9 = '\x02';
  }
  else if (iVar2 == DAT_80326ec8) {
    cVar9 = '\x03';
  }
  else if (iVar2 == DAT_80326ed8) {
    cVar9 = '\x04';
  }
  else if (iVar2 == DAT_80326ee8) {
    cVar9 = '\x05';
  }
  piVar3 = (int *)FUN_80036f50(3,local_28);
  iVar2 = (int)cVar9;
  for (iVar8 = 0; iVar8 < local_28[0]; iVar8 = iVar8 + 1) {
    iVar4 = *piVar3;
    if ((*(short *)(iVar4 + 0x46) == 0x4d7) &&
       (((iVar5 = *(int *)(*(int *)(iVar4 + 0x4c) + 0x14), iVar5 == (&DAT_80326e9c)[iVar2 * 4] ||
         (iVar5 == (&DAT_80326ea0)[iVar2 * 4])) || (iVar5 == (&DAT_80326ea4)[iVar2 * 4])))) {
      FUN_8014c66c(iVar4,iVar1);
      dVar10 = (double)FUN_800216d0(*piVar3 + 0x18,iVar1 + 0x18);
      if ((dVar10 < (double)FLOAT_803e5414) &&
         (iVar4 = FUN_8001ffb4((int)*(short *)(*(int *)(*piVar3 + 0x4c) + 0x18)), iVar4 == 0)) {
        uVar7 = 1;
      }
      cVar6 = cVar6 + '\x01';
      if (cVar6 == '\x03') break;
    }
    piVar3 = piVar3 + 1;
  }
  FUN_8028611c(uVar7);
  return;
}

