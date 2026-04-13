// Function: FUN_80037e6c
// Entry: 80037e6c
// Size: 208 bytes

void FUN_80037e6c(void)

{
  bool bVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_8028683c();
  iVar3 = (int)((ulonglong)uVar8 >> 0x20);
  iVar4 = (int)uVar8;
  uVar7 = (uint)*(byte *)(iVar3 + 0xe9);
  uVar6 = (uint)*(byte *)(iVar4 + 0xe9);
  piVar2 = &DAT_803439b0;
  iVar5 = DAT_803dd878;
  while (((uVar7 != 0 && (uVar6 != 0)) && (bVar1 = iVar5 != 0, iVar5 = iVar5 + -1, bVar1))) {
    if ((*piVar2 == iVar3) && (piVar2[1] == iVar4)) {
      uVar7 = uVar7 - 1;
      (*(code *)piVar2[2])(iVar3,iVar4);
    }
    if ((*piVar2 == iVar4) && (piVar2[1] == iVar3)) {
      uVar6 = uVar6 - 1;
      (*(code *)piVar2[2])(iVar4,iVar3);
    }
    piVar2 = piVar2 + 3;
  }
  FUN_80286888();
  return;
}

