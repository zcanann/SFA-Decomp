// Function: FUN_8004b394
// Entry: 8004b394
// Size: 260 bytes

void FUN_8004b394(void)

{
  short sVar1;
  bool bVar2;
  int *piVar3;
  int iVar4;
  uint uVar5;
  int *piVar6;
  uint uVar7;
  int iVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_8028683c();
  piVar3 = (int *)((ulonglong)uVar9 >> 0x20);
  bVar2 = false;
  for (iVar8 = (int)uVar9; (!bVar2 && (iVar8 != 0)); iVar8 = iVar8 + -1) {
    iVar4 = piVar3[1];
    if (*(short *)((int)piVar3 + 0x22) == 0) {
      uVar7 = 0xffffffff;
    }
    else {
      uVar7 = (uint)*(ushort *)(iVar4 + 0xc);
      *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(iVar4 + *(short *)((int)piVar3 + 0x22) * 8);
      sVar1 = *(short *)((int)piVar3 + 0x22);
      *(short *)((int)piVar3 + 0x22) = sVar1 + -1;
      *(undefined2 *)(iVar4 + 0xc) = *(undefined2 *)(iVar4 + sVar1 * 8 + 4);
      FUN_8004ac50(iVar4,(int)*(short *)((int)piVar3 + 0x22),1);
    }
    if ((int)uVar7 < 0) {
      bVar2 = true;
    }
    else {
      piVar6 = (int *)(*piVar3 + uVar7 * 0x10);
      piVar3[7] = uVar7;
      uVar5 = FUN_8004aba0(piVar3,piVar6);
      if (uVar5 == 0) {
        *(undefined *)((int)piVar6 + 0xe) = 1;
        FUN_8004b11c(piVar3,piVar6,(char)uVar7);
      }
      else {
        bVar2 = true;
      }
    }
  }
  FUN_80286888();
  return;
}

