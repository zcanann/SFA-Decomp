// Function: FUN_8004b218
// Entry: 8004b218
// Size: 260 bytes

void FUN_8004b218(void)

{
  short sVar1;
  bool bVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  int iVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_802860d8();
  piVar3 = (int *)((ulonglong)uVar9 >> 0x20);
  bVar2 = false;
  uVar6 = 0;
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
      FUN_8004aad4(iVar4,(int)*(short *)((int)piVar3 + 0x22),1);
    }
    if ((int)uVar7 < 0) {
      bVar2 = true;
      uVar6 = 0xffffffff;
    }
    else {
      iVar5 = *piVar3 + uVar7 * 0x10;
      piVar3[7] = uVar7;
      iVar4 = FUN_8004aa24(piVar3,iVar5);
      if (iVar4 == 0) {
        *(undefined *)(iVar5 + 0xe) = 1;
        FUN_8004afa0(piVar3,iVar5,uVar7);
      }
      else {
        bVar2 = true;
        uVar6 = 1;
      }
    }
  }
  FUN_80286124(uVar6);
  return;
}

