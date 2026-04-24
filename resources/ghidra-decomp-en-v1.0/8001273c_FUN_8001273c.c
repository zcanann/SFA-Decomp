// Function: FUN_8001273c
// Entry: 8001273c
// Size: 268 bytes

void FUN_8001273c(void)

{
  short sVar1;
  bool bVar2;
  int *piVar3;
  int iVar4;
  short *psVar5;
  int iVar6;
  undefined4 uVar7;
  uint uVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_802860dc();
  piVar3 = (int *)((ulonglong)uVar9 >> 0x20);
  bVar2 = false;
  uVar7 = 0;
  for (iVar6 = (int)uVar9; (!bVar2 && (iVar6 != 0)); iVar6 = iVar6 + -1) {
    iVar4 = piVar3[1];
    if (*(short *)((int)piVar3 + 0x1e) == 0) {
      uVar8 = 0xffffffff;
    }
    else {
      uVar8 = (uint)*(ushort *)(iVar4 + 6);
      *(undefined2 *)(iVar4 + 4) = *(undefined2 *)(iVar4 + *(short *)((int)piVar3 + 0x1e) * 4);
      sVar1 = *(short *)((int)piVar3 + 0x1e);
      *(short *)((int)piVar3 + 0x1e) = sVar1 + -1;
      *(undefined2 *)(iVar4 + 6) = *(undefined2 *)(iVar4 + sVar1 * 4 + 2);
      FUN_80010f6c(iVar4,(int)*(short *)((int)piVar3 + 0x1e),1);
    }
    if ((int)uVar8 < 0) {
      bVar2 = true;
      uVar7 = 0xffffffff;
    }
    else {
      psVar5 = (short *)(*piVar3 + uVar8 * 0xe);
      piVar3[6] = uVar8;
      if ((*psVar5 == *(short *)(piVar3 + 3)) && (psVar5[2] == *(short *)(piVar3 + 4))) {
        bVar2 = true;
        uVar7 = 1;
      }
      else {
        *(undefined *)(psVar5 + 6) = 1;
        FUN_800118ec(piVar3,psVar5,uVar8);
      }
    }
  }
  FUN_80286128(uVar7);
  return;
}

