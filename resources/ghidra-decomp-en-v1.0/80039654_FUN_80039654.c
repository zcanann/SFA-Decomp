// Function: FUN_80039654
// Entry: 80039654
// Size: 480 bytes

void FUN_80039654(int param_1,int param_2)

{
  bool bVar1;
  short sVar2;
  uint uVar3;
  undefined2 uVar4;
  undefined4 uVar5;
  undefined uVar6;
  char *pcVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  
  iVar11 = 0;
  iVar9 = *(int *)(param_1 + 0x50);
  if ((iVar9 != 0) && (pcVar7 = *(char **)(iVar9 + 0xc), pcVar7 != (char *)0x0)) {
    iVar10 = 0;
    for (uVar3 = (uint)*(byte *)(iVar9 + 0x59); uVar3 != 0; uVar3 = uVar3 - 1) {
      if (*pcVar7 == '\x01') {
        iVar11 = *(int *)(param_1 + 0x70) + iVar10;
      }
      pcVar7 = pcVar7 + 2;
      iVar10 = iVar10 + 0x10;
    }
  }
  iVar10 = 0;
  if ((iVar9 != 0) && (pcVar7 = *(char **)(iVar9 + 0xc), pcVar7 != (char *)0x0)) {
    iVar8 = 0;
    for (uVar3 = (uint)*(byte *)(iVar9 + 0x59); uVar3 != 0; uVar3 = uVar3 - 1) {
      if (*pcVar7 == '\0') {
        iVar10 = *(int *)(param_1 + 0x70) + iVar8;
      }
      pcVar7 = pcVar7 + 2;
      iVar8 = iVar8 + 0x10;
    }
  }
  if ((iVar11 != 0) && (iVar10 != 0)) {
    sVar2 = *(short *)(param_2 + 0x22);
    bVar1 = sVar2 == 0;
    if ((0 < sVar2) && (*(int *)(param_2 + 0x24) <= (int)*(short *)(iVar11 + 8))) {
      bVar1 = true;
    }
    if ((sVar2 < 0) && ((int)*(short *)(iVar11 + 8) <= *(int *)(param_2 + 0x24))) {
      bVar1 = true;
    }
    if (bVar1) {
      uVar5 = FUN_800221a0(0xfffffc18,1000);
      *(undefined4 *)(param_2 + 0x24) = uVar5;
      if (*(int *)(param_2 + 0x24) < (int)*(short *)(iVar11 + 8)) {
        uVar4 = 0xff6a;
      }
      else {
        uVar4 = 0x96;
      }
      *(undefined2 *)(param_2 + 0x22) = uVar4;
      uVar6 = FUN_800221a0(0x1e,100);
      *(undefined *)(param_2 + 0x20) = uVar6;
    }
    if (*(char *)(param_2 + 0x20) < '\x01') {
      *(ushort *)(iVar11 + 8) =
           *(short *)(iVar11 + 8) + *(short *)(param_2 + 0x22) * (ushort)DAT_803db410;
      *(undefined2 *)(iVar11 + 10) = 0;
      *(undefined2 *)(iVar10 + 8) = *(undefined2 *)(iVar11 + 8);
      *(undefined2 *)(iVar10 + 10) = 0;
    }
    else {
      *(byte *)(param_2 + 0x20) = *(char *)(param_2 + 0x20) - DAT_803db410;
    }
  }
  return;
}

