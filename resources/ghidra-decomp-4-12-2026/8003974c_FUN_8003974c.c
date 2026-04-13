// Function: FUN_8003974c
// Entry: 8003974c
// Size: 480 bytes

void FUN_8003974c(int param_1,int param_2)

{
  bool bVar1;
  short sVar2;
  undefined2 uVar3;
  uint uVar4;
  char *pcVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  
  iVar9 = 0;
  iVar7 = *(int *)(param_1 + 0x50);
  if ((iVar7 != 0) && (pcVar5 = *(char **)(iVar7 + 0xc), pcVar5 != (char *)0x0)) {
    iVar8 = 0;
    for (uVar4 = (uint)*(byte *)(iVar7 + 0x59); uVar4 != 0; uVar4 = uVar4 - 1) {
      if (*pcVar5 == '\x01') {
        iVar9 = *(int *)(param_1 + 0x70) + iVar8;
      }
      pcVar5 = pcVar5 + 2;
      iVar8 = iVar8 + 0x10;
    }
  }
  iVar8 = 0;
  if ((iVar7 != 0) && (pcVar5 = *(char **)(iVar7 + 0xc), pcVar5 != (char *)0x0)) {
    iVar6 = 0;
    for (uVar4 = (uint)*(byte *)(iVar7 + 0x59); uVar4 != 0; uVar4 = uVar4 - 1) {
      if (*pcVar5 == '\0') {
        iVar8 = *(int *)(param_1 + 0x70) + iVar6;
      }
      pcVar5 = pcVar5 + 2;
      iVar6 = iVar6 + 0x10;
    }
  }
  if ((iVar9 != 0) && (iVar8 != 0)) {
    sVar2 = *(short *)(param_2 + 0x22);
    bVar1 = sVar2 == 0;
    if ((0 < sVar2) && (*(int *)(param_2 + 0x24) <= (int)*(short *)(iVar9 + 8))) {
      bVar1 = true;
    }
    if ((sVar2 < 0) && ((int)*(short *)(iVar9 + 8) <= *(int *)(param_2 + 0x24))) {
      bVar1 = true;
    }
    if (bVar1) {
      uVar4 = FUN_80022264(0xfffffc18,1000);
      *(uint *)(param_2 + 0x24) = uVar4;
      if (*(int *)(param_2 + 0x24) < (int)*(short *)(iVar9 + 8)) {
        uVar3 = 0xff6a;
      }
      else {
        uVar3 = 0x96;
      }
      *(undefined2 *)(param_2 + 0x22) = uVar3;
      uVar4 = FUN_80022264(0x1e,100);
      *(char *)(param_2 + 0x20) = (char)uVar4;
    }
    if (*(char *)(param_2 + 0x20) < '\x01') {
      *(ushort *)(iVar9 + 8) =
           *(short *)(iVar9 + 8) + *(short *)(param_2 + 0x22) * (ushort)DAT_803dc070;
      *(undefined2 *)(iVar9 + 10) = 0;
      *(undefined2 *)(iVar8 + 8) = *(undefined2 *)(iVar9 + 8);
      *(undefined2 *)(iVar8 + 10) = 0;
    }
    else {
      *(byte *)(param_2 + 0x20) = *(char *)(param_2 + 0x20) - DAT_803dc070;
    }
  }
  return;
}

