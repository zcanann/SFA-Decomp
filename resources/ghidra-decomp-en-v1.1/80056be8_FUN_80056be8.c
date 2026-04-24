// Function: FUN_80056be8
// Entry: 80056be8
// Size: 288 bytes

void FUN_80056be8(uint param_1,int param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  iVar1 = 0;
  iVar3 = 0x10;
  do {
    piVar2 = (int *)(DAT_803ddaec + iVar1);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    piVar2 = (int *)(DAT_803ddaec + iVar1 + 0x10);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    piVar2 = (int *)(DAT_803ddaec + iVar1 + 0x20);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    piVar2 = (int *)(DAT_803ddaec + iVar1 + 0x30);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    piVar2 = (int *)(DAT_803ddaec + iVar1 + 0x40);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    iVar1 = iVar1 + 0x50;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  return;
}

