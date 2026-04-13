// Function: FUN_80022f48
// Entry: 80022f48
// Size: 388 bytes

void FUN_80022f48(undefined4 param_1,undefined4 param_2,int param_3,undefined2 param_4,
                 undefined2 param_5,undefined4 param_6)

{
  short sVar1;
  short sVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined8 uVar11;
  
  uVar11 = FUN_80286838();
  iVar5 = (int)((ulonglong)uVar11 >> 0x20);
  for (; uVar3 = param_3 >> 0x1f, (uVar3 * 0x20 | param_3 * 0x8000000 + uVar3 >> 0x1b) != uVar3;
      param_3 = param_3 + 1) {
  }
  iVar9 = (&DAT_80341308)[iVar5 * 5];
  iVar10 = (int)uVar11 * 0x1c;
  iVar6 = iVar9 + iVar10;
  *(undefined2 *)(iVar6 + 8) = param_4;
  iVar8 = *(int *)(iVar6 + 4);
  *(int *)(iVar6 + 4) = param_3;
  *(undefined4 *)(iVar6 + 0x10) = param_6;
  if (param_3 < iVar8) {
    iVar4 = (&DAT_80341304)[iVar5 * 5];
    (&DAT_80341304)[iVar5 * 5] = iVar4 + 1;
    sVar1 = *(short *)(iVar9 + iVar4 * 0x1c + 0xe);
    *(undefined2 *)(iVar6 + 8) = param_5;
    while( true ) {
      iVar5 = iVar8 - param_3;
      uVar3 = iVar5 >> 0x1f;
      if ((uVar3 * 0x20 | iVar5 * 0x8000000 + uVar3 >> 0x1b) == uVar3) break;
      param_3 = param_3 + 1;
    }
    *(int *)(iVar6 + 4) = iVar5;
    piVar7 = (int *)(iVar9 + sVar1 * 0x1c);
    *(undefined2 *)(piVar7 + 2) = param_4;
    *piVar7 = (*(int *)(iVar9 + iVar10) + iVar8) - param_3;
    uVar3 = *piVar7 >> 0x1f;
    if ((uVar3 * 0x20 | *piVar7 * 0x8000000 + uVar3 >> 0x1b) != uVar3) {
      FUN_8007d858();
    }
    iVar5 = iVar9 + sVar1 * 0x1c;
    *(int *)(iVar5 + 4) = param_3;
    *(undefined4 *)(iVar5 + 0x10) = param_6;
    *(undefined4 *)(iVar5 + 0x14) = DAT_803dd79c;
    sVar2 = *(short *)(iVar9 + iVar10 + 0xc);
    *(short *)(iVar5 + 0xc) = sVar2;
    *(short *)(iVar5 + 10) = (short)uVar11;
    *(short *)(iVar9 + iVar10 + 0xc) = sVar1;
    if (sVar2 != -1) {
      *(short *)(iVar9 + sVar2 * 0x1c + 10) = sVar1;
    }
  }
  FUN_80286884();
  return;
}

