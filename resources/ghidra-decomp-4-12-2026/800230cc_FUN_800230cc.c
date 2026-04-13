// Function: FUN_800230cc
// Entry: 800230cc
// Size: 300 bytes

void FUN_800230cc(undefined4 param_1,undefined4 param_2,int param_3,undefined2 param_4,
                 undefined2 param_5,undefined4 param_6)

{
  short sVar1;
  short sVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286834();
  iVar5 = (int)((ulonglong)uVar10 >> 0x20);
  iVar7 = (&DAT_80341308)[iVar5 * 5];
  iVar9 = (int)uVar10 * 0x1c;
  iVar4 = iVar7 + iVar9;
  *(undefined2 *)(iVar4 + 8) = param_4;
  iVar8 = *(int *)(iVar4 + 4);
  *(int *)(iVar4 + 4) = param_3;
  *(undefined4 *)(iVar4 + 0x10) = param_6;
  if (param_3 < iVar8) {
    iVar4 = (&DAT_80341304)[iVar5 * 5];
    (&DAT_80341304)[iVar5 * 5] = iVar4 + 1;
    sVar1 = *(short *)(iVar7 + iVar4 * 0x1c + 0xe);
    piVar6 = (int *)(iVar7 + sVar1 * 0x1c);
    *piVar6 = *(int *)(iVar7 + iVar9) + param_3;
    iVar5 = *piVar6;
    uVar3 = iVar5 >> 0x1f;
    if ((uVar3 * 0x20 | iVar5 * 0x8000000 + uVar3 >> 0x1b) != uVar3) {
      FUN_8007d858();
    }
    iVar5 = iVar7 + sVar1 * 0x1c;
    *(int *)(iVar5 + 4) = iVar8 - param_3;
    *(undefined2 *)(iVar5 + 8) = param_5;
    sVar2 = *(short *)(iVar7 + iVar9 + 0xc);
    *(short *)(iVar5 + 0xc) = sVar2;
    *(short *)(iVar5 + 10) = (short)uVar10;
    *(short *)(iVar7 + iVar9 + 0xc) = sVar1;
    if (sVar2 != -1) {
      *(short *)(iVar7 + sVar2 * 0x1c + 10) = sVar1;
    }
    *(undefined4 *)(iVar7 + iVar9 + 0x14) = DAT_803dd79c;
  }
  FUN_80286880();
  return;
}

