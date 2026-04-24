// Function: FUN_801343cc
// Entry: 801343cc
// Size: 292 bytes

void FUN_801343cc(undefined4 param_1,undefined4 param_2,short *param_3,int param_4,int *param_5)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  short *psVar8;
  int iVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_802860cc();
  iVar9 = 0;
  iVar2 = 0;
  psVar8 = param_3;
  for (iVar3 = 0; iVar3 < param_4; iVar3 = iVar3 + 1) {
    iVar4 = FUN_8001ffb4((int)*psVar8);
    if (iVar4 != 0) {
      iVar2 = iVar2 + 1;
    }
    psVar8 = psVar8 + 2;
  }
  iVar2 = ((param_4 - iVar2) * 0x2a) / 2 + 0x52;
  iVar4 = 0;
  for (iVar3 = 0; iVar7 = (int)((ulonglong)uVar10 >> 0x20), iVar6 = (int)uVar10, iVar3 < param_4;
      iVar3 = iVar3 + 1) {
    iVar1 = FUN_8001ffb4((int)*param_3);
    iVar5 = iVar6;
    if (iVar1 != 0) {
      FUN_80003494(iVar6,iVar7,0x3c);
      *(short *)(iVar6 + 6) = (short)iVar2;
      *(char *)(iVar6 + 0x1a) = (char)iVar4 + -1;
      *(char *)(iVar6 + 0x1b) = (char)iVar4 + '\x01';
      *param_5 = iVar3;
      param_5 = param_5 + 1;
      iVar5 = iVar6 + 0x3c;
      iVar2 = iVar2 + 0x2a;
      iVar4 = iVar4 + 1;
      iVar9 = iVar6;
    }
    param_3 = param_3 + 2;
    uVar10 = CONCAT44(iVar7 + 0x3c,iVar5);
  }
  if (iVar9 != 0) {
    *(undefined *)(iVar9 + 0x1b) = 0xff;
  }
  FUN_80286118(iVar4);
  return;
}

