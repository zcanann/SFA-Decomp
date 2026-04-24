// Function: FUN_80134754
// Entry: 80134754
// Size: 292 bytes

void FUN_80134754(undefined4 param_1,undefined4 param_2,short *param_3,int param_4,int *param_5)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  uint uVar6;
  uint uVar7;
  short *psVar8;
  uint uVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286830();
  uVar9 = 0;
  iVar3 = 0;
  psVar8 = param_3;
  for (iVar4 = 0; iVar4 < param_4; iVar4 = iVar4 + 1) {
    uVar1 = FUN_80020078((int)*psVar8);
    if (uVar1 != 0) {
      iVar3 = iVar3 + 1;
    }
    psVar8 = psVar8 + 2;
  }
  iVar3 = ((param_4 - iVar3) * 0x2a) / 2 + 0x52;
  cVar5 = '\0';
  for (iVar4 = 0; uVar7 = (uint)((ulonglong)uVar10 >> 0x20), uVar1 = (uint)uVar10, iVar4 < param_4;
      iVar4 = iVar4 + 1) {
    uVar2 = FUN_80020078((int)*param_3);
    uVar6 = uVar1;
    if (uVar2 != 0) {
      FUN_80003494(uVar1,uVar7,0x3c);
      *(short *)(uVar1 + 6) = (short)iVar3;
      *(char *)(uVar1 + 0x1a) = cVar5 + -1;
      *(char *)(uVar1 + 0x1b) = cVar5 + '\x01';
      *param_5 = iVar4;
      param_5 = param_5 + 1;
      uVar6 = uVar1 + 0x3c;
      iVar3 = iVar3 + 0x2a;
      cVar5 = cVar5 + '\x01';
      uVar9 = uVar1;
    }
    param_3 = param_3 + 2;
    uVar10 = CONCAT44(uVar7 + 0x3c,uVar6);
  }
  if (uVar9 != 0) {
    *(undefined *)(uVar9 + 0x1b) = 0xff;
  }
  FUN_8028687c();
  return;
}

