// Function: FUN_80286608
// Entry: 80286608
// Size: 200 bytes

int * FUN_80286608(char *param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  char *pcVar3;
  int *piVar4;
  uint uVar5;
  char cVar6;
  int iVar7;
  char cVar8;
  int iVar9;
  int iVar10;
  
  cVar6 = *param_1;
  iVar1 = 8;
  iVar7 = 4;
  cVar8 = '\x01';
  uVar2 = 0;
  iVar9 = 0;
  iVar10 = 4;
  pcVar3 = param_1;
  if (param_2 == 3) {
    cVar6 = param_1[1];
    pcVar3 = param_1 + 1;
    iVar7 = 8;
    iVar9 = 0x20;
    iVar10 = 8;
  }
  uVar5 = (uint)cVar6;
  if (param_2 == 2) {
    iVar7 = 8;
    iVar1 = 7;
    uVar2 = (uint)((uVar5 & 1) != 0);
    cVar8 = '\x02';
  }
  if ((int)uVar5 < iVar1) {
    iVar1 = *(int *)(param_1 + 8);
    *pcVar3 = (char)(uVar5 + uVar2) + cVar8;
    piVar4 = (int *)(iVar1 + iVar9 + (uVar5 + uVar2) * iVar10);
  }
  else {
    *pcVar3 = '\b';
    piVar4 = (int *)(~(iVar7 - 1U) & (iVar7 + *(int *)(param_1 + 4)) - 1U);
    *(int *)(param_1 + 4) = (int)piVar4 + iVar7;
  }
  if (param_2 == 0) {
    piVar4 = (int *)*piVar4;
  }
  return piVar4;
}

