// Function: FUN_8004aa24
// Entry: 8004aa24
// Size: 176 bytes

uint FUN_8004aa24(int *param_1,int *param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar4 = param_1[4];
  iVar3 = *param_2;
  if (*(char *)(iVar3 + 0x19) != '$') {
    uVar1 = countLeadingZeros(iVar3 - iVar4);
    return uVar1 >> 5;
  }
  if ((*(byte *)(param_2 + 3) & 0x80) == 0) {
    if (*(byte *)(iVar3 + 3) != 0) {
      uVar1 = countLeadingZeros((uint)*(byte *)(iVar3 + 3) - iVar4);
      return uVar1 >> 5;
    }
    iVar5 = *(int *)(*param_1 + (uint)*(byte *)(param_2 + 3) * 0x10);
    iVar6 = 0;
    iVar7 = 4;
    iVar2 = iVar5;
    do {
      if (*(int *)(iVar3 + 0x14) == *(int *)(iVar2 + 0x1c)) {
        uVar1 = countLeadingZeros((uint)*(byte *)(iVar6 + iVar5 + 4) - iVar4);
        return uVar1 >> 5;
      }
      iVar2 = iVar2 + 4;
      iVar6 = iVar6 + 1;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
  }
  return 0;
}

