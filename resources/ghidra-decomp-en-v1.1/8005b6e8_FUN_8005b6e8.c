// Function: FUN_8005b6e8
// Entry: 8005b6e8
// Size: 232 bytes

void FUN_8005b6e8(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  
  iVar1 = param_2 / 9 + (param_2 >> 0x1f);
  for (iVar9 = 1; iVar9 <= iVar1 - (iVar1 >> 0x1f); iVar9 = iVar9 * 3 + 1) {
  }
  for (; 0 < iVar9; iVar9 = iVar9 / 3) {
    iVar6 = iVar9 + 1;
    iVar1 = iVar6 * 4;
    iVar5 = param_1 + iVar1;
    iVar2 = (param_2 + 1) - iVar6;
    if (iVar6 <= param_2) {
      do {
        uVar8 = *(uint *)(iVar5 + -4);
        iVar4 = param_1 + iVar1;
        iVar7 = iVar6;
        while ((iVar9 < iVar7 &&
               (uVar3 = *(uint *)(param_1 + (iVar7 - iVar9) * 4 + -4), uVar3 < uVar8))) {
          *(uint *)(iVar4 + -4) = uVar3;
          iVar4 = iVar4 + iVar9 * -4;
          iVar7 = iVar7 - iVar9;
        }
        *(uint *)(param_1 + iVar7 * 4 + -4) = uVar8;
        iVar5 = iVar5 + 4;
        iVar6 = iVar6 + 1;
        iVar1 = iVar1 + 4;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  return;
}

