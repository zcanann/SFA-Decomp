// Function: FUN_800322e8
// Entry: 800322e8
// Size: 232 bytes

void FUN_800322e8(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  
  iVar1 = (param_2 + -1) / 9 + (param_2 + -1 >> 0x1f);
  for (iVar9 = 1; iVar9 <= iVar1 - (iVar1 >> 0x1f); iVar9 = iVar9 * 3 + 1) {
  }
  for (; 0 < iVar9; iVar9 = iVar9 / 3) {
    iVar6 = iVar9 + 1;
    iVar1 = iVar6 * 4;
    piVar4 = (int *)(param_1 + iVar1);
    iVar2 = param_2 - iVar6;
    if (iVar6 < param_2) {
      do {
        iVar8 = *piVar4;
        piVar3 = (int *)(param_1 + iVar1);
        iVar7 = iVar6;
        while ((iVar9 < iVar7 &&
               (iVar5 = *(int *)(param_1 + (iVar7 - iVar9) * 4),
               *(float *)(iVar8 + 4) < *(float *)(iVar5 + 4)))) {
          *piVar3 = iVar5;
          piVar3 = piVar3 + -iVar9;
          iVar7 = iVar7 - iVar9;
        }
        *(int *)(param_1 + iVar7 * 4) = iVar8;
        piVar4 = piVar4 + 1;
        iVar6 = iVar6 + 1;
        iVar1 = iVar1 + 4;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  return;
}

