// Function: FUN_80080138
// Entry: 80080138
// Size: 332 bytes

void FUN_80080138(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  int *piVar8;
  int iVar9;
  int iVar10;
  int *piVar11;
  uint uVar12;
  
  iVar1 = (param_2 + -1) / 9 + (param_2 + -1 >> 0x1f);
  for (iVar4 = 1; iVar4 <= iVar1 - (iVar1 >> 0x1f); iVar4 = iVar4 * 3 + 1) {
  }
  do {
    if (iVar4 < 1) {
      iVar4 = 1;
      if (1 < param_2) {
        if ((8 < param_2 + -1) && (uVar12 = param_2 - 2U >> 3, 1 < param_2 + -8)) {
          do {
            iVar4 = iVar4 + 8;
            uVar12 = uVar12 - 1;
          } while (uVar12 != 0);
        }
        iVar1 = param_2 - iVar4;
        if (iVar4 < param_2) {
          do {
            iVar1 = iVar1 + -1;
          } while (iVar1 != 0);
        }
      }
      return;
    }
    iVar10 = iVar4 + 1;
    iVar1 = iVar10 * 8;
    piVar8 = (int *)(param_1 + iVar1);
    iVar2 = param_2 - iVar10;
    if (iVar10 < param_2) {
      do {
        iVar5 = *piVar8;
        iVar6 = piVar8[1];
        piVar7 = (int *)(param_1 + iVar1);
        for (iVar9 = iVar10; iVar4 < iVar9; iVar9 = iVar9 - iVar4) {
          piVar11 = (int *)(param_1 + (iVar9 - iVar4) * 8);
          iVar3 = *piVar11;
          if (iVar3 <= iVar5) break;
          *piVar7 = iVar3;
          piVar7[1] = piVar11[1];
          piVar7 = piVar7 + iVar4 * -2;
        }
        piVar7 = (int *)(param_1 + iVar9 * 8);
        *piVar7 = iVar5;
        piVar7[1] = iVar6;
        piVar8 = piVar8 + 2;
        iVar10 = iVar10 + 1;
        iVar1 = iVar1 + 8;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    iVar4 = iVar4 / 3;
  } while( true );
}

