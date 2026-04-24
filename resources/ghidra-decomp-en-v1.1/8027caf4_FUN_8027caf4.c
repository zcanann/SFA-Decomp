// Function: FUN_8027caf4
// Entry: 8027caf4
// Size: 252 bytes

void FUN_8027caf4(int param_1,int param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int *piVar7;
  
  if (param_2 < param_3) {
    uVar1 = param_2 + param_3;
    piVar7 = (int *)(param_1 + param_2 * 4);
    iVar6 = *piVar7;
    piVar3 = (int *)(param_1 + (((int)uVar1 >> 1) + (uint)((int)uVar1 < 0 && (uVar1 & 1) != 0)) * 4)
    ;
    iVar4 = param_2 + 1;
    *piVar7 = *piVar3;
    iVar2 = (param_3 + 1) - iVar4;
    *piVar3 = iVar6;
    piVar5 = (int *)(param_1 + iVar4 * 4);
    piVar3 = piVar7;
    iVar6 = param_2;
    if (iVar4 <= param_3) {
      do {
        if (*(uint *)(*piVar5 + 0x1c) < *(uint *)(*piVar7 + 0x1c)) {
          iVar4 = piVar3[1];
          iVar6 = iVar6 + 1;
          piVar3 = piVar3 + 1;
          *piVar3 = *piVar5;
          *piVar5 = iVar4;
        }
        piVar5 = piVar5 + 1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    iVar2 = *piVar7;
    piVar3 = (int *)(param_1 + iVar6 * 4);
    *piVar7 = *piVar3;
    *piVar3 = iVar2;
    FUN_8027caf4(param_1,param_2,iVar6 + -1);
    FUN_8027caf4(param_1,iVar6 + 1,param_3);
  }
  return;
}

