// Function: FUN_801a356c
// Entry: 801a356c
// Size: 120 bytes

void FUN_801a356c(int param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar2 = -1;
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_80036fa4(param_1,0x21);
  if (param_2 == 0) {
    iVar3 = iVar3 + -4;
    while( true ) {
      iVar4 = iVar3 + 4;
      iVar2 = iVar2 + 1;
      if (0xe < iVar2) break;
      piVar1 = (int *)(iVar3 + 0x694);
      iVar3 = iVar4;
      if (*piVar1 != 0) {
        FUN_8002cbc4();
      }
    }
  }
  return;
}

