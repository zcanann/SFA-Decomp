// Function: FUN_801a3b20
// Entry: 801a3b20
// Size: 120 bytes

void FUN_801a3b20(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  iVar2 = -1;
  iVar3 = *(int *)(param_9 + 0xb8);
  uVar5 = FUN_8003709c(param_9,0x21);
  if (param_10 == 0) {
    iVar3 = iVar3 + -4;
    while( true ) {
      iVar4 = iVar3 + 4;
      iVar2 = iVar2 + 1;
      if (0xe < iVar2) break;
      piVar1 = (int *)(iVar3 + 0x694);
      iVar3 = iVar4;
      if (*piVar1 != 0) {
        uVar5 = FUN_8002cc9c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar1);
      }
    }
  }
  return;
}

