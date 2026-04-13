// Function: FUN_801d7a68
// Entry: 801d7a68
// Size: 76 bytes

void FUN_801d7a68(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  int iVar1;
  int *piVar2;
  undefined8 uVar3;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  iVar1 = *piVar2;
  if ((iVar1 != 0) && (param_10 == 0)) {
    uVar3 = FUN_80037da8(param_9,iVar1);
    FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar2);
  }
  return;
}

