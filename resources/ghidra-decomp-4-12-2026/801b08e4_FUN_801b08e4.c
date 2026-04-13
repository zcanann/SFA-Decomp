// Function: FUN_801b08e4
// Entry: 801b08e4
// Size: 56 bytes

void FUN_801b08e4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  int iVar1;
  
  if ((param_10 == 0) && (iVar1 = *(int *)(*(int *)(param_9 + 0xb8) + 8), iVar1 != 0)) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1);
  }
  return;
}

