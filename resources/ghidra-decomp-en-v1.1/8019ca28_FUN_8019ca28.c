// Function: FUN_8019ca28
// Entry: 8019ca28
// Size: 96 bytes

void FUN_8019ca28(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  int iVar1;
  int iVar2;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if (param_10 == 0) {
    iVar2 = 0;
    do {
      if (*(int *)(iVar1 + 0x68c) != 0) {
        param_1 = FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               *(int *)(iVar1 + 0x68c));
      }
      iVar1 = iVar1 + 4;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 6);
  }
  return;
}

