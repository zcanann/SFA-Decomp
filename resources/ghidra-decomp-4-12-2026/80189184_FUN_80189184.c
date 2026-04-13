// Function: FUN_80189184
// Entry: 80189184
// Size: 80 bytes

void FUN_80189184(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x10);
  if (iVar1 != 0) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1);
    FUN_80037da8(param_9,*(int *)(iVar2 + 0x10));
  }
  return;
}

