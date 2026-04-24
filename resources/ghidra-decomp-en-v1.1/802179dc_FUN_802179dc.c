// Function: FUN_802179dc
// Entry: 802179dc
// Size: 108 bytes

void FUN_802179dc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if (*(int *)(iVar1 + 0x194) != 0) {
    FUN_80220104(*(int *)(iVar1 + 0x194));
    param_1 = FUN_80037da8(param_9,*(int *)(iVar1 + 0x194));
  }
  if (*(int *)(iVar1 + 400) != 0) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(iVar1 + 400));
  }
  FUN_8003709c(param_9,3);
  return;
}

