// Function: FUN_802be790
// Entry: 802be790
// Size: 144 bytes

void FUN_802be790(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  undefined8 uVar2;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if (*(uint **)(iVar1 + 0x14f8) != (uint *)0x0) {
    FUN_80026d4c(*(uint **)(iVar1 + 0x14f8));
  }
  FUN_8003709c(param_9,10);
  if ((*(byte *)(iVar1 + 0x14ec) >> 1 & 1) != 0) {
    (**(code **)(*DAT_803dd6e8 + 0x60))();
  }
  if (*(int *)(iVar1 + 0xb54) != 0) {
    uVar2 = FUN_80037da8(param_9,*(int *)(iVar1 + 0xb54));
    FUN_8002cc9c(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(iVar1 + 0xb54));
  }
  return;
}

