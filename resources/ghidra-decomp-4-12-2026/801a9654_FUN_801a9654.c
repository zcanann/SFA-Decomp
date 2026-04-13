// Function: FUN_801a9654
// Entry: 801a9654
// Size: 168 bytes

void FUN_801a9654(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  
  uVar2 = *(undefined4 *)(param_9 + 0xb8);
  iVar1 = *(int *)(param_9 + 200);
  if (iVar1 != 0) {
    uVar3 = FUN_80037da8(param_9,iVar1);
    FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1);
  }
  (**(code **)(*DAT_803dd6d4 + 0x24))(uVar2);
  (**(code **)(*DAT_803dd6f4 + 8))(param_9,0xffff,0,0,0);
  FUN_8000b7dc(param_9,0x7f);
  return;
}

