// Function: FUN_801bf8a4
// Entry: 801bf8a4
// Size: 140 bytes

void FUN_801bf8a4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  int iVar2;
  undefined8 uVar3;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  uVar1 = *(uint *)(*(int *)(iVar2 + 0x40c) + 0x18);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
  }
  uVar3 = FUN_8003709c(param_9,3);
  if (*(int *)(param_9 + 200) != 0) {
    FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
    *(undefined4 *)(param_9 + 200) = 0;
  }
  (**(code **)(*DAT_803dd738 + 0x40))(param_9,iVar2,0);
  return;
}

