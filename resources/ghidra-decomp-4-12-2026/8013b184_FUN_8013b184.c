// Function: FUN_8013b184
// Entry: 8013b184
// Size: 484 bytes

void FUN_8013b184(undefined2 *param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined2 local_28 [2];
  ushort local_24;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  iVar1 = *(int *)(iVar3 + 0x24);
  local_1c = *(undefined4 *)(iVar3 + 0x3d8);
  local_18 = *(undefined4 *)(iVar3 + 0x3dc);
  local_14 = *(undefined4 *)(iVar3 + 0x3e0);
  local_28[0] = *param_1;
  if (*(short *)(iVar1 + 0x46) == 0x1ca) {
    local_24 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x28))();
    local_24 = local_24 & 0xff;
  }
  else if (*(short *)(iVar1 + 0x46) == 0x160) {
    local_24 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x28))();
    local_24 = local_24 & 0xff;
  }
  else {
    local_24 = 0;
  }
  uVar2 = FUN_80022264(0,4);
  if (uVar2 == 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0xca,local_28,0x200001,0xffffffff,0);
  }
  uVar2 = FUN_80022264(0,4);
  if (uVar2 == 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0xcb,local_28,0x200001,0xffffffff,0);
  }
  local_1c = *(undefined4 *)(iVar3 + 0x3e4);
  local_18 = *(undefined4 *)(iVar3 + 1000);
  local_14 = *(undefined4 *)(iVar3 + 0x3ec);
  local_28[0] = *param_1;
  uVar2 = FUN_80022264(0,4);
  if (uVar2 == 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0xca,local_28,0x200001,0xffffffff,0);
  }
  uVar2 = FUN_80022264(0,4);
  if (uVar2 == 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0xcb,local_28,0x200001,0xffffffff,0);
  }
  return;
}

