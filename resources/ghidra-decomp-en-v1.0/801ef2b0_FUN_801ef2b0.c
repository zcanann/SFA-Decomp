// Function: FUN_801ef2b0
// Entry: 801ef2b0
// Size: 168 bytes

void FUN_801ef2b0(undefined2 *param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(code **)(param_1 + 0x5e) = FUN_801eea68;
  *(undefined4 *)(iVar2 + 0x4c) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(iVar2 + 0x50) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(iVar2 + 0x54) = *(undefined4 *)(param_1 + 10);
  *(undefined *)(iVar2 + 100) = 100;
  *param_1 = 0x4000;
  uVar1 = FUN_80054d54(0x156);
  *(undefined4 *)(iVar2 + 0x18) = uVar1;
  uVar1 = FUN_80054d54(0xc0d);
  *(undefined4 *)(iVar2 + 0x1c) = uVar1;
  uVar1 = FUN_80013ec8(0x79,1);
  *(undefined4 *)(iVar2 + 0x14) = uVar1;
  FUN_80035960(param_1,1);
  FUN_80037200(param_1,10);
  return;
}

