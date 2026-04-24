// Function: FUN_801b3bd8
// Entry: 801b3bd8
// Size: 264 bytes

void FUN_801b3bd8(int param_1)

{
  int iVar1;
  int iVar2;
  float local_18 [4];
  
  local_18[0] = FLOAT_803e4910;
  iVar1 = FUN_80036e58(10,param_1,local_18);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  iVar2 = FUN_8001ffb4(0x3e3);
  if (iVar2 == 0) {
    *(undefined *)(param_1 + 0xe4) = 0;
    if ((iVar1 == 0) ||
       (iVar1 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x20))(iVar1,param_1), iVar1 == 0)) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    }
  }
  else {
    *(undefined *)(param_1 + 0xe4) = 1;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) && (*(int *)(param_1 + 0x74) != 0)) {
    FUN_80041018(param_1);
  }
  return;
}

