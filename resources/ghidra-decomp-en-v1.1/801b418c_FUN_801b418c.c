// Function: FUN_801b418c
// Entry: 801b418c
// Size: 264 bytes

void FUN_801b418c(int param_1)

{
  int iVar1;
  uint uVar2;
  float local_18 [4];
  
  local_18[0] = FLOAT_803e55a8;
  iVar1 = FUN_80036f50(10,param_1,local_18);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  uVar2 = FUN_80020078(0x3e3);
  if (uVar2 == 0) {
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
    FUN_80041110();
  }
  return;
}

