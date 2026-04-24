// Function: FUN_801e8c50
// Entry: 801e8c50
// Size: 148 bytes

void FUN_801e8c50(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (((*(byte *)(iVar2 + 0x97) >> 6 & 1) == 0) &&
     (iVar1 = (**(code **)(**(int **)(*(int *)(iVar2 + 0x90) + 0x68) + 0x2c))
                        (*(int *)(iVar2 + 0x90),*(undefined *)(*(int *)(param_1 + 0x4c) + 0x19)),
     iVar1 != 0)) {
    *(byte *)(iVar2 + 0x97) = *(byte *)(iVar2 + 0x97) & 0x7f | 0x80;
  }
  FUN_8011f670(0);
  (**(code **)(**(int **)(*(int *)(iVar2 + 0x90) + 0x68) + 0x40))(*(int *)(iVar2 + 0x90),0xffffffff)
  ;
  return;
}

