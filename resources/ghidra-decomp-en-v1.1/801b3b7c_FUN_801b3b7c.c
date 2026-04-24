// Function: FUN_801b3b7c
// Entry: 801b3b7c
// Size: 144 bytes

void FUN_801b3b7c(int param_1)

{
  int iVar1;
  
  if ((*(char **)(param_1 + 0xb8))[2] == '\x01') {
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
  }
  else if (*(int *)(param_1 + 0xf4) == 0) {
    iVar1 = (int)**(char **)(param_1 + 0xb8);
    if (iVar1 != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(iVar1,param_1,0xffffffff);
    }
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  return;
}

