// Function: FUN_801a4660
// Entry: 801a4660
// Size: 168 bytes

void FUN_801a4660(int param_1)

{
  int iVar1;
  
  if (*(int *)(param_1 + 0xf4) == 0) {
    iVar1 = *(int *)(param_1 + 0x4c);
    if ((*(short *)(iVar1 + 0x1c) != 0) && (**(byte **)(param_1 + 0xb8) >> 5 != 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x54))();
    }
    iVar1 = (int)*(char *)(iVar1 + 0x1e);
    if (iVar1 != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(iVar1,param_1,0xffffffff);
    }
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  return;
}

