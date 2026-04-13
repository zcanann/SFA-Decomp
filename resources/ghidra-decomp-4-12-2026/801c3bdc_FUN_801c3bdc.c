// Function: FUN_801c3bdc
// Entry: 801c3bdc
// Size: 92 bytes

void FUN_801c3bdc(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(uint *)(iVar1 + 0x140) != 0) {
    FUN_8001f448(*(uint *)(iVar1 + 0x140));
    *(undefined4 *)(iVar1 + 0x140) = 0;
    *(undefined *)(iVar1 + 0x144) = 0;
  }
  (**(code **)(*DAT_803dd6d4 + 0x24))(iVar1);
  return;
}

