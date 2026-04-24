// Function: FUN_801e48e8
// Entry: 801e48e8
// Size: 200 bytes

void FUN_801e48e8(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x54);
  if (*(int *)(iVar1 + 0x50) != 0) {
    *(ushort *)(iVar1 + 0x60) = *(ushort *)(iVar1 + 0x60) & 0xfffe;
    iVar1 = 0x32;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0xa7,0,1,0xffffffff,0);
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
    iVar1 = 10;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0xab,0,1,0xffffffff,0);
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return;
}

