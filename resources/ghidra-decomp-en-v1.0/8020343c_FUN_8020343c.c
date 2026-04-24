// Function: FUN_8020343c
// Entry: 8020343c
// Size: 136 bytes

void FUN_8020343c(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  FUN_80036fa4(param_1,3);
  FUN_800139c8(*(undefined4 *)(iVar1 + 0x24));
  if (*(int *)(param_1 + 200) != 0) {
    FUN_8002cbc4();
    *(undefined4 *)(param_1 + 200) = 0;
  }
  (**(code **)(*DAT_803dcab8 + 0x40))(param_1,iVar2,3);
  return;
}

