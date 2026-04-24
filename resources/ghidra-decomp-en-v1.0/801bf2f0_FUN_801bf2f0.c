// Function: FUN_801bf2f0
// Entry: 801bf2f0
// Size: 140 bytes

void FUN_801bf2f0(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(int *)(*(int *)(iVar1 + 0x40c) + 0x18) != 0) {
    FUN_8001f384();
  }
  FUN_80036fa4(param_1,3);
  if (*(int *)(param_1 + 200) != 0) {
    FUN_8002cbc4();
    *(undefined4 *)(param_1 + 200) = 0;
  }
  (**(code **)(*DAT_803dcab8 + 0x40))(param_1,iVar1,0);
  return;
}

