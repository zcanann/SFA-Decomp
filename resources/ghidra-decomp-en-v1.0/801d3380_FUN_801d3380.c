// Function: FUN_801d3380
// Entry: 801d3380
// Size: 84 bytes

void FUN_801d3380(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dca78 + 0x14))();
  if (*(int *)(iVar1 + 0x270) != 0) {
    FUN_8001f384();
    *(undefined4 *)(iVar1 + 0x270) = 0;
  }
  return;
}

