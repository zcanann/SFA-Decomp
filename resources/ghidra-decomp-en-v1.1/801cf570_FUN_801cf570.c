// Function: FUN_801cf570
// Entry: 801cf570
// Size: 84 bytes

void FUN_801cf570(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8003709c(param_1,0x4d);
  if ((*(byte *)(iVar1 + 0x43c) & 0x40) != 0) {
    (**(code **)(*DAT_803dd6e8 + 100))();
  }
  return;
}

