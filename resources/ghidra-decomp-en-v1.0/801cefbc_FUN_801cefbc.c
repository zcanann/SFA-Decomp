// Function: FUN_801cefbc
// Entry: 801cefbc
// Size: 84 bytes

void FUN_801cefbc(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_80036fa4(param_1,0x4d);
  if ((*(byte *)(iVar1 + 0x43c) & 0x40) != 0) {
    (**(code **)(*DAT_803dca68 + 100))();
  }
  return;
}

