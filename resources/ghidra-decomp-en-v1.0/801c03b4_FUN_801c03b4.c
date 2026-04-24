// Function: FUN_801c03b4
// Entry: 801c03b4
// Size: 160 bytes

void FUN_801c03b4(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x1e));
  if (iVar1 != 0) {
    (**(code **)(*DAT_803dca88 + 8))(param_1,*(short *)(iVar2 + 0x1a) + 0x4c6,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x4c8,0,2,0xffffffff,0);
  }
  return;
}

