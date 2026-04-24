// Function: FUN_801c086c
// Entry: 801c086c
// Size: 172 bytes

undefined4 FUN_801c086c(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x1e));
  if (uVar1 != 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,*(short *)(iVar2 + 0x1a) + 0x4c6,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x4c8,0,2,0xffffffff,0);
  }
  return 0;
}

