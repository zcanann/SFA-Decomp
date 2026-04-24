// Function: FUN_801c02b8
// Entry: 801c02b8
// Size: 172 bytes

undefined4 FUN_801c02b8(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x1e));
  if (iVar1 != 0) {
    (**(code **)(*DAT_803dca88 + 8))(param_1,*(short *)(iVar2 + 0x1a) + 0x4c6,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x4c8,0,2,0xffffffff,0);
  }
  return 0;
}

