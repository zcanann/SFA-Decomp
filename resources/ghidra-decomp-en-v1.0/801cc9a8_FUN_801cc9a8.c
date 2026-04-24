// Function: FUN_801cc9a8
// Entry: 801cc9a8
// Size: 132 bytes

void FUN_801cc9a8(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar1 + 0x36) & 2) == 0) {
    FUN_800066e0(param_1,param_1,1,0,0,0);
    *(byte *)(iVar1 + 0x36) = *(byte *)(iVar1 + 0x36) | 2;
  }
  (**(code **)(*DAT_803dca78 + 0x18))(param_1);
  return;
}

