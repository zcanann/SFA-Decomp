// Function: FUN_8020c194
// Entry: 8020c194
// Size: 148 bytes

void FUN_8020c194(void)

{
  int iVar1;
  
  iVar1 = FUN_80286840();
  if (*(short *)(iVar1 + 0x46) == 0x709) {
    FUN_80221fc8(iVar1,*(int *)(iVar1 + 0xb8) + 0x14,3,(uint *)(*(int *)(iVar1 + 0xb8) + 100));
  }
  FUN_8003b9ec(iVar1);
  FUN_8028688c();
  return;
}

