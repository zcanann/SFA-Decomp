// Function: FUN_8022d780
// Entry: 8022d780
// Size: 72 bytes

void FUN_8022d780(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_80036fa4(param_1,0x26);
  DAT_803ddd88 = 0;
  if (*(int *)(iVar1 + 0x450) != 0) {
    FUN_8001f384();
  }
  return;
}

