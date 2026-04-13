// Function: FUN_801d23ac
// Entry: 801d23ac
// Size: 100 bytes

void FUN_801d23ac(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
    FUN_80038524(param_1,0,(float *)(iVar1 + 0x20),(undefined4 *)(iVar1 + 0x24),
                 (float *)(iVar1 + 0x28),0);
  }
  return;
}

