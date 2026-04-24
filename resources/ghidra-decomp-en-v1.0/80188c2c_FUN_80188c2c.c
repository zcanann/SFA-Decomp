// Function: FUN_80188c2c
// Entry: 80188c2c
// Size: 80 bytes

void FUN_80188c2c(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar1 + 0x10) != 0) {
    FUN_8002cbc4();
    FUN_80037cb0(param_1,*(undefined4 *)(iVar1 + 0x10));
  }
  return;
}

