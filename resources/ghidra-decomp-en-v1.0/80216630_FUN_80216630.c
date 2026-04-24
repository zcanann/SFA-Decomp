// Function: FUN_80216630
// Entry: 80216630
// Size: 64 bytes

void FUN_80216630(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar1 + 0x10) != 0) {
    FUN_80023800();
    *(undefined4 *)(iVar1 + 0x10) = 0;
  }
  return;
}

