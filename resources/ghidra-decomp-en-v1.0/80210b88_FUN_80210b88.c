// Function: FUN_80210b88
// Entry: 80210b88
// Size: 88 bytes

void FUN_80210b88(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_80210980;
  *(undefined *)(iVar1 + 8) = 2;
  FUN_8008016c(iVar1 + 4);
  FUN_800200e8(0xe24,1);
  FUN_8000a380(3,2,1000);
  return;
}

