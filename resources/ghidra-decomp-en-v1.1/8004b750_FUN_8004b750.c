// Function: FUN_8004b750
// Entry: 8004b750
// Size: 84 bytes

void FUN_8004b750(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_80023d8c(0x1960,0x10);
  *param_1 = iVar1;
  param_1[1] = *param_1 + 0xfe0;
  param_1[2] = param_1[1] + 0x7f0;
  return;
}

