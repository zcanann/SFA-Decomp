// Function: FUN_800128a8
// Entry: 800128a8
// Size: 84 bytes

void FUN_800128a8(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_80023d8c(0xe88,0x10);
  *param_1 = iVar1;
  param_1[1] = *param_1 + 0xaf0;
  param_1[2] = param_1[1] + 800;
  return;
}

