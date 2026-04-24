// Function: FUN_80012888
// Entry: 80012888
// Size: 84 bytes

void FUN_80012888(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_80023cc8(0xe88,0x10,0);
  *param_1 = iVar1;
  param_1[1] = *param_1 + 0xaf0;
  param_1[2] = param_1[1] + 800;
  return;
}

