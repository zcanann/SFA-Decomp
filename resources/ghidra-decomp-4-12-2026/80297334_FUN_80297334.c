// Function: FUN_80297334
// Entry: 80297334
// Size: 32 bytes

void FUN_80297334(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *param_2 = *(undefined4 *)(iVar1 + 0x24);
  *param_3 = *(undefined4 *)(iVar1 + 0x28);
  *param_4 = *(undefined4 *)(iVar1 + 0x2c);
  return;
}

