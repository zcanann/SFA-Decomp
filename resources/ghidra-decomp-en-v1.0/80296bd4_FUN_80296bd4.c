// Function: FUN_80296bd4
// Entry: 80296bd4
// Size: 32 bytes

void FUN_80296bd4(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *param_2 = *(undefined4 *)(iVar1 + 0x24);
  *param_3 = *(undefined4 *)(iVar1 + 0x28);
  *param_4 = *(undefined4 *)(iVar1 + 0x2c);
  return;
}

