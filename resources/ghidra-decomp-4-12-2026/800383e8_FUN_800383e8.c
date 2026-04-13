// Function: FUN_800383e8
// Entry: 800383e8
// Size: 64 bytes

void FUN_800383e8(int param_1,int param_2,undefined4 *param_3,undefined4 *param_4,
                 undefined4 *param_5)

{
  int iVar1;
  
  iVar1 = param_2 * 0x18;
  *param_3 = *(undefined4 *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) + iVar1);
  *param_4 = *(undefined4 *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) + iVar1 + 4);
  *param_5 = *(undefined4 *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) + iVar1 + 8);
  return;
}

